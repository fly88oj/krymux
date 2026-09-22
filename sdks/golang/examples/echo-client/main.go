// echo-client: a minimal Krymux client example.
//
// It connects to a Krymux server, opens a stream toward the "echo" target
// and round-trips a payload, verifying the echo is byte-exact.
//
// Usage:
//
//	go run ./examples/echo-client -server 127.0.0.1:28443 \
//	    -fp sha256:<server fingerprint> -identity ./demo-client-id \
//	    -size 1048576 -compression deflate
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/fly88oj/krymux-go/pkg/client"
	"github.com/fly88oj/krymux-go/pkg/keys"
	"github.com/fly88oj/krymux-go/pkg/mux"
)

// makePayload builds the echo payload: "random" is fully random,
// "mix" is half random (incompressible) + half repeating (compressible).
func makePayload(size int, pattern string) []byte {
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		log.Fatalf("payload: %v", err)
	}
	if pattern == "mix" && size >= 4 {
		half := size / 2
		unit := []byte("krymux-go-xlang-payload ")
		reps := half/len(unit) + 1
		copy(payload[half:], bytes.Repeat(unit, reps)[:size-half])
	}
	return payload
}

func main() {
	serverAddr := flag.String("server", "127.0.0.1:28443", "server address host:port")
	fp := flag.String("fp", "", "pinned server fingerprint (sha256:... or bare hex)")
	identDir := flag.String("identity", "demo-client-id", "directory for the client identity")
	size := flag.Int("size", 65536, "payload size in bytes")
	compression := flag.String("compression", "auto", "compression request: auto|none|deflate[:level]")
	pattern := flag.String("pattern", "random", "payload pattern: random | mix (half random, half compressible)")
	flag.Parse()

	if *fp == "" {
		log.Fatalf("no -fp given: the client is fail-closed without a pinned server fingerprint")
	}
	identity, err := loadOrCreate(*identDir, "client")
	if err != nil {
		log.Fatalf("identity: %v", err)
	}
	fmt.Printf("client fingerprint: %s\n", identity.Fingerprint)

	start := time.Now()
	session, err := client.Connect(*serverAddr, identity, *fp,
		client.WithName("echo-client"), client.WithKeepalive(30))
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer session.Close("done")
	if rtt, err := session.Ping(); err != nil {
		log.Fatalf("ping: %v", err)
	} else {
		fmt.Printf("tunnel up to %s (ping %s)\n", *serverAddr, rtt)
	}

	host := "echo"
	stream, err := session.OpenStream(mux.Target{Host: &host, Port: 9, Hint: "raw"}, *compression)
	if err != nil {
		log.Fatalf("open stream: %v", err)
	}
	defer stream.Close()
	fmt.Printf("stream open (compression=%s)\n", stream.Compression())

	payload := makePayload(*size, *pattern)
	want := sha256.Sum256(payload)

	go func() {
		_, _ = stream.Write(payload)
		_ = stream.CloseWrite() // half-close: FIN
	}()
	got, err := io.ReadAll(stream) // until the peer's FIN
	if err != nil {
		log.Fatalf("read echo: %v", err)
	}
	gotHash := sha256.Sum256(got)

	status := "MISMATCH"
	if gotHash == want {
		status = "byte-exact"
	}
	fmt.Printf("echoed %d bytes in %s: %s (sha256 %x)\n",
		len(got), time.Since(start).Round(time.Millisecond), status, gotHash[:8])
	if status == "MISMATCH" {
		os.Exit(1)
	}
}

func loadOrCreate(dir, name string) (*keys.Identity, error) {
	keyPath := filepath.Join(dir, name+".key.pem")
	certPath := filepath.Join(dir, name+".crt.pem")
	if _, err := os.Stat(keyPath); err == nil {
		return keys.LoadIdentity(keyPath, certPath)
	}
	id, err := keys.GenerateIdentity("krymux-echo-client")
	if err != nil {
		return nil, err
	}
	if _, _, err := keys.SaveIdentity(dir, id, name); err != nil {
		return nil, err
	}
	return id, nil
}
