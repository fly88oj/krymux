// echo-server: a minimal Krymux server example.
//
// It runs a local TCP echo origin and routes every tunnel stream to it:
//
//	krymux-tunnel style client -> [this server] -> echo origin (bytes echoed back)
//
// Usage:
//
//	go run ./examples/echo-server -addr 127.0.0.1:28443 -identity ./demo-server-id
//
// The server identity is generated on first run and persisted; print the
// fingerprint and put your client's fingerprint in -allow.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/fly88oj/krymux-go/pkg/keys"
	"github.com/fly88oj/krymux-go/pkg/mux"
	"github.com/fly88oj/krymux-go/pkg/server"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:28443", "listen address")
	identDir := flag.String("identity", "demo-server-id", "directory for the server identity")
	allow := flag.String("allow", "", "client fingerprint to whitelist (sha256:... or bare hex); repeatable via ';'")
	flag.Parse()

	identity, err := loadOrCreate(*identDir, "server")
	if err != nil {
		log.Fatalf("identity: %v", err)
	}
	fmt.Printf("server fingerprint: %s\n", identity.Fingerprint)

	if *allow == "" {
		log.Fatalf("no -allow fingerprint given: the server is fail-closed without a client whitelist")
	}
	whitelist := splitAndNormalize(*allow)

	// local echo origin: everything sent to it comes right back
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("echo origin: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	echoAddr := echoLn.Addr().String()
	fmt.Printf("echo origin: %s\n", echoAddr)

	srv, err := server.Listen(*addr, identity, whitelist,
		func(target mux.Target) (net.Conn, error) {
			fmt.Printf("stream -> %s (routed to echo origin)\n", target)
			return net.Dial("tcp", echoAddr)
		},
		server.WithName("echo-server"),
	)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	fmt.Printf("listening on %s\n", srv.Addr())
	log.Fatal(srv.Serve())
}

func loadOrCreate(dir, name string) (*keys.Identity, error) {
	keyPath := filepath.Join(dir, name+".key.pem")
	certPath := filepath.Join(dir, name+".crt.pem")
	if _, err := os.Stat(keyPath); err == nil {
		return keys.LoadIdentity(keyPath, certPath)
	}
	id, err := keys.GenerateIdentity("krymux-echo-server")
	if err != nil {
		return nil, err
	}
	if _, _, err := keys.SaveIdentity(dir, id, name); err != nil {
		return nil, err
	}
	return id, nil
}

func splitAndNormalize(s string) []string {
	var out []string
	for _, part := range splitSemicolon(s) {
		if fp, err := keys.NormalizeFingerprint(part); err == nil {
			out = append(out, fp)
		} else {
			log.Fatalf("bad fingerprint %q: %v", part, err)
		}
	}
	return out
}

func splitSemicolon(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ';' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	out = append(out, cur)
	return out
}
