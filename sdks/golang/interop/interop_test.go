// Package interop tests the Go SDK against the Rust reference
// implementation (krymux-tunnel.exe), the same way interop/test-interop.mjs
// tests the Node SDK:
//
//   - Phase A: Rust server + Go client — 1 MiB echo through a TCP echo
//     origin, byte-exact, for both "none" and "deflate"; plus fail-closed
//     pin verification.
//   - Phase B: Go server + Rust client — the Rust client's SOCKS5 frontend
//     tunnels a raw SOCKS5 dial (Go-side) through the Go server into the
//     echo origin; 1 MiB byte-exact for "none" and "deflate".
//
// The Rust binary is expected at ../../../target/release/krymux-tunnel.exe
// (or $ECTUN_BIN).
package interop

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/fly88oj/krymux-go/pkg/client"
	"github.com/fly88oj/krymux-go/pkg/keys"
	"github.com/fly88oj/krymux-go/pkg/mux"
	"github.com/fly88oj/krymux-go/pkg/server"
)

func rustBin(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("ECTUN_BIN"); p != "" {
		return p
	}
	rel := filepath.Join("..", "..", "..", "target", "release", "krymux-tunnel.exe")
	p, err := filepath.Abs(rel)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		p2 := strings.TrimSuffix(p, ".exe")
		if _, err2 := os.Stat(p2); err2 == nil {
			return p2
		}
		t.Fatalf("rust binary not found at %s (build it with: cargo build --release)", p)
	}
	return p
}

// keygen runs `krymux-tunnel keygen` and returns the new fingerprint; the
// PEM files land in dir/<name>.{key,crt}.pem (the Rust save_identity layout).
func keygen(t *testing.T, bin, dir, role, name string) string {
	t.Helper()
	out, err := exec.Command(bin, "keygen", "--out", dir, "--role", role, "--name", name).CombinedOutput()
	if err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	m := regexp.MustCompile(`fingerprint: (sha256:[0-9a-f]{64})`).FindSubmatch(out)
	if m == nil {
		t.Fatalf("keygen output has no fingerprint:\n%s", out)
	}
	return string(m[1])
}

// startRust spawns a rust process, keeps it alive for the test, and kills it
// during cleanup.
func startRust(t *testing.T, bin string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn %s %s: %v", bin, args, err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})
	return cmd
}

// echoOrigin starts a plain TCP echo server and returns its address.
func echoOrigin(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// waitTCPReady polls the address until a TCP connect succeeds — readiness
// probing, not an idle sleep.
func waitTCPReady(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s never became ready", addr)
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// payload builds 1 MiB: half random (incompressible), half repetitive.
func payload1MiB(t *testing.T) []byte {
	t.Helper()
	p := make([]byte, 1<<20)
	if _, err := rand.Read(p[:1<<19]); err != nil {
		t.Fatal(err)
	}
	for i := 1 << 19; i < len(p); i++ {
		p[i] = byte(i % 251)
	}
	return p
}

func mustHashEqual(t *testing.T, got, want []byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("length mismatch: got %d bytes, want %d", len(got), len(want))
	}
	gh, wh := sha256.Sum256(got), sha256.Sum256(want)
	if gh != wh {
		t.Fatalf("content mismatch: sha256 %x vs %x", gh[:8], wh[:8])
	}
}

// ---------------- Phase A: Rust server + Go client ----------------

func TestRustServerGoClientEcho1MiB(t *testing.T) {
	bin := rustBin(t)
	dir := t.TempDir()

	serverFp := keygen(t, bin, dir, "server", "server")

	// Go client identity, round-tripped through the PEM layout the Rust
	// tools read and write — proves cross-tool certificate compatibility.
	goID, err := keys.GenerateIdentity("interop-go-client")
	if err != nil {
		t.Fatal(err)
	}
	keyPath, certPath, err := keys.SaveIdentity(dir, goID, "goclient")
	if err != nil {
		t.Fatal(err)
	}
	goID, err = keys.LoadIdentity(keyPath, certPath)
	if err != nil {
		t.Fatal(err)
	}

	echoAddr := echoOrigin(t)
	listenPort := freePort(t)
	writeJSON(t, filepath.Join(dir, "server.json"), map[string]any{
		"listen":   fmt.Sprintf("127.0.0.1:%d", listenPort),
		"identity": map[string]string{"key": filepath.Join(dir, "server.key.pem"), "cert": filepath.Join(dir, "server.crt.pem")},
		"auth": map[string]any{
			"mode":         "whitelist",
			"fingerprints": []string{goID.Fingerprint},
		},
		"routes": []map[string]any{
			{"host": []string{"echo"}, "upstream": []any{"127.0.0.1", echoPort(t, echoAddr)}},
		},
		"clientTargets": map[string]any{"enabled": false},
	})

	startRust(t, bin, "server", "--config", filepath.Join(dir, "server.json"))
	addr := fmt.Sprintf("127.0.0.1:%d", listenPort)
	waitTCPReady(t, addr, 20*time.Second)

	session, err := client.Connect(addr, goID, serverFp, client.WithName("interop-go"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer session.Close("done")

	if _, err := session.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	payload := payload1MiB(t)
	for _, algo := range []string{"none", "deflate"} {
		t.Run(algo, func(t *testing.T) {
			host := "echo"
			st, err := session.OpenStream(mux.Target{Host: &host, Port: 9, Hint: "raw"}, algo)
			if err != nil {
				t.Fatalf("open stream: %v", err)
			}
			if st.Compression() != algo {
				t.Fatalf("negotiated %q, want %q", st.Compression(), algo)
			}
			go func() {
				_, _ = st.Write(payload)
				_ = st.CloseWrite() // FIN: half-close
			}()
			got, err := io.ReadAll(st) // until the peer's FIN
			if err != nil {
				t.Fatalf("read echo: %v", err)
			}
			mustHashEqual(t, got, payload)
			_ = st.Close()
		})
	}

	// pin verification is fail-closed: a wrong pin must be refused before
	// the session comes up.
	evil, err := keys.GenerateIdentity("wrong-pin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Connect(addr, goID, evil.Fingerprint); err == nil {
		t.Fatal("connect with a wrong server pin must fail")
	} else if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("expected a pin mismatch error, got: %v", err)
	}
}

func echoPort(t *testing.T, addr string) int {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var p int
	fmt.Sscanf(port, "%d", &p)
	return p
}

// ---------------- Phase B: Go server + Rust client (SOCKS5) ----------------

func TestGoServerRustClientSocks5Echo1MiB(t *testing.T) {
	bin := rustBin(t)
	dir := t.TempDir()

	// Rust client identity from the Rust keygen, whitelisted on the Go
	// server — proves the Go server accepts rustls/rcgen certificates.
	bobFp := keygen(t, bin, dir, "client", "bob")

	goSrvID, err := keys.GenerateIdentity("interop-go-server")
	if err != nil {
		t.Fatal(err)
	}

	echoAddr := echoOrigin(t)
	listenPort := freePort(t)
	socksPort := freePort(t)

	srv, err := server.Listen(
		fmt.Sprintf("127.0.0.1:%d", listenPort),
		goSrvID,
		[]string{bobFp},
		func(target mux.Target) (net.Conn, error) {
			return net.Dial("tcp", echoAddr)
		},
		server.WithName("interop-go-server"),
	)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })

	cfgPath := filepath.Join(dir, "client.json")
	payload := payload1MiB(t)

	for _, comp := range []string{"none", "deflate"} {
		t.Run(comp, func(t *testing.T) {
			writeJSON(t, cfgPath, map[string]any{
				"endpoint":          fmt.Sprintf("127.0.0.1:%d", listenPort),
				"identity":          map[string]string{"key": filepath.Join(dir, "bob.key.pem"), "cert": filepath.Join(dir, "bob.crt.pem")},
				"serverFingerprint": goSrvID.Fingerprint,
				"socks5":            fmt.Sprintf("127.0.0.1:%d", socksPort),
				"compression":       comp,
				"keepaliveSec":      30,
			})
			startRust(t, bin, "client", "--config", cfgPath)
			socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
			waitTCPReady(t, socksAddr, 20*time.Second)

			got := socks5Echo(t, socksAddr, "echo.test", 9, payload)
			mustHashEqual(t, got, payload)
		})
	}
}

// socks5Echo performs a raw SOCKS5 CONNECT through proxy and round-trips
// payload through whatever the tunnel routes to.
func socks5Echo(t *testing.T, proxy, host string, port uint16, payload []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		t.Fatalf("socks5 dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))

	// greeting: no-auth
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("socks5 greeting: %v", err)
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatalf("socks5 greeting reply: %v", err)
	}
	if head[0] != 5 || head[1] != 0 {
		t.Fatalf("socks5 greeting refused: %v", head)
	}

	// CONNECT echo.test:9 (domain address type)
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("socks5 request: %v", err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(conn, rep); err != nil {
		t.Fatalf("socks5 reply: %v", err)
	}
	if rep[1] != 0 {
		t.Fatalf("socks5 CONNECT failed with code %d", rep[1])
	}

	// round-trip the payload
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("socks5 send: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("socks5 receive: %v", err)
	}
	return got
}
