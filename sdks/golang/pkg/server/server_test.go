package server_test

import (
	"crypto/sha256"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/fly88oj/krymux-go/pkg/client"
	"github.com/fly88oj/krymux-go/pkg/keys"
	"github.com/fly88oj/krymux-go/pkg/mux"
	"github.com/fly88oj/krymux-go/pkg/server"
)

// echoUpstream starts a plain TCP echo origin.
func echoUpstream(t *testing.T) string {
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

func TestConnectPinAndWhitelist(t *testing.T) {
	serverID, err := keys.GenerateIdentity("server-test")
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := keys.GenerateIdentity("client-test")
	if err != nil {
		t.Fatal(err)
	}
	strangerID, err := keys.GenerateIdentity("stranger")
	if err != nil {
		t.Fatal(err)
	}

	echoAddr := echoUpstream(t)
	srv, err := server.Listen("127.0.0.1:0", serverID, []string{clientID.Fingerprint},
		func(target mux.Target) (net.Conn, error) {
			return net.Dial("tcp", echoAddr)
		})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	t.Cleanup(func() { srv.Close() })
	addr := srv.Addr().String()

	// 1. happy path: pinned connect + echo
	sess, err := client.Connect(addr, clientID, serverID.Fingerprint, client.WithName("t"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	host := "echo"
	st, err := sess.OpenStream(mux.Target{Host: &host, Port: 9}, "deflate")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	payload := strings.Repeat("krymux tls loopback ", 8000)
	go func() { st.Write([]byte(payload)); st.CloseWrite() }()
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if sha256.Sum256(got) != sha256.Sum256([]byte(payload)) {
		t.Fatal("echo not byte-exact")
	}
	st.Close()
	sess.Close("done")

	// 2. wrong pin fails closed
	if _, err := client.Connect(addr, clientID, strangerID.Fingerprint); err == nil {
		t.Fatal("connect with a wrong pin must fail")
	} else if !strings.Contains(err.Error(), "fingerprint mismatch") &&
		!strings.Contains(err.Error(), "ALPN") {
		t.Fatalf("unexpected pin failure: %v", err)
	}

	// 3. non-whitelisted client is rejected (fail closed, quickly)
	start := time.Now()
	if _, err := client.Connect(addr, strangerID, serverID.Fingerprint); err == nil {
		t.Fatal("non-whitelisted client must be rejected")
	}
	if elapsed := time.Since(start); elapsed > 8*time.Second {
		t.Fatalf("whitelist rejection took %s; fail-closed should be prompt", elapsed)
	}

	// 4. empty whitelist refuses to even start
	if _, err := server.Listen("127.0.0.1:0", serverID, nil, nil); err == nil {
		t.Fatal("empty whitelist must be refused at Listen")
	}
}
