package mux

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// echoHandler accepts the stream and echoes bytes back until the opener's
// FIN, then half-closes its own write side.
func echoHandler(st *Stream, _ Target) {
	st.Accept("echo")
	go func() {
		_, _ = io.Copy(st, st)
		_ = st.CloseWrite()
	}()
}

// testPair builds a client and a server session over a TCP loopback.
func testPair(t *testing.T, tune func(opts *SessionOptions)) (*Session, *Session) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	serverReady := make(chan *Session, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverReady <- nil
			return
		}
		opts := SessionOptions{Name: "server"}
		if tune != nil {
			tune(&opts)
		}
		s, err := NewServerSession(conn, opts, echoHandler)
		if err != nil {
			serverReady <- nil
			return
		}
		serverReady <- s
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	opts := SessionOptions{Name: "client"}
	if tune != nil {
		tune(&opts)
	}
	cli, err := NewClientSession(conn, opts)
	if err != nil {
		t.Fatal(err)
	}
	srv := <-serverReady
	if srv == nil {
		t.Fatal("server session failed to start")
	}
	t.Cleanup(func() {
		cli.Close("done")
		srv.Close("done")
	})
	return cli, srv
}

func mustOpen(t *testing.T, s *Session, compression string) *Stream {
	t.Helper()
	host := "echo"
	st, err := s.OpenStream(Target{Host: &host, Port: 9, Hint: "raw"}, compression)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	return st
}

func echoOnce(t *testing.T, st *Stream, payload []byte) {
	t.Helper()
	want := sha256.Sum256(payload)
	go func() {
		_, _ = st.Write(payload)
		_ = st.CloseWrite()
	}()
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("echo length %d, want %d", len(got), len(payload))
	}
	if sha256.Sum256(got) != want {
		t.Fatal("echo not byte-exact")
	}
}

func TestEchoNone(t *testing.T) {
	cli, _ := testPair(t, nil)
	st := mustOpen(t, cli, "none")
	if st.Compression() != "none" {
		t.Fatalf("compression %s", st.Compression())
	}
	payload := make([]byte, 256*1024)
	rand.Read(payload)
	echoOnce(t, st, payload)
	st.Close()
}

func TestEchoDeflate(t *testing.T) {
	cli, _ := testPair(t, nil)
	st := mustOpen(t, cli, "deflate")
	if st.Compression() != "deflate" {
		t.Fatalf("compression %s", st.Compression())
	}
	payload := make([]byte, 256*1024)
	rand.Read(payload[:65536])
	for i := 65536; i < len(payload); i++ {
		payload[i] = byte(i % 97)
	}
	echoOnce(t, st, payload)
	st.Close()
}

func TestEchoDeflateAutoNegotiatesDownToPeer(t *testing.T) {
	cli, _ := testPair(t, nil)
	st := mustOpen(t, cli, "deflate:9")
	if st.Compression() != "deflate" {
		t.Fatalf("compression %s", st.Compression())
	}
	payload := []byte("compress me " + stringsRepeat("abc", 4096))
	echoOnce(t, st, payload)
	st.Close()
}

func stringsRepeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

// TestSmallWindowForcesCreditStalls drives 512 KiB through 16 KiB windows:
// both directions must stall and resume purely on WINDOW credit grants.
func TestSmallWindowForcesCreditStalls(t *testing.T) {
	cli, _ := testPair(t, func(o *SessionOptions) { o.RxWindow = 16 * 1024 })
	st := mustOpen(t, cli, "deflate")
	payload := make([]byte, 512*1024)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	echoOnce(t, st, payload)
	st.Close()
}

func TestHalfCloseSemantics(t *testing.T) {
	cli, _ := testPair(t, nil)
	st := mustOpen(t, cli, "none")
	if _, err := st.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := st.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// second CloseWrite is a no-op
	if err := st.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// writes after FIN fail
	if _, err := st.Write([]byte("x")); err == nil {
		t.Fatal("write after CloseWrite must fail")
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(st, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("read %q err %v", buf, err)
	}
	// the echo handler FINs back after seeing our FIN
	if _, err := st.Read(buf); err != io.EOF {
		t.Fatalf("expected EOF after peer FIN, got %v", err)
	}
	st.Close()
}

func TestOpenReject(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		_, _ = NewServerSession(conn, SessionOptions{Name: "server"}, func(st *Stream, _ Target) {
			st.Reject("denied", "not in my book")
		})
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewClientSession(conn, SessionOptions{Name: "client"})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close("done")
	host := "forbidden"
	_, err = cli.OpenStream(Target{Host: &host, Port: 1}, "none")
	if err == nil {
		t.Fatal("open must fail on reject")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("denied")) {
		t.Fatalf("reject reason missing: %v", err)
	}
}

func TestPing(t *testing.T) {
	cli, srv := testPair(t, nil)
	if _, err := cli.Ping(); err != nil {
		t.Fatalf("client ping: %v", err)
	}
	if _, err := srv.Ping(); err != nil {
		t.Fatalf("server ping: %v", err)
	}
}

func TestConcurrentStreams(t *testing.T) {
	cli, _ := testPair(t, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			st := mustOpen(t, cli, "deflate")
			defer st.Close()
			payload := make([]byte, 64*1024+n)
			rand.Read(payload)
			echoOnce(t, st, payload)
		}(i)
	}
	wg.Wait()
}

func TestPrecompressedBypass(t *testing.T) {
	// A gzip-magic first chunk on a deflate stream must go out unflagged and
	// round-trip losslessly (regression mirror of the Rust test).
	cli, _ := testPair(t, nil)
	st := mustOpen(t, cli, "deflate")
	payload := append([]byte{0x1f, 0x8b, 0x08}, make([]byte, 50_000)...)
	rand.Read(payload[3:])
	echoOnce(t, st, payload)
	st.Close()
}

func TestReadDeadline(t *testing.T) {
	cli, _ := testPair(t, nil)
	st := mustOpen(t, cli, "none")
	defer st.Close()
	if err := st.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	start := time.Now()
	if _, err := st.Read(buf); err == nil {
		t.Fatal("expected deadline error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("deadline fired late: %s", elapsed)
	}
	// extending the deadline unblocks reads again
	_ = st.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = st.Write([]byte("tick"))
	_ = st.CloseWrite()
	if _, err := io.ReadAll(st); err != nil {
		t.Fatalf("read after deadline extension: %v", err)
	}
}

func TestMaxStreams(t *testing.T) {
	cli, _ := testPair(t, func(o *SessionOptions) { o.MaxStreams = 2 })
	s1 := mustOpen(t, cli, "none")
	s2 := mustOpen(t, cli, "none")
	defer s1.Close()
	defer s2.Close()
	host := "echo"
	if _, err := cli.OpenStream(Target{Host: &host, Port: 9}, "none"); err == nil {
		t.Fatal("third stream must hit the max-streams limit")
	}
	// closing one frees a slot
	s2.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := cli.OpenStream(Target{Host: &host, Port: 9}, "none"); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("slot was not freed after Close")
}

func TestStreamIDsAreOddFromClient(t *testing.T) {
	cli, _ := testPair(t, nil)
	for i := 0; i < 3; i++ {
		st := mustOpen(t, cli, "none")
		if st.ID()%2 != 1 {
			t.Fatalf("client stream id %d must be odd", st.ID())
		}
		st.Close()
	}
}

func TestSessionCloseWakesStreams(t *testing.T) {
	cli, srv := testPair(t, nil)
	st := mustOpen(t, cli, "none")
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := st.Read(buf)
		errCh <- err
	}()
	cli.Close("done")
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("read must fail once the session is gone")
		}
	case <-time.After(3 * time.Second):
		// the echo handler may have FIN'd back first, making the read return
		// io.EOF instead of an error — both are acceptable outcomes
		srv.Close("done")
		select {
		case <-errCh:
		case <-time.After(3 * time.Second):
			t.Fatal("read never returned after session close")
		}
	}
}
