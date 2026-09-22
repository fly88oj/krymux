// Package client implements the Krymux client: TLS 1.3 connect with server
// fingerprint pinning, mirroring crates/krymux/src/client.rs.
package client

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/fly88oj/krymux-go/pkg/keys"
	"github.com/fly88oj/krymux-go/pkg/mux"
)

// ALPN is the protocol identifier required on every krymux TLS connection.
const ALPN = "krymux"

// Options tune Connect. The zero value is fine.
type Options struct {
	// Name is the display name sent in the session HELLO (default "client").
	Name string
	// KeepaliveSec is the keepalive interval in seconds (0 disables).
	KeepaliveSec int
	// RxWindow is the initial per-stream receive window in bytes
	// (0 = mux.DefaultWindow).
	RxWindow uint32
	// DialTimeout bounds the TCP connect (default 5 s).
	DialTimeout time.Duration
	// HandshakeTimeout bounds the TLS handshake (default 10 s).
	HandshakeTimeout time.Duration
}

// Option is a functional option for Connect.
type Option func(*Options)

// WithName sets the HELLO display name.
func WithName(name string) Option { return func(o *Options) { o.Name = name } }

// WithKeepalive enables PING/PONG keepalive at the given interval.
func WithKeepalive(seconds int) Option { return func(o *Options) { o.KeepaliveSec = seconds } }

// WithRxWindow sets the initial per-stream receive window.
func WithRxWindow(bytes uint32) Option { return func(o *Options) { o.RxWindow = bytes } }

// Connect dials addr ("host:port"), performs the TLS 1.3 handshake with ALPN
// "krymux" and the given Ed25519 identity, verifies the pinned
// serverFingerprint (fail closed: mismatch or missing certificate is an
// error and the connection is dropped), and starts the multiplexed session.
func Connect(addr string, identity *keys.Identity, serverFingerprint string, opts ...Option) (*mux.Session, error) {
	var o Options
	for _, fn := range opts {
		fn(&o)
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 5 * time.Second
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 10 * time.Second
	}

	pinned, err := keys.NormalizeFingerprint(serverFingerprint)
	if err != nil {
		return nil, fmt.Errorf("client: server fingerprint: %w", err)
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("client: bad address %q: %w", addr, err)
	}
	tcp, err := dialAll(host, port, o.DialTimeout)
	if err != nil {
		return nil, err
	}
	if tc, ok := tcp.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPN},
		InsecureSkipVerify: true, // we pin the fingerprint ourselves below
		Certificates:       []tls.Certificate{identity.TLSCertificate()},
	}
	tlsConn := tls.Client(tcp, tlsCfg)
	_ = tlsConn.SetDeadline(time.Now().Add(o.HandshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("client: tls handshake: %w", err)
	}
	_ = tlsConn.SetDeadline(time.Time{})

	// fail-closed authorization: ALPN must match and the pinned fingerprint
	// must equal the presented certificate's.
	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != ALPN {
		tlsConn.Close()
		return nil, fmt.Errorf("client: server did not negotiate ALPN %q (got %q)", ALPN, state.NegotiatedProtocol)
	}
	if len(state.PeerCertificates) == 0 {
		tlsConn.Close()
		return nil, fmt.Errorf("client: server did not present a certificate")
	}
	fp, err := keys.FingerprintOfCertDER(state.PeerCertificates[0].Raw)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("client: parse server cert: %w", err)
	}
	if fp != pinned {
		tlsConn.Close()
		return nil, fmt.Errorf("client: server verification failed: fingerprint mismatch (got %s)", shortFp(fp))
	}

	session, err := mux.NewClientSession(tlsConn, mux.SessionOptions{
		Name:         o.Name,
		KeepaliveSec: o.KeepaliveSec,
		RxWindow:     o.RxWindow,
	})
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	return session, nil
}

func shortFp(fp string) string {
	if len(fp) < 19 {
		return fp
	}
	return fp[7:19]
}

// dialAll resolves every address and tries them in turn with a per-address
// timeout, so one blackholed family cannot starve the connect budget.
func dialAll(host, port string, timeout time.Duration) (net.Conn, error) {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("client: resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("client: no addresses for %s", host)
	}
	var lastErr error
	for _, a := range addrs {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(a, port), timeout)
		if err == nil {
			return conn, nil
		}
		lastErr = fmt.Errorf("%s: %w", a, err)
	}
	return nil, fmt.Errorf("client: connect %s:%s failed on all %d addresses; last: %w", host, port, len(addrs), lastErr)
}
