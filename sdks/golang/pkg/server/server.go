// Package server implements the Krymux server: TLS termination, client-cert
// fingerprint whitelisting (fail closed), and per-stream routing to upstream
// connections — mirroring crates/krymux/src/server.rs minus the WebSocket
// branch.
package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/fly88oj/krymux-go/pkg/keys"
	"github.com/fly88oj/krymux-go/pkg/mux"
)

// ALPN is the protocol identifier required on every krymux TLS connection.
const ALPN = "krymux"

// RouteFunc maps each incoming stream target (host:port / unix path) to an
// upstream connection. Returning an error rejects the stream with
// OPEN_ACK {"ok":false,"code":"unreachable"}.
type RouteFunc func(target mux.Target) (net.Conn, error)

// Server accepts Krymux TLS connections on a listener.
type Server struct {
	ln        net.Listener
	tlsCfg    *tls.Config
	whitelist map[string]struct{}
	route     RouteFunc
	opts      mux.SessionOptions

	mu               sync.Mutex
	closing          bool
	conns            map[net.Conn]struct{}
	handshakeTimeout time.Duration
}

// Options tune Listen.
type Options struct {
	// Name is the display name sent in the session HELLO (default "server").
	Name string
	// KeepaliveSec is the keepalive interval in seconds (0 disables).
	KeepaliveSec int
	// RxWindow is the initial per-stream receive window in bytes
	// (0 = mux.DefaultWindow).
	RxWindow uint32
	// HandshakeTimeout bounds each TLS handshake (default 10 s).
	HandshakeTimeout time.Duration
}

// Option is a functional option for Listen.
type Option func(*Options)

// WithName sets the HELLO display name.
func WithName(name string) Option { return func(o *Options) { o.Name = name } }

// WithKeepalive enables PING/PONG keepalive at the given interval.
func WithKeepalive(seconds int) Option { return func(o *Options) { o.KeepaliveSec = seconds } }

// WithRxWindow sets the initial per-stream receive window.
func WithRxWindow(bytes uint32) Option { return func(o *Options) { o.RxWindow = bytes } }

// Listen binds addr ("host:port") and prepares a Krymux server using the
// given Ed25519 identity. Only clients whose certificate fingerprint is in
// the whitelist are admitted (fail closed); each accepted stream is routed
// through route. Call Serve to run the accept loop.
func Listen(addr string, identity *keys.Identity, whitelist []string, route RouteFunc, opts ...Option) (*Server, error) {
	var o Options
	for _, fn := range opts {
		fn(&o)
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 10 * time.Second
	}
	if len(whitelist) == 0 {
		return nil, fmt.Errorf("server: empty whitelist would reject every client (fail closed); pass at least one fingerprint")
	}
	allowed := make(map[string]struct{}, len(whitelist))
	for _, fp := range whitelist {
		norm, err := keys.NormalizeFingerprint(fp)
		if err != nil {
			return nil, fmt.Errorf("server: whitelist entry: %w", err)
		}
		allowed[norm] = struct{}{}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("server: bind %s: %w", addr, err)
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPN},
		Certificates: []tls.Certificate{identity.TLSCertificate()},
		// any presented client certificate; authorization happens by
		// fingerprint after the handshake (fail closed)
		ClientAuth: tls.RequireAnyClientCert,
	}
	return &Server{
		ln:               ln,
		tlsCfg:           tlsCfg,
		whitelist:        allowed,
		route:            route,
		opts:             mux.SessionOptions{Name: o.Name, KeepaliveSec: o.KeepaliveSec, RxWindow: o.RxWindow},
		conns:            make(map[net.Conn]struct{}),
		handshakeTimeout: o.HandshakeTimeout,
	}, nil
}

// Addr returns the bound listener address.
func (srv *Server) Addr() net.Addr { return srv.ln.Addr() }

// Serve runs the accept loop until Close. It never returns a non-nil error
// except for listener faults after Close.
func (srv *Server) Serve() error {
	for {
		conn, err := srv.ln.Accept()
		if err != nil {
			srv.mu.Lock()
			closing := srv.closing
			srv.mu.Unlock()
			if closing {
				return nil
			}
			continue
		}
		go srv.serveConn(conn)
	}
}

// Close stops the listener and every live connection.
func (srv *Server) Close() error {
	srv.mu.Lock()
	if !srv.closing {
		srv.closing = true
	}
	conns := make([]net.Conn, 0, len(srv.conns))
	for c := range srv.conns {
		conns = append(conns, c)
	}
	srv.conns = make(map[net.Conn]struct{})
	srv.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	return srv.ln.Close()
}

func (srv *Server) trackConn(c net.Conn) {
	srv.mu.Lock()
	srv.conns[c] = struct{}{}
	srv.mu.Unlock()
}

func (srv *Server) untrackConn(c net.Conn) {
	srv.mu.Lock()
	delete(srv.conns, c)
	srv.mu.Unlock()
}

func (srv *Server) serveConn(tcp net.Conn) {
	if tc, ok := tcp.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	tlsConn := tls.Server(tcp, srv.tlsCfg)
	_ = tlsConn.SetDeadline(time.Now().Add(srv.handshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		tcp.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	srv.trackConn(tlsConn)
	defer func() {
		srv.untrackConn(tlsConn)
		tlsConn.Close()
	}()

	// authorization: ALPN + presented client-cert fingerprint (fail closed)
	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != ALPN {
		return
	}
	if len(state.PeerCertificates) == 0 {
		return
	}
	fp, err := keys.FingerprintOfCertDER(state.PeerCertificates[0].Raw)
	if err != nil {
		return
	}
	if _, ok := srv.whitelist[fp]; !ok {
		return
	}

	session, err := mux.NewServerSession(tlsConn, srv.opts, srv.streamHandler)
	if err != nil {
		return
	}
	session.WaitClosed()
}

// streamHandler routes one opened stream: resolve the upstream via the
// route callback, acknowledge, and pipe bytes both directions with standard
// half-close propagation.
func (srv *Server) streamHandler(stream *mux.Stream, target mux.Target) {
	if srv.route == nil {
		stream.Reject("nohandler", "server has no stream route")
		return
	}
	upstream, err := srv.route(target)
	if err != nil {
		stream.Reject("unreachable", fmt.Sprintf("route %s: %v", target, err))
		return
	}
	label := upstream.RemoteAddr().String()
	stream.Accept(label)
	defer upstream.Close()

	done := make(chan struct{}, 2)
	// tunnel -> upstream
	go func() {
		_, _ = io.Copy(upstream, stream)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite() // propagate the half-close
		}
		done <- struct{}{}
	}()
	// upstream -> tunnel
	go func() {
		_, _ = io.Copy(stream, upstream)
		_ = stream.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	<-done
}
