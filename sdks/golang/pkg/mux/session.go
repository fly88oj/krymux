// Package mux implements the Krymux multiplexing session: many logical
// full-duplex streams over one ordered encrypted byte stream, wire-compatible
// with the Rust reference implementation (crates/krymux/src/mux.rs).
//
// Goroutines per session: socket reader (frame dispatch, decompression),
// socket writer (ordered frame emission with light batching), credit ticker
// (sub-threshold WINDOW tail flush), keepalive (optional). Ordering per
// stream is guaranteed by construction.
package mux

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fly88oj/krymux-go/pkg/compress"
	"github.com/fly88oj/krymux-go/pkg/frame"
)

// Protocol and tuning constants (mirroring the Rust implementation).
const (
	ProtocolVersion = 1

	DefaultWindow  uint32 = 262_144
	defaultMaxData uint32 = frame.DefaultMaxData
	maxStreamsCap         = 1024

	helloTimeout   = 10 * time.Second
	openAckTimeout = 12 * time.Second
	pingTimeout    = 12 * time.Second
	creditTick     = 5 * time.Millisecond
	maxExpansion   = 32 << 20 // decompressed-chunk expansion cap (attack guard)
	writerBatchCap = 256 * 1024
	// max frames coalesced into one write: bounds queuing latency when a
	// burst of tiny frames (WINDOW credits) is pending — the Go caps of the
	// shared bounded-per-write rule (see ../../WRITER_CONTRACT.md)
	writerBatchFrames = 16
)

// ErrSessionClosed is returned once the session has been torn down (by
// either side).
var ErrSessionClosed = errors.New("krymux: session closed")

// Target describes where a stream should end up, as requested by the opener.
type Target struct {
	Host *string // remote host (nil for unix-socket or port-only targets)
	Port uint16  // remote TCP port (0 when Unix is set)
	Unix *string // unix domain socket path, when the target is a socket
	Hint string  // routing hint, e.g. "raw" or a service name
}

// HostString returns the target host or "" when absent.
func (t Target) HostString() string {
	if t.Host != nil {
		return *t.Host
	}
	return ""
}

// String renders a human-readable description of the target.
func (t Target) String() string {
	if t.Unix != nil {
		return "unix:" + *t.Unix
	}
	return fmt.Sprintf("%s:%d", t.HostString(), t.Port)
}

// StreamHandler receives streams the peer opens (server side).
type StreamHandler func(stream *Stream, target Target)

// SessionOptions are tunables for one multiplexed session.
type SessionOptions struct {
	IsClient     bool   // true on the client side (odd stream ids)
	Name         string // display name exchanged in HELLO
	RxWindow     uint32 // initial per-stream receive window, in bytes (0 = default)
	RxWindowMax  uint32 // upper bound for dynamic window growth (reserved; grants are threshold-based)
	MaxStreams   int    // maximum concurrent streams per session (0 = default)
	KeepaliveSec int    // keepalive interval in seconds (0 disables)
}

func (o *SessionOptions) fill() {
	if o.RxWindow == 0 {
		o.RxWindow = DefaultWindow
	}
	if o.RxWindowMax < o.RxWindow {
		o.RxWindowMax = o.RxWindow
	}
	if o.MaxStreams <= 0 {
		o.MaxStreams = maxStreamsCap
	}
	if o.Name == "" {
		if o.IsClient {
			o.Name = "client"
		} else {
			o.Name = "server"
		}
	}
}

// Session is a multiplexed session over one ordered byte stream.
type Session struct {
	conn     net.Conn
	isClient bool
	name     string
	opts     SessionOptions

	writeCh chan []byte
	doneCh  chan struct{}
	closing atomic.Bool
	closed  atomic.Bool

	mu            sync.Mutex // guards streams, nextID, peerSupported, peerHelloName
	streams       map[uint32]*Stream
	nextID        uint32
	peerSupported []string
	peerHelloName string
	maxStreams    int
	rxWindow      uint32

	helloSeen   atomic.Bool
	peerMaxData atomic.Uint32
	peerWindow  atomic.Int64

	handler StreamHandler

	helloCh chan error // buffered 1: peer HELLO result

	pingsMu  sync.Mutex
	pings    map[[16]byte]chan time.Time
	lastPong atomic.Int64 // unix ms
}

// helloMsg is the JSON capabilities exchange carried by a HELLO frame.
type helloMsg struct {
	V            int      `json:"v"`
	Mode         string   `json:"mode"`
	Name         string   `json:"name"`
	MaxDataFrame uint32   `json:"maxDataFrame"`
	RxWindow     uint32   `json:"rxWindow"`
	MaxStreams   int      `json:"maxStreams"`
	Compression  []string `json:"compression"`
}

// openMsg is the JSON target description carried by an OPEN frame.
type openMsg struct {
	Host        *string `json:"host"`
	Port        uint16  `json:"port"`
	Unix        *string `json:"unix"`
	Hint        string  `json:"hint"`
	Meta        any     `json:"meta"`
	Compression string  `json:"compression"`
}

// openAckMsg is the JSON verdict carried by an OPEN_ACK frame.
type openAckMsg struct {
	OK          bool    `json:"ok"`
	Compression string  `json:"compression,omitempty"`
	Upstream    *string `json:"upstream,omitempty"`
	Code        string  `json:"code,omitempty"`
	Reason      string  `json:"reason,omitempty"`
}

type goawayMsg struct {
	Reason string `json:"reason"`
}

type closeMsg struct {
	Code string `json:"code"`
}

// NewClientSession starts a client-side session on io: sends HELLO, spawns
// the session goroutines, and waits (up to 10 s) for the peer's HELLO.
func NewClientSession(io net.Conn, opts SessionOptions) (*Session, error) {
	opts.IsClient = true
	return newSession(io, opts, nil)
}

// NewServerSession starts a server-side session on io. handler receives
// streams the peer opens.
func NewServerSession(io net.Conn, opts SessionOptions, handler StreamHandler) (*Session, error) {
	opts.IsClient = false
	return newSession(io, opts, handler)
}

func newSession(io net.Conn, opts SessionOptions, handler StreamHandler) (*Session, error) {
	opts.fill()
	s := &Session{
		conn:          io,
		isClient:      opts.IsClient,
		name:          opts.Name,
		opts:          opts,
		writeCh:       make(chan []byte, 1024),
		doneCh:        make(chan struct{}),
		streams:       make(map[uint32]*Stream),
		nextID:        1,
		maxStreams:    opts.MaxStreams,
		rxWindow:      opts.RxWindow,
		peerSupported: []string{compress.AlgoNone},
		peerMaxData:   atomic.Uint32{},
		peerWindow:    atomic.Int64{},
		handler:       handler,
		helloCh:       make(chan error, 1),
		pings:         make(map[[16]byte]chan time.Time),
	}
	if !opts.IsClient {
		s.nextID = 2
	}
	s.peerMaxData.Store(frame.DefaultMaxData)
	s.peerWindow.Store(int64(DefaultWindow))
	s.lastPong.Store(nowMs())

	// HELLO
	mode := "client"
	if !opts.IsClient {
		mode = "server"
	}
	hello := helloMsg{
		V:            ProtocolVersion,
		Mode:         mode,
		Name:         opts.Name,
		MaxDataFrame: frame.DefaultMaxData,
		RxWindow:     opts.RxWindow,
		MaxStreams:   opts.MaxStreams,
		Compression:  compress.Supported(),
	}
	body, _ := json.Marshal(hello)
	s.trySend(frame.Encode(frame.Hello, 0, 0, body))

	go s.writeLoop()
	go s.readLoop()
	go s.creditTicker()
	if opts.KeepaliveSec > 0 {
		go s.keepaliveLoop(time.Duration(opts.KeepaliveSec) * time.Second)
	}

	select {
	case err := <-s.helloCh:
		if err != nil {
			s.shutdown(false, "")
			return nil, err
		}
	case <-time.After(helloTimeout):
		s.shutdown(false, "")
		return nil, errors.New("krymux: peer did not send HELLO")
	}
	return s, nil
}

// OpenStream opens a new stream toward target and waits for the peer's
// OPEN_ACK. compressionReq selects the algorithm ("auto", "none", "deflate",
// or "deflate:<level>") and is negotiated down to what the peer supports.
func (s *Session) OpenStream(target Target, compressionReq string) (*Stream, error) {
	if s.IsClosed() {
		return nil, ErrSessionClosed
	}
	s.mu.Lock()
	if len(s.streams) >= s.maxStreams {
		s.mu.Unlock()
		return nil, fmt.Errorf("krymux: max streams reached (%d)", s.maxStreams)
	}
	sid := s.nextID
	s.nextID += 2
	s.mu.Unlock()

	algo := compress.Negotiate(compressionReq, s.peerList())
	level, _ := compress.ParseLevel(compressionReq)
	st := s.newStream(sid, target, algo, level)
	st.ackCh = make(chan ackResult, 1)

	s.mu.Lock()
	s.streams[sid] = st
	s.mu.Unlock()

	if target.Hint == "" {
		target.Hint = "raw"
	}
	open := openMsg{
		Host:        target.Host,
		Port:        target.Port,
		Unix:        target.Unix,
		Hint:        target.Hint,
		Meta:        nil,
		Compression: algo,
	}
	body, _ := json.Marshal(open)
	if err := s.sendWait(frame.Encode(frame.Open, 0, sid, body)); err != nil {
		s.removeStream(sid)
		return nil, err
	}

	select {
	case r := <-st.ackCh:
		if r.err != nil {
			s.removeStream(sid)
			return nil, r.err
		}
		return st, nil
	case <-time.After(openAckTimeout):
		s.removeStream(sid)
		return nil, errors.New("krymux: open stream timeout")
	case <-s.doneCh:
		s.removeStream(sid)
		return nil, ErrSessionClosed
	}
}

// Close tears the session down, telling the peer why via GOAWAY.
func (s *Session) Close(reason string) { s.shutdown(true, reason) }

// IsClosed reports whether the session has been torn down (by either side).
func (s *Session) IsClosed() bool { return s.closed.Load() }

// WaitClosed resolves when the session ends (peer disconnect, GOAWAY, or
// Close).
func (s *Session) WaitClosed() { <-s.doneCh }

// Ping measures round-trip latency with a PING/PONG exchange.
func (s *Session) Ping() (time.Duration, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, fmt.Errorf("krymux: ping nonce: %w", err)
	}
	ch := make(chan time.Time, 1)
	s.pingsMu.Lock()
	s.pings[nonce] = ch
	s.pingsMu.Unlock()
	defer func() {
		s.pingsMu.Lock()
		delete(s.pings, nonce)
		s.pingsMu.Unlock()
	}()
	if err := s.sendWait(frame.Encode(frame.Ping, 0, 0, nonce[:])); err != nil {
		return 0, err
	}
	select {
	case t0 := <-ch:
		return time.Since(t0), nil
	case <-time.After(pingTimeout):
		return 0, errors.New("krymux: ping timeout")
	case <-s.doneCh:
		return 0, ErrSessionClosed
	}
}

// PeerName returns the display name the peer sent in HELLO ("" before it).
func (s *Session) PeerName() string { return s.peerHelloName }

// ---------------- internal machinery ----------------

func (s *Session) trySend(f []byte) bool {
	select {
	case s.writeCh <- f:
		return true
	case <-s.doneCh:
		return false
	default:
		return false
	}
}

func (s *Session) sendWait(f []byte) error {
	select {
	case s.writeCh <- f:
		return nil
	case <-s.doneCh:
		return ErrSessionClosed
	}
}

func (s *Session) peerList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.peerSupported))
	copy(out, s.peerSupported)
	return out
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	st := s.streams[id]
	delete(s.streams, id)
	s.mu.Unlock()
	if st != nil {
		st.retired.Store(true)
		st.decomp.Close() // release the decoder goroutine, if any
	}
}

// shutdown tears the session down; notify sends a GOAWAY first (best effort,
// exactly like the Rust close()). Idempotent.
func (s *Session) shutdown(notify bool, reason string) {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	if notify {
		body, _ := json.Marshal(goawayMsg{Reason: reason})
		// best-effort, exactly like the Rust send_control/try_send: a full
		// writer queue must not wedge teardown
		s.trySend(frame.Encode(frame.Goaway, 0, 0, body))
	}
	s.closing.Store(true)
	s.teardownStreams()
	close(s.doneCh)
	// a session start still parked on the peer HELLO must fail fast (e.g.
	// the server rejected the client cert and hung up)
	select {
	case s.helloCh <- ErrSessionClosed:
	default:
	}
}

// fatal is the reader/protocol-error teardown path.
func (s *Session) fatal(notify bool, reason string) { s.shutdown(notify, reason) }

func (s *Session) teardownStreams() {
	s.mu.Lock()
	streams := make([]*Stream, 0, len(s.streams))
	for _, st := range s.streams {
		streams = append(streams, st)
	}
	s.streams = make(map[uint32]*Stream)
	s.mu.Unlock()
	for _, st := range streams {
		st.sessionGone()
	}
}

func nowMs() int64 {
	return time.Now().UnixMilli()
}

// writeFrameBatch flushes a coalesced run of frames with one writev-style
// call. On a plain TCP connection net.Buffers.WriteTo issues a single writev
// syscall with no intermediate copy (unlike concatenating into one buffer);
// on other conns (e.g. *tls.Conn) it degrades to sequential writes, which is
// still correct — crypto/tls re-chunks every write into records anyway.
func (s *Session) writeFrameBatch(frames [][]byte) error {
	if len(frames) == 1 {
		_, err := s.conn.Write(frames[0])
		return err
	}
	buf := net.Buffers(frames)
	_, err := buf.WriteTo(s.conn)
	return err
}

func (s *Session) writeLoop() {
	var batch [][]byte
	batchBytes := 0
	for {
		select {
		case f := <-s.writeCh:
			batch = append(batch, f)
			batchBytes = len(f)
		case <-s.doneCh:
			// drain whatever is already queued (GOAWAY included), then stop
			s.drainAndClose()
			return
		}
		// coalesce an already-queued burst into one writev
		for batchBytes < writerBatchCap && len(batch) < writerBatchFrames {
			select {
			case f := <-s.writeCh:
				batch = append(batch, f)
				batchBytes += len(f)
			default:
				goto write
			}
		}
	write:
		if err := s.writeFrameBatch(batch); err != nil {
			s.fatal(false, "")
			return
		}
		batch = batch[:0]
		batchBytes = 0
		if s.closing.Load() {
			s.drainAndClose()
			return
		}
	}
}

// drainAndClose flushes any frames still sitting in writeCh and closes the
// socket; the session is over either way, so a write error here is fine.
func (s *Session) drainAndClose() {
	var batch [][]byte
	for {
		select {
		case f := <-s.writeCh:
			batch = append(batch, f)
			continue
		default:
		}
		break
	}
	if len(batch) > 0 {
		_ = s.writeFrameBatch(batch)
	}
	_ = s.conn.Close()
}

func (s *Session) readLoop() {
	hdr := make([]byte, frame.HeaderSize)
	ourMaxData := int(frame.DefaultMaxData)
	// Payload scratch grown on demand and reused across frames: every
	// consumer (decompress feed, deliver's rbuf copy, JSON decode, PONG echo)
	// copies out of it synchronously, so the per-frame allocation is pure
	// waste under bulk DATA (256 x 64 KiB per 16 MiB otherwise).
	var scratch []byte
	for {
		if _, err := io.ReadFull(s.conn, hdr); err != nil {
			s.fatal(false, "")
			return
		}
		h, err := frame.ParseHeader(hdr)
		if err != nil {
			s.trySend(frame.Encode(frame.Goaway, 0, 0, []byte(`{"reason":"bad frame"}`)))
			s.fatal(false, "")
			return
		}
		if int(h.Length) > frame.MaxPayloadFor(h.Type, ourMaxData) {
			s.trySend(frame.Encode(frame.Goaway, 0, 0, []byte(`{"reason":"oversized frame"}`)))
			s.fatal(false, "")
			return
		}
		if int(h.Length) > cap(scratch) {
			scratch = make([]byte, h.Length)
		}
		payload := scratch[:h.Length]
		if len(payload) > 0 {
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				s.fatal(false, "")
				return
			}
		}
		if !s.helloSeen.Load() && h.Type != frame.Hello {
			s.fatal(true, "frame before HELLO")
			return
		}
		if err := s.handleFrame(h, payload); err != nil {
			s.trySend(frame.Encode(frame.Goaway, 0, 0, []byte(`{"reason":"protocol error"}`)))
			s.fatal(false, "")
			return
		}
	}
}

func (s *Session) handleFrame(h frame.Header, payload []byte) error {
	switch h.Type {
	case frame.Hello:
		if s.helloSeen.Swap(true) {
			return errors.New("second HELLO mid-session")
		}
		var hello helloMsg
		if err := json.Unmarshal(payload, &hello); err != nil {
			return fmt.Errorf("bad HELLO json: %w", err)
		}
		if hello.V != ProtocolVersion {
			return fmt.Errorf("unsupported protocol version %d", hello.V)
		}
		// clamp peer-advertised tunables (a hostile 0 would deadlock windows)
		maxData := hello.MaxDataFrame
		if maxData == 0 {
			maxData = frame.DefaultMaxData
		}
		maxData = clampU32(maxData, 1024, uint32(frame.HardMaxFrame))
		rxw := hello.RxWindow
		if rxw == 0 {
			rxw = DefaultWindow
		}
		rxw = clampU32(rxw, 16*1024, 256*1024*1024)
		comp := hello.Compression
		if len(comp) == 0 {
			comp = []string{compress.AlgoNone}
		}
		s.mu.Lock()
		s.peerSupported = comp
		s.peerHelloName = hello.Name
		s.mu.Unlock()
		s.peerMaxData.Store(maxData)
		s.peerWindow.Store(int64(rxw))
		s.helloCh <- nil
		return nil

	case frame.Open:
		return s.handleOpen(h, payload)

	case frame.OpenAck:
		var ack openAckMsg
		if err := json.Unmarshal(payload, &ack); err != nil {
			return nil // tolerate a malformed ACK on an unknown/vanished stream
		}
		s.mu.Lock()
		st := s.streams[h.StreamID]
		s.mu.Unlock()
		if st != nil {
			st.deliverAck(ack)
		}
		return nil

	case frame.Data:
		s.mu.Lock()
		st := s.streams[h.StreamID]
		s.mu.Unlock()
		if st == nil {
			return nil // data for an unknown/retired stream is dropped
		}
		compressed := h.Flags&frame.FlagCompressed != 0
		fin := h.Flags&frame.FlagFIN != 0
		plain := payload
		if compressed && len(payload) > 0 {
			p, err := st.decomp.Push(payload)
			if err != nil {
				st.abortStream("decompress error")
				return nil
			}
			if len(p) > maxExpansion {
				st.abortStream("decompressed chunk exceeds expansion cap")
				return nil
			}
			plain = p
		}
		if len(plain) > 0 {
			st.deliver(plain)
		}
		if fin {
			if tail, _ := st.decomp.Finish(); len(tail) > 0 {
				st.deliver(tail)
			}
			st.receiveEOF()
		}
		return nil

	case frame.Window:
		if len(payload) != 4 {
			return fmt.Errorf("bad WINDOW frame length %d", len(payload))
		}
		delta := binary.BigEndian.Uint32(payload)
		s.mu.Lock()
		st := s.streams[h.StreamID]
		s.mu.Unlock()
		if st != nil {
			st.grantCredits(int64(delta))
		}
		return nil

	case frame.Close:
		s.mu.Lock()
		st := s.streams[h.StreamID]
		s.mu.Unlock()
		if st != nil {
			st.peerAbort()
		}
		return nil

	case frame.Ping:
		s.trySend(frame.Encode(frame.Pong, 0, 0, payload))
		return nil

	case frame.Pong:
		if len(payload) == 16 {
			var nonce [16]byte
			copy(nonce[:], payload)
			s.lastPong.Store(nowMs())
			s.pingsMu.Lock()
			if ch, ok := s.pings[nonce]; ok {
				delete(s.pings, nonce)
				ch <- time.Now()
			}
			s.pingsMu.Unlock()
		}
		return nil

	case frame.Goaway:
		return errors.New("peer sent GOAWAY")

	default:
		return fmt.Errorf("unknown frame type %d", h.Type)
	}
}

func (s *Session) handleOpen(h frame.Header, payload []byte) error {
	if s.isClient {
		return errors.New("client received OPEN")
	}
	if h.StreamID == 0 || h.StreamID%2 == 0 {
		return fmt.Errorf("bad stream id in OPEN: %d", h.StreamID)
	}
	s.mu.Lock()
	if len(s.streams) >= s.maxStreams {
		s.mu.Unlock()
		s.sendAck(h.StreamID, openAckMsg{OK: false, Code: "maxstreams", Reason: fmt.Sprintf("limit %d", s.maxStreams)})
		return nil
	}
	if _, dup := s.streams[h.StreamID]; dup {
		s.mu.Unlock()
		s.sendAck(h.StreamID, openAckMsg{OK: false, Code: "duplicate", Reason: "stream id already open"})
		return nil
	}
	s.mu.Unlock()

	var open openMsg
	if err := json.Unmarshal(payload, &open); err != nil {
		return fmt.Errorf("bad OPEN json: %w", err)
	}
	target := Target{Host: open.Host, Port: open.Port, Unix: open.Unix, Hint: open.Hint}
	if target.Hint == "" {
		target.Hint = "raw"
	}
	requested := open.Compression
	if requested == "" {
		requested = "auto"
	}
	algo := compress.Negotiate(requested, s.peerList())
	level, _ := compress.ParseLevel(requested)

	if s.handler == nil {
		s.sendAck(h.StreamID, openAckMsg{OK: false, Code: "nohandler", Reason: "server has no stream handler"})
		return nil
	}
	st := s.newStream(h.StreamID, target, algo, level)
	s.mu.Lock()
	// re-check under the lock: two racing OPENs for the same id
	if _, dup := s.streams[h.StreamID]; dup {
		s.mu.Unlock()
		s.sendAck(h.StreamID, openAckMsg{OK: false, Code: "duplicate", Reason: "stream id already open"})
		return nil
	}
	s.streams[h.StreamID] = st
	s.mu.Unlock()

	// pre-ack inbound data must still flow: the stream is registered above.
	// Like the Rust SDK, the handler OWNS the stream: it must Accept or
	// Reject it and may hand it off to another goroutine before returning.
	handler := s.handler
	go handler(st, target)
	return nil
}

func (s *Session) sendAck(sid uint32, ack openAckMsg) {
	body, _ := json.Marshal(ack)
	s.trySend(frame.Encode(frame.OpenAck, 0, sid, body))
}

func (s *Session) creditTicker() {
	t := time.NewTicker(creditTick)
	defer t.Stop()
	for {
		select {
		case <-s.doneCh:
			return
		case <-t.C:
		}
		if s.closed.Load() {
			return
		}
		s.mu.Lock()
		streams := make([]*Stream, 0, len(s.streams))
		for _, st := range s.streams {
			streams = append(streams, st)
		}
		s.mu.Unlock()
		for _, st := range streams {
			st.flushCreditTail()
		}
	}
}

func (s *Session) keepaliveLoop(interval time.Duration) {
	if interval < time.Second {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.doneCh:
			return
		case <-t.C:
		}
		if s.closed.Load() {
			return
		}
		last := s.lastPong.Load()
		if nowMs()-last > interval.Milliseconds()*3 {
			s.shutdown(true, "keepalive timeout")
			return
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return
		}
		if err := s.sendWait(frame.Encode(frame.Ping, 0, 0, nonce[:])); err != nil {
			return
		}
	}
}

func clampU32(v, lo, hi uint32) uint32 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
