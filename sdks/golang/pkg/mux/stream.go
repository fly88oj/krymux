package mux

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fly88oj/krymux-go/pkg/compress"
	"github.com/fly88oj/krymux-go/pkg/frame"
)

// Errors surfaced by Stream.
var (
	ErrWriteClosed = errors.New("krymux: stream write side shut down")
	ErrStreamGone  = errors.New("krymux: stream closed")
)

type ackResult struct {
	upstream string
	err      error
}

// Stream is a logical full-duplex stream inside a Session. It implements
// net.Conn (deadlines included); CloseWrite performs the protocol half-close
// (empty DATA frame with the FIN flag).
//
// A Stream is safe for one concurrent reader and one concurrent writer, like
// a net.Conn.
type Stream struct {
	id     uint32
	sess   *Session
	Target Target

	algo string

	// ----- read side (fed by the session reader goroutine) -----
	rmu       sync.Mutex
	rcond     *sync.Cond
	rbuf      bytes.Buffer
	reof      bool
	rerr      error
	pending   uint32 // receive-window bytes consumed but not yet re-granted
	granted   uint32 // current grant (informational, mirrors Rust rx_granted)
	threshold uint32 // grant threshold: max(rxWindow/4, 16 KiB)
	rdeadline time.Time
	rdExpired bool

	// decompressor is owned exclusively by the session reader goroutine.
	decomp *compress.Decompressor

	// ----- write side -----
	// wmu serializes Write/CloseWrite and guards compressor state. It is
	// NEVER taken by session goroutines: a Write parked on credits holds wmu,
	// so the reader must not block on it (writeClosed is atomic instead).
	wmu         sync.Mutex
	creditMu    sync.Mutex // guards credits + werr + wdeadline
	creditCond  *sync.Cond
	credits     int64
	werr        error
	writeClosed atomic.Bool
	sniffed     bool
	bypassed    bool
	compressor  *compress.Compressor
	wdeadline   time.Time
	wdExpired   bool

	// ----- open handshake -----
	ackCh   chan ackResult
	ackDone atomic.Bool

	retired atomic.Bool
}

var _ net.Conn = (*Stream)(nil)

func (s *Session) newStream(id uint32, target Target, algo string, level int) *Stream {
	st := &Stream{
		id:         id,
		sess:       s,
		Target:     target,
		algo:       algo,
		threshold:  s.rxWindow / 4,
		decomp:     compress.NewDecompressor(algo),
		compressor: compress.NewCompressor(algo, level),
		credits:    s.peerWindow.Load(),
		granted:    s.rxWindow,
	}
	if st.threshold < 16*1024 {
		st.threshold = 16 * 1024
	}
	st.rcond = sync.NewCond(&st.rmu)
	st.creditCond = sync.NewCond(&st.creditMu)
	return st
}

// ID returns the stream's wire id.
func (st *Stream) ID() uint32 { return st.id }

// Compression returns the compression algorithm negotiated for this stream.
func (st *Stream) Compression() string { return st.algo }

// RxGranted returns the current receive-window grant for this stream.
func (st *Stream) RxGranted() uint32 {
	st.rmu.Lock()
	defer st.rmu.Unlock()
	return st.granted
}

// RemoteAddress returns a human-readable description of the stream's target.
func (st *Stream) RemoteAddress() string { return st.Target.String() }

// ---------------- net.Conn ----------------

type muxAddr struct{ network, addr string }

func (a muxAddr) Network() string { return a.network }
func (a muxAddr) String() string  { return a.addr }

func (st *Stream) LocalAddr() net.Addr {
	if st.sess.conn != nil {
		if la := st.sess.conn.LocalAddr(); la != nil {
			return la
		}
	}
	return muxAddr{"krymux", st.sess.name}
}

func (st *Stream) RemoteAddr() net.Addr { return muxAddr{"krymux", st.Target.String()} }

// SetDeadline sets both the read and write deadlines.
func (st *Stream) SetDeadline(t time.Time) error {
	if err := st.SetReadDeadline(t); err != nil {
		return err
	}
	return st.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls. A zero value
// disables the deadline.
func (st *Stream) SetReadDeadline(t time.Time) error {
	st.rmu.Lock()
	st.rdeadline = t
	st.rdExpired = false
	st.rcond.Broadcast()
	st.rmu.Unlock()
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls. A zero value
// disables the deadline.
func (st *Stream) SetWriteDeadline(t time.Time) error {
	st.creditMu.Lock()
	st.wdeadline = t
	st.wdExpired = false
	st.creditCond.Broadcast()
	st.creditMu.Unlock()
	return nil
}

// Read reads logical (decompressed) bytes from the stream. Credits are
// re-granted to the peer as the application consumes data — this is what
// paces the sender (receive-window flow control).
func (st *Stream) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	st.rmu.Lock()
	defer st.rmu.Unlock()
	var timer *time.Timer
	stopTimer := func() {
		if timer != nil {
			timer.Stop()
			timer = nil
		}
	}
	defer stopTimer()
	for {
		if st.rbuf.Len() > 0 {
			n, _ = st.rbuf.Read(p)
			st.grantCredit(uint32(n))
			return n, nil
		}
		if st.reof {
			return 0, io.EOF
		}
		if st.rerr != nil {
			return 0, st.rerr
		}
		if st.rdExpired {
			return 0, os.ErrDeadlineExceeded
		}
		if !st.rdeadline.IsZero() {
			d := time.Until(st.rdeadline)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			if timer == nil {
				timer = time.AfterFunc(d, func() {
					st.rmu.Lock()
					st.rdExpired = true
					st.rcond.Broadcast()
					st.rmu.Unlock()
				})
			}
		}
		st.rcond.Wait()
		stopTimer()
	}
}

// Write writes logical bytes to the stream, blocking until the peer has
// granted enough receive-window credit (pacing the sender). The payload is
// compressed with the stream's negotiated algorithm unless the first chunk
// sniffs as already-compressed content.
func (st *Stream) Write(p []byte) (int, error) {
	if st.writeClosed.Load() {
		return 0, ErrWriteClosed
	}
	st.wmu.Lock()
	defer st.wmu.Unlock()
	if st.writeClosed.Load() {
		return 0, ErrWriteClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	// first-chunk sniffing: pre-compressed payloads bypass compression, and
	// the frames then go out UNFLAGGED or the peer would feed raw bytes to
	// its decompressor and abort the stream
	if !st.sniffed {
		st.sniffed = true
		if st.algo != compress.AlgoNone && compress.LooksPrecompressed(p) {
			st.compressor = compress.NewCompressor(compress.AlgoNone, 0)
			st.bypassed = true
		}
	}
	compressed := !st.bypassed && st.algo != compress.AlgoNone
	wire := p
	if compressed {
		var err error
		wire, err = st.compressor.Push(p)
		if err != nil {
			st.failWrite(err)
			return 0, err
		}
	}
	if len(wire) == 0 {
		return len(p), nil
	}
	// charge-first partial grant (the same interleave as the Rust pump):
	// a partial grant suffices to start sending; waiting for the FULL
	// logical charge before the first byte would deadlock whenever the
	// peer's window is smaller than one chunk.
	charged, err := st.acquire(len(p))
	if err != nil {
		st.failWrite(err)
		return 0, err
	}
	if err := st.sendWire(wire, compressed); err != nil {
		st.failWrite(err)
		return 0, err
	}
	for charged < len(p) {
		more, err := st.acquire(len(p) - charged)
		if err != nil {
			st.failWrite(err)
			return 0, err
		}
		charged += more
	}
	return len(p), nil
}

// CloseWrite half-closes the send direction: an empty DATA frame carrying
// the FIN flag.
func (st *Stream) CloseWrite() error {
	// serialize the flag flip with in-flight Writes so the FIN can never
	// overtake data from a Write that already passed the closed check
	st.wmu.Lock()
	already := st.writeClosed.Swap(true)
	st.wmu.Unlock()
	if already {
		return nil
	}
	err := st.sess.sendWait(frame.Encode(frame.Data, frame.FlagFIN, st.id, nil))
	st.maybeRetire()
	return err
}

// Close aborts the stream. If the peer already FIN'd cleanly the stream is
// retired silently — mirroring the Rust drop semantics; otherwise the peer
// is told via a CLOSE frame so it does not mistake truncation for end of
// stream.
func (st *Stream) Close() error {
	st.writeClosed.Store(true)
	st.rmu.Lock()
	cleanEOF := st.reof
	st.rmu.Unlock()
	if cleanEOF {
		st.removeSelf()
		return nil
	}
	body, _ := json.Marshal(closeMsg{Code: "abort"})
	st.sess.trySend(frame.Encode(frame.Close, 0, st.id, body))
	st.wakeLocal(ErrStreamGone)
	st.removeSelf()
	return nil
}

// Accept acknowledges the stream server-side (sends OPEN_ACK ok). upstream
// is an informational label echoed to the opener ("" sends null).
func (st *Stream) Accept(upstream string) {
	if !st.ackDone.CompareAndSwap(false, true) {
		return
	}
	var up *string
	if upstream != "" {
		up = &upstream
	}
	body, _ := json.Marshal(openAckMsg{OK: true, Compression: st.algo, Upstream: up})
	st.sess.trySend(frame.Encode(frame.OpenAck, 0, st.id, body))
}

// Reject rejects the stream server-side (sends OPEN_ACK not-ok).
func (st *Stream) Reject(code, reason string) {
	if !st.ackDone.CompareAndSwap(false, true) {
		return
	}
	body, _ := json.Marshal(openAckMsg{OK: false, Code: code, Reason: reason})
	st.sess.trySend(frame.Encode(frame.OpenAck, 0, st.id, body))
	st.wakeLocal(ErrStreamGone)
}

// ---------------- internals ----------------

// deliver appends logical bytes for the application (session reader only).
func (st *Stream) deliver(plain []byte) {
	st.rmu.Lock()
	st.rbuf.Write(plain)
	st.rcond.Broadcast()
	st.rmu.Unlock()
}

// receiveEOF marks the read side done after the peer's FIN.
func (st *Stream) receiveEOF() {
	st.rmu.Lock()
	st.reof = true
	st.rcond.Broadcast()
	st.rmu.Unlock()
	st.maybeRetire()
}

// grantCredit accumulates consumed bytes and re-grants them to the peer once
// the threshold is crossed (caller holds rmu).
func (st *Stream) grantCredit(n uint32) {
	st.pending += n
	if st.pending >= st.threshold {
		d := st.pending
		st.pending = 0
		if !st.sess.sendWindow(st.id, d) {
			// writer queue full / session gone: put the credit back for the
			// tail flusher (flushCreditTail retries every tick) — a silently
			// dropped grant would permanently stall the peer's sender. The
			// Rust reference restores the delta the same way.
			st.pending += d
		}
	}
}

// flushCreditTail sends any sub-threshold credit tail (credit ticker).
func (st *Stream) flushCreditTail() {
	st.rmu.Lock()
	if st.pending == 0 {
		st.rmu.Unlock()
		return
	}
	d := st.pending
	st.pending = 0
	st.rmu.Unlock()
	if !st.sess.sendWindow(st.id, d) {
		// writer queue full: put the credit back, retry next tick
		st.rmu.Lock()
		st.pending += d
		st.rmu.Unlock()
	}
}

// grantCredits adds sender-side credits (WINDOW received).
func (st *Stream) grantCredits(delta int64) {
	st.creditMu.Lock()
	st.credits += delta
	st.creditCond.Broadcast()
	st.creditMu.Unlock()
}

// acquire blocks until at least one credit is available, taking up to want.
func (st *Stream) acquire(want int) (int, error) {
	st.creditMu.Lock()
	defer st.creditMu.Unlock()
	for {
		if st.werr != nil {
			return 0, st.werr
		}
		if st.credits > 0 {
			take := int(st.credits)
			if take > want {
				take = want
			}
			st.credits -= int64(take)
			return take, nil
		}
		if st.wdExpired {
			return 0, os.ErrDeadlineExceeded
		}
		if !st.wdeadline.IsZero() && !time.Now().Before(st.wdeadline) {
			return 0, os.ErrDeadlineExceeded
		}
		st.creditCond.Wait()
	}
}

// sendWire frames the wire bytes into DATA frames honoring the peer's
// advertised per-frame cap.
func (st *Stream) sendWire(wire []byte, compressed bool) error {
	maxData := int(st.sess.peerMaxData.Load())
	if maxData <= 0 {
		maxData = int(frame.DefaultMaxData)
	}
	var flags byte
	if compressed {
		flags = frame.FlagCompressed
	}
	for off := 0; off < len(wire); {
		take := len(wire) - off
		if take > maxData {
			take = maxData
		}
		if err := st.sess.sendWait(frame.Encode(frame.Data, flags, st.id, wire[off:off+take])); err != nil {
			return err
		}
		off += take
	}
	return nil
}

// failWrite aborts the stream after a write-side failure.
func (st *Stream) failWrite(err error) {
	body, _ := json.Marshal(closeMsg{Code: "abort"})
	st.sess.trySend(frame.Encode(frame.Close, 0, st.id, body))
	st.wakeLocal(ErrStreamGone)
	st.removeSelf()
}

// peerAbort handles a CLOSE frame from the peer: any CLOSE aborts the stream.
func (st *Stream) peerAbort() {
	st.wakeLocal(ErrStreamGone)
	st.removeSelf()
}

// abortStream aborts after a stream-level protocol failure (decompress error,
// expansion cap).
func (st *Stream) abortStream(reason string) {
	body, _ := json.Marshal(closeMsg{Code: "abort"})
	st.sess.trySend(frame.Encode(frame.Close, 0, st.id, body))
	st.wakeLocal(errors.New("krymux: stream aborted: " + reason))
	st.removeSelf()
}

// sessionGone wakes everything parked on this stream during teardown.
func (st *Stream) sessionGone() {
	st.rmu.Lock()
	if st.rerr == nil && !st.reof {
		st.rerr = ErrSessionClosed
	}
	st.rcond.Broadcast()
	st.rmu.Unlock()
	st.creditMu.Lock()
	if st.werr == nil {
		st.werr = ErrSessionClosed
	}
	st.creditCond.Broadcast()
	st.creditMu.Unlock()
}

// wakeLocal unblocks readers/writers with err and retires the stream locally.
func (st *Stream) wakeLocal(err error) {
	st.rmu.Lock()
	if st.rerr == nil && !st.reof {
		st.rerr = err
	}
	st.rcond.Broadcast()
	st.rmu.Unlock()
	st.creditMu.Lock()
	if st.werr == nil {
		st.werr = err
	}
	st.creditCond.Broadcast()
	st.creditMu.Unlock()
}

func (st *Stream) removeSelf() { st.sess.removeStream(st.id) }

// maybeRetire unregisters the stream once both directions are finished, so
// late WINDOW frames for it are simply ignored. It runs on session
// goroutines and therefore takes no lock a blocked writer could hold.
func (st *Stream) maybeRetire() {
	st.rmu.Lock()
	readDone := st.reof || st.rerr != nil
	pending := st.pending
	st.rmu.Unlock()
	writeDone := st.writeClosed.Load()
	if readDone && writeDone {
		if pending > 0 { // return the tail credit so the peer's window adds up
			st.rmu.Lock()
			st.pending = 0
			st.rmu.Unlock()
			st.sess.sendWindow(st.id, pending)
		}
		st.removeSelf()
	}
}

// deliverAck resolves an OpenStream wait.
func (st *Stream) deliverAck(ack openAckMsg) {
	if st.ackDone.Swap(true) {
		return
	}
	if st.ackCh == nil {
		return
	}
	if ack.OK {
		up := ""
		if ack.Upstream != nil {
			up = *ack.Upstream
		}
		st.ackCh <- ackResult{upstream: up}
	} else {
		st.ackCh <- ackResult{err: errors.New("krymux: open rejected: " + ack.Code + " " + ack.Reason)}
	}
}

// sendWindow emits a WINDOW credit grant; returns false when it was dropped
// (queue full / session gone) so callers can restore the delta.
func (s *Session) sendWindow(sid uint32, delta uint32) bool {
	var p [4]byte
	p[0] = byte(delta >> 24)
	p[1] = byte(delta >> 16)
	p[2] = byte(delta >> 8)
	p[3] = byte(delta)
	return s.trySend(frame.Encode(frame.Window, 0, sid, p[:]))
}
