// Package compress implements the Krymux per-stream, per-direction chunk
// compression with a continuous context flushed at every chunk — the same
// semantics as the Rust implementation (crates/krymux/src/compress.rs).
//
// This SDK implements the "none" and "deflate" algorithms. "deflate" on the
// wire is RAW deflate (no zlib/gzip wrapper), matching the Rust flate2
// DeflateEncoder/DeflateDecoder pair, so Go must use compress/flate directly
// rather than compress/zlib (which adds a zlib header and adler32 trailer).
package compress

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"strings"
	"sync"
)

// Algorithm names used on the wire (HELLO advertisement and OPEN selection).
const (
	AlgoNone    = "none"
	AlgoDeflate = "deflate"
)

// Supported lists the algorithms this SDK supports; advertised in HELLO.
func Supported() []string { return []string{AlgoNone, AlgoDeflate} }

// DefaultLevel returns the default compression level for an algorithm
// (mirrors Rust's default_level).
func DefaultLevel(algo string) int {
	if algo == AlgoDeflate {
		return 6
	}
	return 0
}

// isZstdd reports whether algo is a "zstdd:<8hexfp>" dictionary name.
func isZstdd(algo string) bool {
	rest, ok := strings.CutPrefix(algo, "zstdd")
	if !ok {
		return false
	}
	if len(rest) != 9 || rest[0] != ':' {
		return false
	}
	for _, c := range rest[1:] {
		if !isHex(c) {
			return false
		}
	}
	return true
}

func isHex(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// BaseAlgo strips a level suffix: "deflate:9" -> "deflate".
// A "zstdd:<fp>" request never carries a level.
func BaseAlgo(requested string) string {
	if isZstdd(requested) {
		return requested
	}
	if i := strings.IndexByte(requested, ':'); i >= 0 {
		return requested[:i]
	}
	return requested
}

// ParseLevel parses a level suffix: "deflate:9" -> (9, true); invalid or
// missing -> (0, false). Levels outside 1..22 are rejected.
func ParseLevel(requested string) (int, bool) {
	if isZstdd(requested) {
		return 0, false
	}
	i := strings.IndexByte(requested, ':')
	if i < 0 {
		return 0, false
	}
	lvl := 0
	ok := true
	for _, c := range requested[i+1:] {
		if c < '0' || c > '9' {
			ok = false
			break
		}
		lvl = lvl*10 + int(c-'0')
		if lvl > 99 {
			ok = false
			break
		}
	}
	if !ok || lvl < 1 || lvl > 22 {
		return 0, false
	}
	return lvl, true
}

// Negotiate picks an algorithm from a request plus the peer's supported list,
// mirroring the Rust negotiate() for the algorithms this SDK implements.
// The Rust "auto" preference order (zstdd, zstd, deflate, brotli) collapses
// here to: deflate when the peer lists it, otherwise none.
func Negotiate(requested string, peerSupported []string) string {
	has := func(a string) bool {
		for _, p := range peerSupported {
			if p == a {
				return true
			}
		}
		return false
	}
	switch BaseAlgo(requested) {
	case "", AlgoNone:
		return AlgoNone
	case "auto":
		if has(AlgoDeflate) {
			return AlgoDeflate
		}
		return AlgoNone
	case AlgoDeflate:
		if has(AlgoDeflate) {
			return AlgoDeflate
		}
		return AlgoNone
	default:
		// algorithms this SDK does not implement (brotli, zstd, zstdd, ...)
		return AlgoNone
	}
}

// Well-known magic prefixes of already-compressed content. The sender's first
// chunk is sniffed; a match switches the stream to raw transport (receiver
// side needs nothing: unflagged frames pass raw).
var magicPrefixes = [][]byte{
	{0x1f, 0x8b},             // gzip
	{0x28, 0xb5, 0x2f, 0xfd}, // zstd
	{0x50, 0x4b, 0x03, 0x04}, // zip
	{0x89, 0x50, 0x4e, 0x47}, // png
	{0xff, 0xd8, 0xff},       // jpeg
	{0x37, 0x7a, 0xbc, 0xaf}, // 7z
	{0x52, 0x61, 0x72, 0x21}, // rar
	{0x25, 0x50, 0x44, 0x46}, // %PDF
	{0x42, 0x5a, 0x68},       // bzip2
}

// LooksPrecompressed reports whether a first chunk looks pre-compressed.
func LooksPrecompressed(chunk []byte) bool {
	if len(chunk) < 4 {
		return false
	}
	for _, m := range magicPrefixes {
		if bytes.HasPrefix(chunk, m) {
			return true
		}
	}
	// ISO-BMFF (mp4/mov/heic): "ftyp" at offset 4
	return len(chunk) >= 12 && bytes.Equal(chunk[4:8], []byte("ftyp"))
}

// Compressor is a chunk-oriented compressor holding one continuous context
// per direction. Push compresses one chunk with a flush boundary (deflate
// sync flush) and returns the wire bytes.
type Compressor struct {
	algo string
	w    *flate.Writer
	buf  bytes.Buffer
	none bool
}

// NewCompressor creates a compressor for algo at the given level
// (level <= 0 selects the default for the algorithm).
func NewCompressor(algo string, level int) *Compressor {
	if algo != AlgoDeflate {
		return &Compressor{algo: AlgoNone, none: true}
	}
	if level <= 0 {
		level = DefaultLevel(algo)
	}
	if level > 9 {
		level = 9
	}
	c := &Compressor{algo: AlgoDeflate}
	w, err := flate.NewWriter(&c.buf, level)
	if err != nil { // only for invalid levels; clamped above
		return &Compressor{algo: AlgoNone, none: true}
	}
	c.w = w
	return c
}

// Algo returns the algorithm actually in use.
func (c *Compressor) Algo() string { return c.algo }

// Push compresses one chunk with a flush boundary. Empty input yields empty
// output.
func (c *Compressor) Push(data []byte) ([]byte, error) {
	if c.none || len(data) == 0 {
		out := make([]byte, len(data))
		copy(out, data)
		return out, nil
	}
	if _, err := c.w.Write(data); err != nil {
		return nil, err
	}
	// Sync flush: emits the deflate sync marker so the receiver can decode
	// everything pushed so far.
	if err := c.w.Flush(); err != nil {
		return nil, err
	}
	out := make([]byte, c.buf.Len())
	copy(out, c.buf.Bytes())
	c.buf.Reset()
	return out, nil
}

// Decompressor is a chunk-oriented decompressor holding one continuous
// context per direction.
//
// Go's flate decoder cannot be fed chunk-by-chunk synchronously: a dry
// underlying reader turns into a sticky io.ErrUnexpectedEOF mid-block, which
// would poison the decoder whenever a deflate stream is split across DATA
// frames. Instead a dedicated decoder goroutine reads from a blocking feed
// buffer; Push queues the wire bytes and returns once the decoder has
// consumed them and parked waiting for more input, so delivery stays
// synchronous and per-frame ordered.
type Decompressor struct {
	algo string
	none bool

	feed *feedBuf

	mu     sync.Mutex
	cond   *sync.Cond
	outbox bytes.Buffer
	err    error // terminal decode error
	parks  int   // times the decoder parked waiting for input
}

// NewDecompressor creates a decompressor for algo.
func NewDecompressor(algo string) *Decompressor {
	if algo != AlgoDeflate {
		return &Decompressor{algo: AlgoNone, none: true}
	}
	d := &Decompressor{algo: AlgoDeflate}
	d.cond = sync.NewCond(&d.mu)
	d.feed = newFeedBuf(func() {
		// the decoder consumed everything pushed so far and is about to
		// block for more input — the "parked" signal Push waits on
		d.mu.Lock()
		d.parks++
		d.cond.Broadcast()
		d.mu.Unlock()
	})
	go d.decode()
	return d
}

func (d *Decompressor) decode() {
	fr := flate.NewReader(d.feed)
	buf := make([]byte, 64*1024)
	for {
		n, err := fr.Read(buf)
		if n > 0 {
			d.mu.Lock()
			d.outbox.Write(buf[:n])
			d.cond.Broadcast()
			d.mu.Unlock()
		}
		if err != nil {
			d.mu.Lock()
			if err == io.EOF {
				// our senders never emit a final block; a clean EOF is an
				// unexpected end of the continuous stream
				d.err = fmt.Errorf("compress: deflate stream ended mid-stream")
			} else {
				d.err = fmt.Errorf("compress: inflate: %w", err)
			}
			d.cond.Broadcast()
			d.mu.Unlock()
			return
		}
	}
}

// Push decompresses one wire chunk and returns the logical bytes (may be
// empty when the algorithm emits nothing for this input, or when the tail is
// still held inside the decoder's window — it is delivered by a later Push;
// sync-flushed senders emit everything per chunk).
func (d *Decompressor) Push(wire []byte) ([]byte, error) {
	if d.none || len(wire) == 0 {
		out := make([]byte, len(wire))
		copy(out, wire)
		return out, nil
	}
	d.mu.Lock()
	if d.err != nil {
		err := d.err
		d.mu.Unlock()
		return nil, err
	}
	snap := d.parks
	d.mu.Unlock()

	d.feed.write(wire)

	d.mu.Lock()
	for d.parks <= snap && d.err == nil {
		d.cond.Wait()
	}
	out := append([]byte(nil), d.outbox.Bytes()...)
	d.outbox.Reset()
	err := d.err
	d.mu.Unlock()
	return out, err
}

// Finish drains any lazily-held output at end of stream. Raw deflate streams
// closed per-chunk hold nothing back, so this is a no-op kept for API parity
// with the Rust SDK.
func (d *Decompressor) Finish() ([]byte, error) { return nil, nil }

// Close releases the decoder goroutine. Push afterwards returns the terminal
// error.
func (d *Decompressor) Close() {
	if d.none {
		return
	}
	d.feed.close()
}

// feedBuf is a blocking byte source: the decoder parks in Read/ReadByte
// until more wire bytes arrive (or the feed is closed). onPark fires once
// per park episode; it takes d.mu while holding f.mu, which is safe because
// the lock order feed.mu -> d.mu is never inverted anywhere.
type feedBuf struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	closed bool
	onPark func()
}

func newFeedBuf(onPark func()) *feedBuf {
	f := &feedBuf{onPark: onPark}
	f.cond = sync.NewCond(&f.mu)
	return f
}

func (f *feedBuf) write(b []byte) {
	f.mu.Lock()
	f.buf = append(f.buf, b...)
	f.cond.Broadcast()
	f.mu.Unlock()
}

func (f *feedBuf) close() {
	f.mu.Lock()
	f.closed = true
	f.cond.Broadcast()
	f.mu.Unlock()
}

func (f *feedBuf) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	parked := false
	for len(f.buf) == 0 {
		if f.closed {
			return 0, io.EOF
		}
		if !parked {
			parked = true
			if f.onPark != nil {
				f.onPark()
			}
		}
		f.cond.Wait()
	}
	n := copy(p, f.buf)
	f.buf = f.buf[n:]
	return n, nil
}

func (f *feedBuf) ReadByte() (byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	parked := false
	for len(f.buf) == 0 {
		if f.closed {
			return 0, io.EOF
		}
		if !parked {
			parked = true
			if f.onPark != nil {
				f.onPark()
			}
		}
		f.cond.Wait()
	}
	b := f.buf[0]
	f.buf = f.buf[1:]
	return b, nil
}
