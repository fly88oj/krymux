package compress

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"io"
	"testing"
)

func TestNegotiate(t *testing.T) {
	rustList := []string{"none", "deflate", "brotli"}
	cases := []struct {
		req  string
		peer []string
		want string
	}{
		{"none", rustList, AlgoNone},
		{"", rustList, AlgoNone},
		{"auto", rustList, AlgoDeflate},
		{"deflate", rustList, AlgoDeflate},
		{"deflate:9", rustList, AlgoDeflate},
		{"auto", []string{"none"}, AlgoNone},
		{"deflate", []string{"none", "brotli"}, AlgoNone},
		{"brotli", rustList, AlgoNone}, // not implemented by this SDK
		{"zstd", rustList, AlgoNone},
		{"auto", []string{"none", "zstdd:0123abcd"}, AlgoNone},
	}
	for _, c := range cases {
		if got := Negotiate(c.req, c.peer); got != c.want {
			t.Errorf("Negotiate(%q, %v) = %q, want %q", c.req, c.peer, got, c.want)
		}
	}
}

func TestParseLevel(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int
		ok   bool
	}{
		{"deflate:9", 9, true},
		{"deflate:1", 1, true},
		{"deflate:22", 22, true},
		{"deflate:0", 0, false},
		{"deflate:23", 0, false},
		{"deflate:x", 0, false},
		{"deflate", 0, false},
		{"zstdd:0123abcd", 0, false}, // fingerprint must not read as a level
	} {
		got, ok := ParseLevel(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("ParseLevel(%q) = %d,%v want %d,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestSniff(t *testing.T) {
	if !LooksPrecompressed([]byte{0x1f, 0x8b, 8, 0, 1, 2}) {
		t.Fatal("gzip magic must sniff as pre-compressed")
	}
	if !LooksPrecompressed([]byte{0, 0, 0, 0, 'f', 't', 'y', 'p', 0, 0, 0, 0}) {
		t.Fatal("ftyp at offset 4 must sniff as pre-compressed")
	}
	if LooksPrecompressed([]byte("plain text!")) {
		t.Fatal("text must not sniff as pre-compressed")
	}
	if LooksPrecompressed([]byte{0x1f}) {
		t.Fatal("short chunk must not sniff")
	}
}

func TestDeflateChunkedRoundtrip(t *testing.T) {
	comp := NewCompressor(AlgoDeflate, 6)
	dec := NewDecompressor(AlgoDeflate)
	var logical []byte
	var roundtrip []byte
	chunk := make([]byte, 700)
	for i := 0; i < 200; i++ {
		if _, err := rand.Read(chunk); err != nil {
			t.Fatal(err)
		}
		logical = append(logical, chunk...)
		wire, err := comp.Push(chunk)
		if err != nil {
			t.Fatalf("push: %v", err)
		}
		// each chunk must be decodable immediately (sync-flush semantics)
		out, err := dec.Push(wire)
		if err != nil {
			t.Fatalf("pop: %v", err)
		}
		if !bytes.Equal(out, chunk) {
			t.Fatalf("chunk %d not recoverable per-chunk: got %d bytes want %d", i, len(out), len(chunk))
		}
		roundtrip = append(roundtrip, out...)
	}
	if !bytes.Equal(logical, roundtrip) {
		t.Fatal("round-trip must be lossless")
	}
}

func TestDeflateIsRawDeflate(t *testing.T) {
	// The wire format must be raw deflate (no zlib header 0x78), or the
	// Rust flate2 decoder would reject it.
	comp := NewCompressor(AlgoDeflate, 6)
	wire, err := comp.Push(bytes.Repeat([]byte("krymux raw deflate "), 1000))
	if err != nil {
		t.Fatal(err)
	}
	if wire[0] == 0x78 {
		t.Fatal("wire looks zlib-wrapped; must be raw deflate")
	}
	// cross-check with the stdlib raw flate reader (the stream is
	// sync-flushed, not final-terminated, so read exactly the expected
	// number of bytes rather than to EOF)
	r := flate.NewReader(bytes.NewReader(wire))
	want := bytes.Repeat([]byte("krymux raw deflate "), 1000)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("stdlib flate cannot decode our stream: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("stdlib flate decoded different bytes")
	}
	// ...and compression actually compressed
	if len(wire) > 2000 {
		t.Fatalf("repetitive payload should compress well: wire=%d", len(wire))
	}
}

// TestDeflateSplitWireDecodes reproduces the wire reality of the mux: one
// compressed chunk may be split across several DATA frames at arbitrary
// (non-block-aligned) offsets. The decoder must resume across those splits
// without erroring or losing bytes.
func TestDeflateSplitWireDecodes(t *testing.T) {
	comp := NewCompressor(AlgoDeflate, 6)
	dec := NewDecompressor(AlgoDeflate)
	defer dec.Close()
	var logical, roundtrip []byte
	chunk := make([]byte, 96*1024)
	for i := 0; i < 4; i++ {
		if _, err := rand.Read(chunk); err != nil {
			t.Fatal(err)
		}
		logical = append(logical, chunk...)
		wire, err := comp.Push(chunk)
		if err != nil {
			t.Fatalf("push: %v", err)
		}
		for len(wire) > 0 {
			n := 12345 // deliberately not block-aligned
			if n > len(wire) {
				n = len(wire)
			}
			out, err := dec.Push(wire[:n])
			if err != nil {
				t.Fatalf("split decode at %d: %v", n, err)
			}
			roundtrip = append(roundtrip, out...)
			wire = wire[n:]
		}
	}
	if !bytes.Equal(logical, roundtrip) {
		t.Fatalf("split-wire round-trip must be lossless: %d vs %d bytes", len(logical), len(roundtrip))
	}
}

func TestCompressiblePayloadShrinks(t *testing.T) {
	comp := NewCompressor(AlgoDeflate, 6)
	wire, err := comp.Push(bytes.Repeat([]byte("abcdefgh"), 128*1024))
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) >= 128*1024*8 {
		t.Fatalf("deflate must shrink repetitive input: %d", len(wire))
	}
}

func TestNonePassthrough(t *testing.T) {
	comp := NewCompressor(AlgoNone, 0)
	dec := NewDecompressor(AlgoNone)
	in := []byte("identity")
	w, _ := comp.Push(in)
	if !bytes.Equal(w, in) {
		t.Fatal("none compressor must copy")
	}
	out, err := dec.Push(w)
	if err != nil || !bytes.Equal(out, in) {
		t.Fatal("none decompressor must copy")
	}
}
