package frame

import (
	"bytes"
	"testing"
)

func TestHeaderRoundtrip(t *testing.T) {
	for _, c := range []struct {
		typ, flags byte
		sid, len   uint32
	}{
		{Hello, 0, 0, 120},
		{Data, FlagCompressed | FlagFIN, 0xdeadbeef, 65536},
		{Window, 0, 7, 4},
		{Goaway, 0, 0, 0},
	} {
		hb := HeaderBytes(c.typ, c.flags, c.sid, c.len)
		if len(hb) != HeaderSize {
			t.Fatalf("header length %d", len(hb))
		}
		h, err := ParseHeader(hb[:])
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if h.Type != c.typ || h.Flags != c.flags || h.StreamID != c.sid || h.Length != c.len {
			t.Fatalf("roundtrip mismatch: %+v want %+v", h, c)
		}
	}
}

func TestGoldenHeaderBytes(t *testing.T) {
	// DATA, flags=0x03, stream 1, length 0 — the FIN half-close frame
	got := HeaderBytes(Data, FlagCompressed|FlagFIN, 1, 0)
	want := []byte{0x04, 0x03, 0, 0, 0, 1, 0, 0, 0, 0}
	if !bytes.Equal(got[:], want) {
		t.Fatalf("header bytes %v, want %v", got, want)
	}
	// WINDOW, stream 5, delta 4096
	got = HeaderBytes(Window, 0, 5, 4)
	want = []byte{0x05, 0x00, 0, 0, 0, 5, 0, 0, 0, 4}
	if !bytes.Equal(got[:], want) {
		t.Fatalf("header bytes %v, want %v", got, want)
	}
}

func TestFrameTypeValues(t *testing.T) {
	// The registry is 1-based, matching the Rust FT_* constants exactly.
	for i, want := range []byte{Hello, Open, OpenAck, Data, Window, Close, Ping, Pong, Goaway} {
		if want != byte(i+1) {
			t.Fatalf("frame type %d = %d, breaks the 1-based registry", i+1, want)
		}
	}
}

func TestRejectUnknownType(t *testing.T) {
	if _, err := ParseHeader(make([]byte, HeaderSize)); err == nil {
		t.Fatal("type 0 must be rejected")
	}
	buf := []byte{Hello, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	buf[0] = 42
	if _, err := ParseHeader(buf); err == nil {
		t.Fatal("type 42 must be rejected")
	}
	buf[0] = Goaway + 1
	if _, err := ParseHeader(buf); err == nil {
		t.Fatal("type above Goaway must be rejected")
	}
}

func TestEncode(t *testing.T) {
	f := Encode(Open, 0, 9, []byte("hi"))
	if len(f) != HeaderSize+2 {
		t.Fatalf("frame length %d", len(f))
	}
	h, err := ParseHeader(f[:HeaderSize])
	if err != nil || h.StreamID != 9 || h.Length != 2 || !bytes.Equal(f[HeaderSize:], []byte("hi")) {
		t.Fatalf("bad encode: %+v %v", h, err)
	}
}

func TestMaxPayloadFor(t *testing.T) {
	if MaxPayloadFor(Window, 65536) != 4 {
		t.Fatal("WINDOW cap must be 4")
	}
	if MaxPayloadFor(Close, 65536) != 257 {
		t.Fatal("CLOSE cap must be 257")
	}
	if MaxPayloadFor(Data, 65536) != 65536 {
		t.Fatal("DATA cap must equal our advertised max")
	}
	if MaxPayloadFor(Hello, 65536) != 8192 {
		t.Fatal("HELLO cap must be 8 KiB")
	}
}
