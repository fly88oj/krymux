// Package frame implements the Krymux wire framing, byte-for-byte
// compatible with the Rust reference implementation (crates/krymux/src/frame.rs):
//
//	[type:1][flags:1][streamId:4 BE][length:4 BE]
//
// followed by the payload.
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Frame types (note: 1-based, matching the Rust FT_* constants exactly).
const (
	Hello   byte = 1 // session hello (JSON capabilities exchange)
	Open    byte = 2 // open a new stream (JSON target description)
	OpenAck byte = 3 // accept or reject a stream open (JSON verdict)
	Data    byte = 4 // stream payload bytes
	Window  byte = 5 // receive-window credit grant (4-byte BE delta)
	Close   byte = 6 // abort a stream (code/reason informational)
	Ping    byte = 7 // keepalive ping (16-byte nonce)
	Pong    byte = 8 // keepalive pong (echoes the ping nonce)
	Goaway  byte = 9 // tear down the whole session (JSON reason)
)

// Frame flags.
const (
	FlagCompressed byte = 0x01 // the DATA payload is compressed with the stream's algorithm
	FlagFIN        byte = 0x02 // end of the stream's send direction (half-close)
)

// Size limits, mirroring the Rust constants.
const (
	HeaderSize            = 10
	HardMaxFrame          = 1 << 20   // hard cap on any single frame's payload
	DefaultMaxData uint32 = 64 * 1024 // default maximum DATA payload the peer may send per frame
	MaxHello              = 8 * 1024  // maximum HELLO payload size
	MaxOpen               = 8 * 1024  // maximum OPEN payload size
	MaxControl            = 8 * 1024  // maximum OPEN_ACK / GOAWAY payload size
)

// Errors returned by ParseHeader.
var (
	ErrShortHeader = errors.New("frame: header shorter than 10 bytes")
	ErrUnknownType = errors.New("frame: unknown frame type")
)

// Header is a parsed frame header (everything before the payload).
type Header struct {
	Type     byte   // one of the frame type constants
	Flags    byte   // bitmask of Flag* flags
	StreamID uint32 // stream the frame belongs to (0 for session-level frames)
	Length   uint32 // payload length in bytes
}

// ParseHeader parses a 10-byte header, rejecting unknown frame types.
func ParseHeader(buf []byte) (Header, error) {
	if len(buf) < HeaderSize {
		return Header{}, ErrShortHeader
	}
	t := buf[0]
	if t < Hello || t > Goaway {
		return Header{}, fmt.Errorf("%w %d", ErrUnknownType, t)
	}
	return Header{
		Type:     t,
		Flags:    buf[1],
		StreamID: binary.BigEndian.Uint32(buf[2:6]),
		Length:   binary.BigEndian.Uint32(buf[6:10]),
	}, nil
}

// HeaderBytes builds the fixed 10-byte wire header for a frame.
func HeaderBytes(frameType, flags byte, streamID uint32, length uint32) [HeaderSize]byte {
	var h [HeaderSize]byte
	h[0] = frameType
	h[1] = flags
	binary.BigEndian.PutUint32(h[2:6], streamID)
	binary.BigEndian.PutUint32(h[6:10], length)
	return h
}

// Encode builds one complete wire frame (header plus payload).
func Encode(frameType, flags byte, streamID uint32, payload []byte) []byte {
	h := HeaderBytes(frameType, flags, streamID, uint32(len(payload)))
	out := make([]byte, 0, HeaderSize+len(payload))
	out = append(out, h[:]...)
	return append(out, payload...)
}

// MaxPayloadFor mirrors the receive caps the Rust reader enforces per frame
// type (a violation draws a GOAWAY). ourMaxData is the per-frame DATA cap we
// advertised in HELLO.
func MaxPayloadFor(frameType byte, ourMaxData int) int {
	switch frameType {
	case Hello:
		return MaxHello
	case Open:
		return MaxOpen
	case Window:
		return 4
	case Close:
		return 1 + 256
	case Ping, Pong:
		return 64
	case OpenAck, Goaway:
		return MaxControl
	case Data:
		return ourMaxData
	default:
		return HardMaxFrame
	}
}
