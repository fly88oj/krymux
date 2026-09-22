//! CMPX wire framing, byte-for-byte compatible with the Node reference
//! implementation: `[type:1][flags:1][streamId:4][length:4]` big-endian,
//! followed by the payload.

/// Frame type: session hello (JSON capabilities exchange).
pub const FT_HELLO: u8 = 1;
/// Frame type: open a new stream (JSON target description).
pub const FT_OPEN: u8 = 2;
/// Frame type: accept or reject a stream open (JSON verdict).
pub const FT_OPEN_ACK: u8 = 3;
/// Frame type: stream payload bytes.
pub const FT_DATA: u8 = 4;
/// Frame type: receive-window credit grant (4-byte delta).
pub const FT_WINDOW: u8 = 5;
/// Frame type: abort a stream (code and reason are informational).
pub const FT_CLOSE: u8 = 6;
/// Frame type: keepalive ping (16-byte nonce).
pub const FT_PING: u8 = 7;
/// Frame type: keepalive pong (echoes the ping nonce).
pub const FT_PONG: u8 = 8;
/// Frame type: tear down the whole session (JSON reason).
pub const FT_GOAWAY: u8 = 9;

/// Flag: the DATA payload is compressed with the stream's algorithm.
pub const FLAG_COMPRESSED: u8 = 0x01;
/// Flag: end of the stream's send direction (half-close).
pub const FLAG_FIN: u8 = 0x02;

/// Size of the fixed frame header, in bytes.
pub const HEADER_SIZE: usize = 10;
/// Hard cap on any single frame's payload, DATA included.
pub const HARD_MAX_FRAME: usize = 1 << 20;
/// Default maximum DATA payload the peer may send per frame.
pub const DEFAULT_MAX_DATA: u32 = 64 * 1024;
/// Maximum HELLO payload size.
pub const MAX_HELLO: usize = 8 * 1024;
/// Maximum OPEN payload size.
pub const MAX_OPEN: usize = 8 * 1024;
/// Maximum OPEN_ACK / GOAWAY payload size.
pub const MAX_CONTROL: usize = 8 * 1024;

// Wire-protocol close-code registry (see PROTOCOL.md §4.1) — documentation
// surface for interoperability; the tunnel treats any CLOSE as an abort.
/// Close code: clean end of stream.
#[allow(dead_code)]
pub const CLOSE_EOS: u8 = 0;
/// Close code: stream-level error.
pub const CLOSE_ERROR: u8 = 1;
/// Close code: upstream unreachable.
pub const CLOSE_UNREACHABLE: u8 = 3;
/// Close code: the session is going away.
pub const CLOSE_GOAWAY: u8 = 4;
/// Close code: stream cancelled by its opener.
pub const CLOSE_CANCEL: u8 = 5;

/// A parsed frame header (everything before the payload).
#[derive(Debug, Clone, Copy)]
pub struct FrameHeader {
    /// Frame type; one of the `FT_*` constants.
    pub frame_type: u8,
    /// Bitmask of `FLAG_*` flags.
    pub flags: u8,
    /// Stream the frame belongs to (0 for session-level frames).
    pub stream_id: u32,
    /// Payload length in bytes.
    pub length: u32,
}

impl FrameHeader {
    /// Parses a 10-byte header, rejecting unknown frame types.
    pub fn parse(buf: &[u8; HEADER_SIZE]) -> anyhow::Result<FrameHeader> {
        let frame_type = buf[0];
        if !(FT_HELLO..=FT_GOAWAY).contains(&frame_type) {
            anyhow::bail!("unknown frame type {}", frame_type);
        }
        Ok(FrameHeader {
            frame_type,
            flags: buf[1],
            stream_id: u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]),
            length: u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]),
        })
    }
}

/// Builds the fixed 10-byte wire header for a frame.
pub fn frame_header(frame_type: u8, flags: u8, stream_id: u32, length: u32) -> [u8; HEADER_SIZE] {
    let mut h = [0u8; HEADER_SIZE];
    h[0] = frame_type;
    h[1] = flags;
    h[2..6].copy_from_slice(&stream_id.to_be_bytes());
    h[6..10].copy_from_slice(&length.to_be_bytes());
    h
}

/// Encodes a header plus payload into one complete wire frame.
pub fn encode_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    debug_assert!(payload.len() <= HARD_MAX_FRAME);
    let mut out = Vec::with_capacity(HEADER_SIZE + payload.len());
    out.extend_from_slice(&frame_header(
        frame_type,
        flags,
        stream_id,
        payload.len() as u32,
    ));
    out.extend_from_slice(payload);
    out
}
