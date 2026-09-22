"""Krymux wire framing.

Byte-for-byte compatible with the Rust/Node reference implementations:
``[type:1][flags:1][streamId:4BE][length:4BE]`` followed by the payload.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

# Frame types (must match crates/krymux/src/frame.rs).
FT_HELLO = 1  # session hello (JSON capabilities exchange)
FT_OPEN = 2  # open a new stream (JSON target description)
FT_OPEN_ACK = 3  # accept or reject a stream open (JSON verdict)
FT_DATA = 4  # stream payload bytes
FT_WINDOW = 5  # receive-window credit grant (4-byte delta)
FT_CLOSE = 6  # abort a stream (code/reason are informational)
FT_PING = 7  # keepalive ping (16-byte nonce)
FT_PONG = 8  # keepalive pong (echoes the ping nonce)
FT_GOAWAY = 9  # tear down the whole session (JSON reason)

# Frame flags.
FLAG_COMPRESSED = 0x01  # DATA payload is compressed with the stream's algorithm
FLAG_FIN = 0x02  # end of the stream's send direction (half-close)

# Limits.
HEADER_SIZE = 10
HARD_MAX_FRAME = 1 << 20  # hard cap on any single frame's payload
DEFAULT_MAX_DATA = 64 * 1024  # default max DATA payload the peer may send
MAX_HELLO = 8 * 1024
MAX_OPEN = 8 * 1024
MAX_CONTROL = 8 * 1024  # OPEN_ACK / GOAWAY

# Close codes (informational wire registry; any CLOSE aborts the stream).
CLOSE_EOS = 0
CLOSE_ERROR = 1
CLOSE_UNREACHABLE = 3
CLOSE_GOAWAY = 4
CLOSE_CANCEL = 5


class ProtocolError(Exception):
    """A wire-protocol violation (bad frame type, oversized frame, ...)."""


@dataclass(frozen=True)
class FrameHeader:
    """A parsed frame header (everything before the payload)."""

    frame_type: int
    flags: int
    stream_id: int
    length: int

    @classmethod
    def parse(cls, buf: bytes | bytearray | memoryview) -> "FrameHeader":
        """Parse a 10-byte header, rejecting unknown frame types."""
        if len(buf) < HEADER_SIZE:
            raise ProtocolError("short frame header")
        frame_type = buf[0]
        if not FT_HELLO <= frame_type <= FT_GOAWAY:
            raise ProtocolError(f"unknown frame type {frame_type}")
        return cls(
            frame_type=frame_type,
            flags=buf[1],
            stream_id=int.from_bytes(bytes(buf[2:6]), "big"),
            length=int.from_bytes(bytes(buf[6:10]), "big"),
        )


def frame_header(frame_type: int, flags: int, stream_id: int, length: int) -> bytes:
    """Build the fixed 10-byte wire header for a frame."""
    return (
        bytes((frame_type, flags))
        + stream_id.to_bytes(4, "big")
        + length.to_bytes(4, "big")
    )


def encode_frame(
    frame_type: int, flags: int, stream_id: int, payload: bytes = b""
) -> bytes:
    """Encode a header plus payload into one complete wire frame."""
    if len(payload) > HARD_MAX_FRAME:
        raise ProtocolError("frame payload exceeds HARD_MAX_FRAME")
    return frame_header(frame_type, flags, stream_id, len(payload)) + payload


def payload_cap(frame_type: int) -> int:
    """Per-frame-type payload cap enforced by the receive path (mirrors Rust)."""
    if frame_type == FT_HELLO:
        return MAX_HELLO
    if frame_type == FT_OPEN:
        return MAX_OPEN
    if frame_type == FT_WINDOW:
        return 4
    if frame_type == FT_CLOSE:
        return 1 + 256
    if frame_type in (FT_PING, FT_PONG):
        return 64
    if frame_type in (FT_OPEN_ACK, FT_GOAWAY):
        return MAX_CONTROL
    if frame_type == FT_DATA:
        return DEFAULT_MAX_DATA
    return HARD_MAX_FRAME


async def read_frame(reader: asyncio.StreamReader) -> tuple[FrameHeader, bytes]:
    """Read one complete frame; returns (header, payload).

    Enforces the same length caps as the reference reader, so an oversized
    frame is surfaced as :class:`ProtocolError` instead of a huge allocation.
    """
    header = await reader.readexactly(HEADER_SIZE)
    fh = FrameHeader.parse(header)
    if fh.length > payload_cap(fh.frame_type):
        raise ProtocolError(f"oversized frame: type={fh.frame_type} len={fh.length}")
    if fh.length == 0:
        return fh, b""
    payload = await reader.readexactly(fh.length)
    return fh, payload
