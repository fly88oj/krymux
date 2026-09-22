"""Krymux Python SDK — secure service access over reverse tunnels.

Wire-compatible with the Rust (``crates/krymux``) and Node reference
implementations: 10-byte frames ``[type:1][flags:1][streamId:4BE][length:4BE]``,
TLS 1.3 mTLS with Ed25519 self-signed certificates (ALPN ``krymux``), SPKI
sha256 fingerprint pinning/whitelisting, credit-based flow control, and
optional per-stream compression (``none`` + ``deflate``).
"""

from .client import (
    ALPN,
    ConnectParams,
    EctunClient,
    PinVerificationError,
    client_ssl_context,
    connect,
    parse_endpoint,
)
from .compress import (
    ALGO_DEFLATE,
    ALGO_NONE,
    Compressor,
    Decompressor,
    negotiate,
    supported,
)
from .frame import (
    FLAG_COMPRESSED,
    FLAG_FIN,
    FT_CLOSE,
    FT_DATA,
    FT_GOAWAY,
    FT_HELLO,
    FT_OPEN,
    FT_OPEN_ACK,
    FT_PING,
    FT_PONG,
    FT_WINDOW,
    FrameHeader,
    ProtocolError,
    encode_frame,
)
from .keys import (
    Identity,
    fingerprint_of_cert,
    fingerprint_of_cert_der,
    fingerprint_of_spki,
    generate_identity,
    load_identity,
    normalize_fingerprint,
    save_identity,
)
from .mux import (
    KrymuxError,
    Session,
    SessionClosed,
    SessionOpts,
    StreamRejected,
    Target,
    TunnelStream,
)
from .server import Server, listen

__version__ = "0.1.0"

__all__ = [
    # client
    "ALPN", "ConnectParams", "EctunClient", "PinVerificationError",
    "client_ssl_context", "connect", "parse_endpoint",
    # compress
    "ALGO_DEFLATE", "ALGO_NONE", "Compressor", "Decompressor",
    "negotiate", "supported",
    # frame
    "FLAG_COMPRESSED", "FLAG_FIN", "FT_CLOSE", "FT_DATA", "FT_GOAWAY",
    "FT_HELLO", "FT_OPEN", "FT_OPEN_ACK", "FT_PING", "FT_PONG", "FT_WINDOW",
    "FrameHeader", "ProtocolError", "encode_frame",
    # keys
    "Identity", "fingerprint_of_cert", "fingerprint_of_cert_der",
    "fingerprint_of_spki", "generate_identity", "load_identity",
    "normalize_fingerprint", "save_identity",
    # mux
    "KrymuxError", "Session", "SessionClosed", "SessionOpts",
    "StreamRejected", "Target", "TunnelStream",
    # server
    "Server", "listen",
]
