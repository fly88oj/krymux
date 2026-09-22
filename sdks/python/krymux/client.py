"""Krymux client: TLS 1.3 connect with server-fingerprint pinning (fail
closed) plus a stream-opening API.

ALPN ``krymux``, Ed25519 self-signed client certificate, no CA validation —
the server's identity is the pinned ``sha256:<hex>`` SPKI fingerprint checked
after the handshake, exactly like the Rust implementation.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass

from .keys import Identity, fingerprint_of_cert_der, normalize_fingerprint
from .mux import (
    DEFAULT_RX_WINDOW_MAX,
    DEFAULT_WINDOW,
    Session,
    SessionOpts,
    Target,
    TunnelStream,
)

#: The ALPN protocol identifier required on every krymux TLS connection.
ALPN = "krymux"


class PinVerificationError(ConnectionError):
    """The server's certificate fingerprint did not match the pin."""


def parse_endpoint(endpoint: str) -> tuple[str, int]:
    """Split ``host:port`` / ``[v6]:port`` / ``:port`` / ``port``."""
    s = endpoint.strip()
    if s.startswith("["):
        end = s.find("]")
        if end < 0:
            raise ValueError(f"bad endpoint {endpoint!r}")
        host = s[1:end]
        port = int(s[end + 1 :].lstrip(":"))
        return host, port
    if ":" in s:
        host, port_s = s.rsplit(":", 1)
        host = host or "127.0.0.1"
        return host, int(port_s)
    if s.isdigit():
        return "0.0.0.0", int(s)
    raise ValueError(f"bad endpoint {endpoint!r}")


def client_ssl_context(identity: Identity) -> ssl.SSLContext:
    """TLS 1.3 client context: ALPN ``krymux``, Ed25519 client cert, no CA
    validation (identity comes from the post-handshake fingerprint pin)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols([ALPN])
    cert_path, key_path = identity.ssl_pair()
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx


@dataclass
class ConnectParams:
    """Tunables for :func:`connect`."""

    compression: str = "auto"
    keepalive_sec: float = 30.0
    name: str = "client"
    rx_window: int = DEFAULT_WINDOW
    rx_window_max: int = DEFAULT_RX_WINDOW_MAX


class EctunClient:
    """A connected tunnel: one multiplexed session plus stream defaults."""

    def __init__(self, session: Session, params: ConnectParams):
        self.session = session
        self.params = params

    @property
    def is_closed(self) -> bool:
        return self.session.is_closed

    async def open_stream(self, host: str, port: int,
                          compression: str | None = None) -> TunnelStream:
        """Open a tunneled stream to ``host:port``."""
        comp = compression or self.params.compression
        return await self.session.open_stream(
            Target(host=host or None, port=port, hint="raw"), compression=comp
        )

    async def ping(self) -> float:
        """Round-trip latency in seconds (16-byte PING/PONG nonce)."""
        return await self.session.ping()

    async def wait_closed(self) -> None:
        await self.session.wait_closed()

    def close(self, reason: str = "done") -> None:
        self.session.close(reason)


async def connect(addr: str, identity: Identity, server_fp: str,
                  params: ConnectParams | None = None,
                  *, connect_timeout: float = 10.0) -> EctunClient:
    """Connect to ``addr`` (``host:port``), verify the pinned ``server_fp``
    (fail closed), and start the multiplexed session.

    ``server_fp`` may be ``sha256:<hex>``, bare hex, or a certificate PEM path
    (normalized before use). On fingerprint mismatch or a missing server
    certificate the transport is closed and :class:`PinVerificationError`
    (or ``ConnectionError``) is raised.
    """
    params = params or ConnectParams()
    host, port = parse_endpoint(addr)
    pin = normalize_fingerprint(server_fp)
    ctx = client_ssl_context(identity)

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
        connect_timeout,
    )
    try:
        tls = writer.get_extra_info("ssl_object")
        alpn = tls.selected_alpn_protocol() if tls is not None else None
        if alpn != ALPN:
            raise ConnectionError(f"server did not negotiate the krymux ALPN (got {alpn!r})")
        der = tls.getpeercert(binary_form=True)
        if der is None:
            raise ConnectionError("server did not present a certificate")
        fp = fingerprint_of_cert_der(der)
        if fp != pin:
            raise PinVerificationError(
                f"server verification failed: fingerprint mismatch "
                f"(got {fp[:19]}..., pinned {pin[:19]}...)"
            )
    except (ssl.SSLError, ConnectionError, OSError):
        writer.close()
        raise

    opts = SessionOpts(
        is_client=True,
        name=params.name,
        rx_window=params.rx_window,
        rx_window_max=params.rx_window_max,
        max_streams=1024,
        keepalive_sec=params.keepalive_sec,
    )
    session = await Session.start(reader, writer, opts, on_stream=None)
    return EctunClient(session, params)
