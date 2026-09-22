"""Krymux server: TLS 1.3 termination, fingerprint-whitelist authorization
(fail closed), and per-stream dispatch to an async handler.

TLS policy mirrors the Rust implementation: ALPN ``krymux`` is required,
client certificates are requested but their chain is not trusted — the ONLY
authorization is the post-handshake fingerprint whitelist.

Implementation note: Python's stdlib ``ssl`` aborts the handshake when a
presented client certificate fails CA verification (the Rust side uses a
custom always-accept verifier, which stdlib ssl cannot express). Pass the
whitelisted clients' certificate files via ``trusted_client_certs`` so the
handshake tolerates their self-signed certificates; authorization remains
exclusively the fingerprint whitelist.
"""

from __future__ import annotations

import asyncio
import ssl
from pathlib import Path

from .client import ALPN, parse_endpoint
from .keys import Identity, fingerprint_of_cert_der, normalize_fingerprint
from .mux import (
    DEFAULT_RX_WINDOW_MAX,
    DEFAULT_MAX_STREAMS,
    DEFAULT_WINDOW,
    Session,
    SessionOpts,
    Target,
    TunnelStream,
)

__all__ = ["listen", "Server"]


def server_ssl_context(identity: Identity, trusted_client_certs=None) -> ssl.SSLContext:
    """TLS 1.3 server context: ALPN ``krymux``, own certificate, client
    certificates requested (CERT_OPTIONAL) so their fingerprint can be
    checked after the handshake.

    ``trusted_client_certs`` (paths to or PEM text of client certificates)
    are loaded as handshake trust anchors — see the module docstring.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols([ALPN])
    cert_path, key_path = identity.ssl_pair()
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ctx.verify_mode = ssl.CERT_OPTIONAL
    for item in trusted_client_certs or ():
        text = str(item)
        if text.lstrip().startswith("---"):
            cadata = text
        else:
            if "sha256:" in text or (len(text.strip()) == 64
                                    and all(c in "0123456789abcdefABCDEF" for c in text.strip())):
                raise ValueError(
                    "trusted_client_certs expects certificate files, not fingerprints"
                )
            p = Path(text)
            if not p.is_file():
                raise ValueError(f"trusted client cert not found: {text}")
            cadata = p.read_text()
        try:
            ctx.load_verify_locations(cadata=cadata)
        except ssl.SSLError as e:
            raise ValueError(f"cannot load trusted client cert {text}: {e}") from e
    return ctx


class Server:
    """A running krymux listener."""

    def __init__(self, tcp_server: asyncio.AbstractServer, fingerprints: set[str]):
        self._tcp = tcp_server
        self.fingerprints = fingerprints

    @property
    def sockets(self):
        return list(self._tcp.sockets or [])

    @property
    def addresses(self) -> list[tuple]:
        return [s.getsockname() for s in self.sockets]

    def close(self) -> None:
        self._tcp.close()

    async def wait_closed(self) -> None:
        await self._tcp.wait_closed()


async def listen(
    addr: str,
    identity: Identity,
    handler,
    *,
    fingerprints=(),
    trusted_client_certs=None,
    name: str = "server",
    rx_window: int = DEFAULT_WINDOW,
    rx_window_max: int = DEFAULT_RX_WINDOW_MAX,
    max_streams: int = DEFAULT_MAX_STREAMS,
    keepalive_sec: float = 0.0,
) -> Server:
    """Listen on ``addr`` (``host:port``); authorized connections become
    multiplexed sessions whose streams are handed to ``handler``.

    ``handler`` is ``async def handler(stream: TunnelStream, target: Target)``
    and must ``await stream.accept(...)`` (or ``stream.reject(...)``) before
    pumping data. Authorization is fail-closed: ALPN must be ``krymux``, a
    client certificate must be presented, and its fingerprint must be in the
    normalized ``fingerprints`` whitelist.
    """
    allow = {normalize_fingerprint(f) for f in fingerprints}
    ctx = server_ssl_context(identity, trusted_client_certs)
    opts = SessionOpts(
        is_client=False,
        name=name,
        rx_window=rx_window,
        rx_window_max=rx_window_max,
        max_streams=max_streams,
        keepalive_sec=keepalive_sec,
    )

    async def on_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        session: Session | None = None
        try:
            tls = writer.get_extra_info("ssl_object")
            if tls is None or tls.selected_alpn_protocol() != ALPN:
                return  # fail closed: wrong/missing ALPN
            der = tls.getpeercert(binary_form=True)
            if der is None:
                return  # fail closed: no client certificate
            if fingerprint_of_cert_der(der) not in allow:
                return  # fail closed: fingerprint not whitelisted
            session = await Session.start(reader, writer, opts, on_stream=handler)
            await session.wait_closed()
        except (ssl.SSLError, ConnectionError, OSError):
            pass
        except asyncio.CancelledError:
            raise
        except Exception:
            import traceback

            traceback.print_exc()
        finally:
            if session is not None:
                session.close("server closing")
            try:
                writer.close()
            except Exception:
                pass

    host, port = parse_endpoint(addr)
    tcp_server = await asyncio.start_server(on_connect, host, port, ssl=ctx)
    return Server(tcp_server, allow)
