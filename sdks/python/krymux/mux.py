"""Krymux multiplexing session: many logical full-duplex streams over one
ordered encrypted byte stream. Wire-compatible with the Rust/Node reference
implementations.

Structure: a socket reader task (frame dispatch), a socket writer task
(ordered frame emission), and a small credit ticker that flushes
sub-threshold WINDOW tails. Ordering per stream is guaranteed by
construction — all frames flow through one ordered byte stream.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from dataclasses import dataclass, field

from . import compress
from .compress import Compressor, Decompressor, negotiate, parse_level
from .frame import (
    DEFAULT_MAX_DATA,
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
    ProtocolError,
    encode_frame,
    read_frame,
)

PROTOCOL_VERSION = 1
DEFAULT_WINDOW = 262_144
DEFAULT_RX_WINDOW_MAX = 4_194_304
DEFAULT_MAX_STREAMS = 1024
OPEN_ACK_TIMEOUT = 12.0
HELLO_TIMEOUT = 10.0
CREDIT_TICK = 0.05
#: Expansion bound on one decompressed chunk (compression-bomb guard).
MAX_EXPANSION = 32 * 1024 * 1024
#: Upper bound on frames parked in the session writer queue. Bounded so a
#: stalled transport backpressures the frame producers (stream writes await
#: ``_send_frame``) instead of growing the queue without limit. Per-runtime
#: write caps are part of the shared writer contract (sdks/WRITER_CONTRACT.md).
_WRITER_QUEUE_FRAMES = 256
#: Upper bound on wire bytes coalesced into one transport write by the
#: session writer task (a byte cap; the Rust writer caps FRAMES instead —
#: see sdks/WRITER_CONTRACT.md).
_WRITER_BATCH_BYTES = 256 * 1024

class KrymuxError(Exception):
    """Base class for krymux SDK errors."""


class SessionClosed(KrymuxError):
    """The session (or the underlying transport) is gone."""


class StreamRejected(KrymuxError):
    """The peer refused an OPEN."""

    def __init__(self, code: str, reason: str):
        super().__init__(f"open rejected: {code} {reason}".strip())
        self.code = code
        self.reason = reason


@dataclass
class Target:
    """Where a stream should end up, as requested by the opener."""

    host: str | None = None
    port: int = 0
    unix: str | None = None
    hint: str = "raw"

    def to_json(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "unix": self.unix,
            "hint": self.hint,
            "meta": None,
        }

    @classmethod
    def from_json(cls, v: dict) -> "Target":
        return cls(
            host=v.get("host") if isinstance(v.get("host"), str) else None,
            port=int(v.get("port") or 0),
            unix=v.get("unix") if isinstance(v.get("unix"), str) else None,
            hint=v.get("hint") if isinstance(v.get("hint"), str) else "raw",
        )

    def __str__(self) -> str:  # pragma: no cover - display helper
        if self.unix:
            return f"unix:{self.unix}"
        return f"{self.host or ''}:{self.port}"


@dataclass
class SessionOpts:
    """Tunables for one multiplexed session."""

    is_client: bool
    name: str = "krymux"
    rx_window: int = DEFAULT_WINDOW
    rx_window_max: int = DEFAULT_RX_WINDOW_MAX
    max_streams: int = DEFAULT_MAX_STREAMS
    keepalive_sec: float = 0.0


class _Stream:
    """Shared per-stream state (both directions)."""

    def __init__(self, session: "Session", sid: int, target: Target, algo: str, level: int | None):
        self.session = session
        self.id = sid
        self.target = target
        self.compression = algo
        self._compressor = Compressor(algo, level)
        self._decompressor = Decompressor(algo)
        self._sniffed = False
        self._bypassed = False  # sniff switched compression off: frames unflagged
        # receive side (toward the app)
        self.buf = bytearray()
        self.buf_off = 0  # consumed prefix of buf (compacted lazily)
        self.data_event: asyncio.Event = asyncio.Event()
        self.eof = False
        self.aborted = False
        self.pending_credit = 0  # consumed-but-not-yet-granted logical bytes
        # send side (from the app)
        self.credits = session.peer_window  # granted by the peer's HELLO
        self.credit_event: asyncio.Event = asyncio.Event()
        self.write_closed = False
        self.app_done = False
        # OPEN_ACK plumbing (client side)
        self.ack: asyncio.Future | None = None
        self.ack_done = False

    @property
    def buffered(self) -> int:
        """Unconsumed receive-side bytes."""
        return len(self.buf) - self.buf_off

    def compress_chunk(self, data: bytes) -> tuple[bytes, bool]:
        """Compress one logical chunk; returns (wire_bytes, compressed_flag)."""
        if not self._sniffed:
            self._sniffed = True
            if self.compression != compress.ALGO_NONE and compress.looks_precompressed(data):
                self._compressor = Compressor(compress.ALGO_NONE)
                self._bypassed = True
        if self.compression == compress.ALGO_NONE or self._bypassed:
            # data is already an immutable bytes slice; no defensive copy needed
            return data, False
        return self._compressor.push(data), True

    def decompress_chunk(self, wire: bytes) -> bytes:
        out = self._decompressor.push(wire)
        if len(out) > MAX_EXPANSION:
            raise ProtocolError(f"decompressed chunk exceeds expansion cap ({len(out)} B)")
        return out

    def finish_decompress(self) -> bytes:
        return self._decompressor.finish()


class TunnelStream:
    """A logical full-duplex stream inside a session (async read/write)."""

    def __init__(self, session: "Session", st: _Stream):
        self._session = session
        self._st = st

    # -- identity / introspection -----------------------------------------
    @property
    def stream_id(self) -> int:
        return self._st.id

    @property
    def target(self) -> Target:
        return self._st.target

    @property
    def compression(self) -> str:
        """The compression algorithm negotiated for this stream."""
        return self._st.compression

    @property
    def remote_address(self) -> str:
        return str(self._st.target)

    # -- receive -----------------------------------------------------------
    async def read(self, n: int | None = 65536) -> bytes:
        """Read up to ``n`` bytes; ``b""`` means EOF (clean or aborted).

        ``n=None`` drains the whole receive buffer (v0.1.0 semantics).
        """
        if n is not None and n <= 0:
            raise ValueError("n must be positive")
        st = self._st
        while st.buffered == 0 and not st.eof:
            if self._session.is_closed:
                break
            st.data_event.clear()
            if st.buffered or st.eof:
                break
            await st.data_event.wait()
        avail = st.buffered
        if avail == 0:
            return b""
        if n is None or n > avail:
            n = avail
        # one copy out of the bytearray; consumption advances an offset and
        # only compacts once the consumed prefix is at least half the buffer
        # (a plain ``del buf[:n]`` per read would memmove the whole remainder,
        # quadratic for apps that buffer a large stream before reading it)
        out = bytes(memoryview(st.buf)[st.buf_off : st.buf_off + n])
        st.buf_off += n
        if st.buf_off == len(st.buf):
            st.buf.clear()
            st.buf_off = 0
        elif st.buf_off * 2 >= len(st.buf):
            del st.buf[:st.buf_off]
            st.buf_off = 0
        await self._session._grant_credit(st, n)
        return out

    async def read_all(self) -> bytes:
        """Read until EOF (clean FIN or abort); returns everything."""
        parts: list[bytes] = []
        while True:
            chunk = await self.read(65536)
            if not chunk:
                return b"".join(parts)
            parts.append(chunk)

    # -- send ---------------------------------------------------------------
    async def write(self, data: bytes) -> None:
        """Write logical bytes: compress, credit-gate, frame, and send.

        Credits are charged on logical (uncompressed) bytes in both
        implementations; frame payloads are split to the peer's advertised
        maxDataFrame.
        """
        st = self._st
        if st.write_closed:
            raise KrymuxError("stream write side shut down")
        if st.aborted:
            raise KrymuxError("stream aborted")
        session = self._session
        max_frame = min(session.peer_max_data, DEFAULT_MAX_DATA)
        # bytes(data) would copy an already-immutable payload all over again
        payload = data if type(data) is bytes else bytes(data)
        off = 0
        while off < len(payload):
            chunk = payload[off : off + max_frame]
            off += len(chunk)
            sent = 0
            while sent < len(chunk):
                take = await self._acquire_credits(len(chunk) - sent)
                piece = chunk[sent : sent + take]
                sent += take
                if not piece:
                    continue
                wire, compressed = st.compress_chunk(piece)
                if not wire:
                    continue
                flags = FLAG_COMPRESSED if compressed else 0
                for i in range(0, len(wire), max_frame):
                    await session._send_frame(FT_DATA, flags, st.id, wire[i : i + max_frame])

    async def _acquire_credits(self, want: int) -> int:
        st = self._st
        session = self._session
        while True:
            if st.credits > 0:
                take = min(st.credits, want)
                st.credits -= take
                return take
            if session.is_closed:
                raise SessionClosed("session closed while waiting for credits")
            if st.aborted:
                raise KrymuxError("stream aborted while waiting for credits")
            st.credit_event.clear()
            if st.credits > 0:
                continue
            await st.credit_event.wait()

    async def close_write(self) -> None:
        """Half-close the send direction: DATA frame with the FIN flag."""
        st = self._st
        if st.write_closed:
            return
        st.write_closed = True
        await self._session._send_frame(FT_DATA, FLAG_FIN, st.id, b"")
        self._session._maybe_retire(st)

    # -- server-side open verdict -------------------------------------------
    async def accept(self, upstream: str | None = None) -> None:
        """Server side: acknowledge the stream (sends OPEN_ACK ok)."""
        st = self._st
        if st.ack_done:
            return
        st.ack_done = True
        body = json.dumps({"ok": True, "compression": st.compression, "upstream": upstream})
        await self._session._send_frame(FT_OPEN_ACK, 0, st.id, body.encode())

    async def reject(self, code: str = "denied", reason: str = "") -> None:
        """Server side: reject the stream (sends OPEN_ACK not-ok)."""
        st = self._st
        if st.ack_done:
            return
        st.ack_done = True
        body = json.dumps({"ok": False, "code": code, "reason": reason})
        await self._session._send_frame(FT_OPEN_ACK, 0, st.id, body.encode())
        self._session._abort_stream(st, "rejected")

    # -- teardown -------------------------------------------------------------
    async def abort(self) -> None:
        """Abort the stream (CLOSE frame; the peer must not read truncation
        as EOF)."""
        await self._session._send_frame(
            FT_CLOSE, 0, self._st.id, json.dumps({"code": "abort"}).encode()
        )
        self._session._abort_stream(self._st, "local abort")

    def close(self) -> None:
        """Fire-and-forget abort (sync counterpart of :meth:`abort`)."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.abort())
        except RuntimeError:
            pass


class Session:
    """A multiplexed session over one ordered byte stream."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 opts: SessionOpts, on_stream=None):
        self._reader = reader
        self._writer = writer
        self.opts = opts
        self.is_client = opts.is_client
        self.on_stream = on_stream
        self.streams: dict[int, _Stream] = {}
        self._next_id = 1 if opts.is_client else 2
        self.peer_max_data = DEFAULT_MAX_DATA
        self.peer_window = DEFAULT_WINDOW
        self.peer_supported: list[str] = ["none"]
        self.our_supported = compress.supported()
        self._ready = asyncio.Event()
        self._closed = False
        self._closed_event = asyncio.Event()
        self._wq: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=_WRITER_QUEUE_FRAMES)
        self._pings: dict[bytes, tuple[asyncio.Future, float]] = {}
        self._tasks: list[asyncio.Task] = []
        self._writer_task: asyncio.Task | None = None

    # -- lifecycle ---------------------------------------------------------
    @classmethod
    async def start(cls, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                    opts: SessionOpts, on_stream=None) -> "Session":
        """Send HELLO, start the session tasks, and wait for the peer's HELLO."""
        self = cls(reader, writer, opts, on_stream)
        loop = asyncio.get_running_loop()
        self._writer_task = loop.create_task(self._writer_loop(), name="krymux-writer")
        self._tasks = [
            self._writer_task,
            loop.create_task(self._reader_loop(), name="krymux-reader"),
            loop.create_task(self._ticker_loop(), name="krymux-ticker"),
        ]
        await self._send_hello()
        try:
            await asyncio.wait_for(self._ready.wait(), HELLO_TIMEOUT)
        except asyncio.TimeoutError:
            self._teardown()
            raise KrymuxError("peer did not send HELLO") from None
        return self

    async def _send_hello(self) -> None:
        hello = {
            "v": PROTOCOL_VERSION,
            "mode": "client" if self.is_client else "server",
            "name": self.opts.name,
            "maxDataFrame": DEFAULT_MAX_DATA,
            "rxWindow": self.opts.rx_window,
            "maxStreams": self.opts.max_streams,
            "compression": self.our_supported,
        }
        await self._send_frame(FT_HELLO, 0, 0, json.dumps(hello).encode())

    def close(self, reason: str = "closed") -> None:
        """Tear the session down, telling the peer why via GOAWAY."""
        if self._closed:
            return
        try:
            body = json.dumps({"reason": reason}).encode()
            self._wq.put_nowait(encode_frame(FT_GOAWAY, 0, 0, body))
        except Exception:
            pass
        self._teardown()

    @property
    def is_closed(self) -> bool:
        return self._closed

    async def wait_closed(self) -> None:
        """Resolve when the session ends (peer disconnect, GOAWAY, close)."""
        await self._closed_event.wait()

    # -- client-side API -----------------------------------------------------
    async def open_stream(self, target: Target | None = None, *, host: str | None = None,
                          port: int = 0, unix: str | None = None, hint: str = "raw",
                          compression: str = "auto") -> TunnelStream:
        """Open a new stream toward ``target`` and wait for the peer's OPEN_ACK."""
        if target is None:
            target = Target(host=host or None, port=port, unix=unix, hint=hint)
        if self._closed:
            raise SessionClosed("session is gone")
        if len(self.streams) >= self.opts.max_streams:
            raise KrymuxError(f"max streams reached ({self.opts.max_streams})")
        sid = self._next_id
        self._next_id += 2
        algo = negotiate(compression, self.peer_supported)
        st = _Stream(self, sid, target, algo, parse_level(compression))
        st.ack = asyncio.get_running_loop().create_future()
        self.streams[sid] = st
        body = dict(target.to_json(), compression=algo)
        try:
            await self._send_frame(FT_OPEN, 0, sid, json.dumps(body).encode())
            await asyncio.wait_for(asyncio.shield(st.ack), OPEN_ACK_TIMEOUT)
        except StreamRejected:
            self.streams.pop(sid, None)
            raise
        except asyncio.TimeoutError:
            self.streams.pop(sid, None)
            raise KrymuxError("open stream timeout") from None
        except (SessionClosed, ConnectionError) as e:
            self.streams.pop(sid, None)
            raise
        return TunnelStream(self, st)

    async def ping(self) -> float:
        """Measure round-trip latency with a PING/PONG exchange (seconds)."""
        nonce = secrets.token_bytes(16)
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        t0 = time.monotonic()
        self._pings[nonce] = (fut, t0)
        try:
            await self._send_frame(FT_PING, 0, 0, nonce)
            await asyncio.wait_for(fut, OPEN_ACK_TIMEOUT)
            return time.monotonic() - t0
        finally:
            self._pings.pop(nonce, None)

    # -- frame plumbing --------------------------------------------------------
    async def _send_frame(self, frame_type: int, flags: int, sid: int, payload: bytes) -> None:
        if self._closed and frame_type != FT_GOAWAY:
            raise SessionClosed("session is gone")
        await self._wq.put(encode_frame(frame_type, flags, sid, payload))

    async def _writer_loop(self) -> None:
        while True:
            item = await self._wq.get()
            if item is None:
                break
            # Coalesce whatever else is already queued into one transport
            # write + one drain round-trip (drain-only-queued burst batching,
            # per sdks/WRITER_CONTRACT.md): under bulk load the queue holds a
            # backlog of frames and per-frame writes/drain checks dominate
            # otherwise.
            try:
                parts = [item]
                total = len(item)
                while total < _WRITER_BATCH_BYTES:
                    try:
                        nxt = self._wq.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    if nxt is None:
                        self._wq.put_nowait(None)  # re-arm the sentinel
                        break
                    parts.append(nxt)
                    total += len(nxt)
                self._writer.write(parts[0] if len(parts) == 1 else b"".join(parts))
                await self._writer.drain()
            except (ConnectionError, OSError, asyncio.CancelledError):
                break
            if self._closed and self._wq.empty():
                break  # teardown sentinel was dropped on a full queue; queue drained
        try:
            self._writer.close()
        except Exception:
            pass

    async def _reader_loop(self) -> None:
        try:
            while True:
                fh, payload = await read_frame(self._reader)
                try:
                    self._handle(fh, payload)
                except ProtocolError as e:
                    try:
                        await self._send_frame(
                            FT_GOAWAY, 0, 0, json.dumps({"reason": str(e)}).encode()
                        )
                    except Exception:
                        pass
                    break
        except (asyncio.IncompleteReadError, ConnectionError, OSError, asyncio.CancelledError):
            pass
        except Exception:
            pass
        finally:
            self._teardown()

    async def _ticker_loop(self) -> None:
        """Flush sub-threshold WINDOW credit tails (credits must not be lost)."""
        try:
            while not self._closed:
                await asyncio.sleep(CREDIT_TICK)
                for st in list(self.streams.values()):
                    if st.pending_credit > 0:
                        delta = st.pending_credit
                        st.pending_credit = 0
                        try:
                            await self._send_frame(FT_WINDOW, 0, st.id, delta.to_bytes(4, "big"))
                        except Exception:
                            st.pending_credit += delta
                            break
        except asyncio.CancelledError:
            pass

    # -- dispatch -----------------------------------------------------------------
    def _handle(self, fh, payload: bytes) -> None:
        # pre-HELLO enforcement
        if not self._ready.is_set() and fh.frame_type != FT_HELLO:
            raise ProtocolError("frame before HELLO")
        if fh.frame_type == FT_HELLO:
            self._handle_hello(payload)
        elif fh.frame_type == FT_OPEN:
            self._handle_open(fh, payload)
        elif fh.frame_type == FT_OPEN_ACK:
            self._handle_open_ack(fh, payload)
        elif fh.frame_type == FT_DATA:
            self._handle_data(fh, payload)
        elif fh.frame_type == FT_WINDOW:
            self._handle_window(fh, payload)
        elif fh.frame_type == FT_CLOSE:
            st = self.streams.get(fh.stream_id)
            if st is not None:
                self._abort_stream(st, "peer close")
        elif fh.frame_type == FT_PING:
            try:
                self._wq.put_nowait(encode_frame(FT_PONG, 0, 0, payload))
            except asyncio.QueueFull:
                pass  # writer backed up; the peer's keepalive re-pings
        elif fh.frame_type == FT_PONG:
            if len(payload) == 16:
                entry = self._pings.pop(payload, None)
                if entry is not None and not entry[0].done():
                    entry[0].set_result(True)
        elif fh.frame_type == FT_GOAWAY:
            raise ProtocolError("peer sent GOAWAY")
        else:
            raise ProtocolError(f"unknown frame type {fh.frame_type}")

    def _handle_hello(self, payload: bytes) -> None:
        if self._ready.is_set():
            raise ProtocolError("second HELLO mid-session")
        try:
            hello = json.loads(payload)
        except json.JSONDecodeError:
            raise ProtocolError("bad HELLO json") from None
        if hello.get("v") != PROTOCOL_VERSION:
            raise ProtocolError("unsupported protocol version")
        self.peer_max_data = min(
            max(int(hello.get("maxDataFrame", DEFAULT_MAX_DATA)), 1024), 1 << 20
        )
        self.peer_window = min(
            max(int(hello.get("rxWindow", DEFAULT_WINDOW)), 16 * 1024), 256 * 1024 * 1024
        )
        comp = hello.get("compression")
        if isinstance(comp, list):
            self.peer_supported = [c for c in comp if isinstance(c, str)] or ["none"]
        self._ready.set()

    def _handle_open(self, fh, payload: bytes) -> None:
        if self.is_client:
            raise ProtocolError("client received OPEN")
        if fh.stream_id == 0 or fh.stream_id % 2 == 0:
            raise ProtocolError(f"bad stream id in OPEN: {fh.stream_id}")

        def nack(code: str, reason: str) -> None:
            body = json.dumps({"ok": False, "code": code, "reason": reason})
            try:
                self._wq.put_nowait(encode_frame(FT_OPEN_ACK, 0, fh.stream_id, body.encode()))
            except asyncio.QueueFull:
                pass  # bounded writer queue; the opener times out instead

        if len(self.streams) >= self.opts.max_streams:
            nack("maxstreams", f"limit {self.opts.max_streams}")
            return
        if fh.stream_id in self.streams:
            nack("duplicate", "stream id already open")
            return
        try:
            v = json.loads(payload)
        except json.JSONDecodeError:
            raise ProtocolError("bad OPEN json") from None
        target = Target.from_json(v)
        requested = v.get("compression") if isinstance(v.get("compression"), str) else "auto"
        algo = negotiate(requested, self.peer_supported)
        if self.on_stream is None:
            nack("nohandler", "server has no stream handler")
            return
        st = _Stream(self, fh.stream_id, target, algo, parse_level(requested))
        self.streams[fh.stream_id] = st
        asyncio.get_running_loop().create_task(self._run_handler(st, target))

    async def _run_handler(self, st: _Stream, target: Target) -> None:
        try:
            handler = self.on_stream
            result = handler(TunnelStream(self, st), target)
            if asyncio.iscoroutine(result):
                await result
        except asyncio.CancelledError:
            raise
        except Exception as e:
            if not st.ack_done:
                try:
                    stream = TunnelStream(self, st)
                    await stream.reject("internal", str(e))
                except Exception:
                    pass
        finally:
            st.app_done = True
            try:
                if not st.ack_done:
                    st.ack_done = True
                    body = json.dumps({"ok": False, "code": "internal", "reason": "handler exited without a verdict"})
                    self._wq.put_nowait(encode_frame(FT_OPEN_ACK, 0, st.id, body.encode()))
                if not st.write_closed and not st.eof:
                    # handler gone without a clean FIN: abort so the peer does not
                    # mistake truncation for EOF
                    self._wq.put_nowait(
                        encode_frame(FT_CLOSE, 0, st.id, json.dumps({"code": "abort"}).encode())
                    )
            except asyncio.QueueFull:
                pass  # bounded writer queue; the teardown paths cope
            self._maybe_retire(st)

    def _handle_open_ack(self, fh, payload: bytes) -> None:
        st = self.streams.get(fh.stream_id)
        if st is None or st.ack is None or st.ack.done():
            return
        try:
            v = json.loads(payload)
        except json.JSONDecodeError:
            v = {}
        st.ack_done = True
        if v.get("ok") is True:
            st.ack.set_result(v.get("upstream") or "")
        else:
            st.ack.set_exception(
                StreamRejected(str(v.get("code") or "denied"), str(v.get("reason") or ""))
            )

    def _handle_data(self, fh, payload: bytes) -> None:
        st = self.streams.get(fh.stream_id)
        if st is None:
            return  # unknown stream: drop
        compressed = bool(fh.flags & FLAG_COMPRESSED)
        fin = bool(fh.flags & FLAG_FIN)
        if payload:
            try:
                # payload is a fresh bytes from the reader; no copy needed for
                # the uncompressed path
                plain = st.decompress_chunk(payload) if compressed else payload
            except Exception:
                try:
                    self._wq.put_nowait(
                        encode_frame(FT_CLOSE, 0, st.id, json.dumps({"code": "abort"}).encode())
                    )
                except asyncio.QueueFull:
                    pass
                self._abort_stream(st, "decompress error")
                return
            if plain:
                # No grant here: credits are returned on app consumption (see
                # TunnelStream.read / Session._grant_credit), which bounds
                # st.buf to the advertised window even for slow readers.
                st.buf += plain
                st.data_event.set()
        if fin:
            tail = st.finish_decompress()
            if tail:
                st.buf += tail
            st.eof = True
            st.data_event.set()
            self._maybe_retire(st)

    def _handle_window(self, fh, payload: bytes) -> None:
        if len(payload) != 4:
            raise ProtocolError(f"bad WINDOW frame length {len(payload)}")
        delta = int.from_bytes(payload, "big")
        st = self.streams.get(fh.stream_id)
        if st is not None:
            st.credits += delta
            st.credit_event.set()

    async def _grant_credit(self, st: "_Stream", n: int) -> None:
        """Credit-on-consumption: return consumed logical bytes to the peer
        once the threshold is crossed (the credit ticker flushes sub-threshold
        tails). This is what paces the sender — the receive buffer stays
        bounded by the advertised window even for slow readers, matching the
        Rust/Go/TS SDKs (see sdks/WRITER_CONTRACT.md)."""
        st.pending_credit += n
        threshold = max(self.opts.rx_window // 4, 16 * 1024)
        if st.pending_credit < threshold:
            return
        delta = st.pending_credit
        st.pending_credit = 0
        try:
            await self._send_frame(FT_WINDOW, 0, st.id, delta.to_bytes(4, "big"))
        except Exception:
            st.pending_credit += delta  # never lose consumed-but-ungranted bytes

    # -- stream state helpers ---------------------------------------------------
    def _abort_stream(self, st: _Stream, why: str) -> None:
        st.aborted = True
        st.eof = True
        st.data_event.set()
        st.credit_event.set()
        if st.ack is not None and not st.ack.done():
            st.ack.set_exception(KrymuxError(f"stream aborted before ack ({why})"))
        self._maybe_retire(st)

    def _maybe_retire(self, st: _Stream) -> None:
        """Unregister a stream once nothing needs it: the app side is done AND
        the write direction has finished (so WINDOW grants can stop)."""
        app_finished = st.app_done or st.eof or st.aborted
        write_finished = st.write_closed or st.aborted
        if app_finished and write_finished:
            cur = self.streams.get(st.id)
            if cur is st:
                del self.streams[st.id]
            # final sub-threshold credit flush: never lose granted bytes
            if st.pending_credit > 0:
                delta = st.pending_credit
                st.pending_credit = 0
                try:
                    self._wq.put_nowait(
                        encode_frame(FT_WINDOW, 0, st.id, delta.to_bytes(4, "big"))
                    )
                except Exception:
                    pass
            st.credit_event.set()

    def _teardown(self) -> None:
        if self._closed:
            self._closed_event.set()
            return
        self._closed = True
        for st in list(self.streams.values()):
            st.aborted = True
            st.eof = True
            st.data_event.set()
            st.credit_event.set()
            if st.ack is not None and not st.ack.done():
                st.ack.set_exception(SessionClosed("session closed while opening"))
        self.streams.clear()
        for nonce, (fut, _t) in list(self._pings.items()):
            if not fut.done():
                fut.set_exception(SessionClosed("session closed"))
        self._pings.clear()
        # cancel reader/ticker now; the writer drains whatever is queued
        # (GOAWAY included) and exits on the sentinel below
        for t in self._tasks:
            if t is not self._writer_task:
                t.cancel()
        try:
            self._wq.put_nowait(None)
        except Exception:
            pass
        self._closed_event.set()
