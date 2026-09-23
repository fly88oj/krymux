#!/usr/bin/env python3
"""Echo throughput benchmark for the Python Krymux SDK.

Measures the mux + stream data path (writer batching, framing, flow control,
optional deflate) over a loopback TCP socket pair -- both sessions in this one
process, no TLS (TLS is stdlib-ssl-internal and identical before/after any
SDK-level optimization).

Per combination of payload size (1 MiB, 16 MiB) and compression (none,
deflate): open a stream, push the payload in 64-KiB chunks while draining
the echo concurrently (credits are granted on consumption, so writing
everything before reading would park on the window), half-close, verify
sha256. 3 runs, median one-way payload MiB/s.

    python bench/echo.py

Output lines: ``RESULT py <size>MiB <comp> <median MiB/s>``
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from krymux.mux import Session, SessionOpts, Target  # noqa: E402

CHUNK = 64 * 1024
RUNS = 3
SIZES = (1, 16)  # MiB
COMPS = ("none", "deflate")


def make_payload(size: int) -> bytes:
    """Half random, half compressible -- same pattern as the example clients."""
    half = size // 2
    unit = b"compressible-payload "
    tail = (unit * (half // len(unit) + 1))[:half]
    return os.urandom(half) + tail


async def _handle_stream(stream, _target) -> None:
    await stream.accept()
    # Pipelined echo: keep one write in flight so the read side (whose
    # consumption returns the peer's credits) is never stalled behind a
    # window-blocked write.
    pending = None
    try:
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                break
            if pending is not None:
                await pending
            pending = asyncio.ensure_future(stream.write(chunk))
        if pending is not None:
            await pending
    finally:
        if pending is not None and not pending.done():
            pending.cancel()
    await stream.close_write()


async def run_once(port: int, payload: bytes, comp: str, expect_hash: str) -> float:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    session = await Session.start(
        reader, writer, SessionOpts(is_client=True, name="bench-client")
    )
    t0 = time.monotonic()
    stream = await session.open_stream(
        Target(host="bench", port=9), compression=comp
    )
    # Consume the echo concurrently with writing: credits are granted on app
    # consumption (bounded-memory design, see krymux/mux.py), so a write-
    # everything-first-then-read pattern would park on the window mid-transfer.
    echo = asyncio.ensure_future(stream.read_all())
    for off in range(0, len(payload), CHUNK):
        await stream.write(payload[off : off + CHUNK])
    await stream.close_write()
    got = await echo
    dt = time.monotonic() - t0
    if len(got) != len(payload) or hashlib.sha256(got).hexdigest() != expect_hash:
        raise RuntimeError("echo mismatch (size or sha256)")
    session.close()
    return len(payload) / 1048576 / dt


async def main() -> None:
    server = await asyncio.start_server(
        _client_connected, "127.0.0.1", 0
    )
    port = server.sockets[0].getsockname()[1]

    print(f"bench py python/{sys.version.split()[0]} chunk={CHUNK} runs={RUNS}")
    for size_mib in SIZES:
        payload = make_payload(size_mib * 1048576)
        expect = hashlib.sha256(payload).hexdigest()
        for comp in COMPS:
            mbps = [
                await run_once(port, payload, comp, expect) for _ in range(RUNS)
            ]
            median = statistics.median(mbps)
            runs_str = ", ".join(f"{m:.1f}" for m in mbps)
            print(f"RESULT py {size_mib}MiB {comp} {median:.1f}  (runs: {runs_str})")
    server.close()
    await server.wait_closed()


async def _client_connected(reader, writer) -> None:
    try:
        await Session.start(
            reader,
            writer,
            SessionOpts(is_client=False, name="bench-server"),
            on_stream=_handle_stream,
        )
    except Exception:
        pass


if __name__ == "__main__":
    asyncio.run(main())
