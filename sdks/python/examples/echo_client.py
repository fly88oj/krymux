#!/usr/bin/env python3
"""Krymux echo client example.

Connects to a krymux server, streams a payload through a tunnel stream to an
echo upstream, and verifies the bytes come back unchanged.
"""

import argparse
import asyncio
import hashlib
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import krymux


async def main() -> None:
    ap = argparse.ArgumentParser(description="krymux echo client")
    ap.add_argument("--addr", required=True, help="server endpoint host:port")
    ap.add_argument("--key", required=True, help="Ed25519 private key PEM")
    ap.add_argument("--cert", required=True, help="certificate PEM matching --key")
    ap.add_argument("--fp", required=True, help="pinned server fingerprint (sha256:...)")
    ap.add_argument("--host", default="echo", help="target host to open a stream to")
    ap.add_argument("--port", type=int, default=9, help="target port")
    ap.add_argument("--size", type=int, default=1 << 20, help="payload bytes (default 1 MiB)")
    ap.add_argument("--compression", default="auto", help="none | deflate | auto")
    args = ap.parse_args()

    identity = krymux.load_identity(args.key, args.cert)
    client = await krymux.connect(args.addr, identity, args.fp)

    # exactly args.size bytes: half random (incompressible) + half repeating
    half = args.size // 2
    unit = b"compressible-payload "
    payload = os.urandom(half) + (unit * (half // len(unit) + 1))[: args.size - half]
    t0 = time.monotonic()
    stream = await client.open_stream(args.host, args.port, compression=args.compression)
    print(f"stream open (compression={stream.compression}) -> {stream.remote_address}")
    await stream.write(payload)
    await stream.close_write()
    got = await stream.read_all()
    dt = time.monotonic() - t0

    ok = got == payload
    print(f"sent {len(payload)} bytes, received {len(got)} bytes in {dt:.3f}s")
    print(f"payload sha256 {hashlib.sha256(payload).hexdigest()[:16]}...")
    print("RESULT: OK (byte-exact echo)" if ok else "RESULT: MISMATCH")
    client.close()
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
