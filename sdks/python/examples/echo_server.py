#!/usr/bin/env python3
"""Krymux echo server example.

Runs a krymux TLS listener whose per-stream handler echoes every byte back.
Generate identities with `krymux-tunnel keygen` (Rust CLI) or let this script
generate one and print its fingerprint.
"""

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import krymux


async def echo_handler(stream: krymux.TunnelStream, target: krymux.Target) -> None:
    await stream.accept("echo")
    while True:
        data = await stream.read(65536)
        if not data:
            break
        await stream.write(data)
    await stream.close_write()


async def main() -> None:
    ap = argparse.ArgumentParser(description="krymux echo server")
    ap.add_argument("--listen", default="127.0.0.1:8443", help="host:port to listen on")
    ap.add_argument("--key", help="Ed25519 private key PEM (else one is generated)")
    ap.add_argument("--cert", help="certificate PEM matching --key")
    ap.add_argument("--allow", action="append", default=[],
                    help="authorized client fingerprint (sha256:... / hex / cert path); repeatable")
    ap.add_argument("--trust-cert", action="append", default=[],
                    help="client certificate file to trust during the TLS handshake; repeatable")
    args = ap.parse_args()

    if args.key and args.cert:
        identity = krymux.load_identity(args.key, args.cert)
    elif not args.key and not args.cert:
        identity = krymux.generate_identity("krymux-echo-server")
    else:
        sys.exit("error: --key and --cert must be given together")

    if not args.allow:
        sys.exit("error: refuse-forever mode — pass at least one --allow <fingerprint>")

    server = await krymux.listen(
        args.listen,
        identity,
        echo_handler,
        fingerprints=args.allow,
        trusted_client_certs=args.trust_cert or None,
    )
    for addr in server.addresses:
        print(f"krymux echo server on {addr[0]}:{addr[1]}")
    print(f"server fingerprint (pin this in clients): {identity.fingerprint}")
    await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
