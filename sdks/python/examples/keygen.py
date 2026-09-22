#!/usr/bin/env python3
"""Generate the identity pair used by the cross-language interop matrix.

Writes a "server" and a "client" identity into a directory using the shared
layout all four SDKs produce — ``<name>.key.pem`` (PKCS#8 Ed25519) /
``<name>.crt.pem`` / ``<name>.identity.json`` — and prints both fingerprints.
The PEM files must be loadable by the TypeScript, Go and Rust loaders as well;
that cross-loading is part of what the matrix exercises.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import krymux


def main() -> None:
    ap = argparse.ArgumentParser(description="krymux xlang keygen")
    ap.add_argument("--dir", required=True, help="output directory for the identity pair")
    args = ap.parse_args()

    server = krymux.generate_identity("krymux-xlang-server")
    client = krymux.generate_identity("krymux-xlang-client")
    krymux.save_identity(args.dir, server, "server")
    krymux.save_identity(args.dir, client, "client")
    print(f"server fingerprint: {server.fingerprint}")
    print(f"client fingerprint: {client.fingerprint}")


if __name__ == "__main__":
    main()
