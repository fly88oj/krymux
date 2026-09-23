#!/usr/bin/env python3
"""Interop tests: Python krymux SDK <-> Rust krymux-tunnel binary.

Phase A: Rust server (krymux-tunnel.exe keygen+server, whitelist our Python
         client's fingerprint) -> Python client echoes 1 MiB+ through a TCP
         echo origin, byte-exact, per compression algorithm; plus pin
         fail-closed and unrouted-target rejection checks.
Phase B: Python server -> Rust client via `krymux-tunnel.exe client --socks5`
         + the small SOCKS5 client built in-test (patterns mirror
         ../../interop/test-interop.mjs), 1 MiB echo byte-exact per algorithm.

Runs standalone (`python tests/test_interop_rust.py`) or under pytest.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

SDK_DIR = Path(__file__).resolve().parents[1]
ROOT = SDK_DIR.parents[1]
RS_BIN = Path(os.environ.get("ECTUN_BIN", ROOT / "target" / "release" / "krymux-tunnel.exe"))

sys.path.insert(0, str(SDK_DIR))

import krymux  # noqa: E402

PASS: list[str] = []
FAIL: list[tuple[str, str]] = []


# ---------------------------------------------------------------- helpers


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _wait_tcp(host: str, port: int, timeout: float = 15.0) -> None:
    """Poll until the TCP endpoint accepts (no blind idle sleeps)."""
    deadline = asyncio.get_event_loop().time() + timeout
    while True:
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.close()
            return
        except (ConnectionError, OSError):
            if asyncio.get_event_loop().time() >= deadline:
                raise TimeoutError(f"{host}:{port} never came up") from None
            await asyncio.sleep(0.05)


def _keygen(outdir: Path, role: str, name: str) -> str:
    """Run the Rust keygen; returns the printed fingerprint."""
    proc = subprocess.run(
        [str(RS_BIN), "keygen", "--out", str(outdir), "--role", role, "--name", name],
        capture_output=True, text=True, timeout=60,
    )
    m = re.search(r"fingerprint: (sha256:[0-9a-f]{64})", proc.stdout + proc.stderr)
    if not m:
        raise RuntimeError(f"keygen failed: rc={proc.returncode} {proc.stdout} {proc.stderr}")
    return m.group(1)


def _spawn(args: list[str]) -> subprocess.Popen:
    return subprocess.Popen(
        [str(RS_BIN)] + args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
    )


def _proc_output(proc: subprocess.Popen) -> str:
    try:
        err = proc.stderr.read() if proc.stderr else ""
    except Exception:
        err = ""
    return err or ""


def _write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2))


async def _start_echo_origin() -> int:
    """A TCP echo origin on 127.0.0.1 with half-close propagation."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    writer.write_eof()
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    asyncio.get_event_loop().create_task(_serve_forever(server))
    return port


async def _serve_forever(server: asyncio.AbstractServer) -> None:
    try:
        await server.serve_forever()
    except asyncio.CancelledError:
        pass


async def _socks5_roundtrip(proxy_port: int, host: str, port: int, payload: bytes) -> bytes:
    """Minimal RFC 1928 SOCKS5 CONNECT client (no auth, domain names)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    try:
        writer.write(b"\x05\x01\x00")  # VER NMETHODS [no-auth]
        await writer.drain()
        assert (await reader.readexactly(2)) == b"\x05\x00", "socks5 greeting refused"

        h = host.encode()
        writer.write(bytes([5, 1, 0, 3, len(h)]) + h + port.to_bytes(2, "big"))
        await writer.drain()
        rep = await reader.readexactly(10)  # VER REP RSV ATYP BND.ADDR BND.PORT
        assert rep[1] == 0, f"socks5 connect refused: rep={rep[1]}"

        writer.write(payload)
        await writer.drain()
        parts: list[bytes] = []
        got = 0
        while got < len(payload):
            chunk = await reader.read(65536)
            if not chunk:
                break
            parts.append(chunk)
            got += len(chunk)
        return b"".join(parts)
    finally:
        writer.close()


def _payload_1mib(seed_len: int = 1 << 20) -> bytes:
    return os.urandom(seed_len // 2) + b"compressible-payload " * (seed_len // 44)


# ---------------------------------------------------------------- phase A


async def _phase_a() -> None:
    """Rust server + Python client: 1 MiB echo per algorithm, pin checks."""
    outdir = Path(tempfile.mkdtemp(prefix="krymux-py-interop-a-"))
    server_fp = _keygen(outdir, "server", "server")
    alice_fp = _keygen(outdir, "client", "alice")

    echo_port = await _start_echo_origin()
    listen_port = _free_port()
    _write_json(outdir / "server.json", {
        "listen": f"127.0.0.1:{listen_port}",
        "identity": {
            "key": str(outdir / "server.key.pem"),
            "cert": str(outdir / "server.crt.pem"),
        },
        "auth": {"mode": "whitelist", "fingerprints": [alice_fp]},
        "routes": [{"host": ["echo"], "upstream": ["127.0.0.1", echo_port]}],
        "clientTargets": {"enabled": False},
        "log": {"level": "warn"},
    })

    proc = _spawn(["server", "--config", str(outdir / "server.json")])
    try:
        await _wait_tcp("127.0.0.1", listen_port)

        identity = krymux.load_identity(outdir / "alice.key.pem", outdir / "alice.crt.pem")
        addr = f"127.0.0.1:{listen_port}"
        client = await krymux.connect(addr, identity, server_fp)

        # cross-tool fingerprint agreement: the Rust keygen fp of alice must
        # equal our Python-computed fp of the same PEM pair
        assert identity.fingerprint == alice_fp, "fingerprint mismatch across tools"

        payload = _payload_1mib()
        for algo in ("none", "deflate"):
            stream = await client.open_stream("echo", 9, compression=algo)
            assert stream.compression == algo, f"negotiated {stream.compression}, want {algo}"
            # interleave: the Rust server re-grants credits on consumption,
            # so the echo must be drained while writing (write-all-then-read
            # would park on the receive window mid-transfer)
            echo = asyncio.get_event_loop().create_task(stream.read_all())
            await stream.write(payload)
            await stream.close_write()
            got = await echo
            assert got == payload, f"{algo}: echo not byte-exact ({len(got)} != {len(payload)})"
            PASS.append(f"A: echo {algo} 1MB+ byte-exact (python client -> rust server)")

        # unrouted target must be rejected
        try:
            await client.open_stream("nope.example", 80, compression="none")
            raise AssertionError("unrouted target was not rejected")
        except krymux.StreamRejected as e:
            assert "denied" in str(e) or "route" in str(e), f"unexpected reason: {e}"
            PASS.append("A: unrouted target denied by rust router")

        # pin verification must fail closed on a wrong fingerprint
        try:
            await krymux.connect(addr, identity, "sha256:" + "0" * 64)
            raise AssertionError("wrong pin was accepted")
        except (krymux.PinVerificationError, ConnectionError):
            PASS.append("A: wrong server pin rejected (fail closed)")

        client.close()
        await asyncio.sleep(0)
    finally:
        proc.kill()
        proc.wait()
        if FAIL and FAIL[-1][0].startswith("A:"):
            print(_proc_output(proc), file=sys.stderr)


# ---------------------------------------------------------------- phase B


async def _phase_b() -> None:
    """Python server + Rust client through the SOCKS5 frontend."""
    outdir = Path(tempfile.mkdtemp(prefix="krymux-py-interop-b-"))
    server_id = krymux.generate_identity("krymux-py-server")
    bob_fp = _keygen(outdir, "client", "bob")

    echo_port = await _start_echo_origin()
    listen_port = _free_port()
    socks_port = _free_port()

    async def pipe_to_echo(stream: krymux.TunnelStream, target: krymux.Target) -> None:
        await stream.accept("echo")
        upstream_r, upstream_w = await asyncio.open_connection("127.0.0.1", echo_port)

        async def tunnel_to_upstream() -> None:
            while True:
                data = await stream.read(65536)
                if not data:
                    break
                upstream_w.write(data)
                await upstream_w.drain()
            upstream_w.write_eof()

        async def upstream_to_tunnel() -> None:
            while True:
                data = await upstream_r.read(65536)
                if not data:
                    break
                await stream.write(data)
            await stream.close_write()

        t1 = asyncio.get_event_loop().create_task(tunnel_to_upstream())
        t2 = asyncio.get_event_loop().create_task(upstream_to_tunnel())
        done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        await asyncio.gather(t1, t2, return_exceptions=True)
        upstream_w.close()

    server = await krymux.listen(
        f"127.0.0.1:{listen_port}",
        server_id,
        pipe_to_echo,
        fingerprints=[bob_fp],
        trusted_client_certs=[str(outdir / "bob.crt.pem")],
    )
    try:
        payload = _payload_1mib(768 * 1024)
        for comp in ("none", "deflate"):
            _write_json(outdir / "rs-client.json", {
                "endpoint": f"127.0.0.1:{listen_port}",
                "identity": {
                    "key": str(outdir / "bob.key.pem"),
                    "cert": str(outdir / "bob.crt.pem"),
                },
                "serverFingerprint": server_id.fingerprint,
                "socks5": f"127.0.0.1:{socks_port}",
                "compression": comp,
                "keepaliveSec": 30,
                "log": {"level": "warn"},
            })
            proc = _spawn(["client", "--config", str(outdir / "rs-client.json")])
            try:
                await _wait_tcp("127.0.0.1", socks_port)
                got = await _socks5_roundtrip(socks_port, "echo.x", 9, payload)
                assert got == payload, (
                    f"{comp}: socks5 echo not byte-exact ({len(got)} != {len(payload)})"
                )
                PASS.append(
                    f"B: rust client ({comp}) -> python server, 768KB echo via socks5"
                )
            finally:
                proc.kill()
                proc.wait()
    finally:
        server.close()
        await asyncio.sleep(0)


# ---------------------------------------------------------------- runners


def test_python_client_rust_server() -> None:
    asyncio.run(_phase_a())


def test_rust_client_python_server() -> None:
    asyncio.run(_phase_b())


async def _run_all() -> int:
    for name, fn in (("A: python client <-> rust server", _phase_a),
                     ("B: rust client <-> python server", _phase_b)):
        try:
            await fn()
        except BaseException as e:  # noqa: BLE001 - report and continue
            FAIL.append((name, f"{type(e).__name__}: {e}"))
            import traceback

            traceback.print_exc()
    return 1 if FAIL else 0


if __name__ == "__main__":
    if not RS_BIN.is_file():
        print(f"krymux-tunnel binary not found: {RS_BIN}", file=sys.stderr)
        sys.exit(2)
    rc = asyncio.run(_run_all())
    for name in PASS:
        print(f"  ok {name}")
    for name, err in FAIL:
        print(f"  FAIL {name}: {err}", file=sys.stderr)
    print(f"\ninterop: {len(PASS)} passed, {len(FAIL)} failed")
    sys.exit(rc)
