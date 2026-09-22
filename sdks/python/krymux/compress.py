"""Per-stream, per-direction compression with a continuous context flushed at
every chunk — the same semantics as the Rust/Node reference implementations
(wire-compatible).

This SDK implements ``none`` and ``deflate`` (raw DEFLATE via :mod:`zlib`);
negotiation intersects the request with what both peers support, so a peer
advertising brotli/zstd simply negotiates down to ``none``/``deflate``.
"""

from __future__ import annotations

import zlib

ALGO_NONE = "none"
ALGO_DEFLATE = "deflate"

#: Algorithms this build supports (advertised in HELLO).
SUPPORTED: tuple[str, ...] = (ALGO_NONE, ALGO_DEFLATE)

_DEFAULT_LEVELS = {ALGO_DEFLATE: 6}

#: Well-known magic prefixes of already-compressed content. The sender's first
#: chunk is sniffed; a match bypasses compression (frames go out unflagged).
MAGIC_PREFIXES: tuple[bytes, ...] = (
    b"\x1f\x8b",  # gzip
    b"\x28\xb5\x2f\xfd",  # zstd
    b"\x50\x4b\x03\x04",  # zip
    b"\x89\x50\x4e\x47",  # png
    b"\xff\xd8\xff",  # jpeg
    b"\x37\x7a\xbc\xaf",  # 7z
    b"\x52\x61\x72\x21",  # rar
    b"\x25\x50\x44\x46",  # %PDF
    b"\x42\x5a\x68",  # bzip2
)


def looks_precompressed(chunk: bytes) -> bool:
    """Heuristic: does this first chunk look already-compressed?"""
    if len(chunk) < 4:
        return False
    for magic in MAGIC_PREFIXES:
        if chunk.startswith(magic):
            return True
    # ISO-BMFF (mp4/mov/heic): "ftyp" at offset 4
    return len(chunk) >= 12 and chunk[4:8] == b"ftyp"


def supported() -> list[str]:
    """Algorithms this build supports (HELLO advertisement)."""
    return list(SUPPORTED)


def base_algo(requested: str) -> str:
    """Strip a level suffix: ``"deflate:9"`` -> ``"deflate"``."""
    return requested.split(":", 1)[0]


def parse_level(requested: str) -> int | None:
    """Parse a level suffix: ``"deflate:9"`` -> 9; invalid/missing -> None."""
    i = requested.find(":")
    if i < 0:
        return None
    try:
        lvl = int(requested[i + 1 :])
    except ValueError:
        return None
    return lvl if 1 <= lvl <= 9 else None


def negotiate(requested: str, peer_supported: list[str] | tuple[str, ...]) -> str:
    """Pick an algorithm from a request plus the peer's supported list.

    Only algorithms both sides support can be chosen: ``deflate`` requires the
    peer to advertise it; anything this build cannot compress or decompress
    (brotli, zstd, zstdd) falls back to ``none``. Mirrors the reference
    negotiation's fallback semantics for the algorithms we implement.
    """
    base = base_algo(requested)
    if base in ("", ALGO_NONE):
        return ALGO_NONE
    if base == "auto":
        return ALGO_DEFLATE if ALGO_DEFLATE in peer_supported else ALGO_NONE
    if base == ALGO_DEFLATE:
        return ALGO_DEFLATE if ALGO_DEFLATE in peer_supported else ALGO_NONE
    # brotli / zstd / zstdd:<fp> and anything unknown: not implemented here.
    return ALGO_NONE


class Compressor:
    """Chunk-oriented compressor holding one continuous context per direction."""

    def __init__(self, algo: str, level: int | None = None):
        self._algo = algo
        self._z = None
        if algo == ALGO_DEFLATE:
            lvl = level if level is not None else _DEFAULT_LEVELS[ALGO_DEFLATE]
            self._z = zlib.compressobj(lvl, zlib.DEFLATED, -15)  # raw deflate

    @property
    def algo(self) -> str:
        return self._algo

    def push(self, data: bytes) -> bytes:
        """Compress one chunk with a sync-flush boundary (may be empty only
        for empty input; raw DEFLATE sometimes emits only flush bits)."""
        if not data:
            return b""
        if self._algo == ALGO_NONE:
            return bytes(data)
        out = self._z.compress(data) + self._z.flush(zlib.Z_SYNC_FLUSH)
        return out


class Decompressor:
    """Chunk-oriented decompressor holding one continuous context per direction."""

    def __init__(self, algo: str):
        self._algo = algo
        self._z = zlib.decompressobj(-15) if algo == ALGO_DEFLATE else None

    @property
    def algo(self) -> str:
        return self._algo

    def push(self, wire: bytes) -> bytes:
        """Decompress one wire chunk; returns logical bytes (may be empty)."""
        if not wire:
            return b""
        if self._algo == ALGO_NONE:
            return bytes(wire)
        return self._z.decompress(wire)

    def finish(self) -> bytes:
        """End-of-stream: drain any lazily-held output (a no-op for
        sync-flushed streams, defensive for other producers)."""
        if self._z is not None:
            try:
                return self._z.flush()
            except Exception:
                return b""
        return b""
