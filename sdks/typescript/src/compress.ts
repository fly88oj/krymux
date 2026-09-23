// Per-stream, per-direction compression contexts with *continuous* context:
// chunks are compressed/decompressed through persistent zlib transform streams and
// flushed at frame boundaries (like WebSocket permessage-deflate with context takeover).
//
// This port supports the "none" and "deflate" algorithms (raw DEFLATE via
// node:zlib with Z_SYNC_FLUSH at frame boundaries) — the subset negotiated with
// the Rust implementation's flate2-based deflate, which is byte-compatible.
//
// Determinism note: for zlib-family transforms, the write/flush callback fires only
// after the transform has pushed all output for that input; with a 'data' listener
// attached from construction (flowing mode), pushed output is collected synchronously.

import { Buffer } from 'node:buffer';
import zlib from 'node:zlib';

export const ALGO_NONE = 'none';
export const ALGO_DEFLATE = 'deflate';

/** Algorithms this runtime can actually compress/decompress. */
export const SUPPORTED: readonly string[] = [ALGO_NONE, ALGO_DEFLATE];

/** Context handle shared by both directions of one stream. */
export interface CompCtx {
  write(buf: Buffer): Promise<Buffer | null>;
  end(): Promise<Buffer | null>;
  destroy(): void;
}

class ZCtx implements CompCtx {
  private readonly z: zlib.DeflateRaw | zlib.InflateRaw;
  private readonly parts: Buffer[] = [];
  private err: Error | null = null;

  constructor(z: zlib.DeflateRaw | zlib.InflateRaw) {
    this.z = z;
    z.on('data', (d: Buffer) => this.parts.push(d));
    z.on('error', (e: Error) => {
      this.err = e;
    });
  }

  private _collect(): Buffer | null {
    if (this.parts.length === 0) return null;
    const out = Buffer.concat(this.parts);
    this.parts.length = 0;
    return out;
  }

  write(buf: Buffer): Promise<Buffer | null> {
    return new Promise((res, rej) => {
      if (this.err) return rej(this.err);
      this.z.write(buf, (e) => (e ? rej(e) : res(this._collect())));
    });
  }

  end(): Promise<Buffer | null> {
    return new Promise((res) => {
      if (this.err || this.z.destroyed || this.z.writableEnded) return res(null);
      this.z.end(() => res(this._collect()));
    });
  }

  /** Teardown: end() first so zlib releases its handles, then destroy(). */
  destroy(): void {
    if (this.z.destroyed) return;
    const finish = () => {
      if (!this.z.destroyed) this.z.destroy();
    };
    if (this.z.writableEnded || this.err) {
      finish();
    } else {
      this.z.once('close', finish);
      try {
        this.z.end();
      } catch {
        finish();
      }
      setTimeout(finish, 50).unref();
    }
  }
}

class PassCtx implements CompCtx {
  write(buf: Buffer): Promise<Buffer | null> {
    return Promise.resolve(buf.length ? buf : null);
  }

  async end(): Promise<Buffer | null> {
    return null;
  }

  destroy(): void {}
}

/** Cached list of algorithms usable on this runtime (['none', 'deflate']). */
export function supportedAlgorithms(): Promise<string[]> {
  _supported ??= Promise.resolve([...SUPPORTED]);
  return _supported;
}
let _supported: Promise<string[]> | null = null;

/**
 * Pick an algorithm from a request + peer's supported list. The result is always
 * an algorithm this runtime can handle (never e.g. 'brotli'/'zstd').
 */
export function negotiate(requested: string | null | undefined, peerSupported: readonly string[]): string {
  if (!requested || requested === ALGO_NONE) return ALGO_NONE;
  const base = baseAlgo(requested);
  const pick = (a: string): string | null => (peerSupported.includes(a) && SUPPORTED.includes(a) ? a : null);
  if (base === 'auto') {
    return pick(ALGO_DEFLATE) || ALGO_NONE;
  }
  return pick(base) || ALGO_NONE;
}

/** "deflate:9" -> "deflate" (level suffix stripped; unknown suffixes keep the base). */
export function baseAlgo(requested: string | null | undefined): string {
  const s = String(requested);
  const idx = s.indexOf(':');
  return idx === -1 ? s : s.slice(0, idx);
}

/** "deflate:9" -> 9; invalid/missing -> null. */
export function parseLevel(requested: string | null | undefined): number | null {
  const s = String(requested ?? '');
  const idx = s.indexOf(':');
  if (idx === -1) return null;
  const n = Number(s.slice(idx + 1));
  return Number.isInteger(n) && n >= 1 && n <= 22 ? n : null;
}

// Well-known magic prefixes: content that is already compressed. Streams whose
// first chunk matches are silently switched to 'none' (saves CPU, avoids the
// ~0.3% expansion). Applied per direction by the sender only.
const MAGIC_PREFIXES: Buffer[] = [
  Buffer.from([0x1f, 0x8b]),                   // gzip
  Buffer.from([0x28, 0xb5, 0x2f, 0xfd]),       // zstd
  Buffer.from([0x50, 0x4b, 0x03, 0x04]),       // zip
  Buffer.from([0x89, 0x50, 0x4e, 0x47]),       // png
  Buffer.from([0xff, 0xd8, 0xff]),             // jpeg
  Buffer.from([0x37, 0x7a, 0xbc, 0xaf]),       // 7z
  Buffer.from([0x52, 0x61, 0x72, 0x21]),       // rar
  Buffer.from([0x25, 0x50, 0x44, 0x46]),       // %PDF (not compressed, but incompressible-ish)
  Buffer.from([0x42, 0x5a, 0x68]),             // bzip2
];

/** Heuristic: does this first chunk look pre-compressed? */
export function looksPrecompressed(chunk: Buffer | null): boolean {
  if (!chunk || chunk.length < 4) return false;
  for (const magic of MAGIC_PREFIXES) {
    if (chunk.length >= magic.length && chunk.subarray(0, magic.length).equals(magic)) {
      return true;
    }
  }
  // ISO-BMFF (mp4/mov/heic): "....ftyp" at offset 4
  if (chunk.length >= 12 && chunk[4] === 0x66 && chunk[5] === 0x74 && chunk[6] === 0x79 && chunk[7] === 0x70) {
    return true;
  }
  return false;
}

/**
 * Create a sender-side compression context for one stream direction.
 * write(buf) -> Promise<Buffer|null>, end()/destroy() for teardown.
 */
export function createCompressContext(algo: string, { level }: { level?: number | null } = {}): CompCtx {
  switch (algo) {
    case ALGO_NONE:
      return new PassCtx();
    case ALGO_DEFLATE:
      // flush: Z_SYNC_FLUSH makes every write() emit a sync-flushed block
      // (permessage-deflate style), so one write() per chunk is also the
      // frame boundary; wire output stays a continuous sync-flushed
      // raw-deflate stream.
      return new ZCtx(
        zlib.createDeflateRaw({
          level: level ?? 6, windowBits: 15, memLevel: 8, flush: zlib.constants.Z_SYNC_FLUSH,
        }),
      );
    default:
      throw new Error(`unsupported compression algorithm: ${algo}`);
  }
}

/**
 * Create the matching receiver-side decompression context for one stream
 * direction; same interface as createCompressContext.
 */
export function createDecompressContext(algo: string): CompCtx {
  switch (algo) {
    case ALGO_NONE:
      return new PassCtx();
    case ALGO_DEFLATE:
      return new ZCtx(zlib.createInflateRaw({ windowBits: 15 }));
    default:
      throw new Error(`unsupported compression algorithm: ${algo}`);
  }
}
