// Wire framing: [type:1][flags:1][streamId:4][length:4][payload:length] — all big-endian.
// Byte-for-byte compatible with the Rust (crates/krymux/src/frame.rs) and Node
// (ectun/lib/frame.mjs) implementations of the Krymux protocol.

import { Buffer } from 'node:buffer';

export const FT = Object.freeze({
  HELLO: 1,     // sid=0, both sides, JSON
  OPEN: 2,      // open a stream, JSON target descriptor
  OPEN_ACK: 3,  // accept/reject result, JSON
  DATA: 4,      // payload (maybe compressed; FLAG.FIN marks end-of-stream)
  WINDOW: 5,    // 4-byte BE credit delta
  CLOSE: 6,     // abort/teardown: [code:1][reason:utf8]
  PING: 7,      // sid=0, opaque echo payload
  PONG: 8,      // sid=0, echo of PING
  GOAWAY: 9,    // sid=0, connection-level shutdown, JSON reason
} as const);

export const FLAG = Object.freeze({
  COMPRESSED: 0x01,
  FIN: 0x02,
} as const);

export const CLOSE_CODES = Object.freeze({
  EOS: 0,          // clean end (all data delivered)
  ERROR: 1,        // unexpected error
  REFUSED: 2,      // target refused by policy
  UNREACHABLE: 3,  // upstream dial failed
  GOAWAY: 4,       // connection is going away
  CANCEL: 5,       // caller aborted
  MAX_STREAMS: 6,  // stream limit reached
  PROTO: 7,        // protocol violation
  DENIED: 8,       // auth denied
} as const);

export const HEADER_SIZE = 10;
export const HARD_MAX_FRAME = 1 << 20;      // absolute cap for any frame payload
export const DEFAULT_MAX_DATA = 64 * 1024;  // default max DATA payload
export const MAX_HELLO = 8 * 1024;
export const MAX_OPEN = 8 * 1024;
export const MAX_CONTROL = 1024;            // OPEN_ACK / GOAWAY / CLOSE reason

/** Framing-layer violation; `code` is one of CLOSE_CODES (default PROTO). */
export class ProtocolError extends Error {
  code: number;

  constructor(message: string, code: number = CLOSE_CODES.PROTO) {
    super(message);
    this.name = 'ProtocolError';
    this.code = code;
  }
}

/** One parsed frame handed to the FrameParser callback. */
export interface ParsedFrame {
  type: number;
  flags: number;
  streamId: number;
  payload: Buffer | null;
}

export type FrameCallback = (frame: ParsedFrame) => void;

/** Build a single Buffer frame. */
export function encodeFrame(
  type: number,
  flags: number,
  streamId: number,
  payload: Buffer | null = null,
): Buffer {
  const len = payload ? payload.length : 0;
  if (len > HARD_MAX_FRAME) throw new ProtocolError(`frame payload too large: ${len}`);
  const buf = Buffer.allocUnsafe(HEADER_SIZE + len);
  buf[0] = type;
  buf[1] = flags & 0xff;
  buf.writeUInt32BE(streamId >>> 0, 2);
  buf.writeUInt32BE(len, 6);
  if (len && payload) payload.copy(buf, HEADER_SIZE);
  return buf;
}

/**
 * Incremental frame parser. onFrame({type, flags, streamId, payload}).
 * Throws ProtocolError on oversize/invalid frames — caller must drop the connection.
 */
export class FrameParser {
  private readonly _onFrame: FrameCallback;
  private readonly _maxFrame: number;
  private _buf: Buffer | null = null; // accumulated remainder
  private _count = 0;

  constructor(onFrame: FrameCallback, { maxFrame = HARD_MAX_FRAME }: { maxFrame?: number } = {}) {
    this._onFrame = onFrame;
    this._maxFrame = maxFrame;
  }

  get framesParsed(): number {
    return this._count;
  }

  push(chunk: Buffer): void {
    let buf: Buffer = this._buf ? Buffer.concat([this._buf, chunk]) : chunk;
    this._buf = null;
    for (;;) {
      if (buf.length < HEADER_SIZE) break;
      const type = buf[0];
      const flags = buf[1];
      const streamId = buf.readUInt32BE(2);
      const len = buf.readUInt32BE(6);
      if (type < FT.HELLO || type > FT.GOAWAY) {
        throw new ProtocolError(`unknown frame type: ${type}`);
      }
      if (len > this._maxFrame) {
        throw new ProtocolError(`frame length ${len} exceeds cap ${this._maxFrame}`);
      }
      const total = HEADER_SIZE + len;
      if (buf.length < total) break;
      const payload = len > 0 ? Buffer.from(buf.subarray(HEADER_SIZE, total)) : null;
      this._count++;
      this._onFrame({ type, flags, streamId, payload });
      buf = buf.subarray(total);
      if (buf.length === 0) break;
    }
    this._buf = buf.length ? buf : null;
  }
}
