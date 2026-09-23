// TunnelStream: one logical full-duplex byte stream inside a MuxSession.
//
// - Write path: app chunk -> (optional) continuous-context compression -> one or more
//   DATA frames, gated by a credit window (initially granted by the peer's HELLO,
//   replenished by WINDOW frames). Credits are accounted in *decompressed* bytes.
// - Read path: mux deliver() -> (optional) decompression -> readable side; consumption
//   is reported back with batched WINDOW frames.
// - Half-close: stream.end() sends a FIN flag on the last frame; receiving FIN ends
//   the readable side only. CLOSE aborts both directions.

import { Duplex } from 'node:stream';
import { Buffer } from 'node:buffer';
import { encodeFrame, FT, FLAG, CLOSE_CODES } from './frame.js';
import {
  createCompressContext, createDecompressContext, looksPrecompressed,
  ALGO_NONE, type CompCtx,
} from './compress.js';
import { Batch } from './util.js';
import type { MuxSession } from './mux.js';

/** Stream target descriptor ({host, port} or {unix}); advisory routing metadata. */
export interface StreamTarget {
  host?: string | null;
  port?: number;
  unix?: string | null;
  hint?: string;
  compression?: string;
  meta?: unknown;
}

/** Per-stream counters. */
export interface StreamStats {
  bytesTx: number;
  bytesRx: number;
  framesTx: number;
  framesRx: number;
  startedAt: number;
}

/** One queued write: a compressed chunk (possibly split across frames) or a bare FIN. */
interface SendItem {
  wire: Buffer;
  logical: number;
  cbs: Array<(err?: Error | null) => void>;
  fin: boolean;
  off: number;
  charged: number;
}

/**
 * Max DATA frames coalesced into one socket write — the TS cap of the shared
 * bounded-per-write rule (see ../WRITER_CONTRACT.md).
 */
const TX_BATCH_FRAMES = 16;

/**
 * Scratch for 4-byte WINDOW deltas: encodeFrame() copies the payload into the
 * outgoing frame synchronously, so one shared buffer covers every grant.
 */
const WINDOW_SCRATCH = Buffer.alloc(4);

function windowPayload(delta: number): Buffer {
  WINDOW_SCRATCH.writeUInt32BE(delta >>> 0, 0);
  return WINDOW_SCRATCH;
}

/**
 * One logical full-duplex byte stream inside a MuxSession — a Node Duplex.
 * Client code normally obtains these from MuxSession.openStream() (initiator)
 * or the session's 'stream' event (responder, which must accept()/reject()).
 */
export class TunnelStream extends Duplex {
  readonly mux: MuxSession;
  readonly id: number;
  readonly initiator: boolean;
  target: StreamTarget | null;
  compression: string = ALGO_NONE;
  compressionLevel: number | null = null; // parsed from 'deflate:9'-style requests

  txWindow: number; // credits we may still spend (decompressed bytes)
  abortedReason?: string;

  private _comp: CompCtx | null = null;
  private _decomp: CompCtx | null = null;
  private _sniffed = false;

  private _sendQ: SendItem[] = []; // [{wire, logical, cbs[], fin, off}]
  private _pumping = false;
  private _deliverChain: Promise<unknown> = Promise.resolve();
  private _deliverPending = 0;

  private _pendingRx: Array<Buffer | null> = []; // buffered inbound when the readable buffer is full
  private _eofPushed = false;
  private _finReceived = false;
  private _finSent = false;
  private _closeSent = false;
  private _destroying = false;
  private _ackDone = false;

  // receiver-side dynamic right-sizing (TCP-style): when the app keeps up with
  // everything granted, grow the peer's window multiplicatively up to rxWindowMax.
  private _rxGranted: number;
  private _rxWindowMax: number;
  private _consumedSinceGrow = 0;
  private _growAt = Date.now();
  private _growRetryTimer: NodeJS.Timeout | null = null;
  private _rxRetryTimer: NodeJS.Timeout | null = null;

  private readonly _creditBatch: Batch;

  readonly stats: StreamStats = { bytesTx: 0, bytesRx: 0, framesTx: 0, framesRx: 0, startedAt: Date.now() };

  // OPEN_ACK plumbing (settle-once, order-independent: an ack may legally arrive
  // before the opener attaches its waiters when the transport delivers synchronously)
  private _ackSettled = false;
  private _ackValue: unknown = null;
  private _ackErr: Error | null = null;
  private _ackResolve: ((s: TunnelStream) => void) | null = null;
  private _ackReject: ((e: Error) => void) | null = null;

  constructor(
    mux: MuxSession,
    id: number,
    {
      initiator = false,
      target = null,
      txWindow = 262144,
      rxWindow = 262144,
      rxWindowMax = 4194304,
      highWaterMark = 65536,
    }: {
      initiator?: boolean;
      target?: StreamTarget | null;
      txWindow?: number;
      rxWindow?: number;
      rxWindowMax?: number;
      highWaterMark?: number;
    } = {},
  ) {
    super({ highWaterMark, allowHalfOpen: true });
    this.mux = mux;
    this.id = id;
    this.initiator = initiator;
    this.target = target;
    this.txWindow = txWindow;

    this._rxGranted = rxWindow;
    this._rxWindowMax = Math.max(rxWindow, rxWindowMax);

    this._creditBatch = new Batch(
      (delta) => {
        if (this.destroyed) return;
        this.mux._sendControl(FT.WINDOW, this.id, windowPayload(delta));
      },
      { threshold: Math.max(16384, Math.floor(rxWindow / 4)), intervalMs: 5 },
    );
  }

  // Methods below are package-internal (underscore convention); the MuxSession
  // drives the stream through them.
  _settleAck(err: Error | null, value: unknown = undefined): void {
    if (this._ackSettled) return;
    this._ackSettled = true;
    if (err) {
      this._ackErr = err;
      this._ackReject?.(err);
    } else {
      this._ackValue = value;
      this._ackResolve?.(this);
    }
  }

  _waitAck(): Promise<TunnelStream> {
    if (this._ackSettled) {
      return this._ackErr ? Promise.reject(this._ackErr) : Promise.resolve(this);
    }
    return new Promise((resolve, reject) => {
      this._ackResolve = resolve;
      this._ackReject = reject;
    });
  }

  /** Server: accept the inbound stream (sends OPEN_ACK ok). */
  accept(info: { upstream?: string | null } = {}): void {
    if (this._ackDone || this.initiator) return;
    this._ackDone = true;
    const body = Buffer.from(JSON.stringify({
      ok: true,
      compression: this.compression,
      upstream: info.upstream ?? null,
    }), 'utf8');
    this.mux._sendControl(FT.OPEN_ACK, this.id, body);
    this._ackResolve?.(this);
  }

  /** Server: reject the inbound stream (sends OPEN_ACK error). */
  reject(code = 'denied', reason = ''): void {
    if (this._ackDone || this.initiator) return;
    this._ackDone = true;
    const body = Buffer.from(JSON.stringify({ ok: false, code, reason }), 'utf8');
    this.mux._sendControl(FT.OPEN_ACK, this.id, body);
    const err: Error & { code?: string } = new Error(`stream rejected: ${code}${reason ? ' ' + reason : ''}`);
    err.code = code;
    this._ackReject?.(err);
    this._destroyLocal(null);
  }

  get remoteAddress(): string | null {
    if (!this.target) return null;
    if (this.target.unix) return `unix:${this.target.unix}`;
    return `${this.target.host ?? ''}:${this.target.port ?? 0}`;
  }

  /** Human-readable label, e.g. "TunnelStream#3(a.test:80)". */
  override toString(): string {
    return `TunnelStream#${this.id}${this.target ? `(${this.remoteAddress})` : ''}`;
  }

  // ---------------- write path ----------------

  override _write(chunk: Buffer, _enc: string, cb: (err?: Error | null) => void): void {
    if (this.destroyed) {
      cb(new Error('stream destroyed'));
      return;
    }
    // first-chunk content sniffing: pre-compressed payloads bypass compression
    // (per direction; the receiver decompresses nothing when no frame is flagged)
    if (!this._sniffed && this.compression !== ALGO_NONE && chunk.length > 0) {
      this._sniffed = true;
      if (looksPrecompressed(chunk)) this.compression = ALGO_NONE;
    }
    (async () => {
      let wire: Buffer = chunk;
      try {
        if (this.compression !== ALGO_NONE && chunk.length > 0) {
          this._comp ??= createCompressContext(this.compression, { level: this.compressionLevel });
          // one write() per chunk: the deflate context carries Z_SYNC_FLUSH,
          // so each write() already ends on a sync-flushed frame boundary
          const out = await this._comp.write(chunk);
          if (out) wire = out;
        }
      } catch (err) {
        cb(err as Error);
        return;
      }
      this._sendQ.push({ wire, logical: chunk.length, cbs: [cb], fin: false, off: 0, charged: 0 });
      this._pump();
    })();
  }

  override _final(cb: (err?: Error | null) => void): void {
    this._sendQ.push({ wire: Buffer.alloc(0), logical: 0, cbs: [cb], fin: true, off: 0, charged: 0 });
    this._pump();
  }

  _pump(): void {
    if (this._pumping || this.destroyed) return;
    this._pumping = true;
    (async () => {
      try {
        await this._drainSendQ();
      } catch (err) {
        this._teardownError(err as Error);
      } finally {
        this._pumping = false;
      }
      this._maybeAutoDestroy();
    })();
  }

  /**
   * Send queued items (each possibly across multiple DATA frames), coalescing
   * consecutive frames from the whole queue into single socket writes of up to
   * TX_BATCH_FRAMES frames — the drain-only-queued burst shape shared by every
   * SDK writer (see ../WRITER_CONTRACT.md). Credits are charged incrementally
   * in *logical* (decompressed) bytes and released by the receiver in the same
   * unit, keeping the accounting symmetric even when compression slightly
   * inflates incompressible payloads. Every frame of a compressed item
   * carries FLAG.COMPRESSED — the receiver feeds each into its continuous
   * decompression context.
   *
   * A batch is flushed before any await that can block (credit wait, socket
   * backpressure) and before returning, so per-stream frame ordering — and
   * item callback ordering — is preserved: an item's write callbacks fire only
   * after the write carrying its last frame has been accepted by the socket.
   * Resumable: per-item progress lives on the item itself (off/charged), so a
   * credit-blocked pump resumes where it stopped.
   */
  private async _drainSendQ(): Promise<void> {
    const maxData = this.mux.peerMaxDataFrame;
    const compressed = this.compression !== ALGO_NONE;
    let batch: Buffer[] = [];
    let batchFrames = 0;
    let settled: SendItem[] = [];
    const flush = async (): Promise<boolean> => {
      // fire callbacks for items whose last frame is in this batch
      const done = settled;
      settled = [];
      if (batch.length === 0) {
        for (const it of done) { for (const c of it.cbs) c(); }
        return true;
      }
      const out = batch.length === 1 ? batch[0]! : Buffer.concat(batch);
      batch = [];
      const frames = batchFrames;
      batchFrames = 0;
      const ok = await this.mux._writeData(this, out, frames);
      for (const it of done) { for (const c of it.cbs) c(); }
      return ok;
    };
    let blocked = false;
    for (;;) {
      blocked = false; // fresh drain round; credits may have arrived while parked
      while (this._sendQ.length > 0 && !this.destroyed) {
        const item = this._sendQ[0]!;
        while (item.off < item.wire.length) {
          if (item.charged < item.logical) {
            if (this.txWindow <= 0) {
              blocked = true; // waiting for WINDOW credits; addCredit re-pumps
              break;
            }
            const charge = Math.min(this.txWindow, item.logical - item.charged);
            this.txWindow -= charge;
            item.charged += charge;
          }
          const take = Math.min(maxData, item.wire.length - item.off);
          const isLast = item.off + take >= item.wire.length;
          let flags = 0;
          if (compressed) flags |= FLAG.COMPRESSED;
          if (item.fin && isLast) flags |= FLAG.FIN;
          this.stats.framesTx++;
          batch.push(encodeFrame(FT.DATA, flags, this.id, item.wire.subarray(item.off, item.off + take)));
          batchFrames++;
          item.off += take;
          if (batchFrames >= TX_BATCH_FRAMES) {
            if (!(await flush())) return; // mux socket backpressure; mux re-pumps on drain
          }
        }
        if (blocked) break;
        if (item.fin && item.wire.length === 0) {
          // standalone zero-length FIN frame (empty final chunk)
          this.stats.framesTx++;
          batch.push(encodeFrame(FT.DATA, FLAG.FIN, this.id, null));
          batchFrames++;
        }
        if (item.fin) this._finSent = true;
        this.stats.bytesTx += item.logical;
        settled.push(item);
        this._sendQ.shift();
      }
      // whatever accumulated must reach the socket before we park — a credit
      // block or queue-drain must never drop already-encoded frames
      await flush();
      // Items — or WINDOW credits for a blocked item — may have arrived while
      // flush() was parked on socket backpressure (their _pump() call was a
      // no-op against the in-flight pumping flag), so re-check instead of
      // trusting the pre-park state: exit only when done, destroyed, or
      // genuinely out of credits (addCredit re-pumps when the grant lands).
      if (this.destroyed || this._sendQ.length === 0) return;
      if (blocked && this.txWindow <= 0) return;
    }
  }

  // ---------------- read path ----------------

  /**
   * Inbound frames must be applied strictly in arrival order (decompression
   * contexts are sequential and FIN must not overtake pending DATA), so every
   * deliver() is chained onto a per-stream serial promise. Uncompressed
   * frames take a synchronous fast path when the chain is idle: the step has
   * no await, so running it inline on the parser thread preserves order and
   * skips the per-frame promise-chain allocation (bulk DATA is uncompressed
   * more often than not).
   */
  deliver(payload: Buffer | null, flags: number): void {
    if (this._deliverPending === 0 && !(flags & FLAG.COMPRESSED)) {
      if (!this.destroyed && !this._eofPushed) {
        try {
          this._deliverInbound(payload, (flags & FLAG.FIN) !== 0);
        } catch (err) {
          // A user 'data'/'end' handler throwing synchronously out of push()
          // must tear down only THIS stream, never escalate to a session
          // GOAWAY (the parser would otherwise treat it as a protocol error).
          this._teardownError(err as Error);
        }
      }
      return;
    }
    this._deliverPending++;
    const run = this._deliverChain.then(() => this._deliverStep(payload, flags));
    this._deliverChain = run.catch((err: Error) => this._teardownError(err));
    void run.finally(() => { this._deliverPending--; });
  }

  /** Shared inbound tail: buffer plain bytes, mark FIN, feed the readable side. */
  private _deliverInbound(buf: Buffer | null, fin: boolean): void {
    this.stats.framesRx++;
    if (buf && buf.length > 0) {
      this.stats.bytesRx += buf.length;
      this._pendingRx.push(buf);
    }
    if (fin) {
      this._finReceived = true;
      this._pendingRx.push(null);
    }
    if (this._pendingRx.length > 0) this._flushPendingRx();
    else this._maybeAutoDestroy();
  }

  private async _deliverStep(payload: Buffer | null, flags: number): Promise<void> {
    if (this.destroyed || this._eofPushed) return;
    let buf: Buffer | null = payload;
    try {
      if ((flags & FLAG.COMPRESSED) && payload && payload.length > 0) {
        this._decomp ??= createDecompressContext(this.compression);
        const out = await this._decomp.write(payload);
        buf = out ?? Buffer.alloc(0);
      }
    } catch (err) {
      this._teardownError(err as Error);
      return;
    }
    this._deliverInbound(buf, (flags & FLAG.FIN) !== 0);
  }

  override _read(_size: number): void {
    this._flushPendingRx();
  }

  /**
   * Push buffered inbound data to the readable side.
   * Node's push() accepts data even when it returns false (the return value is
   * advisory), so the only reliable memory bound is our own gate:
   * push while the readable buffer is below its high-water mark. Credits are
   * issued only for pushed data, which in turn bounds the peer's send window.
   * When the gate is closed, a light retry timer keeps probing: consumers do
   * not always drive _read() (paused streams, async-iterator edge cases), and
   * pushing from outside _read() is legal.
   */
  private _flushPendingRx(): void {
    if (this._eofPushed) return;
    while (this._pendingRx.length > 0 && this.readableLength < this.readableHighWaterMark) {
      const item = this._pendingRx[0]!;
      if (item === null) {
        this._pendingRx.shift();
        this._eofPushed = true;
        this.push(null);
        this._clearRxRetry();
        break;
      }
      this.push(item);
      this._pendingRx.shift();
      this._credit(item.length);
    }
    if (this._pendingRx.length > 0 && !this._eofPushed) {
      this._scheduleRxRetry();
    } else {
      this._clearRxRetry();
    }
    this._maybeAutoDestroy();
  }

  private _scheduleRxRetry(): void {
    if (this._rxRetryTimer || this.destroyed) return;
    this._rxRetryTimer = setTimeout(() => {
      this._rxRetryTimer = null;
      if (!this.destroyed) this._flushPendingRx();
    }, 10);
    this._rxRetryTimer.unref();
  }

  private _clearRxRetry(): void {
    if (this._rxRetryTimer) {
      clearTimeout(this._rxRetryTimer);
      this._rxRetryTimer = null;
    }
  }

  private _credit(n: number): void {
    this._creditBatch.add(n);
    this._maybeGrowWindow(n);
  }

  /**
   * Dynamic window right-sizing: when consumption stays high across the
   * growth interval (100ms) and the app has drained its buffer at a quiet
   * evaluation point, the window is the bottleneck — double it (capped at
   * rxWindowMax). Evaluation is always deferred to a timer so the reader
   * gets a turn to drain first (at push time the buffer legitimately holds
   * the just-delivered chunk); unread buffered data at evaluation time
   * disqualifies growth, bounding memory for backpressured streams.
   */
  private _maybeGrowWindow(n: number): void {
    if (this._rxGranted >= this._rxWindowMax) return;
    this._consumedSinceGrow += n;
    if (this._consumedSinceGrow < Math.floor(this._rxGranted / 2)) return;
    if (this._growRetryTimer) return;
    const wait = Math.max(10, 100 - (Date.now() - this._growAt));
    this._growRetryTimer = setTimeout(() => {
      this._growRetryTimer = null;
      if (this.destroyed) return;
      if (Date.now() - this._growAt < 100) return;
      const buffered = this.readableLength + this._pendingRx.length;
      if (buffered * 10 >= this._rxGranted) return;
      const bonus = Math.min(this._rxGranted, this._rxWindowMax - this._rxGranted);
      if (bonus <= 0) return;
      this._rxGranted += bonus;
      this._consumedSinceGrow = 0;
      this._growAt = Date.now();
      this.mux._sendControl(FT.WINDOW, this.id, windowPayload(bonus));
    }, wait);
    this._growRetryTimer.unref();
  }

  // ---------------- control ----------------

  addCredit(delta: number): void {
    if (this.destroyed) return;
    this.txWindow += delta;
    this._pump();
  }

  /** Abort: tell the peer we're gone and drop everything (like a TCP RST). */
  abort(code: number = CLOSE_CODES.CANCEL, reason = ''): void {
    if (this._closeSent || this.destroyed) return;
    this._closeSent = true;
    const reasonBuf = Buffer.from(String(reason).slice(0, 200), 'utf8');
    const body = Buffer.concat([Buffer.from([code & 0xff]), reasonBuf]);
    this.mux._sendControl(FT.CLOSE, this.id, body);
    this._destroyLocal(new Error(`stream aborted: ${code}${reason ? ' ' + reason : ''}`));
  }

  /** Peer sent CLOSE for this stream. */
  peerClosed(code: number, _reason: string): void {
    if (this.destroyed) return;
    if (code === CLOSE_CODES.EOS || code === CLOSE_CODES.CANCEL) {
      this._finReceived = true;
      if (!this._eofPushed) {
        this._pendingRx.push(null);
        this._flushPendingRx();
      }
      this._maybeAutoDestroy();
    } else {
      // peer aborted: surface as 'aborted' + reason, not as an unhandled 'error'
      this._destroySilent(`peer closed stream: code=${code}`);
    }
  }

  _teardownError(err: Error): void {
    if (!this._closeSent && !this.destroyed) {
      this._closeSent = true;
      const reason = Buffer.from(String(err?.message ?? 'error').slice(0, 60), 'utf8');
      this.mux._sendControl(FT.CLOSE, this.id, Buffer.concat([Buffer.from([CLOSE_CODES.ERROR]), reason]));
    }
    this._destroyLocal(err instanceof Error ? err : new Error(String(err)));
  }

  _destroyLocal(err: Error | null): void {
    if (this._destroying) return;
    this._destroying = true;
    this._creditBatch.dispose();
    this._comp?.destroy();
    this._decomp?.destroy();
    this.mux._unmapStream(this);
    if (err) this.destroy(err);
    else this.destroy();
  }

  /**
   * Library-initiated teardown that should not crash apps lacking 'error'
   * listeners: destroy without an error object, expose the reason separately.
   */
  _destroySilent(reason: string): void {
    if (this._destroying || this.destroyed) return;
    this.abortedReason = reason;
    try {
      this.emit('aborted', reason);
    } catch {
      /* listener errors are theirs */
    }
    this._destroyLocal(null);
  }

  private _maybeAutoDestroy(): void {
    if (
      this._finSent && this._finReceived &&
      this._sendQ.length === 0 && !this._pumping &&
      this._pendingRx.length === 0 && // EOF marker still queued: not safe to destroy yet
      (this.readableEnded || this.readableLength === 0)
    ) {
      setImmediate(() => {
        if (this._destroying) return;
        if (this._finSent && this._finReceived && this._sendQ.length === 0) {
          this._destroyLocal(null);
        }
      });
    }
  }

  override _destroy(err: Error | null, cb: (error?: Error | null) => void): void {
    this._creditBatch.dispose();
    this._clearRxRetry();
    if (this._growRetryTimer) {
      clearTimeout(this._growRetryTimer);
      this._growRetryTimer = null;
    }
    super._destroy(err, cb);
  }
}
