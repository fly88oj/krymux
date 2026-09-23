// MuxSession: multiplexes many TunnelStreams over one ordered byte pipe
// (in production a TLS 1.3 socket; in tests a duplexPair).
//
// Handshake: both sides immediately send a HELLO frame (JSON) describing limits and
// supported compression. Effective per-direction data-frame cap and initial stream
// windows derive from the *peer's* HELLO. Streams are client-odd / server-even.

import { EventEmitter } from 'node:events';
import { Buffer } from 'node:buffer';
import type { Duplex } from 'node:stream';
import {
  encodeFrame, FrameParser, FT, CLOSE_CODES, ProtocolError,
  DEFAULT_MAX_DATA, MAX_HELLO, MAX_OPEN, MAX_CONTROL, HARD_MAX_FRAME,
  type ParsedFrame,
} from './frame.js';
import { TunnelStream } from './stream.js';
import { supportedAlgorithms, negotiate, parseLevel } from './compress.js';
import { nowMs, randomId, type Logger } from './util.js';

const PROTO_VERSION = 1;
const DEFAULT_WINDOW = 262144;
const DEFAULT_MAX_STREAMS = 1024;
const OPEN_ACK_TIMEOUT = 12000;

function clamp(v: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, Number(v) || 0));
}

/** Session-wide counters. */
export interface MuxStats {
  startedAt: number;
  framesRx: number;
  framesTx: number;
  wireBytesRx: number;
  wireBytesTx: number;
  streamsOpened: number;
  rttMs: number | null;
}

/** MuxSession constructor options. */
export interface MuxOptions {
  isClient?: boolean;
  name?: string;
  log?: Logger | null;
  maxDataFrame?: number;
  rxWindow?: number;
  rxWindowMax?: number;
  maxStreams?: number;
  keepaliveSec?: number;
  helloTimeoutMs?: number;
}

/** Options for openStream(). */
export interface OpenStreamOptions {
  host?: string | null;
  port?: number;
  unix?: string | null;
  compression?: string;
  hint?: string;
  meta?: unknown;
}

interface PingEntry {
  t0: number;
  resolve: (rtt: number) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
}

/**
 * Multiplexes many TunnelStreams over one ordered, reliable byte pipe
 * (a TLS 1.3 socket in production, a duplexPair in tests). Speaks the Krymux
 * wire protocol: HELLO handshake, OPEN/OPEN_ACK stream setup, credit-windowed
 * DATA with optional per-stream compression, WINDOW flow control, CLOSE,
 * PING/PONG keepalive, and GOAWAY shutdown.
 */
export class MuxSession extends EventEmitter {
  readonly socket: Duplex;
  readonly isClient: boolean;
  readonly name: string;
  readonly log: Logger | null;

  readonly ourMaxDataFrame: number;
  readonly rxWindow: number;
  readonly rxWindowMax: number;
  readonly maxStreams: number;
  readonly keepaliveMs: number;

  private _ourSupported: string[] | null = null; // resolved at HELLO time
  private _peerSupported: string[] | null = null;
  private _peerMaxDataFrame = DEFAULT_MAX_DATA;
  private _peerWindow = DEFAULT_WINDOW;
  private _peerName = '';

  private _streams = new Map<number, TunnelStream>();
  private _nextId: number;
  private readonly _parser: FrameParser;
  private _helloSeen = false;
  private _gone = false;
  private _closeEmitted = false;
  private _drainPromise: Promise<void> | null = null;
  private _drainResolve: (() => void) | null = null;
  private _keepaliveTimer: NodeJS.Timeout | null = null;
  private _pings = new Map<string, PingEntry>();
  private _helloTimer: NodeJS.Timeout;
  private _helloSentPromise: Promise<void> | null = null;
  private readonly _readyPromise: Promise<void>;
  private _readyResolve!: () => void;
  private _readyReject!: (e: Error) => void;

  readonly stats: MuxStats = {
    startedAt: Date.now(),
    framesRx: 0, framesTx: 0,
    wireBytesRx: 0, wireBytesTx: 0,
    streamsOpened: 0,
    rttMs: null,
  };

  constructor(socket: Duplex, opts: MuxOptions = {}) {
    super();
    const {
      isClient = false,
      name = '',
      log = null,
      maxDataFrame = DEFAULT_MAX_DATA,
      rxWindow = DEFAULT_WINDOW,
      rxWindowMax = 4194304,
      maxStreams = DEFAULT_MAX_STREAMS,
      keepaliveSec = 30,
      helloTimeoutMs = 10000,
    } = opts;

    this.socket = socket;
    this.isClient = isClient;
    this.name = name;
    this.log = log;

    this.ourMaxDataFrame = clamp(maxDataFrame, 1024, HARD_MAX_FRAME);
    this.rxWindow = clamp(rxWindow, 16384, 16 * 1024 * 1024);
    this.rxWindowMax = clamp(rxWindowMax, this.rxWindow, 64 * 1024 * 1024);
    this.maxStreams = clamp(maxStreams, 1, 65535);
    this.keepaliveMs = clamp(keepaliveSec, 0, 600) * 1000;

    this._nextId = isClient ? 1 : 2;
    this._parser = new FrameParser((f) => this._onFrame(f), { maxFrame: HARD_MAX_FRAME });

    this._readyPromise = new Promise((resolve, reject) => {
      this._readyResolve = resolve;
      this._readyReject = reject;
    });
    this._helloTimer = setTimeout(() => {
      this._fail(new ProtocolError('peer did not send HELLO in time', CLOSE_CODES.PROTO));
    }, helloTimeoutMs);
    this._helloTimer.unref?.();

    socket.on('data', (chunk: Buffer) => {
      this.stats.wireBytesRx += chunk.length;
      try {
        this._parser.push(chunk);
      } catch (err) {
        this._failProtocol(err as Error);
      }
    });
    socket.on('error', (err: Error) => this._fail(err));
    socket.on('close', () => this._fail(new Error('underlying socket closed')));
    socket.on('end', () => this._fail(new Error('peer closed connection (FIN)')));
    socket.on('drain', () => this._onDrain());

    this.helloSent().catch(() => { /* surfaced via _fail */ });
  }

  get peerMaxDataFrame(): number {
    return this._peerMaxDataFrame;
  }

  get peerName(): string {
    return this._peerName;
  }

  get streamCount(): number {
    return this._streams.size;
  }

  /** Resolves once the peer's HELLO has been received and validated. */
  ready(): Promise<void> {
    return this._readyPromise;
  }

  /** Resolves once OUR HELLO has actually been written to the socket. */
  helloSent(): Promise<void> {
    this._helloSentPromise ??= this._sendHello();
    return this._helloSentPromise;
  }

  // ---------------- lifecycle ----------------

  private async _sendHello(): Promise<void> {
    this._ourSupported = await supportedAlgorithms();
    if (this._gone) return;
    const payload = Buffer.from(JSON.stringify({
      v: PROTO_VERSION,
      mode: this.isClient ? 'client' : 'server',
      name: this.name,
      maxDataFrame: this.ourMaxDataFrame,
      rxWindow: this.rxWindow,
      maxStreams: this.maxStreams,
      compression: this._ourSupported,
    }), 'utf8');
    this._sendControl(FT.HELLO, 0, payload);
  }

  /** Graceful shutdown: send GOAWAY, tear down all streams, end the socket. */
  close(reason = 'going away'): void {
    if (this._gone) return;
    this._gone = true;
    this._closeEmitted = true; // prevent _fail from emitting 'close' again
    try {
      this._sendControl(FT.GOAWAY, 0, Buffer.from(JSON.stringify({ reason }), 'utf8'));
    } catch {
      /* socket may already be gone */
    }
    this._teardownStreams(new Error(`session closed: ${reason}`));
    this.socket.end();
    setTimeout(() => this.socket.destroy(), 2000).unref?.();
    this._stopKeepalive();
    this.emit('close', reason);
  }

  private _fail(err: Error): void {
    if (this._gone && this._closeEmitted) return;
    this._gone = true;
    clearTimeout(this._helloTimer);
    this._stopKeepalive();
    this._teardownStreams(err);
    for (const p of this._pings.values()) p.reject(err);
    this._pings.clear();
    this._readyReject?.(err);
    this.socket.destroy();
    if (!this._closeEmitted) {
      this._closeEmitted = true;
      this.emit('close', err?.message ?? String(err));
      if (this.listenerCount('error') > 0) this.emit('error', err);
    }
  }

  private _failProtocol(err: Error): void {
    // Attempt a best-effort GOAWAY so the peer knows why we dropped them.
    if (!this._gone) {
      try {
        this._sendControl(FT.GOAWAY, 0, Buffer.from(JSON.stringify({
          reason: `protocol error: ${err.message}`,
        }), 'utf8'));
      } catch {
        /* ignore */
      }
    }
    this._fail(err);
  }

  private _teardownStreams(err: Error): void {
    const list = [...this._streams.values()];
    this._streams.clear();
    for (const s of list) {
      try {
        s._destroySilent(err?.message ?? 'session closed');
      } catch {
        /* ignore */
      }
    }
  }

  private _stopKeepalive(): void {
    if (this._keepaliveTimer) {
      clearInterval(this._keepaliveTimer);
      this._keepaliveTimer = null;
    }
  }

  // ---------------- writing ----------------

  // Control frames deliberately bypass the streams' DATA batching: each is a
  // single small frame written straight to the socket. Ordering stays correct
  // because the one socket serializes writes (a control frame issued between
  // two of a stream's batch flushes can never be reordered past them), and
  // holding a WINDOW/OPEN_ACK/GOAWAY behind a credit-blocked stream batch
  // would add latency exactly when the peer is waiting on it.
  _sendControl(type: number, sid: number, payload: Buffer | null): void {
    if (this._gone && type !== FT.GOAWAY) return;
    const frame = encodeFrame(type, 0, sid, payload ?? null);
    this.stats.framesTx++;
    this.stats.wireBytesTx += frame.length;
    this.socket.write(frame);
  }

  /**
   * Write DATA frame(s) on behalf of a stream. `frame` is one already-encoded
   * frame or a coalesced run of frames (frameCount of them) built by the
   * stream's send path; the wire bytes are identical either way. Returns (a
   * promise for) true when written; if the socket is backpressured, waits for
   * drain and then returns true. Order relative to other frames is preserved
   * by the single socket.
   */
  async _writeData(_stream: TunnelStream, frame: Buffer, frameCount = 1): Promise<boolean> {
    this.stats.framesTx += frameCount;
    this.stats.wireBytesTx += frame.length;
    const ok = this.socket.write(frame);
    if (ok) return true;
    if (!this._drainPromise) {
      this._drainPromise = new Promise((resolve) => {
        this._drainResolve = resolve;
      });
    }
    await this._drainPromise;
    return true;
  }

  private _onDrain(): void {
    const resolve = this._drainResolve;
    this._drainPromise = null;
    this._drainResolve = null;
    if (resolve) resolve();
    for (const s of this._streams.values()) s._pump();
  }

  // ---------------- reading ----------------

  private _onFrame({ type, flags, streamId, payload }: ParsedFrame): void {
    this.stats.framesRx++;
    if (!this._helloSeen && type !== FT.HELLO) {
      throw new ProtocolError(`frame type ${type} before HELLO`);
    }
    switch (type) {
      case FT.HELLO: return this._onHello(payload);
      case FT.OPEN: return this._onOpen(streamId, payload);
      case FT.OPEN_ACK: return this._onOpenAck(streamId, payload);
      case FT.DATA: return this._onData(streamId, flags, payload);
      case FT.WINDOW: return this._onWindow(streamId, payload);
      case FT.CLOSE: return this._onClose(streamId, payload);
      case FT.PING:
        // reply only after our own HELLO is on the wire (a peer may ping
        // before its HELLO reached us; our HELLO must still go out first)
        this.helloSent().then(() => {
          if (!this._gone) this._sendControl(FT.PONG, 0, payload);
        }).catch(() => {});
        return;
      case FT.PONG: return this._onPong(payload);
      case FT.GOAWAY: return this._fail(new Error(`peer sent GOAWAY: ${payload?.toString('utf8') ?? ''}`));
      default: throw new ProtocolError(`unknown frame type ${type}`);
    }
  }

  private _onHello(payload: Buffer | null): void {
    if (this._helloSeen) throw new ProtocolError('duplicate HELLO');
    if (!payload || payload.length === 0 || payload.length > MAX_HELLO) {
      throw new ProtocolError('bad HELLO size');
    }
    let hello: any;
    try {
      hello = JSON.parse(payload.toString('utf8'));
    } catch {
      throw new ProtocolError('bad HELLO json');
    }
    if (hello.v !== PROTO_VERSION) throw new ProtocolError(`unsupported protocol version ${hello.v}`);
    this._helloSeen = true;
    clearTimeout(this._helloTimer);
    this._peerSupported = Array.isArray(hello.compression) ? hello.compression : ['none'];
    this._peerMaxDataFrame = clamp(hello.maxDataFrame ?? DEFAULT_MAX_DATA, 1024, HARD_MAX_FRAME);
    this._peerWindow = clamp(hello.rxWindow ?? DEFAULT_WINDOW, 16384, 16 * 1024 * 1024);
    this._peerName = String(hello.name ?? '');
    if (this.keepaliveMs > 0) {
      this._keepaliveTimer = setInterval(() => this._pingTick(), this.keepaliveMs);
      this._keepaliveTimer.unref?.();
    }
    this._readyResolve();
    this.emit('ready');
  }

  private _onOpen(sid: number, payload: Buffer | null): void {
    if (this.isClient) throw new ProtocolError('client received OPEN');
    if (!payload || payload.length === 0 || payload.length > MAX_OPEN) {
      throw new ProtocolError('bad OPEN size');
    }
    // client-initiated streams use odd ids; even (or 0) is a protocol error
    if (sid === 0 || (sid & 1) === 0) throw new ProtocolError(`bad stream id in OPEN: ${sid}`);
    if (this._streams.has(sid)) throw new ProtocolError(`stream ${sid} already exists`);
    if (this._streams.size >= this.maxStreams) {
      this._sendControl(FT.OPEN_ACK, sid, Buffer.from(JSON.stringify({
        ok: false, code: 'maxstreams', reason: `limit ${this.maxStreams}`,
      }), 'utf8'));
      return;
    }
    let target: any;
    try {
      target = JSON.parse(payload.toString('utf8'));
    } catch {
      throw new ProtocolError('bad OPEN json');
    }

    const algo = negotiate(target.compression || 'auto', this._ourSupported ?? ['none']);
    const stream = new TunnelStream(this, sid, {
      initiator: false,
      target,
      txWindow: this._peerWindow,
      rxWindow: this.rxWindow,
      rxWindowMax: this.rxWindowMax,
    });
    stream.compression = algo;
    this._streams.set(sid, stream);
    this.stats.streamsOpened++;

    if (this.listenerCount('stream') === 0) {
      stream.reject('nohandler', 'server has no stream handler');
      return;
    }
    this.emit('stream', stream, { ...target, compression: algo });
  }

  private _onOpenAck(sid: number, payload: Buffer | null): void {
    const stream = this._streams.get(sid);
    if (!stream || !stream.initiator) return;
    if (payload && payload.length > MAX_CONTROL + 4096) throw new ProtocolError('bad OPEN_ACK size');
    let ack: any = {};
    try {
      ack = payload ? JSON.parse(payload.toString('utf8')) : {};
    } catch {
      /* treat as rejection */
    }
    if (ack.ok) {
      if (typeof ack.compression === 'string' && stream.compression === 'none') {
        stream.compression = ack.compression;
      }
      stream._settleAck(null, ack);
    } else {
      const err: Error & { code?: string } = new Error(`open rejected: ${ack.code ?? 'denied'} ${ack.reason ?? ''}`.trim());
      err.code = ack.code;
      this._streams.delete(sid);
      stream._settleAck(err);
      stream._destroyLocal(null); // error already surfaced through the ack promise
    }
  }

  private _onData(sid: number, flags: number, payload: Buffer | null): void {
    const stream = this._streams.get(sid);
    if (!stream) return; // unknown/already-closed stream — ignore, bounded by one frame
    if (payload && payload.length > this.rxWindow + HARD_MAX_FRAME) {
      throw new ProtocolError('DATA exceeds window bounds');
    }
    try {
      stream.deliver(payload, flags);
    } catch (err) {
      // Belt-and-braces to TunnelStream.deliver's own guard: a synchronous
      // throw out of a per-stream handler must tear down only that stream,
      // not escalate to a whole-session GOAWAY.
      stream._teardownError(err as Error);
    }
  }

  private _onWindow(sid: number, payload: Buffer | null): void {
    const stream = this._streams.get(sid);
    if (!stream) return;
    if (!payload || payload.length !== 4) throw new ProtocolError('bad WINDOW frame');
    const delta = payload.readUInt32BE(0);
    if (delta === 0 || delta > 64 * 1024 * 1024) throw new ProtocolError(`bad WINDOW delta ${delta}`);
    stream.addCredit(delta);
  }

  private _onClose(sid: number, payload: Buffer | null): void {
    const stream = this._streams.get(sid);
    if (!stream) return;
    const code = payload && payload.length > 0 ? payload[0]! : CLOSE_CODES.CANCEL;
    const reason = payload && payload.length > 1 ? payload.subarray(1).toString('utf8') : '';
    try {
      stream.peerClosed(code, reason);
    } catch (err) {
      // user 'end'/'close' handlers firing synchronously out of push(null):
      // same per-stream isolation as _onData, never a session GOAWAY
      stream._teardownError(err as Error);
    }
  }

  private _onPong(payload: Buffer | null): void {
    if (!payload || payload.length < 16) return;
    const nonce = payload.subarray(0, 16).toString('hex');
    const entry = this._pings.get(nonce);
    if (!entry) return;
    this._pings.delete(nonce);
    clearTimeout(entry.timer);
    const rtt = nowMs() - entry.t0;
    this.stats.rttMs = this.stats.rttMs == null ? rtt : Math.round(this.stats.rttMs * 0.7 + rtt * 0.3);
    entry.resolve(rtt);
  }

  // ---------------- client API ----------------

  /**
   * Open a new outgoing stream (client role; ids are odd).
   * Resolves with the TunnelStream once the peer's OPEN_ACK arrives.
   * `target` ({host, port} or {unix}) is advisory metadata the server routes on.
   */
  async openStream(
    { host = null, port = 0, unix = null, compression = 'auto', hint = 'raw', meta = undefined }: OpenStreamOptions = {},
  ): Promise<TunnelStream> {
    await this.ready();
    await this.helloSent(); // never send frames before our own HELLO is on the wire
    if (this._gone) throw new Error('session is gone');
    if (this._streams.size >= this.maxStreams) {
      const e: Error & { code?: string } = new Error(`max streams reached (${this.maxStreams})`);
      e.code = 'maxstreams';
      throw e;
    }
    const sid = this._nextId;
    this._nextId += 2;

    const algo = negotiate(compression, this._peerSupported ?? ['none']);
    const stream = new TunnelStream(this, sid, {
      initiator: true,
      target: { host, port, unix, hint, meta },
      txWindow: this._peerWindow,
      rxWindow: this.rxWindow,
      rxWindowMax: this.rxWindowMax,
    });
    stream.compression = algo;
    stream.compressionLevel = parseLevel(compression);
    this._streams.set(sid, stream);
    this.stats.streamsOpened++;

    const openPayload = Buffer.from(JSON.stringify({
      host, port, unix, hint, meta,
      compression: algo,
    }), 'utf8');
    this._sendControl(FT.OPEN, sid, openPayload);

    // The ack may already have settled (synchronous transports deliver in-tick).
    try {
      await Promise.race([
        stream._waitAck(),
        new Promise<never>((_, reject) => {
          const t = setTimeout(() => {
            const e: Error & { code?: string } = new Error('open stream timeout');
            e.code = 'timeout';
            reject(e);
          }, OPEN_ACK_TIMEOUT);
          t.unref?.();
        }),
      ]);
    } catch (err) {
      this._streams.delete(sid);
      stream._destroyLocal(null); // error surfaced through this rejection
      throw err;
    }
    return stream;
  }

  // ---------------- keepalive ----------------

  private _pingTick(): void {
    this.ping().catch(() => { /* failures surface via socket close */ });
  }

  /** Round-trip latency probe; resolves to the RTT in milliseconds. */
  ping(): Promise<number> {
    if (this._gone) return Promise.reject(new Error('session is gone'));
    const nonce = randomId(16);
    const buf = Buffer.from(nonce, 'hex');
    const t0 = nowMs();
    return new Promise((resolve, reject) => {
      const entry: PingEntry = { t0, resolve, reject, timer: null as unknown as NodeJS.Timeout };
      entry.timer = setTimeout(() => {
        this._pings.delete(nonce);
        reject(new Error('ping timeout'));
      }, Math.max(5000, (this.keepaliveMs || 10000) * 2));
      entry.timer.unref?.();
      this._pings.set(nonce, entry);
      this._sendControl(FT.PING, 0, buf);
    });
  }

  _unmapStream(stream: TunnelStream): void {
    if (this._streams.get(stream.id) === stream) {
      this._streams.delete(stream.id);
    }
  }
}
