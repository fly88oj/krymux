// EctunClient: SDK client. Connects to the tunnel endpoint, pins the server's
// key fingerprint, and exposes full-duplex logical streams.

import { EventEmitter } from 'node:events';
import * as tls from 'node:tls';
import type { TLSSocket } from 'node:tls';
import { MuxSession } from './mux.js';
import type { MuxStats, OpenStreamOptions } from './mux.js';
import { clientTlsOptions, verifyServerPin } from './tlsctx.js';
import { parseTarget, type Logger } from './util.js';

/** EctunClient.connect() options. */
export interface ConnectOptions {
  /** "host:port" tunnel endpoint. */
  endpoint: string | [string, number];
  /** Client identity ({certPem, keyPem, fingerprint}) from generateIdentity/loadIdentity. */
  identity: { certPem: string; keyPem: string };
  /** Pinned server key fingerprint ("sha256:..."). */
  serverFingerprint: string;
  /** Compression default for opened streams: none|deflate|auto. */
  compression?: string;
  keepaliveSec?: number;
  connectTimeoutMs?: number;
  name?: string;
  log?: Logger | null;
  tlsOpts?: tls.ConnectionOptions;
  rxWindow?: number;
  rxWindowMax?: number;
}

/**
 * SDK tunnel client. Connect via the static EctunClient.connect() factory,
 * then openStream() logical streams, ping(), and close(). Emits 'close' when
 * the underlying session ends.
 */
export class EctunClient extends EventEmitter {
  #session: MuxSession | null = null;
  #tlsSocket: TLSSocket | null = null;
  #serverFp: string | null = null;
  #closed = false;
  compressionDefault: string = 'auto';

  get session(): MuxSession | null {
    return this.#session;
  }

  get fingerprint(): string | null {
    return this.#serverFp;
  }

  get stats(): MuxStats | null {
    return this.#session?.stats ?? null;
  }

  /**
   * Connect to a tunnel server, pinning its fingerprint.
   * Resolves with a ready EctunClient; rejects on TLS/pin/handshake failure.
   */
  static async connect({
    endpoint,
    identity,
    serverFingerprint,
    compression = 'auto',
    keepaliveSec = 30,
    connectTimeoutMs = 10000,
    name = 'client',
    log = null,
    tlsOpts = {},
    rxWindow = 262144,
    rxWindowMax = 4194304,
  }: ConnectOptions): Promise<EctunClient> {
    if (!identity?.certPem || !identity?.keyPem) throw new Error('client identity required');
    if (!serverFingerprint) throw new Error('serverFingerprint required (pin the server key)');
    const target = parseTarget(endpoint, 0);

    const self = new EctunClient();
    const logger: Logger = log ?? { info() {}, warn() {}, error() {}, debug() {} };

    const tlsSocket = tls.connect({
      host: target.host,
      port: target.port,
      ...clientTlsOptions({ cert: identity.certPem, key: identity.keyPem }),
      ...tlsOpts,
    });
    self.#tlsSocket = tlsSocket;
    tlsSocket.setTimeout(connectTimeoutMs);

    try {
      await new Promise<void>((resolve, reject) => {
        const onTimeout = () => reject(new Error(`connect timeout to ${target.host}:${target.port}`));
        tlsSocket.once('secureConnect', resolve);
        tlsSocket.once('error', reject);
        tlsSocket.once('timeout', onTimeout);
      });
    } catch (err) {
      tlsSocket.destroy();
      throw err;
    }
    tlsSocket.setTimeout(0);

    const pin = verifyServerPin(tlsSocket, serverFingerprint);
    if (!pin.ok) {
      tlsSocket.destroy();
      const e: Error & { code?: string } = new Error(`server verification failed: ${pin.reason}`);
      e.code = 'PIN_MISMATCH';
      throw e;
    }
    self.#serverFp = pin.fingerprint ?? null;
    logger.info?.('tunnel established', { server: `${target.host}:${target.port}`, fp: (pin.fingerprint ?? '').slice(7, 19) });

    const session = new MuxSession(tlsSocket, {
      isClient: true,
      name,
      log: logger,
      keepaliveSec,
      rxWindow,
      rxWindowMax,
    });
    self.#session = session;
    try {
      await session.ready();
    } catch (err) {
      tlsSocket.destroy();
      throw err;
    }

    self.#closed = false;
    session.on('close', (reason: unknown) => {
      if (self.#closed) return;
      self.#closed = true;
      self.emit('close', reason);
    });

    self.compressionDefault = compression;
    return self;
  }

  /** Open a logical stream. Resolves after the server acknowledges. */
  openStream({ host = null, port = 0, unix = null, compression, hint = 'raw', meta = undefined }: Omit<OpenStreamOptions, 'compression'> & { compression?: string } = {}): Promise<import('./stream.js').TunnelStream> {
    if (!this.#session) return Promise.reject(new Error('not connected'));
    return this.#session.openStream({
      host, port, unix, hint, meta,
      compression: compression ?? this.compressionDefault ?? 'auto',
    });
  }

  /** RTT probe through the live session; resolves to milliseconds. */
  ping(): Promise<number> | undefined {
    return this.#session?.ping();
  }

  /** Graceful shutdown (GOAWAY) or immediate teardown when connected. */
  close(reason = 'client shutdown'): void {
    this.#closed = true;
    this.#session?.close(reason);
  }
}
