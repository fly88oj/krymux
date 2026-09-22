// EctunServer: the reverse proxy that terminates encrypted tunnels and forwards
// logical streams to local upstreams according to the routing table.

import * as tls from 'node:tls';
import type { TLSSocket } from 'node:tls';
import * as net from 'node:net';
import { randomBytes } from 'node:crypto';
import { MuxSession } from './mux.js';
import type { TunnelStream } from './stream.js';
import { serverTlsOptions, authorizePeer, compileAuth, type AuthConfig, type CompiledAuth } from './tlsctx.js';
import { compileRoutes } from './router.js';
import type { RouteConfig, ClientTargetsConfig, UpstreamInput } from './router.js';
import { normalizeFingerprint } from './keys.js';
import type { Identity } from './keys.js';
import { parseTarget, fmtBytes, type Logger } from './util.js';

/** Server-wide counters. */
export interface ServerStats {
  startedAt: number | null;
  connectionsTotal: number;
  connectionsActive: number;
  connectionsRejected: number;
  streamsTotal: number;
  streamsActive: number;
  upstreamBytes: number;
  activeStreams: number;
}

/** createProxyServer() options (mirrors the Node SDK; wsIdentity is not ported). */
export interface ProxyServerOptions {
  listen?: string | [string, number];
  /** {certPem, keyPem, fingerprint} from loadIdentity/generateIdentity. */
  identity: { certPem: string; keyPem: string; fingerprint?: string };
  auth?: AuthConfig;
  routes?: RouteConfig[];
  fallbackUpstream?: UpstreamInput;
  clientTargets?: ClientTargetsConfig | boolean | null;
  maxDataFrame?: number;
  rxWindow?: number;
  rxWindowMax?: number;
  maxStreams?: number;
  keepaliveSec?: number;
  connectTimeoutMs?: number;
  log?: Logger | null;
}

/** A running tunnel server handle. */
export interface ProxyServer {
  start(): Promise<net.AddressInfo | string>;
  stop(): Promise<void>;
  /** Update the whitelist at runtime; rotates TLS ticket keys. */
  setAuth(nextAuthCfg: AuthConfig): void;
  setRoutes(next: { routes?: RouteConfig[]; fallbackUpstream?: UpstreamInput; clientTargets?: ClientTargetsConfig | null }): void;
  address(): net.AddressInfo | string | null;
  readonly stats: ServerStats;
}

/**
 * Create the tunnel server: a TLS 1.3 listener that authorizes clients by
 * Ed25519 fingerprint, multiplexes their streams (MuxSession), and routes each
 * stream to a local upstream. Returns {start, stop, setAuth, setRoutes,
 * address, stats}.
 */
export function createProxyServer({
  listen = '127.0.0.1:0',
  identity,
  auth: authCfg = { mode: 'whitelist', fingerprints: [] },
  routes = [],
  fallbackUpstream = null,
  clientTargets = null,
  maxDataFrame,
  rxWindow,
  rxWindowMax,
  maxStreams,
  keepaliveSec = 30,
  connectTimeoutMs = 5000,
  log,
}: ProxyServerOptions): ProxyServer {
  if (!identity?.certPem || !identity?.keyPem) throw new Error('server identity required');

  const logger: Logger = log ?? { info() {}, warn() {}, error() {}, debug() {} };
  let auth: CompiledAuth = compileAuth(authCfg, normalizeFingerprint);
  let router = compileRoutes({ routes, fallbackUpstream, clientTargets });

  const stats: Omit<ServerStats, 'activeStreams'> = {
    startedAt: null,
    connectionsTotal: 0,
    connectionsActive: 0,
    connectionsRejected: 0,
    streamsTotal: 0,
    streamsActive: 0,
    upstreamBytes: 0,
  };

  function startSession(socket: TLSSocket, who: string): void {
    stats.connectionsTotal++;
    stats.connectionsActive++;
    logger.info('client connected', { peer: socket.remoteAddress ?? '?', fp: who });

    const session = new MuxSession(socket, {
      isClient: false,
      name: identity.fingerprint?.slice(7, 19) ?? 'server',
      log: logger,
      maxDataFrame, rxWindow, rxWindowMax, maxStreams, keepaliveSec,
    });
    session.on('stream', (stream: TunnelStream, target: { host?: string | null; port?: number; unix?: string | null }) =>
      handleStream(stream, target, who));
    session.on('close', (reason: unknown) => {
      stats.connectionsActive--;
      logger.info('client disconnected', { peer: socket.remoteAddress ?? '?', fp: who, reason: String(reason).slice(0, 80) });
    });
    socket.on('error', () => { /* already routed through mux failure */ });
  }

  const tlsServer = tls.createServer(
    serverTlsOptions({ cert: identity.certPem, key: identity.keyPem }),
    (tlsSocket) => {
      const peer = tlsSocket.remoteAddress ?? '?';
      const verdict = authorizePeer(tlsSocket, auth);
      if (verdict.ok) {
        const who = (verdict.fingerprint ?? '').slice('sha256:'.length).slice(0, 12);
        startSession(tlsSocket, who);
        return;
      }
      stats.connectionsRejected++;
      logger.warn('rejected connection', { peer, reason: verdict.reason });
      tlsSocket.destroy();
    },
  );
  tlsServer.on('tlsClientError', (err: Error, sock: net.Socket) => {
    stats.connectionsRejected++;
    logger.debug('tls client error', { message: String(err?.message).slice(0, 80), peer: sock?.remoteAddress });
  });

  function handleStream(stream: TunnelStream, target: { host?: string | null; port?: number; unix?: string | null }, who: string): void {
    stats.streamsTotal++;
    const decision = router.resolve(target);
    const where = target?.unix
      ? `unix:${target.unix}`
      : `${target?.host ?? '?'}:${target?.port ?? 0}`;

    if (decision.action === 'deny') {
      logger.warn('stream denied', { who, target: where, reason: decision.reason });
      stream.reject('denied', decision.reason);
      return;
    }

    const upstreamAddr = decision.action === 'route' ? decision.upstream : decision.target;
    const label = upstreamAddr?.unix ? `unix:${upstreamAddr.unix}` : `${upstreamAddr?.host}:${upstreamAddr?.port}`;

    const upstream = upstreamAddr?.unix
      ? net.connect({ path: upstreamAddr.unix })
      : net.connect({ host: upstreamAddr?.host, port: Number(upstreamAddr?.port) });

    let settled = false;
    const dialTimer = setTimeout(() => {
      if (!settled) upstream.destroy();
    }, connectTimeoutMs);

    upstream.on('connect', () => {
      settled = true;
      clearTimeout(dialTimer);
      stats.streamsActive++;
      stream.accept({ upstream: label });
      logger.debug('stream open', { who, target: where, upstream: label });

      pump(stream, upstream, () => {
        stats.streamsActive--;
      });
    });

    upstream.on('error', (err: Error & { code?: string }) => {
      clearTimeout(dialTimer);
      if (!settled) {
        logger.info('upstream unreachable', { who, target: where, upstream: label, message: err.message });
        stream.reject('unreachable', `dial ${label}: ${err.code ?? err.message}`);
      } else {
        stream.abort(1, `upstream error: ${err.code ?? err.message}`);
      }
    });

    stream.on('aborted', (reason: unknown) => {
      logger.debug('stream aborted by peer', { who, target: where, reason: String(reason).slice(0, 60) });
      upstream.destroy();
    });
  }

  function pump(stream: TunnelStream, upstream: net.Socket, onDone: () => void): void {
    let bytesUp = 0;   // client -> upstream
    let bytesDown = 0; // upstream -> client
    let upstreamEnded = false;
    let finished = false;
    const t0 = Date.now();

    stream.on('data', (c: Buffer) => {
      bytesUp += c.length;
    });
    upstream.on('data', (c: Buffer) => {
      bytesDown += c.length;
    });

    const finish = () => {
      if (finished) return; // both sides closing must not double-count
      finished = true;
      stats.upstreamBytes += bytesUp + bytesDown;
      onDone();
      logger.debug('stream closed', {
        ms: Date.now() - t0,
        up: fmtBytes(bytesUp),
        down: fmtBytes(bytesDown),
      });
    };
    stream.on('close', () => {
      upstream.destroy();
      finish();
    });
    upstream.on('end', () => {
      upstreamEnded = true; // pipe() sends FIN after queued data
    });
    upstream.on('close', () => {
      // abort only on premature close (RST-ish); graceful ends flush via pipe+end()
      if (!upstreamEnded && !stream.writableEnded && !stream.destroyed) {
        stream.abort(0, 'upstream closed');
      }
      finish();
    });
    // errors on either side tear both down
    stream.on('error', () => upstream.destroy());
    upstream.on('error', () => stream.destroy());

    upstream.pipe(stream);
    stream.pipe(upstream);
  }

  return {
    async start(): Promise<net.AddressInfo | string> {
      const t = parseTarget(listen, 0);
      await new Promise<void>((resolve, reject) => {
        tlsServer.once('error', reject);
        tlsServer.listen(t.port, t.host, () => {
          stats.startedAt = Date.now();
          const addr = tlsServer.address();
          logger.info('krymux server listening', {
            host: typeof addr === 'object' && addr ? addr.address : '?',
            port: typeof addr === 'object' && addr ? addr.port : 0,
            auth: auth.mode,
            clients: auth.fingerprints.size,
            routes: router.routes.length + (router.fallback ? '+fallback' : ''),
          });
          resolve();
        });
      });
      return tlsServer.address() as net.AddressInfo | string;
    },
    async stop(): Promise<void> {
      await new Promise<void>((resolve) => tlsServer.close(() => resolve()));
      for (const s of (tlsServer as tls.Server & { clients?: Set<net.Socket> }).clients ?? []) s.destroy();
    },
    /** Update the whitelist at runtime; rotates TLS ticket keys so revoked
     *  clients cannot ride existing session tickets. */
    setAuth(nextAuthCfg: AuthConfig): void {
      auth = compileAuth(nextAuthCfg, normalizeFingerprint);
      // tls.Server exposes setTicketKeys on Node >= 20? rotate defensively:
      try {
        (tlsServer as unknown as { setTicketKeys?: (k: Buffer) => void }).setTicketKeys?.(randomBytes(48));
      } catch {
        /* not supported */
      }
      logger.info('auth updated', { mode: auth.mode, clients: auth.fingerprints.size });
    },
    setRoutes(next: { routes?: RouteConfig[]; fallbackUpstream?: UpstreamInput; clientTargets?: ClientTargetsConfig | null }): void {
      router = compileRoutes(next);
    },
    address(): net.AddressInfo | string | null {
      return tlsServer.address();
    },
    get stats(): ServerStats {
      return { ...stats, activeStreams: stats.streamsActive };
    },
  };
}

/** Alias kept for discoverability — same as createProxyServer. */
export const createServer = createProxyServer;
