/**
 * @krymux/sdk public surface — the package entry point.
 * Re-exports the full protocol stack so applications can import everything
 * from '@krymux/sdk': identity/keys, TLS contexts, server, client,
 * multiplexing, framing, compression, routing, and helpers.
 */

export {
  generateIdentity, loadIdentity, saveIdentity, buildSelfSignedCert,
  fingerprintOf, normalizeFingerprint, peerFingerprint, X509Certificate,
} from './keys.js';
export type { Identity } from './keys.js';
export { createProxyServer, createServer } from './server.js';
export type { ProxyServer, ProxyServerOptions, ServerStats } from './server.js';
export { EctunClient } from './client.js';
export type { ConnectOptions } from './client.js';
export { MuxSession } from './mux.js';
export type { MuxOptions, MuxStats, OpenStreamOptions } from './mux.js';
export { TunnelStream } from './stream.js';
export type { StreamTarget, StreamStats } from './stream.js';
export { compileRoutes } from './router.js';
export type { RouteConfig, RouteDecision, UpstreamAddr, UpstreamInput, ClientTargetsConfig } from './router.js';
export {
  serverTlsOptions, clientTlsOptions, authorizePeer, verifyServerPin, compileAuth, ALPN,
} from './tlsctx.js';
export type { AuthConfig, CompiledAuth, AuthVerdict } from './tlsctx.js';
export {
  FT, FLAG, CLOSE_CODES, ProtocolError, encodeFrame, FrameParser,
} from './frame.js';
export type { ParsedFrame } from './frame.js';
export {
  supportedAlgorithms, negotiate, baseAlgo, parseLevel, looksPrecompressed,
  createCompressContext, createDecompressContext,
  ALGO_NONE, ALGO_DEFLATE,
} from './compress.js';
export type { CompCtx } from './compress.js';
export {
  createLog, noopLogger, parseTarget, normalizeHost, hostMatches,
} from './util.js';
export type { Logger, ParsedTarget, TargetInput } from './util.js';

/** Semantic version of this package. */
export const VERSION = '0.1.0';

/** Wire protocol version (Krymux CMPX); must match across implementations. */
export const PROTOCOL_VERSION = 1;
