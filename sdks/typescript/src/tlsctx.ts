// TLS 1.3 security layer.
//
// - Encryption/transport integrity: standard TLS 1.3 (OpenSSL, hardware AES-GCM or
//   ChaCha20-Poly1305). We do NOT hand-roll a handshake.
// - Mutual identity: both sides present self-signed Ed25519 certificates generated
//   by this tool. The certificate is treated as a key container; the canonical
//   identity is sha256(SPKI) — exactly the WireGuard/SSH "public key" model.
// - Server authorization: whitelist of client key fingerprints, or "open" mode
//   (any valid key). Client authorization: pinned server key fingerprint.
// - TLS 1.3 session resumption is contained: fresh random ticketKeys per process
//   (tickets die on restart), ticketKeys rotated whenever the whitelist changes,
//   and connections that present no client certificate (e.g. resumed sessions
//   where OpenSSL does not re-send it) are rejected — fail closed.
//
// Wire facts shared with the Rust implementation (crates/krymux/src/tls.rs):
// ALPN "krymux", TLS 1.3 only, mTLS with Ed25519 self-signed certs.

import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import type * as tls from 'node:tls';
import { peerFingerprint } from './keys.js';
import { toArray } from './util.js';

export const ALPN = 'krymux';

/** TLS server options that require a client certificate without CA validation. */
export function serverTlsOptions({ cert, key, handshakeTimeout = 10000 }: {
  cert: string;
  key: string;
  handshakeTimeout?: number;
}): tls.TlsOptions {
  return {
    cert,
    key,
    ALPNProtocols: [ALPN],
    minVersion: 'TLSv1.3',
    requestCert: true,
    rejectUnauthorized: false, // we authorize by fingerprint below
    handshakeTimeout,
    ticketKeys: randomBytes(48), // per-process; rotated on auth changes
  };
}

/** Compiled runtime authorization state. */
export interface CompiledAuth {
  mode: 'open' | 'whitelist';
  fingerprints: Set<string>;
}

/** Authorization input shape ({ mode, fingerprints[] } or { mode, clients[] }). */
export interface AuthConfig {
  mode?: string;
  fingerprints?: Array<string | { fingerprint?: string; publicKey?: string }>;
  clients?: Array<string | { fingerprint?: string; publicKey?: string }>;
}

/** Normalize an `auth` config block into the runtime shape. */
export function compileAuth(authCfg: AuthConfig = {}, normalizeFingerprintFn: (s: string) => string): CompiledAuth {
  const mode = authCfg.mode === 'open' ? 'open' : 'whitelist';
  const fingerprints = new Set<string>();
  for (const entry of toArray(authCfg.fingerprints ?? authCfg.clients ?? [])) {
    let fp: string | undefined;
    if (typeof entry === 'object' && entry !== null) fp = entry.fingerprint ?? entry.publicKey;
    else fp = entry;
    if (!fp) continue;
    fingerprints.add(normalizeFingerprintFn(fp));
  }
  return { mode, fingerprints };
}

/** Verdict of a post-handshake authorization check. */
export interface AuthVerdict {
  ok: boolean;
  reason?: string;
  fingerprint?: string;
}

/**
 * Decide whether a freshly handshaked server-side TLS connection may proceed.
 * Fail closed: no ALPN match, no cert, unknown fingerprint -> reject.
 */
export function authorizePeer(tlsSocket: tls.TLSSocket, auth: CompiledAuth): AuthVerdict {
  if (tlsSocket.alpnProtocol !== ALPN) {
    return { ok: false, reason: `alpn mismatch: ${tlsSocket.alpnProtocol ?? 'none'}` };
  }
  const fp = peerFingerprint(tlsSocket);
  if (!fp) {
    // covers: no client cert, empty cert (resumed session without cert re-send)
    return { ok: false, reason: 'no client certificate presented' };
  }
  if (auth.mode === 'open') return { ok: true, fingerprint: fp };
  if (auth.fingerprints.has(fp)) return { ok: true, fingerprint: fp };
  return { ok: false, reason: `client fingerprint not whitelisted: ${fp.slice(0, 22)}...` };
}

/** TLS client options; identity is always sent, trust is decided by pinning. */
export function clientTlsOptions({ cert, key, servername = 'krymux' }: {
  cert: string;
  key: string;
  servername?: string;
}): tls.ConnectionOptions {
  return {
    cert,
    key,
    ALPNProtocols: [ALPN],
    minVersion: 'TLSv1.3',
    rejectUnauthorized: false, // we verify the pinned fingerprint ourselves
    servername,
    checkServerIdentity: () => undefined, // pin, do not use CA/name validation
  };
}

/** Verify the server's pinned key fingerprint after the TLS handshake. */
export function verifyServerPin(tlsSocket: tls.TLSSocket, expectedFingerprint: string): AuthVerdict {
  const fp = peerFingerprint(tlsSocket);
  if (!fp) return { ok: false, reason: 'server did not present a certificate' };
  if (fp !== expectedFingerprint) {
    return { ok: false, reason: `server fingerprint mismatch: got ${fp.slice(0, 22)}...` };
  }
  return { ok: true, fingerprint: fp };
}
