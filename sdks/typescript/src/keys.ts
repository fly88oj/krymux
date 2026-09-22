// Identity layer: Ed25519 keypairs, self-signed X.509 certificates (built with src/der.ts),
// and SPKI fingerprints used as the canonical wire identity (like SSH/WireGuard key IDs).
//
// The fingerprint is "sha256:" + hex(sha256(SPKI DER)) — byte-identical to the Rust
// implementation (crates/krymux/src/keys.rs), so whitelists and pins transfer 1:1.

import { Buffer } from 'node:buffer';
import {
  generateKeyPairSync, createHash, createPublicKey, sign as cryptoSign,
  randomBytes, X509Certificate, createPrivateKey,
} from 'node:crypto';
import type { KeyObject, JsonWebKey } from 'node:crypto';
import type { TLSSocket } from 'node:tls';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import * as der from './der.js';

export { X509Certificate };

export const OID_ED25519 = '1.3.101.112';

/** A generated or loaded identity. */
export interface Identity {
  privateKey: KeyObject;
  publicKey: KeyObject;
  keyPem: string;
  certPem: string;
  fingerprint: string;
  /** Only set by loadIdentity(). */
  x509?: X509Certificate;
  /** Only set by loadIdentity(). */
  peerName?: string;
}

/** sha256(SPKI DER), formatted "sha256:<64 lowercase hex>". Stable across cert regeneration. */
export function fingerprintOf(publicKey: KeyObject): string {
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return 'sha256:' + createHash('sha256').update(spki).digest('hex');
}

function wrap64(derBuf: Buffer): string {
  const b64 = derBuf.toString('base64');
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}

/**
 * Build a minimal self-signed Ed25519 certificate.
 * - CN = "<cn> <fingerprint prefix>"; SAN DNS:krymux (name checks are bypassed by our
 *   pinning, SAN kept for interop)
 * - validity: 20 years (UTCTime, capped by the year 2049 per DER)
 */
export function buildSelfSignedCert(
  keyPair: { publicKey: KeyObject; privateKey: KeyObject },
  { cn = 'krymux', days = 7300 }: { cn?: string; days?: number } = {},
): { pem: string; x509: X509Certificate; fingerprint: string } {
  const rawPub = keyPair.publicKey.export({ format: 'jwk' }) as JsonWebKey;
  // For ed25519, raw public key = base64url "x" of the JWK
  if (!rawPub.x) throw new Error('ed25519 public key JWK has no "x"');
  const raw = Buffer.from(rawPub.x, 'base64url');
  const fp = fingerprintOf(keyPair.publicKey).slice('sha256:'.length);
  const commonName = `${cn} ${fp.slice(0, 16)}`;

  const algId = der.ed25519AlgId();
  const name = der.seq(der.rdnSet(der.seq(der.oid('2.5.4.3'), der.utf8Str(commonName))));

  const notBefore = new Date(Date.now() - 24 * 3600 * 1000);
  const notAfter = new Date(Date.now() + days * 24 * 3600 * 1000);
  // UTCTime is only defined up to 2049; clamp.
  if (notAfter.getUTCFullYear() > 2049) notAfter.setUTCFullYear(2049, 11, 31);
  const validity = der.seq(der.utcTime(notBefore), der.utcTime(notAfter));

  let serial = randomBytes(16);
  if (serial[0] === 0) serial[0] = 1; // keep positive
  if (serial[0]! & 0x80) serial = Buffer.concat([Buffer.from([0]), serial]);

  const spki = der.ed25519Spki(raw);

  const extBasicConstraints = der.seq(
    der.oid('2.5.29.19'), der.bool(true), der.octetString(der.seq()),
  );
  const extSan = der.seq(
    der.oid('2.5.29.17'), der.octetString(der.seq(der.ctxPrimitive(2, Buffer.from('krymux', 'ascii')))),
  );
  const extensions = der.ctxExplicit(3, der.seq(extBasicConstraints, extSan));

  const tbs = der.seq(
    der.ctxExplicit(0, der.int(2)), // version v3
    der.int(serial),
    algId,
    name, // issuer (self-signed)
    validity,
    name, // subject
    spki,
    extensions,
  );

  const sig = cryptoSign(null, tbs, keyPair.privateKey);
  const cert = der.seq(tbs, algId, der.bitString(sig));
  const pem = wrap64(cert);

  // Fail fast if we produced anything Node/OpenSSL refuses to parse or verify.
  const x509 = new X509Certificate(pem);
  if (!x509.verify(keyPair.publicKey)) {
    throw new Error('self-signed certificate failed self-verification');
  }
  return { pem, x509, fingerprint: 'sha256:' + fp };
}

/** Generate an identity: Ed25519 keypair + self-signed cert + fingerprint. */
export function generateIdentity({ cn = 'krymux', days = 7300 }: { cn?: string; days?: number } = {}): Identity {
  const keyPair = generateKeyPairSync('ed25519');
  const { pem, fingerprint } = buildSelfSignedCert(keyPair, { cn, days });
  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    keyPem: keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    certPem: pem,
    fingerprint,
  };
}

/**
 * Accept flexible fingerprint inputs:
 *  - "sha256:<hex>" / bare 64-char hex
 *  - base64 SPKI DER (44 chars, as exported by publicKey.export({type:'spki',format:'der'}))
 *  - a PEM public key / certificate
 */
export function normalizeFingerprint(input: string): string {
  if (!input) throw new Error('empty fingerprint input');
  const s = String(input).trim();
  if (s.startsWith('sha256:')) {
    const hex = s.slice(7).replace(/[:\s]/g, '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`bad sha256 fingerprint: ${s}`);
    return 'sha256:' + hex;
  }
  if (/^[0-9a-f:]{64,79}$/i.test(s) && s.replace(/:/g, '').length === 64) {
    return 'sha256:' + s.replace(/:/g, '').toLowerCase();
  }
  if (/^sha256-/.test(s)) { // JWKS-style
    return 'sha256:' + Buffer.from(s.slice(7), 'base64url').toString('hex');
  }
  if (s.startsWith('-----')) { // PEM: public key or certificate
    const asKey = createPublicKey(s);
    return fingerprintOf(asKey);
  }
  if (/^[A-Za-z0-9+/=]+$/.test(s) && s.length >= 40) { // base64 SPKI DER
    const derBuf = Buffer.from(s, 'base64');
    if (derBuf.length >= 40 && derBuf.length <= 120 && derBuf[0] === 0x30) {
      return 'sha256:' + createHash('sha256').update(derBuf).digest('hex');
    }
  }
  throw new Error(`unrecognized fingerprint format: ${String(input).slice(0, 40)}...`);
}

/** Extract the SPKI fingerprint of the peer certificate of a live TLS socket. */
export function peerFingerprint(tlsSocket: TLSSocket): string | null {
  const cert = tlsSocket.getPeerCertificate() as ReturnType<TLSSocket['getPeerCertificate']> & { empty?: boolean };
  if (!cert || cert.empty) return null;
  try {
    const rawDer = Buffer.isBuffer(cert.raw) ? cert.raw : null;
    if (!rawDer) return null;
    const x509 = new X509Certificate(rawDer);
    return fingerprintOf(x509.publicKey);
  } catch {
    return null;
  }
}

function readMaybe(pathOrPem: string): string | null {
  if (typeof pathOrPem !== 'string') return null;
  if (pathOrPem.includes('-----BEGIN')) return pathOrPem;
  const p = resolve(pathOrPem);
  if (!existsSync(p)) throw new Error(`file not found: ${p}`);
  return readFileSync(p, 'utf8');
}

/** Load an identity from PEM strings or file paths. */
export function loadIdentity(
  { key: keyIn, cert: certIn, passphrase }: { key?: string; cert?: string; passphrase?: string } = {},
): Identity {
  const keyPem = readMaybe(keyIn ?? '');
  const certPem = readMaybe(certIn ?? '');
  if (!keyPem || !certPem) throw new Error('identity requires key and cert (PEM or path)');
  const privateKey = passphrase
    ? createPrivateKey({ key: keyPem, passphrase })
    : createPrivateKey(keyPem);
  const x509 = new X509Certificate(certPem);
  const publicKey = x509.publicKey;
  if (fingerprintOf(publicKey) !== fingerprintOf(createPublicKey(privateKey))) {
    throw new Error('identity key does not match certificate');
  }
  return {
    privateKey,
    publicKey,
    x509,
    keyPem,
    certPem,
    fingerprint: fingerprintOf(publicKey),
    peerName: (x509.subject ?? '').toString(),
  };
}

/** Persist an identity to <dir>/<name>.key.pem + <name>.crt.pem + identity.json. */
export function saveIdentity(
  dir: string,
  identity: Identity,
  { name = 'server' }: { name?: string } = {},
): { keyPath: string; certPath: string; fingerprint: string } {
  mkdirSync(dir, { recursive: true });
  const keyPath = join(dir, `${name}.key.pem`);
  const certPath = join(dir, `${name}.crt.pem`);
  writeFileSync(keyPath, identity.keyPem, { mode: 0o600 });
  writeFileSync(certPath, identity.certPem);
  writeFileSync(join(dir, `${name}.identity.json`), JSON.stringify({
    name,
    fingerprint: identity.fingerprint,
    key: keyPath,
    cert: certPath,
    createdAt: new Date().toISOString(),
  }, null, 2));
  return { keyPath, certPath, fingerprint: identity.fingerprint };
}
