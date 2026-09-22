// Minimal DER encoder — just enough for a self-signed Ed25519 X.509 certificate.
// Pure functions returning Buffers, composed bottom-up.

import { Buffer } from 'node:buffer';

function concat(parts: Array<Buffer | null | undefined>): Buffer {
  return Buffer.concat(parts.filter((p): p is Buffer => !!p && p.length > 0));
}

function derLen(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 0x100);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, content: Buffer): Buffer {
  return concat([Buffer.from([tag]), derLen(content.length), content]);
}

/** SEQUENCE */
export function seq(...contents: Array<Buffer | null | undefined>): Buffer {
  return tlv(0x30, concat(contents));
}

/** SET */
export function setOf(...contents: Array<Buffer | null | undefined>): Buffer {
  return tlv(0x31, concat(contents));
}

/** SET OF (same wire form; used for RDN sets) */
export const rdnSet = setOf;

/** INTEGER from a Buffer (already unsigned, we fix sign) or a small number. */
export function int(value: number | Buffer): Buffer {
  let bytes: Buffer;
  if (Buffer.isBuffer(value)) {
    bytes = value;
    while (bytes.length > 1 && bytes[0] === 0) bytes = bytes.subarray(1);
    if (bytes.length === 0) bytes = Buffer.from([0]);
    if (bytes[0]! & 0x80) bytes = concat([Buffer.from([0]), bytes]);
  } else {
    bytes = Buffer.alloc(4);
    bytes.writeUInt32BE(value >>> 0, 0);
    let i = 0;
    while (i < 3 && bytes[i] === 0) i++;
    bytes = bytes.subarray(i);
    if (bytes[0]! & 0x80) bytes = concat([Buffer.from([0]), bytes]);
  }
  return tlv(0x02, bytes);
}

/** OBJECT IDENTIFIER from a dotted string, e.g. "1.3.101.112". */
export function oid(dotted: string): Buffer {
  const parts = dotted.split('.').map((s) => Number(s));
  const body: number[] = [];
  body.push(parts[0]! * 40 + parts[1]!);
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i]!;
    const stack = [v & 0x7f];
    v = Math.floor(v / 128);
    while (v > 0) {
      stack.unshift((v & 0x7f) | 0x80);
      v = Math.floor(v / 128);
    }
    body.push(...stack);
  }
  return tlv(0x06, Buffer.from(body));
}

/** BIT STRING (unused-bits = 0). */
export function bitString(buf: Buffer): Buffer {
  return tlv(0x03, concat([Buffer.from([0x00]), buf]));
}

/** OCTET STRING */
export function octetString(buf: Buffer | number[]): Buffer {
  return tlv(0x04, Buffer.isBuffer(buf) ? buf : Buffer.from(buf));
}

/** UTF8String */
export function utf8Str(s: string): Buffer {
  return tlv(0x0c, Buffer.from(s, 'utf8'));
}

/** UTCTime (dates 1950..2049): YYMMDDHHMMSSZ */
export function utcTime(date: Date): Buffer {
  const p = (n: number) => String(n).padStart(2, '0');
  const d = date;
  const s =
    `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}` +
    `${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x17, Buffer.from(s, 'ascii'));
}

/** BOOLEAN */
export function bool(b: boolean): Buffer {
  return tlv(0x01, Buffer.from([b ? 0xff : 0x00]));
}

/** context-specific constructed [n] EXPLICIT wrapper */
export function ctxExplicit(n: number, content: Buffer): Buffer {
  return tlv(0xa0 | n, content);
}

/** context-specific primitive [n] (e.g. [2] dNSName in SAN) */
export function ctxPrimitive(n: number, content: Buffer | string): Buffer {
  return tlv(0x80 | n, Buffer.isBuffer(content) ? content : Buffer.from(content));
}

/** AlgorithmIdentifier for Ed25519 (RFC 8410: parameters MUST be absent). */
export function ed25519AlgId(): Buffer {
  return seq(oid('1.3.101.112'));
}

/** SubjectPublicKeyInfo for an Ed25519 raw public key (32 bytes). */
export function ed25519Spki(rawPub: Buffer): Buffer {
  return seq(ed25519AlgId(), bitString(rawPub));
}
