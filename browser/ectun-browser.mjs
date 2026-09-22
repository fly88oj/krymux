// Vendored into the krymux repository from the Node reference implementation
// (../ectun/browser/ectun-browser.mjs). Served unchanged by the Rust server at
// GET /sdk/ectun-browser.mjs (embedded at build time by build.rs); the route
// and file names keep their historical "ectun-browser" spelling so existing
// browser imports keep working.
// ectun browser SDK — zero dependencies, ES module.
// Connects a browser directly to an ectun server through any pure-TCP relay
// (frps/frpc): wss:// → TLS (browser) → WebSocket → app-layer P-256 mutual
// signature auth → CMPX multiplexed streams.
//
// Usage:
//   import { getIdentity, connect } from '/sdk/ectun-browser.mjs';
//   const id = await getIdentity();          // P-256 keypair, stored in IndexedDB
//   // register id.fingerprint in the server's auth.fingerprints, then:
//   const c = await connect({ endpoint: 'wss://frps.example:7000',
//                             serverFingerprint: 'sha256:…', identity: id });
//   const s = await c.openStream({ host: 'a.test', port: 80 });
//   await s.write(new TextEncoder().encode('GET / HTTP/1.1\r\nHost: a.test\r\n…'));
//   await s.end();
//   s.onData((chunk) => …); s.onEnd(() => …);
//
// Compression: v1 negotiates 'none' only (the continuous-context wire format
// is ready for deflate/zstd-wasm in a later revision).

// ---------------- frame codec (wire-identical to the native impls) ----------------

const FT = { HELLO: 1, OPEN: 2, OPEN_ACK: 3, DATA: 4, WINDOW: 5, CLOSE: 6, PING: 7, PONG: 8, GOAWAY: 9 };
const FLAG_COMPRESSED = 0x01;
const FLAG_FIN = 0x02;

function encodeFrame(type, flags, streamId, payload) {
  const len = payload ? payload.length : 0;
  const buf = new Uint8Array(10 + len);
  buf[0] = type;
  buf[1] = flags;
  new DataView(buf.buffer).setUint32(2, streamId >>> 0);
  new DataView(buf.buffer).setUint32(6, len);
  if (len) buf.set(payload, 10);
  return buf;
}

function parseFrames(buf, into) {
  let off = 0;
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  while (off + 10 <= buf.length) {
    const type = buf[off];
    const flags = buf[off + 1];
    const sid = dv.getUint32(off + 2);
    const len = dv.getUint32(off + 6);
    if (type < 1 || type > 9) throw new Error('bad frame type ' + type);
    if (off + 10 + len > buf.length) break;
    into.push({ type, flags, sid, payload: buf.subarray(off + 10, off + 10 + len) });
    off += 10 + len;
  }
  return off;
}

// ---------------- identity (WebCrypto P-256, IndexedDB-backed) ----------------

const subtle = () => globalThis.crypto.subtle;

/** Fingerprint of a raw SPKI DER buffer: "sha256:<64 hex>". */
export function fingerprintOfSpki(spkiDer) {
  return crypto.subtle.digest('SHA-256', spkiDer).then((h) =>
    'sha256:' + [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, '0')).join(''));
}

/** Generate-or-load the browser identity (P-256, non-extractable private key). */
export async function getIdentity() {
  if (!globalThis.indexedDB) {
    throw new Error('no IndexedDB; pass identity explicitly (see createIdentity)');
  }
  const db = await openDb();
  const existing = await idbGet(db, 'identity');
  if (existing) return finishIdentity(existing);
  const pair = await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  await idbPut(db, 'identity', pair);
  return finishIdentity(pair);
}

/** Build an identity from an externally generated key pair (Node tests etc.). */
export async function identityFromPair(pair) {
  return finishIdentity(pair);
}

async function finishIdentity(pair) {
  const spki = await subtle().exportKey('spki', pair.publicKey);
  const spkiDer = new Uint8Array(spki);
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, spkiDer,
    fingerprint: await fingerprintOfSpki(spkiDer) };
}

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('ectun', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('kv');
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
function idbGet(db, key) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction('kv', 'readonly');
    const req = tx.objectStore('kv').get(key);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
}
function idbPut(db, key, val) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction('kv', 'readwrite');
    tx.objectStore('kv').put(val, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ---------------- stream ----------------

/**
 * One multiplexed tunnel stream (browser flavor): callback-based reads via
 * onData/onEnd/onAbort, promise-based writes with credit-window backpressure.
 * Obtain instances from the client's openStream().
 */
export class WsStream {
  constructor(client, sid, target, ackPromise) {
    this._client = client;
    this.id = sid;
    this.target = target;
    this._ack = ackPromise;
    this._dataCb = null;
    this._endCb = null;
    this._abortCb = null;
    this._chunks = [];
    this._ended = false;       // remote FIN delivered
    this._finSent = false;
    this._writeQ = [];
    this._pumping = false;
    this._destroyed = false;
    this._closed = false;
  }

  onData(cb) { this._dataCb = cb; this._drainLocal(); }
  onEnd(cb) { this._endCb = cb; this._drainLocal(); }
  onAbort(cb) { this._abortCb = cb; }

  get ready() { return this._ack; }

  /** Write bytes; resolves when accepted (flow-control backpressure). */
  async write(bytes) {
    if (this._destroyed || this._finSent) throw new Error('stream not writable');
    this._writeQ.push({ bytes, fin: false });
    this._pump();
    await new Promise((resolve, reject) => {
      this._writeQ[this._writeQ.length - 1].resolve = resolve;
      this._writeQ[this._writeQ.length - 1].reject = reject;
    });
  }

  async end(tail) {
    if (this._finSent) return;
    const item = { bytes: tail || new Uint8Array(0), fin: true };
    this._writeQ.push(item);
    this._pump();
    await new Promise((resolve, reject) => { item.resolve = resolve; item.reject = reject; });
  }

  close() {
    if (this._closed) return;
    this._closed = true;
    this._destroyed = true;
    const body = new Uint8Array([5]); // CANCEL
    this._client._send(encodeFrame(FT.CLOSE, 0, this.id, body));
    this._client._unmap(this.id);
  }

  async _pump() {
    if (this._pumping || this._destroyed) return;
    this._pumping = true;
    try {
      while (this._writeQ.length && !this._destroyed) {
        const item = this._writeQ[0];
        // flow control: wait for credits to cover the logical size
        await this._client._acquire(this, item.bytes.length);
        this._client._send(encodeFrame(FT.DATA, item.fin ? FLAG_FIN : 0, this.id, item.bytes));
        this._writeQ.shift();
        item.resolve?.();
        if (item.fin) this._finSent = true;
      }
    } catch (e) {
      for (const item of this._writeQ) item.reject?.(e);
      this._writeQ = [];
    } finally {
      this._pumping = false;
    }
  }

  // ---- inbound (called by the client) ----
  _deliver(payload, flags) {
    if (this._destroyed) return;
    if (payload.length) this._chunks.push(payload);
    if (flags & FLAG_FIN) this._chunks.push(null);
    this._drainLocal();
  }
  _abort() {
    if (this._destroyed) return;
    this._destroyed = true;
    for (const item of this._writeQ) item.reject?.(new Error('aborted'));
    this._writeQ = [];
    try { this._abortCb?.('aborted'); } catch { /* theirs */ }
    this._client._unmap(this.id);
  }
  _drainLocal() {
    while (this._chunks.length) {
      const item = this._chunks.shift();
      if (item === null) {
        this._ended = true;
        try { this._endCb?.(); } catch { /* theirs */ }
        return;
      }
      try { this._dataCb?.(item); } catch { /* theirs */ }
      this._client._credit(this.id, item.length);
    }
  }
}

// ---------------- client ----------------

/**
 * Connect to an ectun server over WebSocket: performs the app-layer P-256
 * mutual-signature auth (verifying the pinned server WS fingerprint), then
 * the CMPX HELLO handshake. Resolves with a client exposing openStream(),
 * ping(), and close().
 */
export async function connect({ endpoint, serverFingerprint, identity,
  name = 'browser', rxWindow = 262144, rxWindowMax = 4194304, maxDataFrame = 65536 }) {
  if (!endpoint) throw new Error('endpoint required (wss://host:port)');
  if (!serverFingerprint) throw new Error('serverFingerprint required (pin the server WS key)');
  if (!identity?.privateKey) throw new Error('identity required (getIdentity() or identityFromPair)');

  const ws = new WebSocket(endpoint);
  ws.binaryType = 'arraybuffer';
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = () => reject(new Error('websocket connect failed'));
  });

  // ---- phase 1: app-layer auth ----
  const nonceC = crypto.getRandomValues(new Uint8Array(32));
  const authReply = await wsRoundtrip(ws, {
    t: 'init', spki: b64(identity.spkiDer), nonce: hex(nonceC),
  });
  if (authReply.t !== 'challenge') throw new Error('auth failed: ' + (authReply.reason ?? authReply.t));

  const serverSpki = b64d(authReply.spki);
  const serverFp = await fingerprintOfSpki(serverSpki);
  if (serverFp !== serverFingerprint) {
    ws.close();
    throw new Error('server fingerprint mismatch (got ' + serverFp.slice(7, 23) + '…)');
  }
  const nonceS = unhex(authReply.nonceS);
  const signed = concatBytes(nonceC, nonceS);
  {
    const ok = await subtle().verify({ name: 'ECDSA', hash: 'SHA-256' },
      await subtle().importKey('spki', serverSpki, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']),
      b64d(authReply.sigS), signed);
    if (!ok) { ws.close(); throw new Error('server signature invalid'); }
  }
  const sigC = await subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, identity.privateKey, signed);
  const verdict = await wsRoundtrip(ws, { t: 'response', sig: b64(new Uint8Array(sigC)) });
  if (verdict.t !== 'ok') throw new Error('auth denied: ' + (verdict.reason ?? verdict.t));

  // ---- phase 2: CMPX over binary messages ----
  const client = new EctunBrowserClient(ws, { rxWindow, rxWindowMax, maxDataFrame, name });
  await client._hello();
  return client;
}

class EctunBrowserClient {
  constructor(ws, opts) {
    this._ws = ws;
    this._opts = opts;
    this._streams = new Map();
    this._nextId = 1;
    this._txWindow = new Map();     // sid -> credits (logical bytes)
    this._txWaiters = new Map();    // sid -> [{resolve, reject, need}]
    this._pendingCredit = new Map(); // sid -> accumulated inbound credit
    this._granted = new Map();      // sid -> current window grant (growth state)
    this._peerMaxData = 65536;
    this._gone = false;
    this._helloDone = null;

    ws.onmessage = (ev) => {
      if (typeof ev.data === 'string') return; // ignore stray text
      const frames = [];
      const consumed = parseFrames(new Uint8Array(ev.data), frames);
      if (consumed === 0 && frames.length === 0) { this.close('bad frame'); return; }
      for (const f of frames) this._onFrame(f);
    };
    ws.onclose = () => this._teardown(new Error('websocket closed'));
    ws.onerror = () => this._teardown(new Error('websocket error'));
  }

  _send(bytes) {
    if (this._gone) return;
    // WS-level backpressure: if the socket buffer balloons, drop nothing but
    // let the queue build inside the WS implementation (bounded by credits).
    this._ws.send(bytes);
  }

  async _hello() {
    this._send(encodeFrame(FT.HELLO, 0, 0, encJson({
      v: 1, mode: 'client', name: this._opts.name,
      maxDataFrame: this._opts.maxDataFrame, rxWindow: this._opts.rxWindow,
      maxStreams: 64, compression: ['none'],
    })));
    await new Promise((resolve, reject) => {
      this._helloDone = resolve;
      setTimeout(() => reject(new Error('hello timeout')), 10000);
    });
  }

  async openStream({ host, port }) {
    if (this._gone) throw new Error('client closed');
    const sid = this._nextId;
    this._nextId += 2;
    this._txWindow.set(sid, this._serverRxWindow);
    const ackP = new Promise((resolve, reject) => {
      this._ackWaiters = this._ackWaiters || new Map();
      this._ackWaiters.set(sid, { resolve, reject });
    });
    const stream = new WsStream(this, sid, { host, port }, ackP);
    this._streams.set(sid, stream);
    this._send(encodeFrame(FT.OPEN, 0, sid, encJson({ host, port, hint: 'raw', compression: 'none' })));
    const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error('open timeout')), 12000));
    await Promise.race([ackP, timeout]);
    return stream;
  }

  ping() {
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    this._send(encodeFrame(FT.PING, 0, 0, nonce));
    return new Promise((resolve) => {
      const key = hex(nonce);
      (this._pongs = this._pongs || new Map()).set(key, resolve);
      setTimeout(() => { if (this._pongs.delete(key)) resolve(null); }, 5000);
    });
  }

  close(reason = 'browser shutdown') {
    if (this._gone) return;
    this._send(encodeFrame(FT.GOAWAY, 0, 0, encJson({ reason })));
    this._teardown(null);
    try { this._ws.close(1000); } catch { /* ignore */ }
  }

  _teardown(err) {
    if (this._gone) return;
    this._gone = true;
    // propagate the error to all streams (pending writes reject, readers see abort)
    for (const s of [...this._streams.values()]) s._abort();
    this._streams.clear();
    // wake all pending acquires so they can observe the teardown
    for (const [sid, waiters] of this._txWaiters) {
      for (const w of waiters) w.resolve();
      this._txWaiters.delete(sid);
    }
    // wake hello waiters
    this._helloDone?.();
    if (err && !this._closeCbFired) { this._closeCbFired = true; this.onClose?.(err.message); }
    else if (!this._closeCbFired) { this._closeCbFired = true; this.onClose?.('closed'); }
  }

  _onFrame(f) {
    switch (f.type) {
      case FT.HELLO: {
        const h = JSON.parse(decJson(f.payload));
        this._serverRxWindow = h.rxWindow ?? 262144;
        this._peerMaxData = Math.min(h.maxDataFrame ?? 65536, 65536);
        this._helloDone?.();
        return;
      }
      case FT.OPEN_ACK: {
        const ack = JSON.parse(decJson(f.payload));
        const w = this._ackWaiters?.get(f.sid);
        if (w) {
          this._ackWaiters.delete(f.sid);
          if (ack.ok) w.resolve(); else w.reject(new Error('denied: ' + (ack.reason ?? ack.code)));
          if (!ack.ok) {
            const s = this._streams.get(f.sid);
            this._streams.delete(f.sid);
            s?._destroyed !== undefined && (s._destroyed = true);
          }
        }
        return;
      }
      case FT.DATA: {
        const s = this._streams.get(f.sid);
        if (s) s._deliver(f.payload, f.flags);
        return;
      }
      case FT.WINDOW: {
        const delta = new DataView(f.payload.buffer, f.payload.byteOffset).getUint32(0);
        const cur = (this._txWindow.get(f.sid) ?? 0) + delta;
        this._txWindow.set(f.sid, cur);
        // wake all waiters whose need is now satisfied (credits are re-checked
        // in _acquire's loop, so waking is always safe)
        const waiters = this._txWaiters.get(f.sid);
        if (waiters) {
          for (const w of waiters) {
            if (cur >= w.need) w.resolve();
          }
          this._txWaiters.set(f.sid, waiters.filter((w) => cur < w.need));
        }
        return;
      }
      case FT.CLOSE: {
        const s = this._streams.get(f.sid);
        if (s) { s._chunks.push(null); s._drainLocal(); s._destroyed = true; this._streams.delete(f.sid); }
        return;
      }
      case FT.PONG: {
        const key = hex(f.payload.subarray(0, 16));
        const r = this._pongs?.get(key);
        if (r) { this._pongs.delete(key); r(Date.now()); }
        return;
      }
      case FT.PING: {
        this._send(encodeFrame(FT.PONG, 0, 0, f.payload));
        return;
      }
      case FT.GOAWAY: this._teardown(new Error('server goaway')); return;
      default:
    }
  }

  // ---- flow control (sender side) ----
  async _acquire(stream, need) {
    const sid = stream.id;
    for (;;) {
      const credits = this._txWindow.get(sid) ?? 0;
      if (credits >= need) {
        this._txWindow.set(sid, credits - need);
        return;
      }
      // not enough credits: wait for a WINDOW frame to wake us
      await new Promise((resolve) => {
        if (!this._txWaiters.has(sid)) this._txWaiters.set(sid, []);
        const entry = { resolve, need };
        this._txWaiters.get(sid).push(entry);
        // safety: also resolve on teardown
        if (this._gone) resolve();
      });
      if (this._gone) throw new Error('client closed');
    }
  }

  // ---- flow control (receiver side: credits + growth) ----
  _credit(sid, n) {
    const acc = (this._pendingCredit.get(sid) ?? 0) + n;
    const granted = this._granted.get(sid) ?? this._opts.rxWindow;
    if (acc >= Math.max(16384, granted >> 2)) {
      this._pendingCredit.set(sid, 0);
      this._sendCredit(sid, acc);
      this._maybeGrow(sid, acc);
    } else {
      this._pendingCredit.set(sid, acc);
      this._deferCreditTail();
    }
  }
  _deferCreditTail() {
    if (this._creditTimer) return;
    this._creditTimer = setTimeout(() => {
      this._creditTimer = null;
      for (const [sid, acc] of this._pendingCredit) {
        if (acc > 0) { this._pendingCredit.set(sid, 0); this._sendCredit(sid, acc); }
      }
    }, 5);
  }
  _sendCredit(sid, delta) {
    const p = new Uint8Array(4);
    new DataView(p.buffer).setUint32(0, delta >>> 0);
    this._send(encodeFrame(FT.WINDOW, 0, sid, p));
  }
  _maybeGrow(sid, consumed) {
    this._granted = this._granted || new Map();
    const granted = this._granted.get(sid) ?? this._opts.rxWindow;
    const max = this._opts.rxWindowMax;
    if (granted >= max) return;
    if (consumed < granted >> 1) return;
    const now = Date.now();
    this._growAt = this._growAt || new Map();
    const last = this._growAt.get(sid) ?? 0;
    if (now - last < 100) return;
    const s = this._streams.get(sid);
    // drain gate: unread chunks mean the app is not keeping up
    if (s && s._chunks.length > 4) return;
    const bonus = Math.min(granted, max - granted);
    if (bonus <= 0) return;
    this._granted.set(sid, granted + bonus);
    this._growAt.set(sid, now);
    this._sendCredit(sid, bonus);
  }

  _unmap(sid) {
    this._streams.delete(sid);
    this._txWindow.delete(sid);
    this._txWaiters.delete(sid);
    this._pendingCredit.delete(sid);
    this._granted?.delete(sid);
  }
}

// ---------------- small helpers ----------------

function wsRoundtrip(ws, obj) {
  return new Promise((resolve, reject) => {
    const onMessage = (ev) => {
      if (typeof ev.data !== 'string') return;
      cleanup();
      try { resolve(JSON.parse(ev.data)); } catch (e) { reject(e); }
    };
    const onClose = () => { cleanup(); reject(new Error('closed during auth')); };
    const cleanup = () => {
      if (ws.removeEventListener) {
        ws.removeEventListener('message', onMessage);
        ws.removeEventListener('close', onClose);
      } else {
        ws.onmessage = null;
        ws.onclose = null;
      }
    };
    if (ws.addEventListener) {
      ws.addEventListener('message', onMessage);
      ws.addEventListener('close', onClose);
    } else {
      ws.onmessage = onMessage;
      ws.onclose = onClose;
    }
    ws.send(JSON.stringify(obj));
  });
}

function encJson(o) { return new TextEncoder().encode(JSON.stringify(o)); }
function decJson(b) { return new TextDecoder().decode(b); }
function b64(u8) { let s = ''; for (const b of u8) s += String.fromCharCode(b); return btoa(s); }
function b64d(s) { const bin = atob(s); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
function hex(u8) { return [...u8].map((b) => b.toString(16).padStart(2, '0')).join(''); }
function unhex(s) { const u = new Uint8Array(s.length / 2); for (let i = 0; i < u.length; i++) u[i] = parseInt(s.substr(i * 2, 2), 16); return u; }
function concatBytes(a, b) { const u = new Uint8Array(a.length + b.length); u.set(a); u.set(b, a.length); return u; }
