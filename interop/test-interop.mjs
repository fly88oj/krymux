// Interop tests: Rust krymux binary <-> Node reference implementation.
// Phase A: Rust server + Node client (compression, vhost, whitelist)
// Phase B: Node server + Rust client via SOCKS5 (integrity through frontend)
import { spawn } from 'node:child_process';
import * as net from 'node:net';
import * as http from 'node:http';
import * as crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import { writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Rust binary under test: ECTUN_BIN env var (path to krymux-tunnel.exe),
// defaulting to the release build next to this repo.
const RS = process.env.ECTUN_BIN
  ?? fileURLToPath(new URL('../target/release/krymux-tunnel.exe', import.meta.url));
const KEYDIR = 'C:/tmp/rs-interop';

const { createProxyServer, EctunClient, generateIdentity, loadIdentity } = await import('file:///C:/Users/FLYING/.zcode/workspace/default/ectun/lib/index.mjs');
const assert = (await import('node:assert/strict')).default;

const tmpJson = (p, o) => writeFileSync(p, JSON.stringify(o, null, 2));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const run = (cmd, args) => new Promise((resolve, reject) => {
  const p = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let err = '';
  p.stderr.on('data', (c) => { err += c; });
  p.stdout.on('data', () => {});
  p.once('error', reject);
  p.once('spawn', () => resolve({ proc: p, stderr: err }));
});

function keygen(args) {
  return new Promise((resolve, reject) => {
    const p = spawn(RS, ['keygen', ...args]);
    let out = '';
    p.stdout.on('data', (c) => { out += c; });
    p.stderr.on('data', (c) => { out += c; });
    p.once('exit', () => {
      const m = out.match(/fingerprint: (sha256:[0-9a-f]{64})/);
      m ? resolve(m[1]) : reject(new Error('keygen failed: ' + out));
    });
  });
}

function startEcho() {
  const srv = net.createServer((s) => s.pipe(s));
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r({ srv, port: srv.address().port })));
}

function startHttp(body) {
  const srv = http.createServer((req, res) => res.end(`${body} host=${req.headers.host}\n`));
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r({ srv, port: srv.address().port })));
}

async function readAll(stream) {
  const parts = [];
  for await (const c of stream) parts.push(c);
  return Buffer.concat(parts);
}

const PASS = [];
const FAIL = [];
function report(name, err) {
  if (err) { FAIL.push(name); console.error(`✖ ${name}: ${err.message ?? err}`); }
  else { PASS.push(name); console.log(`✔ ${name}`); }
}

rmSync(KEYDIR, { recursive: true, force: true });

// ================= Phase A: Rust server + Node client =================
{
  const serverFp = await keygen(['--out', `${KEYDIR}`, '--role', 'server', '--name', 'server']);
  const aliceFp = await keygen(['--out', `${KEYDIR}`, '--role', 'client', '--name', 'alice']);
  const malloryFp = await keygen(['--out', `${KEYDIR}`, '--role', 'client', '--name', 'mallory']);

  const echo = await startEcho();
  const originA = await startHttp('origin-a');
  const originB = await startHttp('origin-b');

  tmpJson(`${KEYDIR}/server.json`, {
    listen: '127.0.0.1:28443',
    identity: { key: `${KEYDIR}/server.key.pem`, cert: `${KEYDIR}/server.crt.pem` },
    auth: { mode: 'whitelist', fingerprints: [aliceFp] },
    routes: [
      { host: ['a.test'], upstream: ['127.0.0.1', originA.port] },
      { host: ['*.test'], upstream: ['127.0.0.1', originB.port] },
      { host: ['echo'], upstream: ['127.0.0.1', echo.port] },
    ],
    clientTargets: { enabled: false },
  });
  const rsServer = spawn(RS, ['server', '--config', `${KEYDIR}/server.json`], { stdio: ['ignore', 'ignore', 'inherit'], env: { ...process.env, ECTUN_LOG: 'debug' } });
  await sleep(3000);

  // 1. Node client with the rust-generated alice identity (cross-tool certs)
  const alice = loadIdentity({ key: `${KEYDIR}/alice.key.pem`, cert: `${KEYDIR}/alice.crt.pem` });
  const client = await EctunClient.connect({
    endpoint: '127.0.0.1:28443',
    identity: alice,
    serverFingerprint: serverFp,
  });

  // echo integrity per algorithm
  const payload = Buffer.concat([
    crypto.randomBytes(1024 * 1024),
    Buffer.from('compressible '.repeat(64 * 1024)),
  ]);
  for (const algo of ['none', 'deflate', 'brotli']) {
    try {
      const s = await client.openStream({ host: 'echo', port: 9, compression: algo });
      s.write(payload); s.end();
      const out = await readAll(s);
      assert.ok(out.equals(payload), `${algo} integrity`);
      report(`A: echo ${algo} 1MB+ byte-exact (node client -> rust server)`);
    } catch (e) { report(`A: echo ${algo}`, e); }
  }

  // vhost routing
  for (const [host, expect] of [['a.test', 'origin-a'], ['other.test', 'origin-b']]) {
    try {
      const s = await client.openStream({ host, port: 80, compression: 'none', hint: 'http' });
      s.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
      s.end();
      const out = (await readAll(s)).toString();
      assert.match(out, new RegExp(expect));
      report(`A: vhost ${host} -> ${expect}`);
    } catch (e) { report(`A: vhost ${host}`, e); }
  }

  // denied target
  try {
    await assert.rejects(
      () => client.openStream({ host: 'nope.example', port: 80 }),
      (e) => /no route|denied/i.test(e.message),
    );
    report('A: unrouted target denied');
  } catch (e) { report('A: deny', e); }

  // whitelist rejection: rust mallory key from node
  try {
    const mallory = loadIdentity({ key: `${KEYDIR}/mallory.key.pem`, cert: `${KEYDIR}/mallory.crt.pem` });
    await assert.rejects(
      () => EctunClient.connect({ endpoint: '127.0.0.1:28443', identity: mallory, serverFingerprint: serverFp }),
      (e) => /handshake|certificate|socket|ECONNRESET|closed/i.test(e.message),
    );
    report('A: non-whitelisted key rejected');
  } catch (e) { report('A: whitelist reject', e); }

  // 2. Rust client -> Rust server (fresh server instance for a clean field)
  tmpJson(`${KEYDIR}/rs-pair-server.json`, {
    listen: '127.0.0.1:28453',
    identity: { key: `${KEYDIR}/server.key.pem`, cert: `${KEYDIR}/server.crt.pem` },
    auth: { mode: 'whitelist', fingerprints: [aliceFp] },
    routes: [
      { host: ['a.test'], upstream: ['127.0.0.1', originA.port] },
      { host: ['*.test'], upstream: ['127.0.0.1', originB.port] },
    ],
  });
  const pairServer = spawn(RS, ['server', '--config', `${KEYDIR}/rs-pair-server.json`], { stdio: ['ignore', 'ignore', 'inherit'] });
  await sleep(1200);
  tmpJson(`${KEYDIR}/rs-pair-client.json`, {
    endpoint: '127.0.0.1:28453',
    identity: { key: `${KEYDIR}/alice.key.pem`, cert: `${KEYDIR}/alice.crt.pem` },
    serverFingerprint: serverFp,
    socks5: '127.0.0.1:12811',
    compression: 'none',
  });
  const pairClient = spawn(RS, ['client', '--config', `${KEYDIR}/rs-pair-client.json`], { stdio: ['ignore', 'ignore', 'inherit'] });
  await sleep(1500);
  try {
    const out = await socks5Get('127.0.0.1:12811', 'a.test', 80);
    assert.match(out, /origin-a/);
    report('A: rust client socks5 -> rust server vhost (curl)');
  } catch (e) { report('A: rust<->rust socks5', e); }
  pairClient.kill();
  await sleep(300);
  pairServer.kill();
  await sleep(300);

  client.close();
  rsServer.kill();
  echo.srv.close(); originA.srv.close(); originB.srv.close();
}

// ================= Phase B: Node server + Rust client =================
{
  const serverId = generateIdentity({ cn: 'interop-node-server' });
  const bobFp = await keygen(['--out', `${KEYDIR}`, '--role', 'client', '--name', 'bob']);

  const echo = await startEcho();
  const server = createProxyServer({
    listen: '127.0.0.1:28444',
    identity: serverId,
    auth: { mode: 'whitelist', fingerprints: [bobFp] },
    routes: [{ host: '*', upstream: { host: '127.0.0.1', port: echo.port } }],
    log: { info() {}, warn() {}, error() {}, debug() {} },
  });
  await server.start();

  for (const comp of ['none', 'deflate', 'brotli']) {
    tmpJson(`${KEYDIR}/rs-client-b.json`, {
      endpoint: '127.0.0.1:28444',
      identity: { key: `${KEYDIR}/bob.key.pem`, cert: `${KEYDIR}/bob.crt.pem` },
      serverFingerprint: serverId.fingerprint,
      socks5: '127.0.0.1:12809',
      compression: comp,
    });
    const rsClient = spawn(RS, ['client', '--config', `${KEYDIR}/rs-client-b.json`], { stdio: ['ignore', 'ignore', 'inherit'] });
    await sleep(1000);
    try {
      const payload = Buffer.concat([
        crypto.randomBytes(768 * 1024),
        Buffer.from('interop payload '.repeat(48 * 1024)),
      ]);
      const out = await socks5Echo('127.0.0.1:12809', 'echo.x', 9, payload);
      assert.ok(out.equals(payload), 'byte integrity');
      report(`B: rust client (${comp}) -> node server, 1MB echo via socks5`);
    } catch (e) { report(`B: ${comp}`, e); }
    rsClient.kill();
    await sleep(300);
  }
  await server.stop();
  echo.srv.close();
}

console.log(`\ninterop: ${PASS.length} passed, ${FAIL.length} failed`);
try { global.gc?.(); } catch {}
process.exit(FAIL.length ? 1 : 0);

// ---------- SOCKS5 helpers ----------
async function socks5Get(proxy, host, port) {
  const [phost, pport] = proxy.split(':');
  const sock = net.connect({ host: phost, port: Number(pport) });
  await once(sock, 'connect');
  sock.write(Buffer.from([5, 1, 0]));
  await readN(sock, 2);
  const h = Buffer.from(host);
  sock.write(Buffer.from([5, 1, 0, 3, h.length, ...h, port >> 8, port & 0xff]));
  const rep = await readN(sock, 10);
  if (rep[1] !== 0) throw new Error('socks5 reply ' + rep[1]);
  sock.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
  // read like a browser/curl would: grab the response, then close ourselves
  const parts = [];
  for await (const c of sock) {
    parts.push(c);
    const body = Buffer.concat(parts).toString();
    if (body.includes('\r\n\r\n') && body.length > 30) break;
  }
  sock.destroy();
  return Buffer.concat(parts).toString();
}

async function socks5Echo(proxy, host, port, payload) {
  const [phost, pport] = proxy.split(':');
  const sock = net.connect({ host: phost, port: Number(pport) });
  await once(sock, 'connect');
  sock.write(Buffer.from([5, 1, 0]));
  await readN(sock, 2);
  const h = Buffer.from(host);
  sock.write(Buffer.from([5, 1, 0, 3, h.length, ...h, port >> 8, port & 0xff]));
  const rep = await readN(sock, 10);
  if (rep[1] !== 0) throw new Error('socks5 reply ' + rep[1]);
  sock.write(payload);
  const parts = [];
  let got = 0;
  for await (const c of sock) { parts.push(c); got += c.length; if (got >= payload.length) break; }
  sock.destroy();
  return Buffer.concat(parts);
}

function once(ev, name) { return new Promise((r) => ev.once(name, r)); }
async function readN(sock, n) {
  let acc = Buffer.alloc(0);
  while (acc.length < n) {
    const c = await once(sock, 'data');
    acc = Buffer.concat([acc, c]);
  }
  return acc.subarray(0, n);
}
