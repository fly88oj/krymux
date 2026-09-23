// Minimal unit check: a user 'data' handler that throws SYNCHRONOUSLY must
// tear down only its own stream, never escalate to a whole-session GOAWAY.
//
// Uses an in-process duplexPair (no TLS, no Rust binary): a client and a
// server MuxSession wired directly together. Stream #1 gets a throwing
// flowing-mode 'data' handler — Node emits such handlers synchronously out of
// push() (flowing && empty buffer && !sync), which is exactly the path that
// used to propagate the throw up through the frame parser into the socket
// 'data' handler and kill the session. Assertions:
//   1. stream #1 is torn down (destroyed with its error contained),
//   2. the session survives (no 'close'),
//   3. another stream opened afterwards echoes byte-exact.
//
//   npx tsx scripts/test-stream-isolation.ts

import { duplexPair } from 'node:stream';
import { Buffer } from 'node:buffer';
import * as assert from 'node:assert/strict';
import { MuxSession } from '../src/mux.js';
import type { TunnelStream } from '../src/stream.js';

setTimeout(() => {
  console.error('stream-isolation: GLOBAL TIMEOUT');
  process.exit(2);
}, 30_000).unref();

const [clientSock, serverSock] = duplexPair();

let sessionClosed = false;
const client = new MuxSession(clientSock, { isClient: true, name: 'iso-client' });
client.on('close', () => { sessionClosed = true; });
client.on('error', () => { /* surfaced via assertions below */ });

const server = new MuxSession(serverSock, { isClient: false, name: 'iso-server' });
server.on('error', () => {});
server.on('stream', (s: TunnelStream) => {
  s.accept({ upstream: 'iso' });
  s.on('error', () => {});
  s.pipe(s); // echo
});

await client.ready();
await server.ready();

// 1. a throwing flowing-mode 'data' handler tears down only its stream.
// Waiters are attached BEFORE the write that triggers delivery: the teardown
// (destroy -> 'error' + 'close') fires on the nextTick immediately after the
// synchronous throw, earlier than any promise continuation could attach.
// (A manual close-only promise, not events.once(): once() also listens for
// 'error' and would reject with the very error we want contained.)
const bad = await client.openStream({ host: 'iso', port: 9, compression: 'none' });
const badClosed = new Promise<void>((r) => bad.once('close', r));
const sawThrow = new Promise<Error>((resolve) => {
  bad.on('data', () => {
    const e = new Error('user handler boom');
    resolve(e);
    throw e;
  });
});
// swallow the surfaced stream error so the process does not die on an
// unhandled 'error' event — the point is containment, not suppression
bad.on('error', () => {});
bad.write(Buffer.from('trigger'));

await sawThrow;
await badClosed;
assert.ok(bad.destroyed, 'bad stream must be destroyed');
assert.ok(!sessionClosed, 'session must NOT close because one data handler threw');

// 2. the session still carries traffic: a fresh stream echoes byte-exact
const good = await client.openStream({ host: 'iso', port: 9, compression: 'none' });
good.on('error', (e: Error) => { throw e; });
const payload = Buffer.from('still-alive-after-neighbor-teardown');
const echoed = (async () => {
  const parts: Buffer[] = [];
  for await (const c of good) parts.push(c as Buffer);
  return Buffer.concat(parts);
})();
good.write(payload);
good.end();
const out = await echoed;
assert.ok(out.equals(payload), `echo not byte-exact: ${out.toString()}`);
assert.ok(!sessionClosed, 'session must stay open after the teardown');

client.close('done');
server.close('done');
clientSock.destroy();
serverSock.destroy();

console.log('ok   throwing data handler tears down only its stream (neighbor echo intact, session alive)');
console.log('\nstream-isolation: 1 passed, 0 failed');
process.exit(0);
