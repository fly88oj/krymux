// Echo throughput benchmark for the TypeScript Krymux SDK.
//
// Measures the mux + stream data path (writer batching, framing, flow control,
// optional deflate) over a loopback TCP socket pair — both sessions in this
// one process, no TLS (TLS is OpenSSL-internal and identical before/after any
// SDK-level optimization).
//
// Per combination of payload size (1 MiB, 16 MiB) and compression (none,
// deflate): open a stream, push the payload in 64-KiB chunks, half-close, read
// the echo back, verify sha256. 3 runs, median one-way payload MiB/s.
//
//   node node_modules/tsx/dist/cli.mjs bench/echo.ts
//
// Output lines: `RESULT ts <size>MiB <comp> <median MiB/s>`

import * as net from 'node:net';
import { once } from 'node:events';
import { createHash, randomFillSync } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { MuxSession } from '../src/mux.js';
import type { TunnelStream } from '../src/stream.js';

const CHUNK = 64 * 1024;
const RUNS = 3;
const SIZES = [1, 16]; // MiB
const COMPS = ['none', 'deflate'] as const;

/** Same pattern as examples/echo.ts clients: half random, half compressible. */
function makePayload(size: number): Buffer {
  const half = size >> 1;
  const buf = Buffer.allocUnsafe(size);
  randomFillSync(buf, 0, half);
  buf.fill(Buffer.from('compressible-payload '), half, size);
  return buf;
}

function serve(sock: net.Socket): MuxSession {
  const ms = new MuxSession(sock, { isClient: false, name: 'bench-server', keepaliveSec: 0 });
  ms.on('stream', (s: TunnelStream) => {
    s.accept({ upstream: 'echo' });
    s.on('error', () => {});
    s.pipe(s);
  });
  ms.on('error', () => {});
  return ms;
}

async function runOnce(port: number, payload: Buffer, comp: string, expectHash: string): Promise<number> {
  const sock = net.connect({ host: '127.0.0.1', port });
  const ms = new MuxSession(sock, { isClient: true, name: 'bench-client', keepaliveSec: 0 });
  ms.on('error', () => {});
  await ms.ready();
  const t0 = process.hrtime.bigint();
  const stream = await ms.openStream({ host: 'bench', port: 9, compression: comp });
  // Consume the echo concurrently with writing: the receive window is granted
  // as the app drains data (bounded-memory design), so a write-everything-
  // first-then-read pattern would park on credits mid-transfer.
  const echo = (async () => {
    const hash = createHash('sha256');
    for await (const c of stream) hash.update(c as Buffer);
    return hash.digest('hex');
  })();
  for (let off = 0; off < payload.length; off += CHUNK) {
    if (!stream.write(payload.subarray(off, off + CHUNK))) await once(stream, 'drain');
  }
  stream.end();
  const got = await echo;
  const dt = Number(process.hrtime.bigint() - t0) / 1e9;
  if (got !== expectHash) throw new Error(`echo mismatch: ${got} != ${expectHash}`);
  const closed = once(ms, 'close'); // close() emits 'close' synchronously
  ms.close('done');
  await closed;
  sock.destroy();
  return payload.length / 1048576 / dt;
}

async function main(): Promise<void> {
  const listener = net.createServer((sock) => serve(sock));
  await new Promise<void>((r) => listener.listen(0, '127.0.0.1', r));
  const port = (listener.address() as net.AddressInfo).port;

  console.log(`bench ts node/${process.version} chunk=${CHUNK} runs=${RUNS}`);
  for (const sizeMiB of SIZES) {
    const payload = makePayload(sizeMiB * 1048576);
    const expectHash = createHash('sha256').update(payload).digest('hex');
    for (const comp of COMPS) {
      const mbps: number[] = [];
      for (let i = 0; i < RUNS; i++) mbps.push(await runOnce(port, payload, comp, expectHash));
      mbps.sort((a, b) => a - b);
      const median = mbps[Math.floor(mbps.length / 2)]!;
      console.log(`RESULT ts ${sizeMiB}MiB ${comp} ${median.toFixed(1)}  (runs: ${mbps.map((m) => m.toFixed(1)).join(', ')})`);
    }
  }
  listener.close();
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
