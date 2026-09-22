// Cross-language interop runner for the Krymux matrix (../../scripts/xlang-matrix.sh).
//
// The TS SDK's example (examples/echo.ts) runs both ends in one process, so the
// matrix driver needs standalone processes. This tool provides the three
// subcommands the matrix exercises, with the same CLI shape as the Go and
// Python example binaries:
//
//   keygen  --dir <d>
//        Generate "server" and "client" identities into <dir> as
//        <name>.key.pem / <name>.crt.pem / <name>.identity.json (the shared
//        layout all four SDKs write). The PEMs must be loadable by the Go and
//        Python loaders (PKCS#8 key + certificate) — that cross-loading is
//        itself part of the matrix.
//
//   server  --key <p> --cert <p> --allow <fp> --port <n>
//        TLS tunnel server that whitelists <fp>, routes every stream to an
//        internal TCP echo origin, and stays up until killed.
//
//   client  --key <p> --cert <p> --fp <server-fp> --addr host:port
//           [--size bytes] [--compression none|deflate]
//        Connect, pin the server fingerprint, open one stream, echo a mixed
//        random+compressible payload, verify byte-exactness, exit 0/1.
//
//   npx tsx scripts/xlang-tools.ts <subcommand> ...

import * as net from 'node:net';
import * as crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import {
  EctunClient, createProxyServer, generateIdentity, loadIdentity, saveIdentity,
} from '../src/index.js';
import type { TunnelStream } from '../src/index.js';

function arg(name: string, def?: string): string {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1) {
    if (def === undefined) throw new Error(`missing --${name}`);
    return def;
  }
  const v = process.argv[i + 1];
  if (v === undefined || v.startsWith('--')) throw new Error(`--${name} needs a value`);
  return v;
}

function has(name: string): boolean {
  return process.argv.includes(`--${name}`);
}

/** Exactly `size` bytes: half random (incompressible), half repeating. */
function payloadMixed(size: number): Buffer {
  const half = Math.floor(size / 2);
  const pattern = Buffer.from('krymux-ts-xlang-payload ');
  const reps = Math.ceil(half / pattern.length);
  const compressible = Buffer.concat(Array(reps).fill(pattern)).subarray(0, half);
  return Buffer.concat([crypto.randomBytes(half), compressible]);
}

async function cmdKeygen(): Promise<void> {
  const dir = arg('dir');
  const server = generateIdentity({ cn: 'krymux-xlang-server' });
  const client = generateIdentity({ cn: 'krymux-xlang-client' });
  saveIdentity(dir, server, { name: 'server' });
  saveIdentity(dir, client, { name: 'client' });
  console.log(`server fingerprint: ${server.fingerprint}`);
  console.log(`client fingerprint: ${client.fingerprint}`);
}

async function cmdServer(): Promise<void> {
  const key = arg('key');
  const cert = arg('cert');
  const allow = arg('allow');
  const port = Number(arg('port'));

  // plain TCP echo origin with half-close propagation
  const echoServer = net.createServer((sock) => sock.pipe(sock));
  await new Promise<void>((r) => echoServer.listen(0, '127.0.0.1', r));
  const echoPort = (echoServer.address() as net.AddressInfo).port;

  const identity = loadIdentity({ key, cert });
  const server = createProxyServer({
    listen: `127.0.0.1:${port}`,
    identity,
    auth: { mode: 'whitelist', fingerprints: [allow] },
    routes: [{ host: '*', upstream: { host: '127.0.0.1', port: echoPort } }],
  });
  await server.start();
  console.log(`server fingerprint (pin this in clients): ${identity.fingerprint}`);
  console.log(`listening on 127.0.0.1:${port}`);
  // the TLS listener keeps the event loop alive
}

async function cmdClient(): Promise<void> {
  const key = arg('key');
  const cert = arg('cert');
  const fp = arg('fp');
  const addr = arg('addr');
  const size = Number(arg('size', '1048576'));
  const compression = arg('compression', 'auto');

  const identity = loadIdentity({ key, cert });
  const client = await EctunClient.connect({
    endpoint: addr,
    identity,
    serverFingerprint: fp,
  });
  console.log(`tunnel up to ${addr} (server ${client.fingerprint?.slice(0, 19)}...)`);

  const payload = payloadMixed(size);
  const t0 = Date.now();
  const stream: TunnelStream = await client.openStream({ host: 'echo', port: 9, compression });
  console.log(`stream open (compression=${stream.compression})`);

  stream.end(payload); // write + FIN (half-close) in one step
  const parts: Buffer[] = [];
  for await (const c of stream) parts.push(c as Buffer);
  const got = Buffer.concat(parts);
  const dt = (Date.now() - t0) / 1000;

  client.close('done');
  if (got.length !== payload.length || !got.equals(payload)) {
    console.log(`sent ${payload.length} bytes, received ${got.length} bytes in ${dt.toFixed(3)}s`);
    console.log('RESULT: MISMATCH');
    process.exit(1);
  }
  console.log(`sent ${payload.length} bytes, received ${got.length} bytes in ${dt.toFixed(3)}s`);
  console.log('RESULT: OK (byte-exact echo)');
  process.exit(0);
}

async function main(): Promise<void> {
  const sub = process.argv[2] ?? '';
  switch (sub) {
    case 'keygen': return cmdKeygen();
    case 'server': return cmdServer();
    case 'client': return cmdClient();
    default:
      console.error('usage: xlang-tools.ts keygen|server|client [options]');
      process.exit(has('help') ? 0 : 2);
  }
}

main().catch((err: Error) => {
  console.error(`xlang-tools: ${err?.stack ?? err}`);
  process.exit(1);
});
