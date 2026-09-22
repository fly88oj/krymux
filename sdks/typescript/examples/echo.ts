// Minimal end-to-end example: a local TCP echo origin behind a Krymux tunnel
// server, driven by a Krymux client — both from this SDK, in one process.
//
//   npx tsx examples/echo.ts

import * as net from 'node:net';
import { Buffer } from 'node:buffer';
import {
  EctunClient, createProxyServer, generateIdentity, PROTOCOL_VERSION,
} from '../src/index.js';

const text = (buf: Buffer) => buf.toString('utf8');

// 1. plain TCP echo origin
const echoServer = net.createServer((sock) => sock.pipe(sock));
await new Promise<void>((r) => echoServer.listen(0, '127.0.0.1', r));
const echoPort = (echoServer.address() as net.AddressInfo).port;
console.log(`echo origin listening on 127.0.0.1:${echoPort}`);

// 2. tunnel server: whitelist exactly our client key, route everything to echo
const serverIdentity = generateIdentity({ cn: 'example-server' });
const clientIdentity = generateIdentity({ cn: 'example-client' });
const server = createProxyServer({
  listen: '127.0.0.1:0',
  identity: serverIdentity,
  auth: { mode: 'whitelist', fingerprints: [clientIdentity.fingerprint] },
  routes: [{ host: '*', upstream: { host: '127.0.0.1', port: echoPort } }],
});
await server.start();
const tunnelPort = (server.address() as net.AddressInfo).port;
console.log(`tunnel server on 127.0.0.1:${tunnelPort} (server key ${serverIdentity.fingerprint.slice(7, 19)}...)`);

// 3. client: pin the server key, open a stream, echo a message
const client = await EctunClient.connect({
  endpoint: `127.0.0.1:${tunnelPort}`,
  identity: clientIdentity,
  serverFingerprint: serverIdentity.fingerprint,
});
const rtt = await client.ping();
console.log(`tunnel up (rtt ${rtt}ms, protocol v${PROTOCOL_VERSION})`);

const stream = await client.openStream({ host: 'echo.example', port: 80, compression: 'deflate' });
stream.end(Buffer.from('hello over krymux\n'));
const chunks: Buffer[] = [];
for await (const c of stream) chunks.push(c as Buffer);
console.log(`echoed: ${text(Buffer.concat(chunks)).trim()}`);

client.close('done');
await server.stop();
echoServer.close();
console.log('clean shutdown');
