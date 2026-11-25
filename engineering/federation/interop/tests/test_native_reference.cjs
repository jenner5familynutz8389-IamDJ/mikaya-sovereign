'use strict';
// Executed synthetic cross-language conformance. No ACT code/device, no sockets,
// no production identity, admission, wallet, payment, or firmware operation.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {spawn} = require('node:child_process');

const python = process.env.MIKAYA_REFERENCE_PYTHON || 'python3';
const reference = path.resolve(__dirname, '../native-reference.py');
const nodeFixture = path.resolve(__dirname, '../fixtures/node-contract-peer.cjs');
const vectors = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../fixtures/canonical-vectors.json'), 'utf8'));

class Peer {
 constructor(command, args, env = {}) {
  this.child = spawn(command, args, {stdio: ['pipe', 'pipe', 'pipe'], env: {...process.env, ...env}});
  this.pending = []; this.serial = 0; this.stderr = '';
  this.input = Buffer.alloc(0);
  this.child.stderr.on('data', part => { this.stderr = (this.stderr + part).slice(-2000); });
  const receive = line => {
   const pending = this.pending.shift();
   if (!pending) return;
   clearTimeout(pending.timer);
   try {
    const reply = JSON.parse(line.toString('utf8'));
    if (reply.id !== null && reply.id !== pending.id) throw Error('reference reply ID mismatch');
    if (reply.ok !== true) throw Error(reply.error || 'reference refused');
    pending.resolve(reply.result);
   } catch (error) { pending.reject(error); }
  };
  this.child.stdout.on('data', part => {
   this.input = Buffer.concat([this.input, part]);
   let lf;
   while ((lf = this.input.indexOf(10)) !== -1) {
    receive(this.input.subarray(0, lf));
    this.input = this.input.subarray(lf + 1);
   }
  });
  const fail = error => {
   for (const pending of this.pending.splice(0)) { clearTimeout(pending.timer); pending.reject(error); }
  };
  this.child.once('error', error => fail(Error('reference process unavailable: ' + error.code)));
  this.child.once('exit', code => fail(Error('reference exited ' + code + (this.stderr ? ': ' + this.stderr : ''))));
 }
 send(line, id) {
  return new Promise((resolve, reject) => {
   const timer = setTimeout(() => { this.child.kill('SIGTERM'); reject(Error('reference operation exceeded 15s bound')); }, 15000);
   this.pending.push({id, resolve, reject, timer});
   this.child.stdin.write(line + '\n');
  });
 }
 call(op, args = {}) {
  const id = ++this.serial;
  return this.send(JSON.stringify({...args, id, op}), id);
 }
 rawValue(raw) {
  const id = ++this.serial;
  return this.send('{"id":' + id + ',"op":"canonical","value":' + raw + '}', id);
 }
 async close() {
  if (this.child.exitCode !== null || this.child.signalCode !== null) return;
  await new Promise(resolve => {
   const timer = setTimeout(() => { this.child.kill('SIGTERM'); resolve(); }, 1000);
   this.child.once('exit', () => { clearTimeout(timer); resolve(); });
   this.child.stdin.end();
  });
 }
}

function processes(t, backend = 'auto') {
 const node = new Peer(process.execPath, [nodeFixture]);
 const py = new Peer(python, ['-u', reference], {MIKAYA_REFERENCE_CRYPTO: backend});
 t.after(async () => { await Promise.all([node.close(), py.close()]); });
 return {node, py};
}

async function paired(t, backend = 'auto') {
 const peers = processes(t, backend);
 const [N, P] = await Promise.all([peers.node.call('init'), peers.py.call('init')]);
 assert.notEqual(N.pid, P.pid);
 assert.notEqual(N.pid, process.pid);
 assert.notEqual(P.pid, process.pid);
 assert.notEqual(N.fingerprint, P.fingerprint);
 assert.equal(P.privateKeyExported, false);
 assert.equal(N.privateKeyExported, false);
 assert.equal(P.referenceOnly, true);
 await Promise.all([
  peers.node.call('pin', {publicPem: P.publicPem, expectedFingerprint: P.fingerprint}),
  peers.py.call('pin', {publicPem: N.publicPem, expectedFingerprint: N.fingerprint})
 ]);
 return {...peers, N, P};
}

const nonce = () => crypto.randomBytes(16).toString('hex');
const dot = (a = [2, -3, 4], b = [5, 6, 7]) => ({schema: 'mikaya.federation.job.v1', id: nonce(), capability: 'compute.dot.v1', payload: {a, b}});
const hashJob = () => ({schema: 'mikaya.federation.job.v1', id: nonce(), capability: 'compute.sha256.v1', payload: {challengeHex: '0123456789abcdef'.repeat(4)}});

async function exchange(sender, recipient, senderInfo, recipientInfo, job, nowMs = Date.now()) {
 const requestAuth = await sender.call('sign-request', {to: recipientInfo.fingerprint,
  method: 'POST', route: '/v1/task', body: job, nonce: nonce(), issuedAtMs: nowMs});
 const response = await recipient.call('respond', {method: 'POST', route: '/v1/task', auth: requestAuth, body: job, nowMs});
 assert.equal(await sender.call('verify-response', {auth: response.auth, body: response.body,
  expectedPeer: recipientInfo.fingerprint, nonce: requestAuth.nonce, nowMs}), true);
 assert.equal(await sender.call('verify-receipt', {body: response.body, job, expectedWorker: recipientInfo.fingerprint}), true);
 assert.equal(response.auth.to, senderInfo.fingerprint);
 return {route: '/v1/task', requestAuth, requestBody: job, responseAuth: response.auth, body: response.body};
}

function proof(peers, exchanges) {
 return {schema: 'mikaya.federation.public-evidence.v1', mode: 'LOCAL_TWO_PROCESSES_ONE_DEVICE',
  createdAtMs: Date.now(), publicKeys: {[peers.N.fingerprint]: peers.N.publicPem, [peers.P.fingerprint]: peers.P.publicPem}, exchanges};
}

test('stdlib reference and Node agree on golden UTF-16, surrogate, integer and malformed JSON vectors', async t => {
 const {node, py} = processes(t);
 for (const vector of vectors) {
  if (vector.reject) {
   await assert.rejects(py.rawValue(vector.json), undefined, vector.name + ' Python');
   await assert.rejects(node.rawValue(vector.json), undefined, vector.name + ' Node');
  } else {
   const [actual, expected] = await Promise.all([py.rawValue(vector.json), node.rawValue(vector.json)]);
   assert.equal(actual.canonical, vector.canonical, vector.name);
   assert.deepEqual(actual, expected, vector.name);
  }
 }
});

test('canonical bytes match controls, nested data, edge Unicode keys and binary64 JSON semantics', async t => {
 const {node, py} = processes(t);
 const controls = Array.from({length: 32}, (_, i) => String.fromCharCode(i)).join('');
 const keys = ['', '\u0000', 'a', '\ud7ff', '\ud800', '\ud800\udc00', '\udbff\udfff', '\udc00', '\ue000', '\uffff', '😀', 'é', 'é'];
 const value = Object.fromEntries(keys.map((key, i) => [key, {n: i, text: controls + ' / " \\ \u2028\u2029 😀', flags: [true, false, null]}]));
 const [left, right] = await Promise.all([py.call('canonical', {value}), node.call('canonical', {value})]);
 assert.deepEqual(left, right);
 // JSON.parse converts these textual numbers to binary64 first. Matching it
 // does not mean the protocol accepts fractional Number values.
 for (const raw of ['-0.0', '1e-400', '1.000000000000000000001', '9007199254740991.1']) {
  assert.deepEqual(await py.rawValue(raw), await node.rawValue(raw), raw);
 }
 await assert.rejects(py.rawValue('"literal\nnewline"'));
 await assert.rejects(node.rawValue('"literal\nnewline"'));
});

test('fingerprint hashes exact normalized SPKI PEM bytes, including final LF, rather than DER or input formatting', async t => {
 const {node, py, N, P} = await paired(t);
 for (const metadata of [N, P]) {
  const variants = [metadata.publicPem, metadata.publicPem.replaceAll('\n', '\r\n'), metadata.publicPem.trimEnd()];
  for (const publicPem of variants) {
   const actual = await py.call('fingerprint', {publicPem});
   assert.equal(actual.publicPem, metadata.publicPem);
   assert.equal(actual.fingerprint, metadata.fingerprint);
   assert.deepEqual(actual, await node.call('fingerprint', {publicPem}));
  }
  const der = crypto.createPublicKey(metadata.publicPem).export({type: 'spki', format: 'der'});
  assert.notEqual(crypto.createHash('sha256').update(der).digest('hex'), metadata.fingerprint);
  assert.equal(crypto.createHash('sha256').update(metadata.publicPem).digest('hex'), metadata.fingerprint);
 }
 await assert.rejects(py.call('fingerprint', {publicPem: 'not a public key'}), /PEM/);
 await assert.rejects(py.call('pin', {publicPem: N.publicPem, expectedFingerprint: '0'.repeat(64)}), /fingerprint/);
});

test('different Node and Python processes exchange signed bounded work in BOTH directions and production verifies combined evidence', async t => {
 const peers = await paired(t);
 const {node, py, N, P} = peers;
 const outward = await exchange(node, py, N, P, dot());
 const inward = await exchange(py, node, P, N, hashJob());
 assert.equal(outward.body.result, 20);
 const checked = await node.call('verify-evidence', {proof: proof(peers, [outward, inward])});
 assert.equal(checked.valid, true);
 assert.equal(checked.jobs, 2);
 assert.equal(checked.participants, 2);
 assert.equal(await node.call('journal-valid'), true);
 await exchange(node, py, N, P, hashJob());
 await exchange(py, node, P, N, dot([1000, -1000], [-1000, 1000]));
 // The evidence is a synthetic local language test, never ACT or hardware proof.
 assert.equal(JSON.stringify(proof(peers, [outward, inward])).includes('PRIVATE KEY'), false);
});

test('both verifiers reject recipient, method, route, body, shape, age and signature tampering before consuming a valid nonce', async t => {
 const {node, py, N, P} = await paired(t);
 for (const [sender, receiver, recipient] of [[node, py, P], [py, node, N]]) {
  const body = dot(), nowMs = Date.now();
  const auth = await sender.call('sign-request', {to: recipient.fingerprint, method: 'POST', route: '/v1/task', body, nonce: nonce(), issuedAtMs: nowMs});
  const valid = {auth, method: 'POST', route: '/v1/task', body, nowMs};
  const invalid = [
   {...valid, method: 'GET'}, {...valid, route: '/v1/hello'},
   {...valid, body: {...body, payload: {a: [99], b: [1]}}},
   {...valid, auth: {...auth, to: '0'.repeat(64)}},
   {...valid, auth: {...auth, extra: 'not allowed'}},
   {...valid, auth: {...auth, from: 'f'.repeat(64)}},
   {...valid, nowMs: nowMs + 60001}, {...valid, nowMs: nowMs - 60001},
   {...valid, auth: {...auth, signature: auth.signature.slice(0, -1)}},
   {...valid, auth: {...auth, signature: auth.signature + '='}},
   {...valid, auth: {...auth, signature: true}},
   {...valid, auth: {...auth, signature: (auth.signature[0] === 'A' ? 'B' : 'A') + auth.signature.slice(1)}}
  ];
  for (const bad of invalid) await assert.rejects(receiver.call('verify-request', bad));
  await receiver.call('verify-request', valid);
  await assert.rejects(receiver.call('verify-request', valid), /replay/);
 }
});

test('request signatures bind the exact REQ domain and safe canonical Unicode bytes', async t => {
 const {node, py, N, P} = await paired(t);
 const body = {'\ue000': ['\ud800', '😀'], '𐀀': -0, text: 'é versus é\u2028'};
 const nowMs = Date.now();
 const auth = await node.call('sign-request', {to: P.fingerprint, method: 'POST', route: '/v1/hello', body, nonce: nonce(), issuedAtMs: nowMs});
 const {signature, ...envelope} = auth;
 for (const domain of ['RES', 'WRONG']) {
  const wrong = await node.call('sign-domain-fixture', {domain, envelope});
  await assert.rejects(py.call('verify-request', {method: 'POST', route: '/v1/hello', body, auth: {...auth, signature: wrong}, nowMs}), /signature/);
 }
 assert.ok(signature);
 await py.call('verify-request', {method: 'POST', route: '/v1/hello', body, auth, nowMs});
 const args = {to: N.fingerprint, method: 'POST', route: '/v1/hello', body, nonce: nonce(), issuedAtMs: nowMs};
 const first = await py.call('sign-request', args), second = await py.call('sign-request', args);
 assert.equal(first.signature, second.signature, 'Ed25519 deterministic signing of identical bytes');
 await node.call('verify-request', {method: 'POST', route: '/v1/hello', body, auth: first, nowMs});
});

test('both response verifiers bind nonce, signer, target, body digest, time and signature', async t => {
 const {node, py, N, P} = await paired(t);
 for (const [sender, worker, senderInfo, workerInfo] of [[node, py, N, P], [py, node, P, N]]) {
  const ex = await exchange(sender, worker, senderInfo, workerInfo, dot());
  const valid = {auth: ex.responseAuth, body: ex.body, expectedPeer: workerInfo.fingerprint,
   nonce: ex.requestAuth.nonce, nowMs: ex.responseAuth.issuedAtMs};
  for (const bad of [
   {...valid, nonce: nonce()}, {...valid, expectedPeer: '0'.repeat(64)},
   {...valid, body: {...ex.body, result: 21}},
   {...valid, auth: {...ex.responseAuth, to: 'f'.repeat(64)}},
   {...valid, auth: {...ex.responseAuth, signature: ex.responseAuth.signature.slice(1)}},
   {...valid, auth: {...ex.responseAuth, unexpected: true}},
   {...valid, nowMs: valid.nowMs + 60001}
  ]) await assert.rejects(sender.call('verify-response', bad));
  assert.equal(await sender.call('verify-response', valid), true);
 }
});

test('a correctly signed wrong computation still fails independently recomputed production evidence', async t => {
 const peers = await paired(t), {node, py, N, P} = peers;
 const out = await exchange(node, py, N, P, dot());
 const back = await exchange(py, node, P, N, hashJob());
 const wrongBody = {...out.body, result: out.body.result + 1};
 const wrongAuth = await py.call('sign-response', {to: N.fingerprint, inReplyTo: out.requestAuth.nonce,
  body: wrongBody, issuedAtMs: out.responseAuth.issuedAtMs});
 assert.equal(await node.call('verify-response', {auth: wrongAuth, body: wrongBody,
  expectedPeer: P.fingerprint, nonce: out.requestAuth.nonce, nowMs: wrongAuth.issuedAtMs}), true);
 await assert.rejects(node.call('verify-evidence', {proof: proof(peers, [{...out, body: wrongBody, responseAuth: wrongAuth}, back])}), /computation result/);
 for (const bad of [{...back.body, requestSha256: '0'.repeat(64)}, {...back.body, jobId: nonce()}, {...back.body, extra: true}]) {
  await assert.rejects(py.call('verify-receipt', {body: bad, job: back.requestBody, expectedWorker: N.fingerprint}), /receipt/);
 }
 const one = dot([1], [1]);
 const receipt = await py.call('receipt', {job: one});
 await assert.rejects(py.call('verify-receipt', {body: {...receipt, result: true}, job: one, expectedWorker: P.fingerprint}), /receipt/);
});

test('bounded compute rejects unknown capabilities, booleans, fractions, oversized vectors and malformed schemas in both implementations', async t => {
 const {node, py} = processes(t);
 const base = dot();
 const invalid = [dot([], []), dot(Array(17).fill(1), Array(17).fill(2)), dot([1001], [1]), dot([1], [2, 3]),
  dot([true], [1]), dot([1.1], [1]), dot(['1'], [1]), {...base, capability: 'shell.exec'},
  {...base, payload: {...base.payload, extra: true}}, {...base, extra: true},
  {...base, id: 'A'.repeat(32)}, {...hashJob(), payload: {challengeHex: 'ABCDEF01'.repeat(8)}}];
 for (const job of invalid) {
  await assert.rejects(node.call('compute', {job}));
  await assert.rejects(py.call('compute', {job}));
 }
 assert.equal(await py.call('compute', {job: dot(Array(16).fill(1000), Array(16).fill(1000))}), 16000000);
});

test('one-use jobs and revoked pins fail closed in each process without claiming durable Python replay state', async t => {
 const {node, py, N, P} = await paired(t);
 for (const [sender, receiver, senderInfo, recipientInfo] of [[node, py, N, P], [py, node, P, N]]) {
  const job = dot();
  await exchange(sender, receiver, senderInfo, recipientInfo, job);
  const nowMs = Date.now();
  const request = await sender.call('sign-request', {to: recipientInfo.fingerprint, method: 'POST', route: '/v1/task', body: job, nonce: nonce(), issuedAtMs: nowMs});
  await assert.rejects(receiver.call('respond', {method: 'POST', route: '/v1/task', body: job, auth: request, nowMs}), /duplicate job/);
 }
 const job = dot(), nowMs = Date.now();
 const signed = await node.call('sign-request', {to: P.fingerprint, method: 'POST', route: '/v1/task', body: job, nonce: nonce(), issuedAtMs: nowMs});
 const signedBack = await py.call('sign-request', {to: N.fingerprint, method: 'POST', route: '/v1/task', body: job, nonce: nonce(), issuedAtMs: nowMs});
 await py.call('revoke', {fingerprint: N.fingerprint});
 await node.call('revoke', {fingerprint: P.fingerprint});
 await assert.rejects(py.call('verify-request', {method: 'POST', route: '/v1/task', body: job, auth: signed, nowMs}), /revoked/);
 await assert.rejects(node.call('verify-request', {method: 'POST', route: '/v1/task', body: job, auth: signedBack, nowMs}), /revoked/);
 assert.equal((await py.call('describe')).persistentReplayProtection, false);
 await assert.rejects(py.call('init'), /already initialized/);
});

test('installed OpenSSL fallback actually signs and verifies Ed25519 across separate processes, with tamper rejection', async t => {
 // Required execution, not a skip: missing crypto tooling is an explicit failure.
 const peers = await paired(t, 'openssl'), {node, py, N, P} = peers;
 assert.equal(P.cryptoBackend, 'openssl');
 const out = await exchange(node, py, N, P, dot());
 const back = await exchange(py, node, P, N, hashJob());
 assert.equal((await node.call('verify-evidence', {proof: proof(peers, [out, back])})).valid, true);
 const damaged = {...back.responseAuth, signature: 'A'.repeat(86) + '=='};
 await assert.rejects(py.call('verify-response', {auth: damaged, body: back.body,
  expectedPeer: N.fingerprint, nonce: back.requestAuth.nonce, nowMs: back.responseAuth.issuedAtMs}), /signature/);
});
