'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const direct = require('../direct-transport.cjs');
const session = require('../session-adapter.cjs');
const mac = require('../capability-macaroons.cjs');
const ledgers = require('../ledger-receipts.cjs');

function distribution(a,b) {
  return { schema: 'mikaya.interop.distribution-policy.v1', policyId: 'owner-compute-fixture', unit: ledgers.UNIT, rates: ['compute.dot.v1','compute.sha256.v1'].map(capability => ({ capability, creditUnits: 1000 })), beneficiaries: [a,b].map(peer => ({ fingerprint: peer.fingerprint, basisPoints: 5000 })) };
}

async function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mikaya-direct-'));
  fs.chmodSync(root, 0o700);
  const a = path.join(root, 'a'), b = path.join(root, 'b');
  const A = direct.initialize(a), B = direct.initialize(b);
  const policy = distribution(A,B);
  direct.pinPeer(a, B, policy); direct.pinPeer(b, A, policy);
  const servers = [], clients = [];
  t.after(async () => {
    for (const client of clients) client.close();
    await Promise.all(servers.map(server => new Promise(resolve => { if (!server.server.listening) return resolve(); server.server.once('close', resolve); server.close(); })));
    fs.rmSync(root, { recursive: true, force: true });
  });
  async function listen(stateDir = b) { const server = await direct.startServer({ stateDir, host: '127.0.0.1', port: 0 }); servers.push(server); return server; }
  async function client(server, stateDir = a) { const result = await direct.connect({ stateDir, host: '127.0.0.1', port: server.address.port, timeoutMs: 2000 }); clients.push(result); return result; }
  return { root, a, b, A, B, servers, clients, listen, client };
}
function rawFrame(s) { const raw = Buffer.from(s), header = Buffer.alloc(4); header.writeUInt32BE(raw.length); return Buffer.concat([header, raw]); }
function changePolicy(stateDir, change) {
  const file = path.join(stateDir, 'direct-transport', 'owner-policy.json');
  fs.writeFileSync(file, JSON.stringify({ ...JSON.parse(fs.readFileSync(file)), ...change }), { mode: 0o600 });
}
function awaitClose(socket) { return new Promise(resolve => { if (socket.destroyed) return resolve(); socket.once('close', resolve); }); }
function request(stateDir, peer, capability = 'compute.dot.v1') { return session.makeRequest({ holderPrivateKey: direct.loadOwn(stateDir).privateKey, workerPublicKey: peer.publicKey, job: direct.makeJob(capability) }); }

test('actual mutual TLS exchanges preserve contract, exporter binding, persistent session, and replay refusal', async t => {
  const f = await fixture(t), server = await f.listen();
  assert.equal(JSON.parse(fs.readFileSync(path.join(f.b,'direct-transport','server.lock'))).phase, 'READY');
  const result = await direct.exercise({ stateDir: f.a, host: '127.0.0.1', port: server.address.port });
  assert.equal(result.allVerified, true);
  assert.equal(result.exchanges.length, 2);
  assert.equal(result.exchanges[0].response.body.result, 32);
  assert.equal(result.exchanges[1].response.body.result, crypto.createHash('sha256').update(Buffer.alloc(32, 0xa5)).digest('hex'));
  for (const exchange of result.exchanges) {
    assert.equal(exchange.negotiatedProtocol, 'TLSv1.3');
    assert.equal(exchange.verified.evidenceVerified, true);
    assert.equal(exchange.replayRefused, true);
    assert.equal(exchange.transportEvidence.workerCertificateSha256, f.B.tlsCertificateSha256);
    assert.equal(exchange.transportEvidence.holderCertificateSha256, f.A.tlsCertificateSha256);
  }
  assert.equal(result.exchanges[0].transportEvidence.channelBindingSha256, result.exchanges[1].transportEvidence.channelBindingSha256);
  assert.equal(mac.inspectReplayState(path.join(f.b, 'replay')).records, 2);
  assert.equal(direct.readLedger(path.join(f.b, 'direct-transport')).sequence, 7);
  const aLedger = ledgers.verifyReceiptLedger({ ledgerDir: path.join(f.a,'direct-transport','receipt-ledger'), nodePublicKey: f.A.publicKey });
  const bLedger = ledgers.verifyReceiptLedger({ ledgerDir: path.join(f.b,'direct-transport','receipt-ledger'), nodePublicKey: f.B.publicKey });
  assert.equal(aLedger.receipts, 2); assert.equal(bLedger.receipts, 2);
  assert.deepEqual(aLedger.totals, bLedger.totals);
  assert.notEqual(aLedger.ledgerId, bLedger.ledgerId);
  assert.equal(result.exchanges[0].workerLedger.accounting.paymentSettled, false);
  assert.equal(ledgers.verifyReceiptCheckpoint({ checkpoint: result.exchanges[0].workerLedger.checkpoint, nodePublicKey: f.B.publicKey }).verified, true);
});

test('both roles operate over independently authenticated TLS listeners', async t => {
  const f = await fixture(t), sa = await f.listen(f.a), sb = await f.listen(f.b);
  const [ab, ba] = await Promise.all([
    direct.exercise({ stateDir: f.a, host: '127.0.0.1', port: sb.address.port }),
    direct.exercise({ stateDir: f.b, host: '127.0.0.1', port: sa.address.port })
  ]);
  assert.equal(ab.allVerified && ba.allVerified, true);
  assert.equal(ab.exchanges[0].response.auth.from, f.B.fingerprint);
  assert.equal(ba.exchanges[0].response.auth.from, f.A.fingerprint);
  assert.notEqual(ab.exchanges[0].transportEvidence.channelBindingSha256, ba.exchanges[0].transportEvidence.channelBindingSha256);
});

test('unpaired client certificate is refused before a capability can be granted', async t => {
  const f = await fixture(t), c = path.join(f.root, 'c'), C = direct.initialize(c); direct.pinPeer(c, f.B, distribution(C,f.B));
  const server = await f.listen();
  await assert.rejects(direct.exercise({ stateDir: c, host: '127.0.0.1', port: server.address.port, timeoutMs: 2000 }));
  assert.equal(mac.inspectReplayState(path.join(f.b, 'replay')).records, 0);
  assert.equal(direct.readLedger(path.join(f.b, 'direct-transport')).sequence, 1);
});

test('client refuses a server whose certificate is not its pinned certificate', async t => {
  const f = await fixture(t), c = path.join(f.root, 'c'), C = direct.initialize(c); direct.pinPeer(c, f.A, distribution(C,f.A));
  const server = await f.listen(c);
  await assert.rejects(direct.connect({ stateDir: f.a, host: '127.0.0.1', port: server.address.port, timeoutMs: 2000 }));
});

test('owner pairing validates signed app identity and TLS certificate binding', async t => {
  const f = await fixture(t);
  assert.throws(() => direct.validatePeer({ ...f.B, fingerprint: f.A.fingerprint }), /identity mismatch/);
  assert.throws(() => direct.validatePeer({ ...f.B, profileSha256: '0'.repeat(64) }), /signature refused/);
  assert.throws(() => direct.validatePeer({ ...f.B, tlsCertificateSha256: f.A.tlsCertificateSha256 }), /digest mismatch/);
  assert.throws(() => direct.validatePeer({ ...f.B, hardwareAttested: true }), /scope refused/);
  assert.throws(() => direct.validatePeer({ ...f.B, additional: true }), /schema refused/);
  assert.throws(() => direct.validatePeer({ ...f.B, profileSha256: [f.B.profileSha256] }), /fields refused/);
});

test('holder application identity cannot be substituted within an authenticated TLS channel', async t => {
  const f = await fixture(t), server = await f.listen(), client = await f.client(server);
  const wrong = session.makeRequest({ holderPrivateKey: crypto.generateKeyPairSync('ed25519').privateKey, workerPublicKey: f.B.publicKey, job: direct.makeJob('compute.dot.v1') });
  await assert.rejects(client.requestFrame('grant', wrong), /identity binding refused/);
  assert.equal(mac.inspectReplayState(path.join(f.b, 'replay')).records, 0);
});

test('tampered application signatures are refused on an otherwise valid TLS channel', async t => {
  const f = await fixture(t), server = await f.listen(), client = await f.client(server);
  const req = request(f.a, f.B); req.auth.signature = Buffer.alloc(64).toString('base64');
  await assert.rejects(client.requestFrame('grant', req), /signature refused/);
  assert.equal(mac.inspectReplayState(path.join(f.b, 'replay')).records, 0);
});

test('active connection enforces changed operation allowlist before granting work', async t => {
  const f = await fixture(t), server = await f.listen(), client = await f.client(server);
  changePolicy(f.b, { allowedCapabilities: ['compute.sha256.v1'] });
  await assert.rejects(client.perform(direct.makeJob('compute.dot.v1')), /excluded by owner policy/);
  assert.equal(mac.inspectReplayState(path.join(f.b, 'replay')).records, 0);
  assert.equal((await client.perform(direct.makeJob('compute.sha256.v1'))).verified.evidenceVerified, true);
});

test('owner disable immediately rejects active work and closes the listener', async t => {
  const f = await fixture(t), server = await f.listen(), client = await f.client(server);
  direct.setEnabled(f.b, false);
  await assert.rejects(client.perform(direct.makeJob('compute.dot.v1')));
  await new Promise(resolve => server.server.listening ? server.server.once('close', resolve) : resolve());
  assert.equal(server.server.listening, false);
  assert.equal(mac.inspectReplayState(path.join(f.b, 'replay')).records, 0);
  await assert.rejects(direct.startServer({ stateDir: f.b, host: '127.0.0.1', port: 0 }), /policy disabled/);
});

test('kill-switch file terminates an established connection and listener', async t => {
  const f = await fixture(t), server = await f.listen(), client = await f.client(server);
  fs.writeFileSync(path.join(f.b, 'direct-transport', 'kill-switch'), 'owner stop\n', { mode: 0o600, flag: 'wx' });
  await awaitClose(client.socket);
  await new Promise(resolve => server.server.listening ? server.server.once('close', resolve) : resolve());
  assert.equal(server.server.listening, false);
  await assert.rejects(direct.startServer({ stateDir: f.b, host: '127.0.0.1', port: 0 }), /kill switch active/);
});

test('missing or malformed current policy refuses startup and active work', async t => {
  const f = await fixture(t), server = await f.listen(), client = await f.client(server);
  fs.writeFileSync(path.join(f.b, 'direct-transport', 'owner-policy.json'), '{broken');
  await assert.rejects(client.perform(direct.makeJob('compute.dot.v1')));
  await new Promise(resolve => server.server.listening ? server.server.once('close', resolve) : resolve());
  await assert.rejects(direct.startServer({ stateDir: f.b, host: '127.0.0.1', port: 0 }));
});

test('durable replay refuses an old grant and request after listener restart', async t => {
  const f = await fixture(t), first = await f.listen(), client = await f.client(first);
  const req = request(f.a, f.B), grant = await client.requestFrame('grant', req);
  await client.requestFrame('execute', req, grant.token);
  client.close();
  await new Promise(resolve => { first.server.once('close', resolve); first.close(); });
  const second = await f.listen(), fresh = await f.client(second);
  assert.notEqual(client.binding, fresh.binding);
  await assert.rejects(fresh.requestFrame('execute', req, grant.token), /request replay refused/);
  assert.equal(mac.inspectReplayState(path.join(f.b, 'replay')).records, 1);
});

test('startup refuses corrupt replay journal and concurrent server lock', async t => {
  const f = await fixture(t), server = await f.listen();
  await assert.rejects(direct.startServer({ stateDir: f.b, host: '127.0.0.1', port: 0 }), /EEXIST/);
  await new Promise(resolve => { server.server.once('close', resolve); server.close(); });
  fs.writeFileSync(path.join(f.b, 'replay', 'capability-state.json'), JSON.stringify({ schema: mac.PROFILE + '.state', records: [{ nonsense: true }] }));
  await assert.rejects(direct.startServer({ stateDir: f.b, host: '127.0.0.1', port: 0 }), /invalid replay record/);
});

test('TLS exporter mismatch closes channel before grant or execution', async t => {
  const f = await fixture(t), server = await f.listen(), client = await f.client(server);
  client.socket.write(direct.frame({ id: crypto.randomBytes(16).toString('hex'), type: 'grant', channelBindingSha256: '0'.repeat(64), request: request(f.a, f.B) }));
  await awaitClose(client.socket);
  assert.equal(mac.inspectReplayState(path.join(f.b, 'replay')).records, 0);
  assert.equal(direct.readLedger(path.join(f.b, 'direct-transport')).sequence, 1);
});

test('oversized frame header closes authenticated connection before body buffering', async t => {
  const f = await fixture(t), server = await f.listen(), client = await f.client(server);
  const header = Buffer.alloc(4); header.writeUInt32BE(direct.MAX_FRAME + 1); client.socket.write(header);
  await awaitClose(client.socket);
  assert.equal(mac.inspectReplayState(path.join(f.b, 'replay')).records, 0);
});

test('framing handles fragmented records and refuses duplicate keys, unsafe numbers and invalid UTF8', () => {
  const out = [], consume = direct.decoder(value => out.push(value)), packet = direct.frame({ a: 1, b: 'data' });
  for (let i=0;i<packet.length;i++) consume(packet.subarray(i,i+1));
  assert.deepEqual(out, [{ a: 1, b: 'data' }]);
  assert.throws(() => direct.decoder(() => {})(rawFrame('{"a":1,"a":2}')), /noncanonical or duplicate-key/);
  assert.throws(() => direct.decoder(() => {})(rawFrame('{"a":9007199254740992}')), /unsafe number/);
  assert.throws(() => direct.decoder(() => {})(Buffer.from([0,0,0,1,0xff])));
  assert.throws(() => direct.decoder(() => {})(Buffer.from([0,0,0,0])), /frame size/);
});

test('private address restriction refuses wildcard, public, URL and hostname targets', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.0.152', '100.88.163.38', '172.16.0.1', '::1', 'fd12::1']) assert.equal(direct.safeAddress(ip), ip);
  for (const ip of ['0.0.0.0', '::', '8.8.8.8', '100.63.0.1', '172.15.0.1', 'example.com', 'https://192.168.0.1', 'fe80::1']) assert.throws(() => direct.safeAddress(ip));
});

test('transport proof tampering fails channel, peer, transcript or signature verification', async t => {
  const f = await fixture(t), server = await f.listen(), client = await f.client(server);
  const proof = await client.perform(direct.makeJob('compute.dot.v1'));
  const options = { own: f.A, peer: f.B, request: proof.request, response: proof.response, binding: client.binding, workerLedger: proof.workerLedger };
  assert.equal(direct.verifyTransportEvidence(proof.transportEvidence, options), true);
  assert.throws(() => direct.verifyTransportEvidence({ ...proof.transportEvidence, channelBindingSha256: '0'.repeat(64) }, options), /channel or profile binding/);
  assert.throws(() => direct.verifyTransportEvidence({ ...proof.transportEvidence, workerCertificateSha256: f.A.tlsCertificateSha256 }, options), /peer binding/);
  assert.throws(() => direct.verifyTransportEvidence({ ...proof.transportEvidence, requestSha256: '0'.repeat(64) }, options), /transcript binding/);
  assert.throws(() => direct.verifyTransportEvidence({ ...proof.transportEvidence, workerLedgerRecordSha256: '0'.repeat(64) }, options), /ledger binding/);
  assert.throws(() => direct.verifyTransportEvidence({ ...proof.transportEvidence, signature: Buffer.alloc(64).toString('base64') }, options), /signature refused/);
});

test('tightened current byte limit closes an already authenticated partial-frame sender', { timeout: 3000 }, async t => {
  const f = await fixture(t), server = await f.listen(), client = await f.client(server);
  changePolicy(f.b, { maxConnectionBytes: 8192 });
  const partial = Buffer.alloc(8200); partial.writeUInt32BE(59000, 0); client.socket.write(partial);
  await awaitClose(client.socket);
  assert.equal(mac.inspectReplayState(path.join(f.b, 'replay')).records, 0);
});

test('tampered worker receipt ledger fails closed before reporting successful work', async t => {
  const f = await fixture(t), server = await f.listen(), client = await f.client(server);
  const genesis = path.join(f.b,'direct-transport','receipt-ledger','000000.json');
  const original = fs.readFileSync(genesis,'utf8'); fs.writeFileSync(genesis, original.replace('owner-compute-fixture','altered-owner-policy'));
  await assert.rejects(client.perform(direct.makeJob('compute.dot.v1')), /hash mismatch|noncanonical receipt ledger entry/);
  // The replay reservation remains consumed after refusal; retry cannot duplicate work.
  assert.equal(mac.inspectReplayState(path.join(f.b, 'replay')).records, 1);
  assert.equal(ledgers.verifyReceiptLedger({ ledgerDir: path.join(f.a,'direct-transport','receipt-ledger'), nodePublicKey: f.A.publicKey }).receipts, 0);
});

test('paired latency benchmark executes both conditions and retains signed receipts without presuming speedup', async t => {
  const f = await fixture(t), server = await f.listen();
  const result = await direct.benchmark({ stateDir: f.a, host: '127.0.0.1', port: server.address.port }, 3);
  assert.equal(result.freshTlsEachJob.samples.length, 3);
  assert.equal(result.persistentTls.samples.length, 3);
  assert.equal(result.receipts.length, 6);
  assert.equal(result.bulkThroughputMeasured, false);
  assert.equal(result.persistentFasterInThisRun, result.persistentTls.medianMs < result.freshTlsEachJob.medianMs);
  assert.equal(mac.inspectReplayState(path.join(f.b, 'replay')).records, 6);
});

test('validly signed worker proof cannot substitute inconsistent accounting or checkpoint linkage', async t => {
  const f = await fixture(t), server = await f.listen(), client = await f.client(server);
  const proof = await client.perform(direct.makeJob('compute.dot.v1'));
  const options = { policy: distribution(f.A,f.B), request: proof.request, response: proof.response, evidence: proof.evidence, holderFingerprint: f.A.fingerprint, workerFingerprint: f.B.fingerprint, workerPublicKey: f.B.publicKey };
  assert.equal(direct.verifyWorkerLedgerRecord(proof.workerLedger, options), true);
  const changed = structuredClone(proof.workerLedger); changed.accounting.creditUnits += 1;
  const { signature: ignored, ...unsigned } = proof.transportEvidence;
  unsigned.workerLedgerRecordSha256 = crypto.createHash('sha256').update(session.boundedCanonical(changed)).digest('hex');
  const signed = { ...unsigned, signature: crypto.sign(null, Buffer.from('MIKAYA-INTEROP-DIRECT/1\nTRANSPORT_EVIDENCE\n' + require('../../live/federation-node.cjs').canonical(unsigned)), direct.loadOwn(f.b).privateKey).toString('base64') };
  // A genuine peer signature alone is insufficient to accept changed economics.
  assert.equal(direct.verifyTransportEvidence(signed, { own: f.A, peer: f.B, request: proof.request, response: proof.response, binding: client.binding, workerLedger: changed }), true);
  assert.throws(() => direct.verifyWorkerLedgerRecord(changed, options), /accounting disagrees/);
  assert.throws(() => direct.verifyWorkerLedgerRecord({ ...proof.workerLedger, receiptSha256: '0'.repeat(64) }, options), /receipt binding/);
  assert.throws(() => direct.verifyWorkerLedgerRecord({ ...proof.workerLedger, index: proof.workerLedger.index + 1 }, options), /checkpoint linkage/);
  assert.throws(() => direct.verifyWorkerLedgerRecord({ ...proof.workerLedger, paymentSettled: true }, options), /scope or index/);
});
