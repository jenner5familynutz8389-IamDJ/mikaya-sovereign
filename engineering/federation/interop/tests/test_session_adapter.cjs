'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const session = require('../session-adapter.cjs');
const mac = require('../capability-macaroons.cjs');
const fed = require('../../live/federation-node.cjs');

function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mikaya-interop-session-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const stateDir = path.join(dir, 'replay');
  mac.initializeReplayState(stateDir);
  const holder = crypto.generateKeyPairSync('ed25519');
  const worker = crypto.generateKeyPairSync('ed25519');
  const rootKey = crypto.randomBytes(32);
  const nowMs = Date.now();
  const profile = { schema: 'mikaya.interop.synthetic-profile.v1', platform: 'node', synthetic: true };
  const job = { schema: 'mikaya.federation.job.v1', id: crypto.randomBytes(16).toString('hex'), capability: 'compute.dot.v1', payload: { a: [1, 2, 3], b: [4, 5, 6] } };
  const request = session.makeRequest({ holderPrivateKey: holder.privateKey, workerPublicKey: worker.publicKey, job, nowMs });
  const token = mac.mintTestCapability({ rootKey, holderKeySha256: request.auth.from, audience: request.auth.to, profileSha256: session.profileDigest(profile), operation: job.capability, bodySha256: request.auth.bodySha256, issuedAtMs: nowMs, expiresAtMs: nowMs + 60000, maxUses: 2, maxBytes: 8192 });
  const args = { request, token, rootKey, holderPublicKey: holder.publicKey, workerPrivateKey: worker.privateKey, profile, stateDir, policy: session.conformancePolicy(), nowMs };
  return { ...args, args, dir, holder, worker, job };
}
test('signed Node request plus real capability produces a verifiable bounded receipt', t => {
  const f = fixture(t);
  const out = session.acceptConformanceRequest(f.args);
  assert.equal(out.response.body.result, 32);
  const verified = session.verifyReceipt({ request: f.request, response: out.response, holderPublicKey: f.holder.publicKey, workerPublicKey: f.worker.publicKey, nowMs: f.nowMs });
  assert.equal(verified.verified, true);
  assert.equal(verified.executionAuthorized, false);
  assert.equal(out.evidence.hardwareAttested, false);
  assert.equal(out.evidence.productionAdmission, false);
});
test('a tampered request is rejected before consuming the valid capability', t => {
  const f = fixture(t);
  const changed = JSON.parse(JSON.stringify(f.request)); changed.body.payload.a[0] = 99;
  assert.throws(() => session.acceptConformanceRequest({ ...f.args, request: changed }), /digest/);
  assert.equal(session.acceptConformanceRequest(f.args).response.body.result, 32);
});
test('valid signatures cannot move the capability to a different job body', t => {
  const f = fixture(t);
  const job = { ...f.job, payload: { a: [1], b: [2] } };
  const request = session.makeRequest({ holderPrivateKey: f.holder.privateKey, workerPublicKey: f.worker.publicKey, job, nowMs: f.nowMs });
  assert.throws(() => session.acceptConformanceRequest({ ...f.args, request }), /body|binding|caveat/);
});
test('profile substitution is rejected despite a valid request signature', t => {
  const f = fixture(t);
  assert.throws(() => session.acceptConformanceRequest({ ...f.args, profile: { ...f.profile, platform: 'different' } }), /profile|binding|caveat/);
});
test('owner test kill switch and operation removal are enforced', t => {
  const f = fixture(t);
  assert.throws(() => session.acceptConformanceRequest({ ...f.args, policy: { ...f.policy, enabled: false } }), /disabled/);
  assert.throws(() => session.acceptConformanceRequest({ ...f.args, policy: { ...f.policy, allowedCapabilities: ['compute.sha256.v1'] } }), /excluded/);
  assert.equal(session.acceptConformanceRequest(f.args).response.body.result, 32);
});
test('an authenticated request cannot be replayed after a fresh module load', t => {
  const f = fixture(t);
  session.acceptConformanceRequest(f.args);
  delete require.cache[require.resolve('../session-adapter.cjs')];
  const reloaded = require('../session-adapter.cjs');
  assert.throws(() => reloaded.acceptConformanceRequest(f.args), /replay|nonce|consumed/);
});
test('wrong holder key, wrong recipient, stale request and oversized input fail closed', t => {
  const f = fixture(t), other = crypto.generateKeyPairSync('ed25519');
  assert.throws(() => session.acceptConformanceRequest({ ...f.args, holderPublicKey: other.publicKey }), /identity/);
  assert.throws(() => session.acceptConformanceRequest({ ...f.args, workerPrivateKey: other.privateKey }), /identity/);
  assert.throws(() => session.acceptConformanceRequest({ ...f.args, nowMs: f.nowMs + 60001 }), /expired/);
  assert.throws(() => session.acceptConformanceRequest({ ...f.args, policy: { ...f.policy, maxRequestBytes: 32 } }), /budget|string/);
});
test('cyclic, accessor, oversized and unsafe-number values cannot reach canonical signing', () => {
  const cyclic = {}; cyclic.x = cyclic;
  assert.throws(() => session.boundedCanonical(cyclic), /cyclic/);
  const accessor = {}; Object.defineProperty(accessor, 'x', { enumerable: true, get() { throw new Error('must not run'); } });
  assert.throws(() => session.boundedCanonical(accessor), /accessor/);
  assert.throws(() => session.boundedCanonical({ n: 9007199254740992 }), /unsafe/);
  assert.throws(() => session.boundedCanonical({ x: 'x'.repeat(9000) }), /limit|budget/);
});
test('capability attenuation lowers allowed bytes and cannot turn a result into payment authority', t => {
  const f = fixture(t);
  const token = mac.attenuateCapability(f.token, { maxBytes: 1 });
  assert.throws(() => session.acceptConformanceRequest({ ...f.args, token }), /bytes|budget|limit/);
  const out = session.acceptConformanceRequest(f.args);
  assert.equal(out.evidence.paymentAuthorized, false);
  assert.equal(out.evidence.firmwareAuthorized, false);
  assert.equal(fed.fp(f.worker.publicKey), out.response.body.workerFingerprint);
});
test('signed conformance evidence binds the actual profile and both complete envelopes', t => {
  const f = fixture(t), out = session.acceptConformanceRequest(f.args);
  const args = { request: f.request, response: out.response, evidence: out.evidence, holderPublicKey: f.holder.publicKey, workerPublicKey: f.worker.publicKey, profileSha256: session.profileDigest(f.profile), nowMs: f.nowMs };
  const verified = session.verifyConformanceReceipt(args);
  assert.equal(verified.evidenceVerified, true);
  assert.equal(verified.profileSha256, session.profileDigest(f.profile));
  assert.equal(verified.hardwareAttested, false);
  assert.throws(() => session.verifyConformanceReceipt({ ...args, profileSha256: 'f'.repeat(64) }), /profile binding/);
  assert.throws(() => session.verifyConformanceReceipt({ ...args, profileSha256: 'f'.repeat(64), evidence: { ...out.evidence, profileSha256: 'f'.repeat(64) } }), /signature/);
  assert.throws(() => session.verifyConformanceReceipt({ ...args, evidence: { ...out.evidence, requestNonce: 'f'.repeat(32) } }), /binding/);
  const response = JSON.parse(JSON.stringify(out.response)); response.body.result++;
  assert.throws(() => session.verifyConformanceReceipt({ ...args, response }), /binding/);
  const request = JSON.parse(JSON.stringify(f.request)); request.auth.issuedAtMs++;
  assert.throws(() => session.verifyConformanceReceipt({ ...args, request }), /binding/);
});
test('conformance evidence rejects extra fields, claims of authority, stale evidence and noncanonical signatures', t => {
  const f = fixture(t), out = session.acceptConformanceRequest(f.args);
  const args = { request: f.request, response: out.response, evidence: out.evidence, holderPublicKey: f.holder.publicKey, workerPublicKey: f.worker.publicKey, profileSha256: session.profileDigest(f.profile), nowMs: f.nowMs };
  assert.throws(() => session.verifyConformanceReceipt({ ...args, evidence: { ...out.evidence, unexpected: true } }), /schema/);
  for (const field of ['hardwareAttested', 'productionAdmission', 'paymentAuthorized', 'firmwareAuthorized']) {
    assert.throws(() => session.verifyConformanceReceipt({ ...args, evidence: { ...out.evidence, [field]: true } }), /security limits/);
  }
  assert.throws(() => session.verifyConformanceReceipt({ ...args, nowMs: f.nowMs + 60001 }), /expired/);
  assert.throws(() => session.verifyConformanceReceipt({ ...args, evidence: { ...out.evidence, signature: out.evidence.signature.slice(0, -1) } }), /signature/);
  const { signature, ...body } = out.evidence;
  const wrongDomain = crypto.sign(null, Buffer.from('MIKAYA-INDEPENDENT-FEDERATION/1\nEVIDENCE\n' + fed.canonical(body)), f.worker.privateKey).toString('base64');
  assert.throws(() => session.verifyConformanceReceipt({ ...args, evidence: { ...body, signature: wrongDomain } }), /signature/);
});
test('array identifiers, nonces and hash challenges cannot exploit legacy regexp coercion', t => {
  const f = fixture(t);
  assert.throws(() => session.makeRequest({ holderPrivateKey: f.holder.privateKey, workerPublicKey: f.worker.publicKey, job: { ...f.job, id: [f.job.id] }, nowMs: f.nowMs }), /string/);
  assert.throws(() => session.makeRequest({ holderPrivateKey: f.holder.privateKey, workerPublicKey: f.worker.publicKey, job: f.job, nonce: [f.request.auth.nonce], nowMs: f.nowMs }), /nonce/);
  const job = { ...f.job, capability: 'compute.sha256.v1', payload: { challengeHex: ['a'.repeat(64)] } };
  assert.throws(() => session.makeRequest({ holderPrivateKey: f.holder.privateKey, workerPublicKey: f.worker.publicKey, job, nowMs: f.nowMs }), /string/);
  const request = JSON.parse(JSON.stringify(f.request)); request.auth.nonce = [request.auth.nonce];
  assert.throws(() => session.verifyRequest({ request, holderPublicKey: f.holder.publicKey, workerPublicKey: f.worker.publicKey, nowMs: f.nowMs }), /string/);
  assert.throws(() => session.boundedCanonical([, 1]), /array/);
});
test('correctly signed malformed jobs are rejected before capability reservation', t => {
  const f = fixture(t), request = JSON.parse(JSON.stringify(f.request));
  request.body.id = [request.body.id];
  request.auth.bodySha256 = fed.sha(fed.canonical(request.body));
  const { signature, ...unsigned } = request.auth;
  request.auth.signature = crypto.sign(null, Buffer.from('MIKAYA-INDEPENDENT-FEDERATION/1\nREQ\n' + fed.canonical(unsigned)), f.holder.privateKey).toString('base64');
  assert.throws(() => session.verifyRequest({ request, holderPublicKey: f.holder.publicKey, workerPublicKey: f.worker.publicKey, nowMs: f.nowMs }), /string/);
  const out = session.acceptConformanceRequest(f.args);
  assert.equal(out.response.body.result, 32);
  const response = JSON.parse(JSON.stringify(out.response));
  response.body.jobId = request.body.id;
  response.body.requestSha256 = request.auth.bodySha256;
  response.auth.bodySha256 = fed.sha(fed.canonical(response.body));
  const { signature: oldSignature, ...reply } = response.auth;
  response.auth.signature = crypto.sign(null, Buffer.from('MIKAYA-INDEPENDENT-FEDERATION/1\nRES\n' + fed.canonical(reply)), f.worker.privateKey).toString('base64');
  assert.throws(() => session.verifyReceipt({ request, response, holderPublicKey: f.holder.publicKey, workerPublicKey: f.worker.publicKey, nowMs: f.nowMs }), /string/);
});
