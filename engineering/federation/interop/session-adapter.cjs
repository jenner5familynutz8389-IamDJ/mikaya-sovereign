#!/usr/bin/env node
'use strict';
/**
 * Offline conformance adapter for the existing federation wire contract.
 * It verifies a real Ed25519 request before consuming a first-party macaroon.
 * It has no listener, production enrollment, shell, wallet or firmware route.
 */
const crypto = require('node:crypto');
const fed = require('../live/federation-node.cjs');
const receipts = require('../live/act-backend-compat.cjs');
const macaroons = require('./capability-macaroons.cjs');
const DOMAIN = 'MIKAYA-INDEPENDENT-FEDERATION/1\n';
const EVIDENCE_DOMAIN = 'MIKAYA-INTEROP-CONFORMANCE/1\n';
const EVIDENCE_SCHEMA = 'mikaya.interop.conformance-evidence.v1';
const HASH = /^[a-f0-9]{64}$/;
const NONCE = /^[a-f0-9]{32}$/;
const CAPS = new Set(['compute.dot.v1', 'compute.sha256.v1']);
const REQUEST_KEYS = ['schema', 'from', 'to', 'method', 'route', 'bodySha256', 'nonce', 'issuedAtMs', 'signature'];
const EVIDENCE_KEYS = ['schema', 'mode', 'from', 'to', 'requestNonce', 'requestSha256', 'requestBodySha256', 'responseSha256', 'profileSha256', 'issuedAtMs', 'softwareSignatureVerified', 'hardwareAttested', 'productionAdmission', 'paymentAuthorized', 'firmwareAuthorized', 'signature'];
function ensure(ok, message) { if (!ok) throw new Error(message); }
function plain(v) { return v !== null && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype; }
function exact(v, keys) { return plain(v) && Object.keys(v).sort().join('|') === [...keys].sort().join('|'); }
function boundedCanonical(value, maxBytes = 8192) {
  let remaining = 2048;
  const seen = new WeakSet();
  function check(v, depth) {
    ensure(--remaining >= 0 && depth <= 20, 'message structure limit exceeded');
    if (v === null || typeof v === 'boolean') return;
    if (typeof v === 'string') { ensure(v.length <= maxBytes, 'string limit exceeded'); return; }
    if (typeof v === 'number') { ensure(Number.isSafeInteger(v), 'unsafe number refused'); return; }
    ensure(Array.isArray(v) || plain(v), 'non-JSON value refused');
    ensure(!seen.has(v), 'cyclic or shared object refused'); seen.add(v);
    if (Array.isArray(v)) ensure(v.length <= remaining && Object.keys(v).length === v.length && Object.keys(v).every((key, i) => key === String(i)), 'sparse or non-JSON array refused');
    for (const key of Object.keys(v)) {
      const d = Object.getOwnPropertyDescriptor(v, key);
      ensure(d && Object.hasOwn(d, 'value'), 'accessor refused');
      check(d.value, depth + 1);
    }
  }
  check(value, 0);
  const out = fed.canonical(value);
  ensure(Buffer.byteLength(out) <= maxBytes, 'message byte budget exceeded');
  return out;
}
function publicKey(key) {
  const k = key && key.type === 'public' ? key : crypto.createPublicKey(key);
  ensure(k.asymmetricKeyType === 'ed25519', 'Ed25519 identity required');
  return k;
}
function privateKey(key) {
  const k = key && key.type === 'private' ? key : crypto.createPrivateKey(key);
  ensure(k.asymmetricKeyType === 'ed25519', 'Ed25519 signing key required');
  return k;
}
function sign(kind, body, key, domain = DOMAIN) {
  return { ...body, signature: crypto.sign(null, Buffer.from(domain + kind + '\n' + fed.canonical(body)), privateKey(key)).toString('base64') };
}
function signatureOk(kind, auth, key, domain = DOMAIN) {
  if (typeof auth.signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(auth.signature)) return false;
  const { signature, ...unsigned } = auth;
  const bytes = Buffer.from(signature, 'base64');
  return bytes.length === 64 && bytes.toString('base64') === signature && crypto.verify(null, Buffer.from(domain + kind + '\n' + fed.canonical(unsigned)), publicKey(key), bytes);
}
function profileDigest(profile) { return fed.sha(boundedCanonical(profile, 65536)); }
function conformancePolicy() {
  return { schema: 'mikaya.interop.conformance-policy.v1', enabled: true, allowedCapabilities: [...CAPS], maxRequestBytes: 8192 };
}
function validatePolicy(policy) {
  ensure(exact(policy, ['schema', 'enabled', 'allowedCapabilities', 'maxRequestBytes']) && policy.schema === 'mikaya.interop.conformance-policy.v1', 'conformance policy schema refused');
  ensure(policy.enabled === true, 'owner test policy disabled');
  ensure(Array.isArray(policy.allowedCapabilities) && policy.allowedCapabilities.length > 0 && policy.allowedCapabilities.length <= CAPS.size && new Set(policy.allowedCapabilities).size === policy.allowedCapabilities.length && policy.allowedCapabilities.every(x => CAPS.has(x)), 'policy capability refused');
  ensure(Number.isSafeInteger(policy.maxRequestBytes) && policy.maxRequestBytes > 0 && policy.maxRequestBytes <= 8192, 'policy byte budget refused');
}
function validateJob(job) {
  ensure(plain(job) && ['schema', 'id', 'capability'].every(field => typeof job[field] === 'string'), 'job string fields refused');
  if (job.capability === 'compute.sha256.v1') ensure(plain(job.payload) && typeof job.payload.challengeHex === 'string', 'hash challenge string required');
  return fed.computeJob(job);
}
function makeRequest({ holderPrivateKey, workerPublicKey, job, nonce = crypto.randomBytes(16).toString('hex'), nowMs = Date.now() }) {
  const key = privateKey(holderPrivateKey);
  ensure(typeof nonce === 'string' && NONCE.test(nonce) && Number.isSafeInteger(nowMs) && nowMs >= 0, 'request nonce or time refused');
  const bodyBytes = boundedCanonical(job);
  // Validate the fixed bounded job schema before creating a signed fixture.
  validateJob(job);
  const from = fed.fp(publicKey(key)), to = fed.fp(publicKey(workerPublicKey));
  ensure(from !== to, 'independent identities required');
  const auth = sign('REQ', { schema: 'mikaya.federation.request.v1', from, to, method: 'POST', route: '/v1/task', bodySha256: fed.sha(bodyBytes), nonce, issuedAtMs: nowMs }, key);
  const request = { auth, body: job };
  boundedCanonical(request);
  return request;
}
function verifyRequest({ request, holderPublicKey, workerPublicKey, nowMs = Date.now(), maxBytes = 8192 }) {
  const encoded = boundedCanonical(request, maxBytes);
  ensure(exact(request, ['auth', 'body']) && exact(request.auth, REQUEST_KEYS), 'signed request schema refused');
  const a = request.auth;
  ensure(REQUEST_KEYS.filter(field => field !== 'issuedAtMs').every(field => typeof a[field] === 'string'), 'request string fields refused');
  const holder = publicKey(holderPublicKey), worker = publicKey(workerPublicKey);
  ensure(a.schema === 'mikaya.federation.request.v1' && a.from === fed.fp(holder) && a.to === fed.fp(worker) && a.from !== a.to, 'request identity binding refused');
  ensure(a.method === 'POST' && a.route === '/v1/task', 'request route refused');
  ensure(NONCE.test(a.nonce) && Number.isSafeInteger(a.issuedAtMs) && a.issuedAtMs >= 0 && Number.isSafeInteger(nowMs) && nowMs >= 0 && Math.abs(nowMs - a.issuedAtMs) <= 60000, 'request expired or invalid time');
  ensure(a.bodySha256 === fed.sha(boundedCanonical(request.body)), 'request body digest refused');
  ensure(signatureOk('REQ', a, holder), 'request signature refused');
  ensure(CAPS.has(request.body.capability), 'request operation refused');
  // Validate the complete fixed job schema before a grant or replay reservation.
  // These two bounded pure computations have no external side effects.
  validateJob(request.body);
  return { holderKeySha256: a.from, audience: a.to, operation: request.body.capability, bodySha256: a.bodySha256, requestNonce: a.nonce, requestBytes: Buffer.byteLength(encoded) };
}
function acceptConformanceRequest({ request, token, rootKey, holderPublicKey, workerPrivateKey, profile, stateDir, policy, nowMs = Date.now() }) {
  validatePolicy(policy);
  const workerKey = privateKey(workerPrivateKey);
  const context = verifyRequest({ request, holderPublicKey, workerPublicKey: publicKey(workerKey), nowMs, maxBytes: policy.maxRequestBytes });
  ensure(policy.allowedCapabilities.includes(context.operation), 'operation excluded by current owner test policy');
  context.profileSha256 = profileDigest(profile);
  // No caller-supplied authenticated flag or fingerprint is accepted here.
  const capability = macaroons.verifyCapability({ token, rootKey, context, nowMs, stateDir });
  const result = fed.computeJob(request.body);
  const body = { schema: 'mikaya.federation.result.v1', jobId: request.body.id, capability: context.operation, workerFingerprint: context.audience, requestSha256: context.bodySha256, result };
  const auth = sign('RES', { schema: 'mikaya.federation.response.v1', from: context.audience, to: context.holderKeySha256, inReplyTo: context.requestNonce, bodySha256: fed.sha(fed.canonical(body)), issuedAtMs: nowMs }, workerKey);
  const response = { auth, body };
  // Separate signed extension: the existing federation envelopes stay intact.
  // This authenticates a software-observed profile digest, not hardware state.
  const evidence = sign('EVIDENCE', {
    schema: EVIDENCE_SCHEMA, mode: 'OFFLINE_CONFORMANCE',
    from: context.audience, to: context.holderKeySha256,
    requestNonce: context.requestNonce,
    requestSha256: fed.sha(boundedCanonical(request)),
    requestBodySha256: context.bodySha256,
    responseSha256: fed.sha(boundedCanonical(response)),
    profileSha256: context.profileSha256, issuedAtMs: nowMs,
    softwareSignatureVerified: true, hardwareAttested: false,
    productionAdmission: false, paymentAuthorized: false, firmwareAuthorized: false
  }, workerKey, EVIDENCE_DOMAIN);
  return { response, capability, evidence };
}
function verifyReceipt({ request, response, holderPublicKey, workerPublicKey, nowMs = Date.now() }) {
  verifyRequest({ request, holderPublicKey, workerPublicKey, nowMs });
  boundedCanonical(response);
  return receipts.verifyDeterministicReceipt({ request, response, ownerPublicKey: holderPublicKey, actPublicKey: workerPublicKey, expectedActFingerprint: fed.fp(publicKey(workerPublicKey)), nowMs });
}
function verifyConformanceReceipt({ request, response, evidence, holderPublicKey, workerPublicKey, profileSha256, nowMs = Date.now() }) {
  boundedCanonical(evidence);
  ensure(exact(evidence, EVIDENCE_KEYS) && evidence.schema === EVIDENCE_SCHEMA && evidence.mode === 'OFFLINE_CONFORMANCE', 'conformance evidence schema refused');
  ensure(evidence.softwareSignatureVerified === true && evidence.hardwareAttested === false && evidence.productionAdmission === false && evidence.paymentAuthorized === false && evidence.firmwareAuthorized === false, 'conformance evidence security limits refused');
  ensure(typeof profileSha256 === 'string' && HASH.test(profileSha256) && evidence.profileSha256 === profileSha256, 'conformance evidence profile binding refused');
  ensure(evidence.from === fed.fp(publicKey(workerPublicKey)) && evidence.to === fed.fp(publicKey(holderPublicKey)) && evidence.from !== evidence.to, 'conformance evidence identity binding refused');
  ensure(Number.isSafeInteger(nowMs) && nowMs >= 0 && Number.isSafeInteger(evidence.issuedAtMs) && evidence.issuedAtMs >= 0 && Math.abs(nowMs - evidence.issuedAtMs) <= 60000, 'conformance evidence expired or invalid time');
  boundedCanonical(request); boundedCanonical(response);
  ensure(evidence.requestNonce === request.auth?.nonce && evidence.requestSha256 === fed.sha(boundedCanonical(request)) && evidence.requestBodySha256 === request.auth?.bodySha256 && evidence.responseSha256 === fed.sha(boundedCanonical(response)) && evidence.issuedAtMs === response.auth?.issuedAtMs, 'conformance evidence request or response binding refused');
  ensure(signatureOk('EVIDENCE', evidence, workerPublicKey, EVIDENCE_DOMAIN), 'conformance evidence signature refused');
  const result = verifyReceipt({ request, response, holderPublicKey, workerPublicKey, nowMs });
  return Object.freeze({ ...result, profileSha256, evidenceVerified: true });
}
module.exports = { boundedCanonical, profileDigest, conformancePolicy, makeRequest, verifyRequest, acceptConformanceRequest, verifyReceipt, verifyConformanceReceipt };
