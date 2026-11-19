'use strict';
const crypto = require('node:crypto');
const {canonical, validateIntent} = require('./transaction-journal.cjs');
const fed = require('../live/federation-node.cjs');
const DOMAIN = 'MIKAYA-ACT-COLLABORATION/1\n';
const SHA = /^[0-9a-f]{64}$/;
const NONCE = /^[0-9a-f]{32}$/;
function fail(code) { const e = new Error(code); e.code = code; throw e; }
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const exact = (o, keys) => o && Object.getPrototypeOf(o) === Object.prototype && Object.keys(o).sort().join('|') === keys.slice().sort().join('|');
function parseCanonical(bytes, limit = 8192) {
  if (!Buffer.isBuffer(bytes) || bytes.length > limit) fail('MESSAGE_TOO_LARGE');
  let value; try { value = JSON.parse(bytes.toString('utf8')); } catch { fail('INVALID_JSON'); }
  if (!Buffer.from(canonical(value)).equals(bytes)) fail('NONCANONICAL_JSON');
  return value;
}
function signatureValid(signature, text, publicKey) {
  if (typeof signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(signature)) return false;
  const b = Buffer.from(signature, 'base64');
  return b.toString('base64') === signature && crypto.verify(null, Buffer.from(text), publicKey, b);
}
function makeRequest({node, to, capability, operation, resource, payload, transactionId = crypto.randomUUID(), expiresAtMs, nowMs = Date.now(), intent, nonce = crypto.randomBytes(16).toString('hex')}) {
  if (!SHA.test(to) || typeof capability !== 'string' || !NONCE.test(nonce)) fail('REQUEST_CONFIGURATION_INVALID');
  const stable = intent || {schema: 'mikaya.act.transaction-intent.v1', transactionId, sender: node.meta.fingerprint,
    recipient: to, operation, resource, payloadSha256: sha(canonical(payload)), policyVersion: 'collaboration-v1', expiresAtMs};
  validateIntent(stable);
  if (stable.sender !== node.meta.fingerprint || stable.recipient !== to || stable.payloadSha256 !== sha(canonical(payload))) fail('INTENT_PAYLOAD_MISMATCH');
  const attempt = {schema: 'mikaya.act.request-attempt.v1', nonce, issuedAtMs: nowMs,
    intentSha256: sha(canonical(stable)), capabilitySha256: sha(capability), method: 'POST', route: '/v1/collaboration'};
  const signature = crypto.sign(null, Buffer.from(DOMAIN + 'REQ\n' + canonical(attempt)), node.privateKey).toString('base64');
  return {intent: stable, payload, capability, attempt, signature};
}
function verifyRequest({request, node, peer, nowMs = Date.now()}) {
  if (!Number.isSafeInteger(nowMs) || nowMs <= 0) fail('CLOCK_INVALID');
  if (!exact(request, ['intent', 'payload', 'capability', 'attempt', 'signature'])) fail('REQUEST_SHAPE_INVALID');
  const {intent, payload, capability, attempt, signature} = request;
  validateIntent(intent);
  if (nowMs >= intent.expiresAtMs) fail('INTENT_EXPIRED');
  if (fed.fp(peer.publicKey) !== peer.fingerprint) fail('PEER_KEY_MISMATCH');
  if (intent.sender !== peer.fingerprint || intent.recipient !== node.meta.fingerprint ||
      intent.payloadSha256 !== sha(canonical(payload))) fail('INTENT_BINDING_INVALID');
  if (!exact(attempt, ['schema', 'nonce', 'issuedAtMs', 'intentSha256', 'capabilitySha256', 'method', 'route']) ||
      attempt.schema !== 'mikaya.act.request-attempt.v1' || !NONCE.test(attempt.nonce) ||
      !Number.isSafeInteger(attempt.issuedAtMs) || attempt.issuedAtMs > nowMs + 5000 || nowMs - attempt.issuedAtMs > 60000 ||
      attempt.intentSha256 !== sha(canonical(intent)) || typeof capability !== 'string' ||
      attempt.capabilitySha256 !== sha(capability) || attempt.method !== 'POST' || attempt.route !== '/v1/collaboration') fail('ATTEMPT_INVALID_OR_EXPIRED');
  if (!signatureValid(signature, DOMAIN + 'REQ\n' + canonical(attempt), peer.publicKey)) fail('REQUEST_SIGNATURE_INVALID');
  return intent;
}
function signResponse({node, request, body, nowMs = Date.now()}) {
  const auth = {schema: 'mikaya.act.response.v1', sender: node.meta.fingerprint, recipient: request.intent.sender,
    inReplyTo: request.attempt.nonce, intentSha256: sha(canonical(request.intent)), bodySha256: sha(canonical(body)), issuedAtMs: nowMs};
  return {auth, body, signature: crypto.sign(null, Buffer.from(DOMAIN + 'RES\n' + canonical(auth)), node.privateKey).toString('base64')};
}
function verifyResponse({response, request, publicKey, nowMs = Date.now()}) {
  if (!Number.isSafeInteger(nowMs) || nowMs <= 0) fail('CLOCK_INVALID');
  if (!exact(response, ['auth', 'body', 'signature'])) fail('RESPONSE_SHAPE_INVALID');
  const a = response.auth;
  if (!exact(a, ['schema', 'sender', 'recipient', 'inReplyTo', 'intentSha256', 'bodySha256', 'issuedAtMs']) ||
      a.schema !== 'mikaya.act.response.v1' || a.sender !== request.intent.recipient || a.recipient !== request.intent.sender ||
      fed.fp(publicKey) !== a.sender || a.inReplyTo !== request.attempt.nonce || a.intentSha256 !== sha(canonical(request.intent)) ||
      a.bodySha256 !== sha(canonical(response.body)) || !Number.isSafeInteger(a.issuedAtMs) ||
      a.issuedAtMs > nowMs + 5000 || nowMs - a.issuedAtMs > 60000 ||
      !signatureValid(response.signature, DOMAIN + 'RES\n' + canonical(a), publicKey)) fail('RESPONSE_BINDING_INVALID');
  return response.body;
}
module.exports = {canonical, sha, exact, fail, parseCanonical, makeRequest, verifyRequest, signResponse, verifyResponse};
