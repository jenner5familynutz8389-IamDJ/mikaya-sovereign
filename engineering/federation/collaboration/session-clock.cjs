'use strict';
// Peer time is used only for this peer's outbound attempts and response checks.
// It never changes the owner clock, capability lifetime or existing admission.
const crypto = require('node:crypto');
const {performance} = require('node:perf_hooks');
const fed = require('../live/federation-node.cjs');
const {canonical, exact, fail, sha} = require('./protocol.cjs');
const DOMAIN = 'MIKAYA-ACT-COLLABORATION/1\n';
const FP = /^[0-9a-f]{64}$/, NONCE = /^[0-9a-f]{32}$/;
const MAX_RTT_MS = 2000, MAX_AGE_MS = 30000;
function validSignature(signature, text, key) {
  return typeof signature === 'string' && /^[A-Za-z0-9+/]{86}==$/.test(signature) &&
    crypto.verify(null, Buffer.from(text), key, Buffer.from(signature, 'base64'));
}
function validBody(b) {
  return exact(b, ['schema', 'sender', 'recipient', 'nonce', 'method', 'route']) &&
    b.schema === 'mikaya.act.clock-challenge.v1' && FP.test(b.sender) && FP.test(b.recipient) &&
    b.sender !== b.recipient && NONCE.test(b.nonce) && b.method === 'POST' && b.route === '/v1/session';
}
function makeChallenge({node, to, nonce = crypto.randomBytes(16).toString('hex')}) {
  const body = {schema: 'mikaya.act.clock-challenge.v1', sender: node.meta.fingerprint, recipient: to,
    nonce, method: 'POST', route: '/v1/session'};
  if (!validBody(body)) fail('CLOCK_CHALLENGE_INVALID');
  return {body, signature: crypto.sign(null, Buffer.from(DOMAIN + 'SESSION_REQ\n' + canonical(body)), node.privateKey).toString('base64')};
}
function verifyChallenge({challenge, node, peer}) {
  if (!exact(challenge, ['body', 'signature']) || !validBody(challenge.body) ||
      challenge.body.sender !== peer.fingerprint || fed.fp(peer.publicKey) !== peer.fingerprint ||
      challenge.body.recipient !== node.meta.fingerprint ||
      !validSignature(challenge.signature, DOMAIN + 'SESSION_REQ\n' + canonical(challenge.body), peer.publicKey)) fail('CLOCK_CHALLENGE_INVALID');
  return challenge.body;
}
function signClockResponse({node, challenge, nowMs = Date.now()}) {
  if (!validBody(challenge.body) || challenge.body.recipient !== node.meta.fingerprint ||
      !Number.isSafeInteger(nowMs) || nowMs <= 0) fail('CLOCK_RESPONSE_INVALID');
  const body = {schema: 'mikaya.act.clock-response.v1', sender: node.meta.fingerprint,
    recipient: challenge.body.sender, nonce: challenge.body.nonce, challengeSha256: sha(canonical(challenge)),
    serverTimeMs: nowMs, policyVersion: 'collaboration-v1'};
  return {body, signature: crypto.sign(null, Buffer.from(DOMAIN + 'SESSION_RES\n' + canonical(body)), node.privateKey).toString('base64')};
}
function verifyClockResponse({response, challenge, publicKey, startMonoMs, endMonoMs}) {
  const b = response?.body, rttMs = endMonoMs - startMonoMs;
  if (!Number.isFinite(startMonoMs) || !Number.isFinite(endMonoMs) || startMonoMs < 0 ||
      rttMs < 0 || rttMs > MAX_RTT_MS) fail('CLOCK_RTT_UNSAFE');
  if (!exact(response, ['body', 'signature']) || !validBody(challenge?.body) ||
      !exact(b, ['schema', 'sender', 'recipient', 'nonce', 'challengeSha256', 'serverTimeMs', 'policyVersion']) ||
      b.schema !== 'mikaya.act.clock-response.v1' || b.sender !== challenge.body.recipient ||
      fed.fp(publicKey) !== b.sender || b.recipient !== challenge.body.sender || b.nonce !== challenge.body.nonce ||
      b.challengeSha256 !== sha(canonical(challenge)) || b.policyVersion !== 'collaboration-v1' ||
      !Number.isSafeInteger(b.serverTimeMs) || b.serverTimeMs <= 0 ||
      !validSignature(response.signature, DOMAIN + 'SESSION_RES\n' + canonical(b), publicKey)) fail('CLOCK_RESPONSE_INVALID');
  return Object.freeze({peer: b.sender, serverTimeAtEndMs: b.serverTimeMs + rttMs / 2,
    endMonoMs, rttMs, signedResponse: response});
}
function peerNow(calibration, monoMs = performance.now()) {
  const age = monoMs - calibration.endMonoMs;
  if (!Number.isFinite(monoMs) || !Number.isFinite(age) || age < 0 || age > MAX_AGE_MS ||
      !Number.isFinite(calibration.serverTimeAtEndMs)) fail('CLOCK_CALIBRATION_STALE');
  const time = Math.floor(calibration.serverTimeAtEndMs + age);
  if (!Number.isSafeInteger(time) || time <= 0) fail('CLOCK_CALIBRATION_INVALID');
  return time;
}
module.exports = {MAX_RTT_MS, MAX_AGE_MS, makeChallenge, verifyChallenge, signClockResponse, verifyClockResponse, peerNow};
