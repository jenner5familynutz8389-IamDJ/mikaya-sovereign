'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const clock = require('../session-clock.cjs');
const protocol = require('../protocol.cjs');
const fed = require('../../live/federation-node.cjs');
function identity() {
  const pair = crypto.generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({type: 'spki', format: 'pem'});
  return {meta: {fingerprint: fed.fp(publicKey)}, publicKey, privateKey: pair.privateKey};
}
function fixture() {
  const a = identity(), b = identity(), c = identity();
  const challenge = clock.makeChallenge({node: a, to: b.meta.fingerprint});
  const peer = {fingerprint: a.meta.fingerprint, publicKey: a.publicKey};
  const response = clock.signClockResponse({node: b, challenge, nowMs: 100000});
  return {a, b, c, challenge, peer, response};
}
const clone = value => structuredClone(value);
test('signed clock sample survives independent owner wall clocks without changing guards', () => {
  const {a, b, challenge, peer, response} = fixture();
  assert.equal(clock.verifyChallenge({challenge, node: b, peer}).nonce, challenge.body.nonce);
  const calibrated = clock.verifyClockResponse({response, challenge, publicKey: b.publicKey, startMonoMs: 10, endMonoMs: 110});
  assert.equal(clock.peerNow(calibrated, 210), 100150);
  const request = protocol.makeRequest({node: a, to: b.meta.fingerprint, capability: 'fixture', operation: 'collaboration.describe.v1',
    resource: 'collaboration:self', payload: {}, nowMs: clock.peerNow(calibrated, 210), expiresAtMs: 110000});
  assert.doesNotThrow(() => protocol.verifyRequest({request, node: b, peer, nowMs: 100200}));
  const reply = protocol.signResponse({node: b, request, body: {accepted: true}, nowMs: 100250});
  assert.throws(() => protocol.verifyResponse({response: reply, request, publicKey: b.publicKey, nowMs: 94000}), /RESPONSE_BINDING_INVALID/);
  assert.deepEqual(protocol.verifyResponse({response: reply, request, publicKey: b.publicKey, nowMs: clock.peerNow(calibrated, 310)}), {accepted: true});
});
test('clock challenge rejects wrong peer, recipient, signature, route and extra fields', () => {
  const {b, c, challenge, peer} = fixture();
  const verify = value => clock.verifyChallenge({challenge: value, node: b, peer});
  for (const mutate of [x => {x.body.nonce = '0'.repeat(32);}, x => {x.body.route = '/v1/collaboration';},
    x => {x.body.recipient = c.meta.fingerprint;}, x => {x.extra = true;}, x => {x.signature = '!';}]) {
    const copy = clone(challenge); mutate(copy); assert.throws(() => verify(copy), /CLOCK_CHALLENGE_INVALID/);
  }
  assert.throws(() => clock.verifyChallenge({challenge, node: b, peer: {...peer, publicKey: c.publicKey}}), /CLOCK_CHALLENGE_INVALID/);
});
test('clock reply is bound to its fresh challenge and cannot be replayed into the next exchange', () => {
  const {a, b, c, challenge, response} = fixture();
  const input = {response, challenge, publicKey: b.publicKey, startMonoMs: 1, endMonoMs: 2};
  const next = clock.makeChallenge({node: a, to: b.meta.fingerprint});
  assert.throws(() => clock.verifyClockResponse({...input, challenge: next}), /CLOCK_RESPONSE_INVALID/);
  assert.throws(() => clock.verifyClockResponse({...input, publicKey: c.publicKey}), /CLOCK_RESPONSE_INVALID/);
  for (const mutate of [x => {x.body.serverTimeMs++;}, x => {x.body.recipient = c.meta.fingerprint;},
    x => {x.body.policyVersion = 'relaxed';}, x => {x.extra = 1;}, x => {x.signature = challenge.signature;}]) {
    const copy = clone(response); mutate(copy); assert.throws(() => clock.verifyClockResponse({...input, response: copy}), /CLOCK_RESPONSE_INVALID/);
  }
});
test('clock samples reject unbounded RTT and impossible monotonic time', () => {
  const {b, challenge, response} = fixture();
  for (const [startMonoMs, endMonoMs] of [[1, 2002], [2, 1], [-1, 1], [NaN, 2], [1, Infinity]]) {
    assert.throws(() => clock.verifyClockResponse({response, challenge, publicKey: b.publicKey, startMonoMs, endMonoMs}), /CLOCK_RTT_UNSAFE/);
  }
});
test('calibration expires and rejects monotonic rollback without extending authority', () => {
  const {b, challenge, response} = fixture();
  const calibrated = clock.verifyClockResponse({response, challenge, publicKey: b.publicKey, startMonoMs: 1, endMonoMs: 101});
  assert.equal(clock.peerNow(calibrated, 30101), 130050);
  for (const time of [30102, 100, NaN, Infinity]) assert.throws(() => clock.peerNow(calibrated, time), /CLOCK_CALIBRATION_STALE/);
  for (const nowMs of [0, -1, 0.5, NaN, Infinity]) assert.throws(() => clock.signClockResponse({node: b, challenge, nowMs}), /CLOCK_RESPONSE_INVALID/);
});
