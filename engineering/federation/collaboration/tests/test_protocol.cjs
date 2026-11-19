'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const protocol = require('../protocol.cjs');
const fed = require('../../live/federation-node.cjs');

function identity() {
  const keys = crypto.generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({type: 'spki', format: 'pem'});
  return {meta: {fingerprint: fed.fp(publicKey)}, publicKey, privateKey: keys.privateKey};
}
function setup() {
  const a = identity(), b = identity(), outsider = identity();
  const peer = {fingerprint: a.meta.fingerprint, publicKey: a.publicKey};
  const input = {node: a, to: b.meta.fingerprint, capability: 'test-credential-only', operation: 'evidence.ingest.v1',
    resource: 'evidence:fixture', payload: {measurement: 7}, transactionId: 'immutable-transaction-1',
    expiresAtMs: 120000, nowMs: 10000, nonce: '1'.repeat(32)};
  const request = protocol.makeRequest(input);
  return {a, b, outsider, peer, input, request};
}
const clone = object => JSON.parse(JSON.stringify(object));

test('request and response signatures round-trip with expected participant fingerprints', () => {
  const {a, b, peer, request} = setup();
  assert.deepEqual(protocol.verifyRequest({request, node: b, peer, nowMs: 10001}), request.intent);
  const response = protocol.signResponse({node: b, request, body: {accepted: true}, nowMs: 10002});
  assert.deepEqual(protocol.verifyResponse({response, request, publicKey: b.publicKey, nowMs: 10003}), {accepted: true});
  assert.equal(response.auth.recipient, a.meta.fingerprint);
});

test('payload, credential and stable-intent modifications are signature-bound', () => {
  const {b, peer, request} = setup();
  for (const mutate of [value => { value.payload.measurement++; }, value => { value.capability += '.changed'; },
    value => { value.intent.operation = 'artifact.fetch.v1'; }, value => { value.intent.transactionId = 'different-id'; }]) {
    const value = clone(request); mutate(value);
    assert.throws(() => protocol.verifyRequest({request: value, node: b, peer, nowMs: 10000}));
  }
});

test('wrong recipient and unrecognized peer are rejected', () => {
  const {b, outsider, peer, request} = setup();
  assert.throws(() => protocol.verifyRequest({request, node: outsider, peer, nowMs: 10000}), /INTENT_BINDING_INVALID/);
  assert.throws(() => protocol.verifyRequest({request, node: b, peer: {fingerprint: outsider.meta.fingerprint, publicKey: outsider.publicKey}, nowMs: 10000}), /INTENT_BINDING_INVALID/);
});

test('a public key cannot be paired with another declared peer fingerprint', () => {
  const {a, b, outsider, input} = setup();
  const impostor = {meta: a.meta, privateKey: outsider.privateKey};
  const request = protocol.makeRequest({...input, node: impostor});
  assert.throws(() => protocol.verifyRequest({request, node: b,
    peer: {fingerprint: a.meta.fingerprint, publicKey: outsider.publicKey}, nowMs: 10000}));
});

test('expired immutable intent is refused even with a fresh valid attempt', () => {
  const {b, peer, input} = setup();
  const request = protocol.makeRequest({...input, expiresAtMs: 10000});
  assert.throws(() => protocol.verifyRequest({request, node: b, peer, nowMs: 10000}));
});

test('attempt nonce, route, method and timestamp are covered by the request signature', () => {
  const {b, peer, request} = setup();
  for (const mutation of [{nonce: '2'.repeat(32)}, {route: '/v1/task'}, {method: 'GET'}, {issuedAtMs: 10001}]) {
    const value = clone(request); Object.assign(value.attempt, mutation);
    assert.throws(() => protocol.verifyRequest({request: value, node: b, peer, nowMs: 10001}));
  }
});

test('old and excessively future attempts fail with valid signatures', () => {
  const {b, peer, input} = setup();
  assert.throws(() => protocol.verifyRequest({request: protocol.makeRequest({...input, nowMs: 15001}), node: b, peer, nowMs: 10000}), /ATTEMPT_INVALID_OR_EXPIRED/);
  assert.throws(() => protocol.verifyRequest({request: protocol.makeRequest({...input, nowMs: 10000}), node: b, peer, nowMs: 70001}), /ATTEMPT_INVALID_OR_EXPIRED/);
});

test('nonfinite or noninteger verifier clock values fail closed', () => {
  const {b, peer, request} = setup();
  const response = protocol.signResponse({node: b, request, body: {accepted: true}, nowMs: 10001});
  for (const nowMs of [NaN, Infinity, 0, 10001.5]) {
    assert.throws(() => protocol.verifyRequest({request, node: b, peer, nowMs}));
    assert.throws(() => protocol.verifyResponse({response, request, publicKey: b.publicKey, nowMs}));
  }
});

test('an authenticated retry changes attempt metadata while preserving immutable intent digest', () => {
  const {b, peer, input, request} = setup();
  const retry = protocol.makeRequest({...input, intent: request.intent, nowMs: 10002,
    nonce: '2'.repeat(32), capability: 'fresh-credential-for-same-intent'});
  assert.deepEqual(retry.intent, request.intent);
  assert.equal(retry.attempt.intentSha256, request.attempt.intentSha256);
  assert.notEqual(retry.attempt.capabilitySha256, request.attempt.capabilitySha256);
  assert.notEqual(retry.signature, request.signature);
  assert.deepEqual(protocol.verifyRequest({request: retry, node: b, peer, nowMs: 10002}), request.intent);
});

test('response binds content, recipient, request nonce and immutable intent', () => {
  const {b, input, request} = setup();
  const response = protocol.signResponse({node: b, request, body: {accepted: true}, nowMs: 10001});
  for (const mutate of [value => { value.body.accepted = false; }, value => { value.auth.recipient = 'a'.repeat(64); },
    value => { value.auth.inReplyTo = '2'.repeat(32); }, value => { value.auth.intentSha256 = 'b'.repeat(64); }]) {
    const value = clone(response); mutate(value);
    assert.throws(() => protocol.verifyResponse({response: value, request, publicKey: b.publicKey, nowMs: 10002}), /RESPONSE_BINDING_INVALID/);
  }
  const retry = protocol.makeRequest({...input, intent: request.intent, nowMs: 10002, nonce: '2'.repeat(32)});
  assert.throws(() => protocol.verifyResponse({response, request: retry, publicKey: b.publicKey, nowMs: 10002}), /RESPONSE_BINDING_INVALID/);
});

test('response refuses wrong key, stale timestamp and request-domain signature', () => {
  const {b, outsider, request} = setup();
  const response = protocol.signResponse({node: b, request, body: {accepted: true}, nowMs: 10001});
  assert.throws(() => protocol.verifyResponse({response, request, publicKey: outsider.publicKey, nowMs: 10002}), /RESPONSE_BINDING_INVALID/);
  assert.throws(() => protocol.verifyResponse({response, request, publicKey: b.publicKey, nowMs: 70002}), /RESPONSE_BINDING_INVALID/);
  assert.throws(() => protocol.verifyResponse({response: {...response, signature: request.signature}, request, publicKey: b.publicKey, nowMs: 10002}), /RESPONSE_BINDING_INVALID/);
});

test('request and response require exact envelopes and canonical signature encoding', () => {
  const {b, peer, request} = setup();
  for (const signature of [request.signature + '\n', '!', Buffer.alloc(64).toString('base64')]) {
    assert.throws(() => protocol.verifyRequest({request: {...request, signature}, node: b, peer, nowMs: 10000}));
  }
  assert.throws(() => protocol.verifyRequest({request: {...request, ignored: true}, node: b, peer, nowMs: 10000}), /REQUEST_SHAPE_INVALID/);
  const response = protocol.signResponse({node: b, request, body: null, nowMs: 10001});
  assert.throws(() => protocol.verifyResponse({response: {...response, ignored: true}, request, publicKey: b.publicKey, nowMs: 10001}), /RESPONSE_SHAPE_INVALID/);
});

test('canonical parser accepts the one wire encoding and rejects duplicate keys or spelling aliases', () => {
  const value = {a: ['one', 2], b: {ready: true}};
  assert.deepEqual(protocol.parseCanonical(Buffer.from(protocol.canonical(value))), value);
  for (const raw of ['{"a":1,"a":2}', '{"b":2,"a":1}', '{ "a":1}', '{"a":1.0}', '{"a":1e0}', '{"a":-0}', '{"a":"\\u0061"}']) {
    assert.throws(() => protocol.parseCanonical(Buffer.from(raw)), /NONCANONICAL_JSON/);
  }
});

test('canonical parser refuses invalid UTF-8, excessive depth and oversized input', () => {
  assert.throws(() => protocol.parseCanonical(Buffer.from([0x22, 0xc3, 0x28, 0x22])), /NONCANONICAL_JSON/);
  const deep = '['.repeat(18) + '0' + ']'.repeat(18);
  assert.throws(() => protocol.parseCanonical(Buffer.from(deep)), /JSON_DEPTH_REFUSED/);
  assert.throws(() => protocol.parseCanonical(Buffer.alloc(8193, 32)), /MESSAGE_TOO_LARGE/);
  assert.throws(() => protocol.parseCanonical('not a buffer'), /MESSAGE_TOO_LARGE/);
});

test('prototype fields, noninteger numeric values and payload mismatch are refused', () => {
  assert.throws(() => protocol.parseCanonical(Buffer.from('{"__proto__":{}}')), /JSON_KEY_REFUSED/);
  assert.throws(() => protocol.parseCanonical(Buffer.from('{"value":1.5}')), /JSON_VALUE_REFUSED/);
  const {input, request} = setup();
  assert.throws(() => protocol.makeRequest({...input, intent: request.intent, payload: {measurement: 8}}), /INTENT_PAYLOAD_MISMATCH/);
});
