'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { createHmac, X509Certificate } = require('node:crypto');
const {
  SCHEMA, VERSION, MAX_TOKEN_BYTES, MAX_CAVEATS, MAX_LIFETIME_MS,
  CapabilityError, issue, attenuate, verify, keyBindingForCertificate,
} = require('../capability.cjs');
const fixture = require('../fixtures/capability-v1.json');
const rootKey = Buffer.from(fixture.rootKeyHex, 'hex');
const nowMs = fixture.nowMs;

function claims(changes = {}) {
  return { ...structuredClone(fixture.claims), ...changes };
}

function context(changes = {}) {
  const c = fixture.claims;
  return {
    rootKey, nowMs, channelAuthenticated: true,
    issuer: c.issuer, issuerKeyId: c.issuerKeyId, audience: c.audience,
    peer: c.peer, keyBinding: c.keyBinding, issuerEpoch: c.issuerEpoch,
    policyVersion: c.policyVersion, operation: 'evidence.ingest.v1',
    resource: c.resources[0], requestBytes: 100,
    ...changes,
  };
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function unpack(token) {
  return JSON.parse(Buffer.from(token.slice('mcap1.'.length), 'base64url').toString());
}

function pack(envelope) {
  return 'mcap1.' + Buffer.from(canonical(envelope)).toString('base64url');
}

function rejects(fn, code) {
  assert.throws(fn, (error) => {
    assert.ok(error instanceof CapabilityError, `unexpected error type: ${error.name}`);
    if (code) assert.equal(error.code, code);
    assert.match(error.message, /^Capability denied \(CAP_[A-Z_]+\)$/);
    assert.ok(!error.message.includes(fixture.baseToken));
    assert.ok(!error.message.includes(fixture.claims.peer));
    return true;
  });
}

test('base token bytes match the independent Python stdlib oracle', () => {
  assert.equal(issue({ rootKey, claims: claims(), nowMs }), fixture.baseToken);
  const result = verify(fixture.baseToken, context());
  assert.equal(result.grantId, fixture.claims.grantId);
  assert.equal(result.usageLimit, 3);
  assert.equal(result.expiresAtMs, nowMs + 120_000);
});

test('attenuation bytes match the independent oracle and preserve root grant identity', () => {
  assert.equal(attenuate(fixture.baseToken, fixture.caveats), fixture.attenuatedToken);
  const result = verify(fixture.attenuatedToken, context({ operation: 'receipt.read.v1' }));
  assert.equal(result.grantId, fixture.expected.grantId);
  assert.equal(result.usageLimit, fixture.expected.usageLimit);
  assert.equal(result.grantUsageLimit, fixture.expected.grantUsageLimit);
  assert.equal(result.expiresAtMs, fixture.expected.expiresAtMs);
  assert.deepEqual(result.claims.scopes, fixture.expected.scopes);
  assert.equal(result.claims.limits.maxBytes, fixture.expected.maxBytes);
});

test('independent attenuation steps yield the same bytes as one combined attenuation', () => {
  let token = fixture.baseToken;
  for (const caveat of fixture.caveats) token = attenuate(token, [caveat]);
  assert.equal(token, fixture.attenuatedToken);
});

test('token alone and absent/false channel authentication are refused', () => {
  rejects(() => verify(fixture.baseToken), 'CAP_CHANNEL');
  rejects(() => verify(fixture.baseToken, context({ channelAuthenticated: undefined })), 'CAP_CHANNEL');
  rejects(() => verify(fixture.baseToken, context({ channelAuthenticated: false })), 'CAP_CHANNEL');
  rejects(() => verify(fixture.baseToken, context({ channelAuthenticated: 'true' })), 'CAP_CHANNEL');
});

test('wrong issuer key cannot authenticate a token', () => {
  rejects(() => verify(fixture.baseToken, context({ rootKey: Buffer.alloc(32, 42) })), 'CAP_SIGNATURE');
});

test('every configured identity, audience and policy context is checked', () => {
  for (const field of ['issuer', 'issuerKeyId', 'audience', 'peer', 'policyVersion']) {
    rejects(() => verify(fixture.baseToken, context({ [field]: 'different' })), 'CAP_CONTEXT');
    rejects(() => verify(fixture.baseToken, context({ [field]: undefined })), 'CAP_INVALID');
  }
  rejects(() => verify(fixture.baseToken, context({ issuerEpoch: 5 })), 'CAP_CONTEXT');
  rejects(() => verify(fixture.baseToken, context({ keyBinding: 'sha256:' + 'c'.repeat(64) })), 'CAP_CONTEXT');
});

test('no wildcard, prefix or implicit new-operation authorization', () => {
  rejects(() => verify(fixture.baseToken, context({ operation: 'evidence.ingest.v2' })), 'CAP_SCOPE');
  rejects(() => verify(fixture.baseToken, context({ resource: fixture.claims.resources[0] + '/extra' })), 'CAP_RESOURCE');
  rejects(() => issue({ rootKey, claims: claims({ scopes: ['*'] }), nowMs }), 'CAP_INVALID');
  rejects(() => issue({ rootKey, claims: claims({ resources: ['*'] }), nowMs }), 'CAP_INVALID');
});

test('claims cannot be changed, added or removed without a valid issuer MAC', () => {
  const envelope = unpack(fixture.baseToken);
  envelope.claims.scopes = ['device.control.v1'];
  rejects(() => verify(pack(envelope), context({ operation: 'device.control.v1' })), 'CAP_SIGNATURE');
  const missing = unpack(fixture.baseToken);
  delete missing.claims.grantId;
  rejects(() => verify(pack(missing), context()), 'CAP_INVALID');
  const extra = unpack(fixture.baseToken);
  extra.claims.admin = true;
  rejects(() => verify(pack(extra), context()), 'CAP_INVALID');
});

test('changed, removed or reordered caveats fail the chained MAC', () => {
  for (const mutate of [
    (c) => { c[1].value = 3; },
    (c) => { c.pop(); },
    (c) => { [c[0], c[1]] = [c[1], c[0]]; },
  ]) {
    const envelope = unpack(fixture.attenuatedToken);
    mutate(envelope.caveats);
    rejects(() => verify(pack(envelope), context({ operation: 'receipt.read.v1' })), 'CAP_SIGNATURE');
  }
});

test('adding broader scope or limits never restores removed authority', () => {
  const token = attenuate(fixture.attenuatedToken, [
    { field: 'scopes', value: ['device.control.v1', 'evidence.ingest.v1', 'receipt.read.v1'] },
    { field: 'limits.uses', value: 20 },
    { field: 'limits.maxBytes', value: 100_000 },
    { field: 'expiresAtMs', value: nowMs + 1_000_000 },
  ]);
  const result = verify(token, context({ operation: 'receipt.read.v1' }));
  assert.equal(result.usageLimit, 1);
  assert.equal(result.expiresAtMs, fixture.expected.expiresAtMs);
  assert.equal(result.claims.limits.maxBytes, 1024);
  rejects(() => verify(token, context()), 'CAP_SCOPE');
  rejects(() => verify(token, context({ operation: 'device.control.v1' })), 'CAP_SCOPE');
});

test('nonintersecting scope and resource restrictions produce no matching authority', () => {
  const scopeToken = attenuate(fixture.baseToken, [{ field: 'scopes', value: ['artifact.fetch.v1'] }]);
  rejects(() => verify(scopeToken, context()), 'CAP_SCOPE');
  rejects(() => verify(scopeToken, context({ operation: 'artifact.fetch.v1' })), 'CAP_SCOPE');
  const resourceToken = attenuate(fixture.baseToken, [{ field: 'resources', value: ['sha256:' + 'c'.repeat(64)] }]);
  rejects(() => verify(resourceToken, context()), 'CAP_RESOURCE');
});

test('key, peer and grant binding cannot be transferred by another caveat', () => {
  for (const caveat of [
    { field: 'keyBinding', value: 'sha256:' + 'c'.repeat(64) },
    { field: 'peer', value: 'another-peer' },
    { field: 'grantId', value: 'another-grant' },
    { field: 'audience', value: 'another-service' },
    { field: 'issuerEpoch', value: 5 },
    { field: 'policyVersion', value: 'another-policy' },
  ]) {
    const token = attenuate(fixture.baseToken, [caveat]);
    rejects(() => verify(token, context()), 'CAP_RESTRICTED');
  }
});

test('time checks are inclusive at not-before and exclusive at expiry', () => {
  verify(fixture.baseToken, context({ nowMs }));
  verify(fixture.baseToken, context({ nowMs: nowMs + MAX_LIFETIME_MS - 1 }));
  rejects(() => verify(fixture.baseToken, context({ nowMs: nowMs - 1 })), 'CAP_TIME');
  rejects(() => verify(fixture.baseToken, context({ nowMs: nowMs + MAX_LIFETIME_MS })), 'CAP_TIME');
});

test('time attenuation can only shrink the accepted interval', () => {
  const token = attenuate(fixture.baseToken, [
    { field: 'notBeforeMs', value: nowMs + 10_000 },
    { field: 'notBeforeMs', value: nowMs - 10_000 },
    { field: 'expiresAtMs', value: nowMs + 20_000 },
    { field: 'expiresAtMs', value: nowMs + 40_000 },
  ]);
  rejects(() => verify(token, context()), 'CAP_TIME');
  verify(token, context({ nowMs: nowMs + 10_000 }));
  rejects(() => verify(token, context({ nowMs: nowMs + 20_000 })), 'CAP_TIME');
});

test('contradictory time caveats never authorize a request', () => {
  const token = attenuate(fixture.baseToken, [{ field: 'notBeforeMs', value: nowMs + 200_000 }]);
  rejects(() => verify(token, context({ nowMs: nowMs + 200_000 })), 'CAP_TIME');
});

test('issuer refuses lifetime beyond 120 seconds, expired tokens and far future issuance', () => {
  rejects(() => issue({ rootKey, claims: claims({ expiresAtMs: nowMs + 120_001 }), nowMs }), 'CAP_TIME');
  rejects(() => issue({ rootKey, claims: claims(), nowMs: nowMs + 120_000 }), 'CAP_TIME');
  rejects(() => issue({ rootKey, claims: claims({ notBeforeMs: nowMs + 120_000, expiresAtMs: nowMs + 240_000 }), nowMs }), 'CAP_TIME');
});

test('byte limit and concurrency/use attenuation cannot be bypassed', () => {
  verify(fixture.attenuatedToken, context({ operation: 'receipt.read.v1', requestBytes: 1024 }));
  rejects(() => verify(fixture.attenuatedToken, context({ operation: 'receipt.read.v1', requestBytes: 1025 })), 'CAP_LIMIT');
  for (const field of ['limits.uses', 'limits.maxConcurrent']) {
    rejects(() => verify(attenuate(fixture.baseToken, [{ field, value: 0 }]), context()), 'CAP_LIMIT');
  }
  const emptyBodyOnly = attenuate(fixture.baseToken, [{ field: 'limits.maxBytes', value: 0 }]);
  verify(emptyBodyOnly, context({ requestBytes: 0 }));
  rejects(() => verify(emptyBodyOnly, context({ requestBytes: 1 })), 'CAP_LIMIT');
});

test('verifier exposes stable shared-grant budget without pretending to consume it', () => {
  const resultA = verify(fixture.attenuatedToken, context({ operation: 'receipt.read.v1' }));
  const another = attenuate(fixture.baseToken, [{ field: 'limits.uses', value: 2 }]);
  const resultB = verify(another, context());
  assert.equal(resultA.grantId, resultB.grantId);
  assert.equal(resultA.grantUsageLimit, resultB.grantUsageLimit);
  assert.equal(resultB.usageLimit, 2);
  assert.deepEqual(verify(fixture.attenuatedToken, context({ operation: 'receipt.read.v1' })), resultA);
});

test('unknown caveats and third-party/discharge fields are rejected', () => {
  rejects(() => attenuate(fixture.baseToken, [{ field: 'allowEverything', value: true }]), 'CAP_CAVEAT');
  rejects(() => attenuate(fixture.baseToken, [{ field: 'scopes', value: ['receipt.read.v1'], location: 'untrusted' }]), 'CAP_INVALID');
  const unknown = unpack(fixture.baseToken);
  unknown.discharges = [];
  rejects(() => verify(pack(unknown), context()), 'CAP_INVALID');
});

test('missing, unknown, duplicate and ambiguous claims are rejected at issue time', () => {
  for (const field of Object.keys(fixture.claims)) {
    const c = claims();
    delete c[field];
    rejects(() => issue({ rootKey, claims: c, nowMs }), 'CAP_INVALID');
  }
  rejects(() => issue({ rootKey, claims: claims({ unknown: 'x' }), nowMs }), 'CAP_INVALID');
  rejects(() => issue({ rootKey, claims: claims({ scopes: ['receipt.read.v1', 'receipt.read.v1'] }), nowMs }), 'CAP_INVALID');
  rejects(() => issue({ rootKey, claims: claims({ scopes: ['receipt.read.v1', 'evidence.ingest.v1'] }), nowMs }), 'CAP_INVALID');
});

test('unsupported schema or format versions are refused', () => {
  assert.equal(SCHEMA, fixture.claims.schema);
  assert.equal(VERSION, fixture.claims.version);
  rejects(() => issue({ rootKey, claims: claims({ schema: 'mikaya.act.capability.v2' }), nowMs }), 'CAP_VERSION');
  rejects(() => issue({ rootKey, claims: claims({ version: 2 }), nowMs }), 'CAP_VERSION');
  rejects(() => verify(fixture.baseToken.replace('mcap1.', 'mcap2.'), context()), 'CAP_VERSION');
});

test('invalid numerical representations and arbitrary identifiers are refused', () => {
  for (const value of [NaN, Infinity, -1, -0, 1.5, Number.MAX_SAFE_INTEGER + 1, '4']) {
    rejects(() => issue({ rootKey, claims: claims({ issuerEpoch: value }), nowMs }), 'CAP_INVALID');
    rejects(() => verify(fixture.baseToken, context({ requestBytes: value })), 'CAP_INVALID');
  }
  for (const value of ['', 'contains a space', 'a\nb', 'unicode-\u202e', '*', 'x'.repeat(129)]) {
    rejects(() => issue({ rootKey, claims: claims({ peer: value }), nowMs }), 'CAP_INVALID');
  }
});

test('duplicate JSON keys, whitespace and alternate encodings are refused', () => {
  const wire = Buffer.from(fixture.baseToken.slice('mcap1.'.length), 'base64url').toString();
  for (const changed of [
    wire.replace('"version":1', '"version":1,"version":1'),
    wire.replace('"version":1', '"version":1.0'),
    wire.replace('"version":1', '"version":1e0'),
    wire.replace('"peer"', '"p\\u0065er"'),
    wire + '\n',
    JSON.stringify(JSON.parse(wire), null, 2),
  ]) rejects(() => verify('mcap1.' + Buffer.from(changed).toString('base64url'), context()), 'CAP_INVALID');
  rejects(() => verify(fixture.baseToken + '=', context()), 'CAP_INVALID');
  rejects(() => verify(fixture.baseToken + '\n', context()), 'CAP_INVALID');
});

test('malformed, non-JSON, invalid UTF-8 and deeply nested input fail boundedly', () => {
  for (const input of [
    null, {}, 123, 'mcap1.', 'mcap1.@@',
    'mcap1.' + Buffer.from('not json').toString('base64url'),
    'mcap1.' + Buffer.from([0xff, 0xfe]).toString('base64url'),
    'mcap1.' + Buffer.from('['.repeat(900) + '0' + ']'.repeat(900)).toString('base64url'),
  ]) rejects(() => verify(input, context()));
});

test('4 KiB and 16 caveat budgets are enforced on every entry path', () => {
  rejects(() => verify('mcap1.' + 'a'.repeat(MAX_TOKEN_BYTES), context()), 'CAP_SIZE');
  const caveat = { field: 'limits.uses', value: 1 };
  const atLimit = attenuate(fixture.baseToken, Array.from({ length: MAX_CAVEATS }, () => caveat));
  verify(atLimit, context());
  rejects(() => attenuate(atLimit, [caveat]), 'CAP_SIZE');
  const over = unpack(atLimit);
  over.caveats.push(caveat);
  rejects(() => verify(pack(over), context()), 'CAP_SIZE');
  const longResources = Array.from({ length: 16 }, (_, i) => `r${String(i).padStart(2, '0')}` + 'a'.repeat(189));
  rejects(() => issue({ rootKey, claims: claims({ resources: longResources }), nowMs }), 'CAP_SIZE');
});

test('untrusted accessor/prototype objects are not issuer claims', () => {
  const getterClaims = claims();
  Object.defineProperty(getterClaims, 'peer', { enumerable: true, get() { throw new Error('must not run'); } });
  rejects(() => issue({ rootKey, claims: getterClaims, nowMs }), 'CAP_INVALID');
  rejects(() => issue({ rootKey, claims: Object.assign(Object.create({ admin: true }), claims()), nowMs }), 'CAP_INVALID');
});

test('root key must contain at least 256 bits of supplied binary key material', () => {
  for (const rootKey of ['not-a-secret', Buffer.alloc(0), Buffer.alloc(31), Buffer.alloc(65)]) {
    rejects(() => issue({ rootKey, claims: claims(), nowMs }), 'CAP_KEY');
  }
});

test('renewed certificates with the same public key have the same SPKI binding', () => {
  const certA = new X509Certificate(readFileSync(path.join(__dirname, '../fixtures/capability-cert-a.public-cert.txt')));
  const certB = new X509Certificate(readFileSync(path.join(__dirname, '../fixtures/capability-cert-b.public-cert.txt')));
  const expected = readFileSync(path.join(__dirname, '../fixtures/capability-cert-spki.sha256'), 'utf8').trim();
  assert.notEqual(certA.fingerprint256, certB.fingerprint256);
  assert.equal(keyBindingForCertificate(certA.raw), expected);
  assert.equal(keyBindingForCertificate(certB.raw), expected);
});

test('invalid certificate failures do not expose parser internals', () => {
  for (const cert of [undefined, 'not DER', Buffer.alloc(0), Buffer.from('not a certificate'), Buffer.alloc(65537)]) {
    rejects(() => keyBindingForCertificate(cert), 'CAP_CERTIFICATE');
  }
});

test('all capability outputs are detached from mutable issuer inputs', () => {
  const c = claims();
  const token = issue({ rootKey, claims: c, nowMs });
  c.limits.uses = 999;
  const verified = verify(token, context());
  verified.claims.limits.uses = 1000;
  assert.equal(verify(token, context()).usageLimit, 3);
});

test('a bearer cannot forge a new root by reusing the exposed final MAC as a key', () => {
  const envelope = unpack(fixture.attenuatedToken);
  const forged = claims({ scopes: ['device.control.v1'] });
  const fakeMac = createHmac('sha256', Buffer.from(envelope.mac, 'hex'))
    .update('MIKAYA-ACT-CAPABILITY-V1-ROOT\0').update(canonical(forged)).digest('hex');
  rejects(() => verify(pack({ claims: forged, caveats: [], mac: fakeMac }), context({ operation: 'device.control.v1' })), 'CAP_SIGNATURE');
});
