'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const federation = require('../../live/federation-node.cjs');
const {
  DOMAIN, CHUNK_SIZE, MAX_BYTES, signManifest, verifyManifest, digestManifest,
  readChunk, manifestResource, chunkResource, createReceiver,
} = require('../distribution.cjs');

function setup(t, size = 131109) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'mikaya-distribution-test-'));
  const keys = crypto.generateKeyPairSync('ed25519');
  const expectedPublisher = federation.fp(keys.publicKey);
  const nowMs = Date.now();
  const bytes = Buffer.alloc(size);
  for (let i = 0; i < size; i++) bytes[i] = i % 251;
  const manifest = signManifest({ bytes, artifactId: 'public-toybox-fixture', version: '1.0.0', sequence: 1, ...keys, nowMs });
  const directory = path.join(parent, 'receiver');
  const open = (changes = {}) => createReceiver({ directory, manifest, publisherPublicKey: keys.publicKey,
    expectedPublisher, nowMs, ...changes });
  const issue = (changes = {}) => signManifest({ bytes, artifactId: manifest.artifactId, version: '1.0.0', sequence: 1, ...keys, nowMs, ...changes });
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  return { parent, directory, keys, expectedPublisher, nowMs, bytes, manifest, open, issue };
}

function verify(f, manifest = f.manifest, changes = {}) {
  return verifyManifest({ manifest, publisherPublicKey: f.keys.publicKey, expectedPublisher: f.expectedPublisher,
    nowMs: f.nowMs, ...changes });
}
function reject(fn, code) {
  assert.throws(fn, error => { assert.equal(error.code, code); assert.ok(error.message.length < 100); return true; });
}
function signChanged(manifest, fields, privateKey) {
  const { signature, ...body } = { ...manifest, ...fields };
  return { ...body, signature: crypto.sign(null, Buffer.from(DOMAIN + federation.canonical(body)), privateKey).toString('base64') };
}

test('signed manifest pins original federation Ed25519 identity and bounded chunks', t => {
  const f = setup(t);
  const result = verify(f);
  assert.equal(result.publisher, federation.fp(f.keys.publicKey));
  assert.equal(result.length, 131109);
  assert.equal(result.chunks, 3);
  assert.deepEqual(f.manifest.chunks.map(c => c.length), [65536, 65536, 37]);
  assert.ok(Buffer.byteLength(federation.canonical(f.manifest)) <= 8192);
  assert.equal(manifestResource(result.manifestDigest), `manifest:${result.manifestDigest}`);
  assert.equal(chunkResource(result.manifestDigest, 2), `manifest:${result.manifestDigest}:chunk:2`);
});

test('manifest tampering, wrong publisher and wrong expected digest are rejected', t => {
  const f = setup(t);
  reject(() => verify(f, { ...f.manifest, version: 'malicious' }), 'DISTRIBUTION_SIGNATURE_INVALID');
  reject(() => verify(f, f.manifest, { expectedPublisher: 'a'.repeat(64) }), 'DISTRIBUTION_PUBLISHER_MISMATCH');
  const other = crypto.generateKeyPairSync('ed25519');
  reject(() => verify(f, f.manifest, { publisherPublicKey: other.publicKey }), 'DISTRIBUTION_PUBLISHER_MISMATCH');
  reject(() => verify(f, f.manifest, { expectedManifestDigest: 'a'.repeat(64) }), 'DISTRIBUTION_MANIFEST_DIGEST_MISMATCH');
  reject(() => verify(f, f.manifest, { expectedArtifactId: 'other' }), 'DISTRIBUTION_ARTIFACT_MISMATCH');
});

test('future, expired and excessive-lifetime manifests are refused', t => {
  const f = setup(t);
  reject(() => verify(f, f.manifest, { nowMs: f.nowMs - 1 }), 'DISTRIBUTION_MANIFEST_EXPIRED_OR_FUTURE');
  reject(() => verify(f, f.manifest, { nowMs: f.manifest.expiresAtMs }), 'DISTRIBUTION_MANIFEST_EXPIRED_OR_FUTURE');
  reject(() => f.issue({ expiresAtMs: f.nowMs + 86400001 }), 'DISTRIBUTION_ISSUE_INVALID');
});

test('path-like artifact labels, unknown fields and malformed chunk metadata fail', t => {
  const f = setup(t);
  for (const artifactId of ['../outside', '/absolute', 'a/../../b', '.', '..', 'a\\b']) {
    reject(() => f.issue({ artifactId }), 'DISTRIBUTION_ISSUE_INVALID');
    reject(() => verify(f, signChanged(f.manifest, { artifactId }, f.keys.privateKey)), 'DISTRIBUTION_MANIFEST_INVALID');
  }
  reject(() => verify(f, { ...f.manifest, path: '/tmp/anything' }), 'DISTRIBUTION_MANIFEST_INVALID');
  const changed = structuredClone(f.manifest);
  changed.chunks[0].offset = 1;
  reject(() => verify(f, changed), 'DISTRIBUTION_CHUNK_METADATA_INVALID');
});

test('non-Ed25519 signing and mismatched signer keys are refused', t => {
  const f = setup(t);
  const other = crypto.generateKeyPairSync('ed25519');
  reject(() => f.issue({ publicKey: other.publicKey }), 'DISTRIBUTION_KEY_MISMATCH');
  const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  reject(() => f.issue({ privateKey: ec.privateKey, publicKey: ec.publicKey }), 'DISTRIBUTION_KEY_TYPE');
});

test('publisher checks entire immutable source before serving any chunk', t => {
  const f = setup(t);
  assert.deepEqual(readChunk(f.bytes, f.manifest, 0), f.bytes.subarray(0, CHUNK_SIZE));
  const changed = Buffer.from(f.bytes);
  changed[changed.length - 1] ^= 1;
  reject(() => readChunk(changed, f.manifest, 0), 'DISTRIBUTION_SOURCE_CHANGED');
  reject(() => readChunk(f.bytes, f.manifest, -1), 'DISTRIBUTION_SOURCE_OR_INDEX_INVALID');
  reject(() => readChunk(f.bytes, f.manifest, 3), 'DISTRIBUTION_SOURCE_OR_INDEX_INVALID');
});

test('receiver verifies bytes, resumes exact manifest and finalizes without activation', t => {
  const f = setup(t);
  let receiver = f.open({ initialize: true });
  assert.deepEqual(receiver.status({ nowMs: f.nowMs }).missingChunks, [0, 1, 2]);
  const first = receiver.acceptChunk({ index: 0, bytes: readChunk(f.bytes, f.manifest, 0), nowMs: f.nowMs });
  assert.equal(first.duplicate, false);
  assert.equal(first.chunkVerified, true);
  assert.equal(first.contentVerified, false);
  assert.equal(first.activationAuthorized, false);
  receiver.close();
  receiver = f.open();
  const resumed = receiver.status({ nowMs: f.nowMs });
  assert.deepEqual(resumed.missingChunks, [1, 2]);
  assert.equal(resumed.verifiedBytes, 65536);
  let transferred = 0;
  for (const index of resumed.missingChunks) {
    const bytes = readChunk(f.bytes, f.manifest, index);
    transferred += bytes.length;
    receiver.acceptChunk({ index, bytes, nowMs: f.nowMs });
  }
  assert.equal(transferred, 65573);
  const final = receiver.finalize({ nowMs: f.nowMs });
  assert.equal(final.contentVerified, true);
  assert.equal(final.activationAuthorized, false);
  assert.equal(final.duplicate, false);
  assert.deepEqual(fs.readFileSync(final.path), f.bytes);
  assert.equal(fs.statSync(final.path).mode & 0o777, 0o600);
  assert.equal(receiver.finalize({ nowMs: f.nowMs }).duplicate, true);
  assert.equal(receiver.status({ nowMs: f.nowMs }).complete, true);
  receiver.close();
});

test('duplicate chunk is idempotent; tampered or oversized network bytes are refused', t => {
  const f = setup(t);
  const receiver = f.open({ initialize: true });
  const bytes = readChunk(f.bytes, f.manifest, 0);
  receiver.acceptChunk({ index: 0, bytes, nowMs: f.nowMs });
  assert.equal(receiver.acceptChunk({ index: 0, bytes, nowMs: f.nowMs }).duplicate, true);
  const bad = Buffer.from(bytes); bad[0] ^= 1;
  reject(() => receiver.acceptChunk({ index: 0, bytes: bad, nowMs: f.nowMs }), 'DISTRIBUTION_CHUNK_HASH_MISMATCH');
  reject(() => receiver.acceptChunk({ index: 0, bytes: Buffer.alloc(65537), nowMs: f.nowMs }), 'DISTRIBUTION_CHUNK_LENGTH');
  reject(() => receiver.finalize({ nowMs: f.nowMs }), 'DISTRIBUTION_INCOMPLETE');
  receiver.close();
});

test('tampered cache cannot be resumed or silently repaired', t => {
  const f = setup(t);
  let receiver = f.open({ initialize: true });
  receiver.acceptChunk({ index: 0, bytes: readChunk(f.bytes, f.manifest, 0), nowMs: f.nowMs });
  receiver.close();
  const file = path.join(f.directory, `chunk-${digestManifest(f.manifest)}-0.bin`);
  const damaged = fs.readFileSync(file); damaged[0] ^= 1; fs.writeFileSync(file, damaged);
  receiver = f.open();
  reject(() => receiver.status({ nowMs: f.nowMs }), 'DISTRIBUTION_CACHE_HASH_MISMATCH');
  reject(() => receiver.acceptChunk({ index: 0, bytes: readChunk(f.bytes, f.manifest, 0), nowMs: f.nowMs }), 'DISTRIBUTION_CACHE_HASH_MISMATCH');
  receiver.close();
});

test('chunk symlinks and hardlinks do not escape the receiver directory', t => {
  const f = setup(t);
  const receiver = f.open({ initialize: true });
  const file = path.join(f.directory, `chunk-${digestManifest(f.manifest)}-0.bin`);
  const outside = path.join(f.parent, 'outside');
  fs.writeFileSync(outside, readChunk(f.bytes, f.manifest, 0), { mode: 0o600 });
  fs.symlinkSync(outside, file);
  reject(() => receiver.acceptChunk({ index: 0, bytes: readChunk(f.bytes, f.manifest, 0), nowMs: f.nowMs }), 'DISTRIBUTION_CACHE_UNSAFE');
  fs.unlinkSync(file);
  let hardlinkCreated = false;
  try {
    fs.linkSync(outside, file);
    hardlinkCreated = true;
  } catch (error) {
    if (process.platform !== 'android' || !['EACCES', 'EPERM'].includes(error.code)) throw error;
    assert.throws(() => fs.lstatSync(file), { code: 'ENOENT' });
    assert.deepEqual(fs.readFileSync(outside), readChunk(f.bytes, f.manifest, 0));
    assert.equal(fs.lstatSync(outside).nlink, 1);
    t.diagnostic(`Native Android kernel blocked hard-link fixture creation (${error.code}); destination absent and source unchanged. Runtime hard-link rejection is exercised when fixture creation is permitted.`);
  }
  if (hardlinkCreated) reject(() => receiver.status({ nowMs: f.nowMs }), 'DISTRIBUTION_CACHE_UNSAFE');
  assert.deepEqual(fs.readFileSync(outside), readChunk(f.bytes, f.manifest, 0));
  receiver.close();
});

test('unsafe receiver directory and competing writer are refused', t => {
  const f = setup(t);
  const receiver = f.open({ initialize: true });
  reject(() => f.open(), 'WRITER_LEASE_HOLD');
  reject(() => f.open({ initialize: true }), 'STATE_INITIALIZATION_REFUSED');
  receiver.close();
  fs.chmodSync(f.directory, 0o755);
  reject(() => f.open(), 'STATE_DIRECTORY_UNSAFE');
  fs.chmodSync(f.directory, 0o700);
  const alias = path.join(f.parent, 'alias'); fs.symlinkSync(f.directory, alias);
  reject(() => f.open({ directory: alias }), 'STATE_DIRECTORY_UNSAFE');
});

test('same sequence with different signed bytes is equivocation', t => {
  const f = setup(t);
  const receiver = f.open({ initialize: true }); receiver.close();
  const alternate = f.issue({ bytes: Buffer.from('different public content') });
  reject(() => f.open({ manifest: alternate }), 'DISTRIBUTION_VERSION_EQUIVOCATION');
});

test('new manifest starts an empty exact-digest cache; old sequence cannot resume', t => {
  const f = setup(t);
  let receiver = f.open({ initialize: true });
  receiver.acceptChunk({ index: 0, bytes: readChunk(f.bytes, f.manifest, 0), nowMs: f.nowMs });
  receiver.close();
  const next = f.issue({ version: '2.0.0', sequence: 2, nowMs: f.nowMs + 1 });
  receiver = f.open({ manifest: next, nowMs: f.nowMs + 1 });
  assert.equal(receiver.status({ nowMs: f.nowMs + 1 }).verifiedBytes, 0);
  assert.deepEqual(receiver.status({ nowMs: f.nowMs + 1 }).missingChunks, [0, 1, 2]);
  receiver.close();
  reject(() => f.open({ nowMs: f.nowMs + 1 }), 'DISTRIBUTION_ROLLBACK_REFUSED');
});

test('a different publisher or artifact cannot reuse receiver state', t => {
  const f = setup(t);
  const receiver = f.open({ initialize: true }); receiver.close();
  const other = crypto.generateKeyPairSync('ed25519');
  const foreign = f.issue({ ...other, sequence: 2 });
  reject(() => f.open({ manifest: foreign, publisherPublicKey: other.publicKey, expectedPublisher: federation.fp(other.publicKey) }), 'DISTRIBUTION_SOURCE_CHANGED');
  reject(() => f.open({ manifest: f.issue({ artifactId: 'other-artifact', sequence: 2 }) }), 'DISTRIBUTION_SOURCE_CHANGED');
});

test('clock rollback and manifest expiry prevent additional fetch acceptance', t => {
  const f = setup(t);
  const receiver = f.open({ initialize: true });
  receiver.status({ nowMs: f.nowMs + 1000 });
  reject(() => receiver.status({ nowMs: f.nowMs + 999 }), 'DISTRIBUTION_CLOCK_ROLLBACK_HOLD');
  reject(() => receiver.acceptChunk({ index: 0, bytes: readChunk(f.bytes, f.manifest, 0), nowMs: f.manifest.expiresAtMs }), 'DISTRIBUTION_MANIFEST_EXPIRED_OR_FUTURE');
  receiver.close();
});

test('whole-object digest is checked independently of valid chunk hashes', t => {
  const f = setup(t, 80);
  const inconsistent = signChanged(f.manifest, { sha256: 'a'.repeat(64) }, f.keys.privateKey);
  const receiver = f.open({ initialize: true, manifest: inconsistent });
  receiver.acceptChunk({ index: 0, bytes: f.bytes, nowMs: f.nowMs });
  reject(() => receiver.finalize({ nowMs: f.nowMs }), 'DISTRIBUTION_WHOLE_HASH_MISMATCH');
  receiver.close();
});

test('partial cache and altered permissions fail closed', t => {
  const f = setup(t);
  const receiver = f.open({ initialize: true });
  const file = path.join(f.directory, `chunk-${digestManifest(f.manifest)}-0.bin`);
  fs.writeFileSync(file, Buffer.alloc(12), { mode: 0o600 });
  reject(() => receiver.status({ nowMs: f.nowMs }), 'DISTRIBUTION_CACHE_UNSAFE');
  fs.unlinkSync(file);
  receiver.acceptChunk({ index: 0, bytes: readChunk(f.bytes, f.manifest, 0), nowMs: f.nowMs });
  fs.chmodSync(file, 0o644);
  reject(() => receiver.status({ nowMs: f.nowMs }), 'DISTRIBUTION_CACHE_UNSAFE');
  receiver.close();
});

test('empty public artifact verifies without inventing a chunk', t => {
  const f = setup(t, 0);
  const receiver = f.open({ initialize: true });
  assert.deepEqual(receiver.status({ nowMs: f.nowMs }).missingChunks, []);
  const result = receiver.finalize({ nowMs: f.nowMs });
  assert.equal(result.length, 0);
  assert.equal(fs.statSync(result.path).size, 0);
  assert.equal(result.activationAuthorized, false);
  receiver.close();
});

test('gateway control budget supports a maximum 1MiB public object and refuses larger input', t => {
  const f = setup(t, MAX_BYTES);
  assert.equal(f.manifest.chunks.length, 16);
  assert.ok(Buffer.byteLength(federation.canonical(f.manifest)) <= 8192);
  assert.equal(readChunk(f.bytes, f.manifest, 15).length, CHUNK_SIZE);
  reject(() => f.issue({ bytes: Buffer.alloc(MAX_BYTES + 1) }), 'DISTRIBUTION_ISSUE_INVALID');
});

test('caller mutation cannot change an already opened receiver contract', t => {
  const f = setup(t, 100);
  const receiver = f.open({ initialize: true });
  f.manifest.chunks[0].sha256 = 'a'.repeat(64);
  f.manifest.artifactId = 'other';
  receiver.acceptChunk({ index: 0, bytes: f.bytes, nowMs: f.nowMs });
  assert.equal(receiver.finalize({ nowMs: f.nowMs }).artifactId, 'public-toybox-fixture');
  receiver.close();
});
