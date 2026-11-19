'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {spawnSync} = require('node:child_process');
const {createArtifactPolicy, validateManifest, RELEASE_DOMAIN} = require('../artifact-policy.cjs');
const {canonical, sha} = require('../transaction-journal.cjs');
const AHAVA = require.resolve('../../../../ahava/core.js');

function fixture(t) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'mikaya-artifact-test-'));
  const directory = path.join(parent, 'artifact-policy');
  t.after(() => fs.rmSync(parent, {recursive: true, force: true}));
  const keys = crypto.generateKeyPairSync('ed25519');
  const pem = keys.publicKey.export({type: 'spki', format: 'pem'});
  return {parent, directory, privateKey: keys.privateKey, pem, publisher: sha(pem)};
}
function signManifest(f, changes = {}, data = Buffer.from('test artifact')) {
  const aes = crypto.randomBytes(32), chunks = [];
  for (let offset = 0; offset < data.length; offset += 65536) {
    const plaintext = data.subarray(offset, offset + 65536), nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', aes, nonce);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    chunks.push({id: sha(encrypted), nonce: nonce.toString('hex'), tag: cipher.getAuthTag().toString('hex'), plainSha256: sha(plaintext), length: plaintext.length});
  }
  const body = {schema: 'ahava.signed-manifest.v1', node: 'fixture', createdAt: new Date(1000).toISOString(),
    name: 'weights.bin', length: data.length, plainSha256: sha(data), chunkSize: 65536, chunks,
    publicKey: f.pem, signer: f.publisher, ...changes};
  return {...body, signature: crypto.sign(null, Buffer.from(canonical(body)), f.privateKey).toString('base64')};
}
function release(f, manifest, changes = {}) {
  const body = {schema: 'mikaya.act.artifact-release.v1', publisher: f.publisher, artifactId: 'model:fixture',
    manifestDigest: sha(canonical(manifest)), sequence: 1, issuedAtMs: 1000, expiresAtMs: 50000, ...changes};
  return {...body, signature: crypto.sign(null, Buffer.from(RELEASE_DOMAIN + canonical(body)), f.privateKey).toString('base64')};
}
function request(f, manifest, metadata = release(f, manifest), changes = {}) {
  return {manifest, release: metadata, publisherPublicKey: f.pem, expectedPublisher: f.publisher,
    expectedManifestDigest: sha(canonical(manifest)), expectedArtifactId: 'model:fixture', nowMs: 2000, ...changes};
}

test('real AHAVA store manifest passes metadata verification without exposing its mesh key', t => {
  const f = fixture(t);
  const run = spawnSync(process.execPath, ['-e', `
    const fs=require('node:fs'),path=require('node:path'),core=require(process.argv[1]);
    const ledger=path.join(process.env.HOME,'sovereign_exec','ledger');
    fs.mkdirSync(ledger,{recursive:true,mode:0o700});
    fs.writeFileSync(path.join(ledger,'.mesh_token'),'ab'.repeat(32),{mode:0o600});
    const input=path.join(process.env.HOME,'artifact.bin');fs.writeFileSync(input,'actual ahava fixture');
    const stored=core.store(input);process.stdout.write(JSON.stringify(core.pack(stored.id).manifest));
  `, AHAVA], {env: {...process.env, HOME: f.parent, AHAVA_NODE: 'fixture'}, encoding: 'utf8', timeout: 3000});
  assert.equal(run.status, 0, run.stderr);
  const manifest = JSON.parse(run.stdout);
  const verified = validateManifest({manifest, publisherPublicKey: manifest.publicKey, expectedPublisher: manifest.signer,
    expectedManifestDigest: sha(canonical(manifest))});
  assert.equal(verified.length, Buffer.byteLength('actual ahava fixture'));
  assert.equal(verified.publisher, manifest.signer);
});

test('verified metadata persists sequence and explicitly grants no fetch, content or activation authority', t => {
  const f = fixture(t), manifest = signManifest(f);
  let policy = createArtifactPolicy({directory: f.directory, initialize: true});
  const receipt = policy.verifyAndRecord(request(f, manifest));
  assert.equal(receipt.metadataVerified, true);
  for (const field of ['contentVerified', 'fetchAuthorized', 'activationAuthorized']) assert.equal(receipt[field], false);
  assert.equal(receipt.duplicate, false);
  policy.close();
  policy = createArtifactPolicy({directory: f.directory});
  assert.equal(policy.inspect({publisher: f.publisher, artifactId: 'model:fixture'}).sequence, 1);
  assert.equal(policy.verifyAndRecord(request(f, manifest, release(f, manifest), {nowMs: 2001})).duplicate, true);
  policy.close();
});

test('unauthorized publisher, substituted immutable digest and artifact scope fail', t => {
  const f = fixture(t), manifest = signManifest(f), policy = createArtifactPolicy({directory: f.directory, initialize: true});
  assert.throws(() => policy.verifyAndRecord(request(f, manifest, undefined, {expectedPublisher: 'a'.repeat(64)})), /ARTIFACT_PUBLISHER_MISMATCH/);
  assert.throws(() => policy.verifyAndRecord(request(f, manifest, undefined, {expectedManifestDigest: 'b'.repeat(64)})), /ARTIFACT_MANIFEST_DIGEST_MISMATCH/);
  assert.throws(() => policy.verifyAndRecord(request(f, manifest, undefined, {expectedArtifactId: 'model:other'})), /ARTIFACT_RELEASE_INVALID_OR_EXPIRED/);
  assert.equal(policy.inspect({publisher: f.publisher, artifactId: 'model:fixture'}), null);
  policy.close();
});

test('manifest and release signatures are independently verified', t => {
  const f = fixture(t), manifest = signManifest(f), policy = createArtifactPolicy({directory: f.directory, initialize: true});
  const forged = {...manifest, signature: Buffer.alloc(64).toString('base64')};
  assert.throws(() => policy.verifyAndRecord(request(f, forged)), /ARTIFACT_MANIFEST_SIGNATURE_INVALID/);
  const metadata = {...release(f, manifest), signature: Buffer.alloc(64).toString('base64')};
  assert.throws(() => policy.verifyAndRecord(request(f, manifest, metadata)), /ARTIFACT_RELEASE_SIGNATURE_INVALID/);
  policy.close();
});

test('signed downgrade remains rejected after process reopen', t => {
  const f = fixture(t), old = signManifest(f), next = signManifest(f, {}, Buffer.from('new version'));
  let policy = createArtifactPolicy({directory: f.directory, initialize: true});
  policy.verifyAndRecord(request(f, next, release(f, next, {sequence: 2, issuedAtMs: 2000, expiresAtMs: 60000}), {nowMs: 3000}));
  policy.close(); policy = createArtifactPolicy({directory: f.directory});
  assert.throws(() => policy.verifyAndRecord(request(f, old, release(f, old), {nowMs: 3001})), /ARTIFACT_ROLLBACK_REFUSED/);
  assert.equal(policy.inspect({publisher: f.publisher, artifactId: 'model:fixture'}).sequence, 2);
  policy.close();
});

test('same sequence cannot change content or extend expiry through a newly signed release', t => {
  const f = fixture(t), manifest = signManifest(f), policy = createArtifactPolicy({directory: f.directory, initialize: true});
  policy.verifyAndRecord(request(f, manifest));
  const altered = signManifest(f, {}, Buffer.from('different content'));
  assert.throws(() => policy.verifyAndRecord(request(f, altered)), /ARTIFACT_VERSION_EQUIVOCATION/);
  assert.throws(() => policy.verifyAndRecord(request(f, manifest, release(f, manifest, {expiresAtMs: 60000}))), /ARTIFACT_VERSION_EQUIVOCATION/);
  policy.close();
});

test('higher sequence cannot regress issuance or expiry', t => {
  const f = fixture(t), manifest = signManifest(f), policy = createArtifactPolicy({directory: f.directory, initialize: true});
  policy.verifyAndRecord(request(f, manifest));
  assert.throws(() => policy.verifyAndRecord(request(f, manifest, release(f, manifest, {sequence: 2, issuedAtMs: 999, expiresAtMs: 60000}))), /ARTIFACT_EXPIRY_ROLLBACK_REFUSED/);
  assert.throws(() => policy.verifyAndRecord(request(f, manifest, release(f, manifest, {sequence: 2, issuedAtMs: 1500, expiresAtMs: 50000}))), /ARTIFACT_EXPIRY_ROLLBACK_REFUSED/);
  policy.close();
});

test('expired frozen metadata fails, including an otherwise identical retry', t => {
  const f = fixture(t), manifest = signManifest(f), policy = createArtifactPolicy({directory: f.directory, initialize: true});
  policy.verifyAndRecord(request(f, manifest));
  assert.throws(() => policy.verifyAndRecord(request(f, manifest, undefined, {nowMs: 50000})), /ARTIFACT_RELEASE_INVALID_OR_EXPIRED/);
  assert.equal(policy.inspect({publisher: f.publisher, artifactId: 'model:fixture'}).expiresAtMs, 50000);
  policy.close();
});

test('observed clock floor survives duplicate reads and reopening', t => {
  const f = fixture(t), manifest = signManifest(f);
  let policy = createArtifactPolicy({directory: f.directory, initialize: true});
  policy.verifyAndRecord(request(f, manifest));
  policy.verifyAndRecord(request(f, manifest, undefined, {nowMs: 10000}));
  policy.close(); policy = createArtifactPolicy({directory: f.directory});
  assert.throws(() => policy.verifyAndRecord(request(f, manifest, undefined, {nowMs: 9999})), /ARTIFACT_CLOCK_ROLLBACK_HOLD/);
  policy.close();
});

test('signed malformed manifest fields, traversal names and noncanonical public keys fail', t => {
  const f = fixture(t), policy = createArtifactPolicy({directory: f.directory, initialize: true});
  for (const mutation of [{name: '../weights.bin'}, {unknown: 'extension'}, {chunkSize: 1}, {length: -1}, {createdAt: 'not-a-time'}]) {
    const manifest = signManifest(f, mutation);
    assert.throws(() => policy.verifyAndRecord(request(f, manifest)), /ARTIFACT_MANIFEST_INVALID/);
  }
  const manifest = signManifest(f);
  assert.throws(() => policy.verifyAndRecord(request(f, manifest, undefined, {publisherPublicKey: f.pem + '\n'})), /ARTIFACT_PUBLISHER_MISMATCH/);
  policy.close();
});

test('chunk count, lengths, extra fields and repeated GCM nonces fail before state changes', t => {
  const f = fixture(t), policy = createArtifactPolicy({directory: f.directory, initialize: true});
  const base = signManifest(f, {}, Buffer.alloc(65537, 5));
  const mutations = [base.chunks.slice(0, 1), base.chunks.map((c, i) => i ? {...c, length: 2} : c),
    base.chunks.map((c, i) => i ? {...c, extra: true} : c), base.chunks.map(c => ({...c, nonce: base.chunks[0].nonce}))];
  for (const chunks of mutations) {
    const manifest = signManifest(f, {chunks}, Buffer.alloc(65537, 5));
    assert.throws(() => policy.verifyAndRecord(request(f, manifest)), /ARTIFACT_(MANIFEST_INVALID|CHUNK_METADATA_INVALID)/);
  }
  assert.equal(policy.inspect({publisher: f.publisher, artifactId: 'model:fixture'}), null);
  policy.close();
});

test('release lifetime, future issuance and wrong signing domain fail', t => {
  const f = fixture(t), manifest = signManifest(f), policy = createArtifactPolicy({directory: f.directory, initialize: true});
  assert.throws(() => policy.verifyAndRecord(request(f, manifest, release(f, manifest, {expiresAtMs: 86402000}))), /ARTIFACT_RELEASE_INVALID_OR_EXPIRED/);
  assert.throws(() => policy.verifyAndRecord(request(f, manifest, release(f, manifest, {issuedAtMs: 10000}))), /ARTIFACT_RELEASE_INVALID_OR_EXPIRED/);
  const {signature, ...body} = release(f, manifest);
  const wrong = {...body, signature: crypto.sign(null, Buffer.from(canonical(body)), f.privateKey).toString('base64')};
  assert.throws(() => policy.verifyAndRecord(request(f, manifest, wrong)), /ARTIFACT_RELEASE_SIGNATURE_INVALID/);
  policy.close();
});

test('artifact policy retains private-file and exclusive-lease constraints', t => {
  const f = fixture(t), manifest = signManifest(f), policy = createArtifactPolicy({directory: f.directory, initialize: true});
  assert.throws(() => createArtifactPolicy({directory: f.directory}), /WRITER_LEASE_HOLD/);
  const state = path.join(f.directory, 'state.json'); fs.chmodSync(state, 0o644);
  assert.throws(() => policy.verifyAndRecord(request(f, manifest)), /STATE_FILE_UNSAFE/);
  fs.chmodSync(state, 0o600);
  policy.close();
});

test('fresh higher-sequence metadata succeeds without claiming object verification', t => {
  const f = fixture(t), first = signManifest(f), second = signManifest(f, {}, Buffer.from('updated version'));
  const policy = createArtifactPolicy({directory: f.directory, initialize: true});
  policy.verifyAndRecord(request(f, first));
  const receipt = policy.verifyAndRecord(request(f, second, release(f, second, {sequence: 2, issuedAtMs: 2500, expiresAtMs: 60000}), {nowMs: 3000}));
  assert.equal(receipt.sequence, 2);
  assert.equal(receipt.contentVerified, false);
  assert.equal(policy.inspect({publisher: f.publisher, artifactId: 'model:fixture'}).manifestDigest, sha(canonical(second)));
  policy.close();
});
