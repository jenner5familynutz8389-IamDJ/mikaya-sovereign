'use strict';

// Metadata verification only. This module does not fetch/decrypt chunks, open
// AHAVA's private mesh key, install files, execute code, or activate artifacts.
const crypto = require('node:crypto');
const {openPrivateStore, canonical} = require('./transaction-journal.cjs');
const {sha} = require('../../../ahava/core.js');
const HEX = /^[0-9a-f]{64}$/;
const CHUNK_SIZE = 65536;
const MAX_FILE = 32 * 1024 * 1024;
const MAX_MANIFEST = 250000;
const MAX_ENTRIES = 2048;
const RELEASE_DOMAIN = 'MIKAYA-ACT-ARTIFACT-RELEASE/1\n';
const MANIFEST_KEYS = ['schema', 'node', 'createdAt', 'name', 'length', 'plainSha256', 'chunkSize', 'chunks', 'publicKey', 'signer', 'signature'];
const RELEASE_KEYS = ['schema', 'publisher', 'artifactId', 'manifestDigest', 'sequence', 'issuedAtMs', 'expiresAtMs', 'signature'];
const ENTRY_KEYS = ['publisher', 'artifactId', 'manifestDigest', 'sequence', 'issuedAtMs', 'expiresAtMs', 'releaseSha256'];
function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).sort().join('|') === [...keys].sort().join('|'); }
const positive = value => Number.isSafeInteger(value) && value > 0;
const artifactId = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$/.test(value);
const copy = value => JSON.parse(canonical(value));

function publicKey(pem, expectedPublisher) {
  if (typeof pem !== 'string' || pem.length > 1024 || !pem.startsWith('-----BEGIN PUBLIC KEY-----\n') || !HEX.test(expectedPublisher)) fail('ARTIFACT_PUBLISHER_INVALID');
  let key;
  try { key = crypto.createPublicKey(pem); } catch { fail('ARTIFACT_PUBLISHER_INVALID'); }
  if (key.asymmetricKeyType !== 'ed25519' || key.export({type: 'spki', format: 'pem'}) !== pem || sha(Buffer.from(pem)) !== expectedPublisher) fail('ARTIFACT_PUBLISHER_MISMATCH');
  return key;
}
function signatureValid(signature, bytes, key) {
  if (typeof signature !== 'string' || signature.length !== 88 || !/^[A-Za-z0-9+/]{86}==$/.test(signature)) return false;
  const buffer = Buffer.from(signature, 'base64');
  return buffer.length === 64 && buffer.toString('base64') === signature && crypto.verify(null, Buffer.from(bytes), key, buffer);
}

function validateManifest({manifest, publisherPublicKey, expectedPublisher, expectedManifestDigest}) {
  if (!HEX.test(expectedManifestDigest)) fail('ARTIFACT_DIGEST_REQUIRED');
  const key = publicKey(publisherPublicKey, expectedPublisher);
  if (!exact(manifest, MANIFEST_KEYS) || manifest.schema !== 'ahava.signed-manifest.v1' ||
      typeof manifest.node !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(manifest.node) ||
      typeof manifest.name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(manifest.name) ||
      typeof manifest.createdAt !== 'string' || !Number.isFinite(Date.parse(manifest.createdAt)) ||
      new Date(manifest.createdAt).toISOString() !== manifest.createdAt ||
      !Number.isSafeInteger(manifest.length) || manifest.length < 0 || manifest.length > MAX_FILE ||
      manifest.chunkSize !== CHUNK_SIZE || !HEX.test(manifest.plainSha256) ||
      manifest.publicKey !== publisherPublicKey || manifest.signer !== expectedPublisher ||
      !Array.isArray(manifest.chunks) || manifest.chunks.length !== Math.ceil(manifest.length / CHUNK_SIZE)) fail('ARTIFACT_MANIFEST_INVALID');
  const nonces = new Set();
  for (let index = 0; index < manifest.chunks.length; index++) {
    const chunk = manifest.chunks[index];
    if (!exact(chunk, ['id', 'nonce', 'tag', 'plainSha256', 'length']) ||
        !HEX.test(chunk.id) || !HEX.test(chunk.plainSha256) || typeof chunk.nonce !== 'string' || !/^[0-9a-f]{24}$/.test(chunk.nonce) ||
        typeof chunk.tag !== 'string' || !/^[0-9a-f]{32}$/.test(chunk.tag) ||
        chunk.length !== Math.min(CHUNK_SIZE, manifest.length - index * CHUNK_SIZE) ||
        nonces.has(chunk.nonce)) fail('ARTIFACT_CHUNK_METADATA_INVALID');
    nonces.add(chunk.nonce);
  }
  const bytes = canonical(manifest);
  if (Buffer.byteLength(bytes) > MAX_MANIFEST || sha(bytes) !== expectedManifestDigest) fail('ARTIFACT_MANIFEST_DIGEST_MISMATCH');
  const {signature, ...body} = manifest;
  if (!signatureValid(signature, canonical(body), key)) fail('ARTIFACT_MANIFEST_SIGNATURE_INVALID');
  return {manifestDigest: expectedManifestDigest, publisher: expectedPublisher, length: manifest.length, chunks: manifest.chunks.length};
}

function validateRelease({release, key, expectedPublisher, expectedManifestDigest, expectedArtifactId, nowMs, maxReleaseLifetimeMs}) {
  if (!artifactId(expectedArtifactId) || !exact(release, RELEASE_KEYS) || release.schema !== 'mikaya.act.artifact-release.v1' ||
      release.publisher !== expectedPublisher || release.manifestDigest !== expectedManifestDigest || release.artifactId !== expectedArtifactId ||
      !positive(release.sequence) || !positive(release.issuedAtMs) || !positive(release.expiresAtMs) || !positive(nowMs) ||
      release.issuedAtMs > nowMs + 5000 || release.expiresAtMs <= release.issuedAtMs || nowMs >= release.expiresAtMs ||
      release.expiresAtMs - release.issuedAtMs > maxReleaseLifetimeMs) fail('ARTIFACT_RELEASE_INVALID_OR_EXPIRED');
  const {signature, ...body} = release;
  if (!signatureValid(signature, RELEASE_DOMAIN + canonical(body), key)) fail('ARTIFACT_RELEASE_SIGNATURE_INVALID');
  return sha(canonical(release));
}
function validatePolicyState(payload) {
  if (!exact(payload, ['lastObservedMs', 'entries']) || !Number.isSafeInteger(payload.lastObservedMs) || payload.lastObservedMs < 0 ||
      !Array.isArray(payload.entries) || payload.entries.length > MAX_ENTRIES) fail('ARTIFACT_POLICY_STATE_INVALID');
  const seen = new Set();
  for (const entry of payload.entries) {
    if (!exact(entry, ENTRY_KEYS) || !HEX.test(entry.publisher) || !artifactId(entry.artifactId) ||
        !HEX.test(entry.manifestDigest) || !HEX.test(entry.releaseSha256) || !positive(entry.sequence) ||
        !positive(entry.issuedAtMs) || !positive(entry.expiresAtMs) || entry.expiresAtMs <= entry.issuedAtMs) fail('ARTIFACT_POLICY_STATE_INVALID');
    const id = canonical([entry.publisher, entry.artifactId]);
    if (seen.has(id)) fail('ARTIFACT_POLICY_DUPLICATE_HOLD');
    seen.add(id);
  }
}

function createArtifactPolicy({directory, initialize = false, maxReleaseLifetimeMs = 86400000}) {
  if (!positive(maxReleaseLifetimeMs) || maxReleaseLifetimeMs > 7 * 86400000) fail('ARTIFACT_LIFETIME_CONFIGURATION_INVALID');
  const store = openPrivateStore({directory, initialize, schema: 'mikaya.act.artifact-policy.v1',
    initialPayload: {lastObservedMs: 0, entries: []}, validatePayload: validatePolicyState});
  function verifyAndRecord({manifest, release, publisherPublicKey, expectedPublisher, expectedManifestDigest, expectedArtifactId, nowMs = Date.now()}) {
    const payload = store.snapshot();
    if (!positive(nowMs) || nowMs < payload.lastObservedMs) fail('ARTIFACT_CLOCK_ROLLBACK_HOLD');
    const verified = validateManifest({manifest, publisherPublicKey, expectedPublisher, expectedManifestDigest});
    const key = publicKey(publisherPublicKey, expectedPublisher);
    const releaseSha256 = validateRelease({release, key, expectedPublisher, expectedManifestDigest, expectedArtifactId, nowMs, maxReleaseLifetimeMs});
    const entry = {publisher: expectedPublisher, artifactId: expectedArtifactId, manifestDigest: expectedManifestDigest,
      sequence: release.sequence, issuedAtMs: release.issuedAtMs, expiresAtMs: release.expiresAtMs, releaseSha256};
    const index = payload.entries.findIndex(item => item.publisher === expectedPublisher && item.artifactId === expectedArtifactId);
    let duplicate = false;
    if (index !== -1) {
      const old = payload.entries[index];
      if (entry.sequence < old.sequence) fail('ARTIFACT_ROLLBACK_REFUSED');
      if (entry.sequence === old.sequence) {
        if (entry.releaseSha256 !== old.releaseSha256) fail('ARTIFACT_VERSION_EQUIVOCATION');
        duplicate = true;
      } else {
        if (entry.issuedAtMs < old.issuedAtMs || entry.expiresAtMs <= old.expiresAtMs) fail('ARTIFACT_EXPIRY_ROLLBACK_REFUSED');
        payload.entries[index] = entry;
      }
    } else {
      if (payload.entries.length >= MAX_ENTRIES) fail('ARTIFACT_POLICY_CAPACITY_HOLD');
      payload.entries.push(entry);
    }
    // Persist the observed time even for a repeated manifest, so clock rollback
    // cannot extend a previously observed metadata freshness window.
    payload.lastObservedMs = nowMs;
    store.commit(payload);
    return {schema: 'mikaya.act.artifact-metadata-receipt.v1', ...verified, artifactId: expectedArtifactId,
      sequence: release.sequence, releaseSha256, expiresAtMs: release.expiresAtMs, duplicate,
      metadataVerified: true, contentVerified: false, fetchAuthorized: false, activationAuthorized: false};
  }
  function inspect({publisher, artifactId: id}) {
    if (!HEX.test(publisher) || !artifactId(id)) fail('ARTIFACT_POLICY_LOOKUP_INVALID');
    const entry = store.snapshot().entries.find(item => item.publisher === publisher && item.artifactId === id);
    return entry ? copy(entry) : null;
  }
  return Object.freeze({verifyAndRecord, inspect, close: store.close});
}

module.exports = {createArtifactPolicy, validateManifest, RELEASE_DOMAIN};
