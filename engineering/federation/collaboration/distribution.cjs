'use strict';

// Public byte artifacts only. This does not open AHAVA mesh keys, activate
// content, fetch URLs, execute files, or change the original AHAVA protocol.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const federation = require('../live/federation-node.cjs');
const { openPrivateStore } = require('./transaction-journal.cjs');
const F = fs.constants;
const SCHEMA = 'mikaya.act.public-artifact.v1';
const DOMAIN = 'MIKAYA-ACT-PUBLIC-ARTIFACT/1\n';
const CHUNK_SIZE = 65_536;
const MAX_BYTES = CHUNK_SIZE * 16;
const MAX_MANIFEST_BYTES = 8192;
const MAX_LIFETIME_MS = 86_400_000;
const MAX_CACHED_MANIFESTS = 16;
const HEX = /^[0-9a-f]{64}$/;
const MANIFEST_KEYS = ['schema', 'publisher', 'artifactId', 'version', 'sequence',
  'issuedAtMs', 'expiresAtMs', 'length', 'chunkSize', 'sha256', 'chunks', 'signature'];
const ENTRY_KEYS = ['manifestDigest', 'sequence', 'issuedAtMs', 'expiresAtMs', 'length', 'chunks'];

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function exact(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const actual = Reflect.ownKeys(value);
  return actual.length === keys.length && actual.every(key => keys.includes(key) &&
    Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'));
}
const safeInt = (value, min = 0) => Number.isSafeInteger(value) && value >= min && !Object.is(value, -0);
const label = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(value) && !value.includes('..');
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const clone = value => JSON.parse(federation.canonical(value));

function signingKey(input, privateRequired = false) {
  try {
    const key = input?.type === (privateRequired ? 'private' : 'public') ? input :
      (privateRequired ? crypto.createPrivateKey(input) : crypto.createPublicKey(input));
    if (key.asymmetricKeyType !== 'ed25519') fail('DISTRIBUTION_KEY_TYPE');
    return key;
  } catch (error) {
    if (error.code === 'DISTRIBUTION_KEY_TYPE') throw error;
    fail('DISTRIBUTION_KEY_INVALID');
  }
}

function validateShape(manifest) {
  if (!exact(manifest, MANIFEST_KEYS) || manifest.schema !== SCHEMA || !HEX.test(manifest.publisher) ||
      !label(manifest.artifactId) || !label(manifest.version) || !safeInt(manifest.sequence, 1) ||
      !safeInt(manifest.issuedAtMs, 1) || !safeInt(manifest.expiresAtMs, 1) ||
      manifest.expiresAtMs <= manifest.issuedAtMs || manifest.expiresAtMs - manifest.issuedAtMs > MAX_LIFETIME_MS ||
      !safeInt(manifest.length) || manifest.length > MAX_BYTES || manifest.chunkSize !== CHUNK_SIZE ||
      !HEX.test(manifest.sha256) || !Array.isArray(manifest.chunks) ||
      manifest.chunks.length !== Math.ceil(manifest.length / CHUNK_SIZE) ||
      typeof manifest.signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(manifest.signature)) fail('DISTRIBUTION_MANIFEST_INVALID');
  for (let index = 0; index < manifest.chunks.length; index++) {
    const chunk = manifest.chunks[index];
    if (!exact(chunk, ['index', 'offset', 'length', 'sha256']) || chunk.index !== index ||
        chunk.offset !== index * CHUNK_SIZE || chunk.length !== Math.min(CHUNK_SIZE, manifest.length - chunk.offset) ||
        !HEX.test(chunk.sha256)) fail('DISTRIBUTION_CHUNK_METADATA_INVALID');
  }
  if (Buffer.byteLength(federation.canonical(manifest)) > MAX_MANIFEST_BYTES) fail('DISTRIBUTION_MANIFEST_TOO_LARGE');
}

function digestManifest(manifest) {
  validateShape(manifest);
  return sha(federation.canonical(manifest));
}

function signManifest({ bytes, artifactId, version, sequence, privateKey, publicKey,
  nowMs = Date.now(), expiresAtMs = nowMs + 3_600_000 }) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > MAX_BYTES || !label(artifactId) || !label(version) ||
      !safeInt(sequence, 1) || !safeInt(nowMs, 1) || !safeInt(expiresAtMs, 1) ||
      expiresAtMs <= nowMs || expiresAtMs - nowMs > MAX_LIFETIME_MS) fail('DISTRIBUTION_ISSUE_INVALID');
  const source = Buffer.from(bytes);
  const privateObject = signingKey(privateKey, true), publicObject = signingKey(publicKey);
  if (federation.fp(crypto.createPublicKey(privateObject)) !== federation.fp(publicObject)) fail('DISTRIBUTION_KEY_MISMATCH');
  const chunks = [];
  for (let offset = 0; offset < source.length; offset += CHUNK_SIZE) {
    const chunk = source.subarray(offset, offset + CHUNK_SIZE);
    chunks.push({ index: chunks.length, offset, length: chunk.length, sha256: sha(chunk) });
  }
  const body = { schema: SCHEMA, publisher: federation.fp(publicObject), artifactId, version, sequence,
    issuedAtMs: nowMs, expiresAtMs, length: source.length, chunkSize: CHUNK_SIZE, sha256: sha(source), chunks };
  const signature = crypto.sign(null, Buffer.from(DOMAIN + federation.canonical(body)), privateObject).toString('base64');
  const manifest = { ...body, signature };
  validateShape(manifest);
  return manifest;
}

function verifyManifest({ manifest, publisherPublicKey, expectedPublisher, expectedManifestDigest,
  expectedArtifactId, nowMs = Date.now() }) {
  validateShape(manifest);
  if (!safeInt(nowMs, 1) || nowMs < manifest.issuedAtMs || nowMs >= manifest.expiresAtMs) fail('DISTRIBUTION_MANIFEST_EXPIRED_OR_FUTURE');
  const key = signingKey(publisherPublicKey);
  if (!HEX.test(expectedPublisher) || federation.fp(key) !== expectedPublisher || manifest.publisher !== expectedPublisher) fail('DISTRIBUTION_PUBLISHER_MISMATCH');
  if (expectedArtifactId !== undefined && expectedArtifactId !== manifest.artifactId) fail('DISTRIBUTION_ARTIFACT_MISMATCH');
  const { signature, ...body } = manifest;
  const signatureBytes = Buffer.from(signature, 'base64');
  if (signatureBytes.length !== 64 || signatureBytes.toString('base64') !== signature ||
      !crypto.verify(null, Buffer.from(DOMAIN + federation.canonical(body)), key, signatureBytes)) fail('DISTRIBUTION_SIGNATURE_INVALID');
  const manifestDigest = digestManifest(manifest);
  if (expectedManifestDigest !== undefined && (!HEX.test(expectedManifestDigest) || expectedManifestDigest !== manifestDigest)) fail('DISTRIBUTION_MANIFEST_DIGEST_MISMATCH');
  return { manifestDigest, publisher: expectedPublisher, artifactId: manifest.artifactId, version: manifest.version,
    sequence: manifest.sequence, length: manifest.length, chunks: manifest.chunks.length, expiresAtMs: manifest.expiresAtMs };
}

function readChunk(sourceBytes, manifest, index) {
  validateShape(manifest);
  if (!(sourceBytes instanceof Uint8Array) || sourceBytes.byteLength !== manifest.length ||
      sourceBytes.byteLength > MAX_BYTES || !safeInt(index) || index >= manifest.chunks.length) fail('DISTRIBUTION_SOURCE_OR_INDEX_INVALID');
  const bytes = Buffer.from(sourceBytes);
  if (sha(bytes) !== manifest.sha256) fail('DISTRIBUTION_SOURCE_CHANGED');
  const meta = manifest.chunks[index], chunk = bytes.subarray(meta.offset, meta.offset + meta.length);
  if (sha(chunk) !== meta.sha256) fail('DISTRIBUTION_CHUNK_HASH_MISMATCH');
  return Buffer.from(chunk);
}

function manifestResource(manifestDigest) {
  if (!HEX.test(manifestDigest)) fail('DISTRIBUTION_RESOURCE_INVALID');
  return `manifest:${manifestDigest}`;
}
function chunkResource(manifestDigest, index) {
  if (!safeInt(index) || index >= 16) fail('DISTRIBUTION_RESOURCE_INVALID');
  return `${manifestResource(manifestDigest)}:chunk:${index}`;
}

function validateState(payload) {
  if (!exact(payload, ['publisher', 'artifactId', 'lastObservedMs', 'entries']) || !HEX.test(payload.publisher) ||
      !label(payload.artifactId) || !safeInt(payload.lastObservedMs) || !Array.isArray(payload.entries) ||
      payload.entries.length > MAX_CACHED_MANIFESTS) fail('DISTRIBUTION_STATE_INVALID');
  let sequence = 0, issued = 0;
  const digests = new Set();
  for (const entry of payload.entries) {
    if (!exact(entry, ENTRY_KEYS) || !HEX.test(entry.manifestDigest) || digests.has(entry.manifestDigest) ||
        !safeInt(entry.sequence, 1) || entry.sequence <= sequence || !safeInt(entry.issuedAtMs, 1) || entry.issuedAtMs < issued ||
        !safeInt(entry.expiresAtMs, 1) || entry.expiresAtMs <= entry.issuedAtMs || entry.expiresAtMs - entry.issuedAtMs > MAX_LIFETIME_MS ||
        !safeInt(entry.length) || entry.length > MAX_BYTES || entry.chunks !== Math.ceil(entry.length / CHUNK_SIZE)) fail('DISTRIBUTION_STATE_INVALID');
    sequence = entry.sequence; issued = entry.issuedAtMs; digests.add(entry.manifestDigest);
  }
}

function fileIdentity(stat) {
  return [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs, stat.nlink].map(String).join(':');
}
function privateFile(stat) {
  return stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1n &&
    (Number(stat.mode) & 0o777) === 0o600 &&
    (typeof process.getuid !== 'function' || stat.uid === BigInt(process.getuid()));
}

function readCached(file, expectedLength, expectedDigest, sync = false) {
  let before;
  try { before = fs.lstatSync(file, { bigint: true }); }
  catch (error) { if (error.code === 'ENOENT') return null; fail('DISTRIBUTION_CACHE_IO_HOLD'); }
  if (!privateFile(before) || before.size !== BigInt(expectedLength)) fail('DISTRIBUTION_CACHE_UNSAFE');
  let fd;
  try {
    fd = fs.openSync(file, F.O_RDONLY | F.O_NOFOLLOW | F.O_NONBLOCK);
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!privateFile(opened) || fileIdentity(opened) !== fileIdentity(before)) fail('DISTRIBUTION_CACHE_CHANGED');
    const bytes = Buffer.alloc(expectedLength + 1);
    let read = 0;
    while (read < bytes.length) {
      const count = fs.readSync(fd, bytes, read, bytes.length - read, null);
      if (!count) break;
      read += count;
    }
    if (read !== expectedLength || fileIdentity(fs.fstatSync(fd, { bigint: true })) !== fileIdentity(before) ||
        fileIdentity(fs.lstatSync(file, { bigint: true })) !== fileIdentity(before)) fail('DISTRIBUTION_CACHE_CHANGED');
    const result = bytes.subarray(0, read);
    if (sha(result) !== expectedDigest) fail('DISTRIBUTION_CACHE_HASH_MISMATCH');
    if (sync) fs.fsyncSync(fd);
    return result;
  } catch (error) {
    if (typeof error.code === 'string' && error.code.startsWith('DISTRIBUTION_')) throw error;
    fail('DISTRIBUTION_CACHE_IO_HOLD');
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}

function createReceiver({ directory, manifest, publisherPublicKey, expectedPublisher, initialize = false, nowMs = Date.now() }) {
  const trustedManifest = clone(manifest);
  const verified = verifyManifest({ manifest: trustedManifest, publisherPublicKey, expectedPublisher, nowMs });
  const publicPem = signingKey(publisherPublicKey).export({ type: 'spki', format: 'pem' });
  const store = openPrivateStore({ directory, initialize, schema: 'mikaya.act.public-distribution-state.v1',
    initialPayload: { publisher: expectedPublisher, artifactId: trustedManifest.artifactId, lastObservedMs: 0, entries: [] },
    validatePayload: validateState });
  let rootFd;
  function at(time) {
    const state = store.snapshot();
    if (!safeInt(time, 1) || time < state.lastObservedMs) fail('DISTRIBUTION_CLOCK_ROLLBACK_HOLD');
    verifyManifest({ manifest: trustedManifest, publisherPublicKey: publicPem, expectedPublisher,
      expectedManifestDigest: verified.manifestDigest, expectedArtifactId: state.artifactId, nowMs: time });
    if (state.publisher !== expectedPublisher) fail('DISTRIBUTION_SOURCE_CHANGED');
    const latest = state.entries[state.entries.length - 1];
    if (!latest || latest.manifestDigest !== verified.manifestDigest) fail('DISTRIBUTION_SUPERSEDED_HOLD');
    return state;
  }
  function markTime(state, time) {
    if (state.lastObservedMs !== time) { state.lastObservedMs = time; store.commit(state); }
  }
  function chunkPath(index) {
    return path.join(directory, `chunk-${verified.manifestDigest}-${index}.bin`);
  }
  const outputPath = path.join(directory, `artifact-${verified.manifestDigest}.bin`);
  try {
    const state = store.snapshot();
    if (state.publisher !== expectedPublisher || state.artifactId !== trustedManifest.artifactId) fail('DISTRIBUTION_SOURCE_CHANGED');
    if (nowMs < state.lastObservedMs) fail('DISTRIBUTION_CLOCK_ROLLBACK_HOLD');
    const latest = state.entries[state.entries.length - 1];
    if (latest) {
      if (trustedManifest.sequence < latest.sequence) fail('DISTRIBUTION_ROLLBACK_REFUSED');
      if (trustedManifest.sequence === latest.sequence && verified.manifestDigest !== latest.manifestDigest) fail('DISTRIBUTION_VERSION_EQUIVOCATION');
      if (trustedManifest.sequence > latest.sequence && trustedManifest.issuedAtMs < latest.issuedAtMs) fail('DISTRIBUTION_ISSUED_TIME_ROLLBACK');
    }
    if (!latest || verified.manifestDigest !== latest.manifestDigest) {
      if (state.entries.length >= MAX_CACHED_MANIFESTS) fail('DISTRIBUTION_CACHE_CAPACITY_HOLD');
      state.entries.push({ manifestDigest: verified.manifestDigest, sequence: trustedManifest.sequence,
        issuedAtMs: trustedManifest.issuedAtMs, expiresAtMs: trustedManifest.expiresAtMs,
        length: trustedManifest.length, chunks: trustedManifest.chunks.length });
    }
    state.lastObservedMs = nowMs; store.commit(state);
    rootFd = fs.openSync(directory, F.O_RDONLY | F.O_DIRECTORY | F.O_NOFOLLOW);
  } catch (error) {
    store.close();
    throw error;
  }

  function writeVerified(file, bytes, digest) {
    const existing = readCached(file, bytes.length, digest, true);
    if (existing) { fs.fsyncSync(rootFd); return true; }
    let fd;
    try {
      fd = fs.openSync(file, F.O_WRONLY | F.O_CREAT | F.O_EXCL | F.O_NOFOLLOW, 0o600);
      fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
      store.snapshot(); fs.fsyncSync(rootFd);
      return false;
    } catch (error) {
      // Keep partial bytes for explicit inspection. Resume never trusts them:
      // the next operation must recheck file type, size and signed content hash.
      fail('DISTRIBUTION_DURABILITY_HOLD');
    } finally { if (fd !== undefined) fs.closeSync(fd); }
  }
  function acceptChunk({ index, bytes, nowMs = Date.now() }) {
    const state = at(nowMs);
    if (!safeInt(index) || index >= trustedManifest.chunks.length || !(bytes instanceof Uint8Array)) fail('DISTRIBUTION_CHUNK_INVALID');
    const meta = trustedManifest.chunks[index];
    if (bytes.byteLength !== meta.length || bytes.byteLength > CHUNK_SIZE) fail('DISTRIBUTION_CHUNK_LENGTH');
    const copy = Buffer.from(bytes);
    if (sha(copy) !== meta.sha256) fail('DISTRIBUTION_CHUNK_HASH_MISMATCH');
    const duplicate = writeVerified(chunkPath(index), copy, meta.sha256);
    markTime(state, nowMs);
    return { manifestDigest: verified.manifestDigest, index, bytes: copy.length, sha256: meta.sha256,
      duplicate, chunkVerified: true, contentVerified: false, activationAuthorized: false };
  }
  function status({ nowMs = Date.now() } = {}) {
    const state = at(nowMs), missingChunks = [];
    let verifiedBytes = 0;
    for (const meta of trustedManifest.chunks) {
      const bytes = readCached(chunkPath(meta.index), meta.length, meta.sha256);
      if (bytes === null) missingChunks.push(meta.index); else verifiedBytes += bytes.length;
    }
    const complete = readCached(outputPath, trustedManifest.length, trustedManifest.sha256) !== null;
    markTime(state, nowMs);
    return { ...verified, missingChunks, verifiedBytes, verifiedChunks: trustedManifest.chunks.length - missingChunks.length,
      complete, contentVerified: complete, activationAuthorized: false };
  }
  function finalize({ nowMs = Date.now() } = {}) {
    const state = at(nowMs), chunks = [];
    for (const meta of trustedManifest.chunks) {
      const bytes = readCached(chunkPath(meta.index), meta.length, meta.sha256);
      if (bytes === null) fail('DISTRIBUTION_INCOMPLETE');
      chunks.push(bytes);
    }
    const bytes = Buffer.concat(chunks);
    if (bytes.length !== trustedManifest.length || sha(bytes) !== trustedManifest.sha256) fail('DISTRIBUTION_WHOLE_HASH_MISMATCH');
    const duplicate = writeVerified(outputPath, bytes, trustedManifest.sha256);
    markTime(state, nowMs);
    return { schema: 'mikaya.act.public-artifact-receipt.v1', ...verified,
      sha256: trustedManifest.sha256, path: outputPath, duplicate,
      contentVerified: true, activationAuthorized: false };
  }
  function close() {
    try { store.close(); } finally { if (rootFd !== undefined) { fs.closeSync(rootFd); rootFd = undefined; } }
  }
  return Object.freeze({ acceptChunk, status, finalize, close });
}

module.exports = { SCHEMA, DOMAIN, CHUNK_SIZE, MAX_BYTES, MAX_MANIFEST_BYTES, MAX_LIFETIME_MS,
  signManifest, verifyManifest, digestManifest, readChunk, manifestResource, chunkResource, createReceiver };
