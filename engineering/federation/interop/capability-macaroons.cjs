'use strict';

/**
 * First-party Macaroon V2 conformance boundary; no resource handlers or sockets.
 *
 * Uses the established libmacaroons/go-macaroon root-key derivation, chained
 * HMAC-SHA256 and V2 TLV wire format, with independent upstream vectors in tests.
 * This is deliberately a restricted implementation: no V1/JSON wire format,
 * third-party caveats, L402 payments, hardware attestation or live admission.
 * Node's vetted crypto implementation supplies HMAC; no new crypto primitive.
 *
 * IMPORTANT: context MUST be derived by the caller from an already verified
 * signed request / authenticated channel, never copied from untrusted claims.
 * Verification consumes a local replay/budget reservation BEFORE returning.
 * A successful result authorizes no execution by itself. Existing owner policy,
 * kill switch and handler allowlists must still be checked by the caller.
 *
 * Sources (Git blob IDs pin the reviewed source bytes):
 * https://github.com/go-macaroon/macaroon/blob/v2/crypto.go
 *   c7e98e51471a38181224021dada7c5c8544a7b73
 * https://github.com/go-macaroon/macaroon/blob/v2/marshal-v2.go
 *   e02131f29781a5299a347f86e8c6af7a1e933edf
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { TextDecoder } = require('node:util');

const PROFILE = 'mikaya.federation.capability.v1';
const MAX_DURATION_MS = 120000;
const MAX_TOKEN_BYTES = 16384;
const MAX_CAVEATS = 48;
const MAX_STATE_BYTES = 4 * 1024 * 1024;
const MAX_RECORDS = 10000;
const HASH = /^[a-f0-9]{64}$/;
const NONCE = /^[a-f0-9]{32}$/;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const NUM = /^(0|[1-9][0-9]{0,15})$/;
const REQUIRED = ['profile','environment','holder','audience','profile_sha256',
  'operation','body_sha256','issued_ms','expires_ms','max_uses','max_bytes'];
const utf8 = new TextDecoder('utf-8', { fatal: true });
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
const hmac = (key, bytes) => crypto.createHmac('sha256', key).update(bytes).digest();
const plain = o => o !== null && typeof o === 'object' &&
  !Array.isArray(o) && Object.getPrototypeOf(o) === Object.prototype;
const exact = (o, keys) => plain(o) && Object.keys(o).sort().join('|') === [...keys].sort().join('|');
function ensure(ok, message) { if (!ok) throw new Error(message); }
function bytes(x, name) {
  ensure(typeof x === 'string' || Buffer.isBuffer(x) || x instanceof Uint8Array, name + ' must be bytes or text');
  return Buffer.from(x);
}
function uint(value, name, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  ensure(Number.isSafeInteger(value) && value >= minimum && value <= maximum, name + ' out of range');
  return value;
}
function parseUint(value, name) {
  ensure(NUM.test(value), 'invalid numeric caveat: ' + name);
  return uint(Number(value), name);
}
function varint(value) {
  uint(value, 'length', 0, MAX_TOKEN_BYTES);
  const result = [];
  do { let octet = value % 128; value = Math.floor(value / 128); if (value) octet |= 128; result.push(octet); } while (value);
  return Buffer.from(result);
}
function packet(tag, value) {
  return Buffer.concat([Buffer.from([tag]), varint(value.length), value]);
}
function tokenBytes(token) {
  if (Buffer.isBuffer(token) || token instanceof Uint8Array) {
    ensure(token.length <= MAX_TOKEN_BYTES, 'macaroon too large');
    return Buffer.from(token);
  }
  ensure(typeof token === 'string' && token.length > 0 && token.length <= Math.ceil(MAX_TOKEN_BYTES * 4 / 3) && /^[A-Za-z0-9_-]+$/.test(token), 'noncanonical macaroon encoding');
  const result = Buffer.from(token, 'base64url');
  ensure(result.length <= MAX_TOKEN_BYTES && result.toString('base64url') === token, 'noncanonical macaroon encoding');
  return result;
}
function encodeMacaroon(m) {
  ensure(m && m.version === 2 && Array.isArray(m.caveats) && m.caveats.length <= MAX_CAVEATS, 'unsupported macaroon');
  const id = bytes(m.identifier, 'identifier'), location = bytes(m.location || '', 'location');
  ensure(id.length > 0 && id.length <= 512 && location.length <= 512, 'macaroon header length');
  const chunks = [Buffer.from([2])];
  if (location.length) chunks.push(packet(1, location));
  chunks.push(packet(2, id), Buffer.from([0]));
  for (const value of m.caveats) {
    const c = bytes(value, 'caveat');
    ensure(c.length > 0 && c.length <= 1024, 'caveat length');
    chunks.push(packet(2, c), Buffer.from([0]));
  }
  const sig = bytes(m.signature, 'signature');
  ensure(sig.length === 32, 'invalid macaroon signature size');
  chunks.push(Buffer.from([0]), packet(6, sig));
  const result = Buffer.concat(chunks);
  ensure(result.length <= MAX_TOKEN_BYTES, 'macaroon too large');
  return result.toString('base64url');
}
function decodeMacaroon(token) {
  const b = tokenBytes(token); let pos = 0;
  ensure(b[pos++] === 2, 'only macaroon V2 is supported');
  function read() {
    ensure(pos < b.length, 'truncated macaroon');
    const tag = b[pos++];
    if (tag === 0) return { tag, value: Buffer.alloc(0) };
    const start = pos; let length = 0, scale = 1, octet;
    do {
      ensure(pos < b.length && pos - start < 3, 'invalid macaroon length');
      octet = b[pos++]; length += (octet & 127) * scale; scale *= 128;
    } while (octet & 128);
    ensure(length <= MAX_TOKEN_BYTES && b.subarray(start, pos).equals(varint(length)), 'noncanonical macaroon length');
    ensure(pos + length <= b.length, 'truncated macaroon field');
    const value = Buffer.from(b.subarray(pos, pos + length)); pos += length;
    return { tag, value };
  }
  let p = read(), location = '';
  if (p.tag === 1) { ensure(p.value.length <= 512, 'location too long'); location = utf8.decode(p.value); p = read(); }
  ensure(p.tag === 2 && p.value.length > 0 && p.value.length <= 512, 'invalid macaroon header');
  const identifier = p.value;
  ensure(read().tag === 0, 'invalid macaroon header terminator');
  const caveats = [];
  for (;;) {
    p = read(); if (p.tag === 0) break;
    ensure(p.tag === 2 && p.value.length > 0 && p.value.length <= 1024, 'unsupported caveat field');
    caveats.push(p.value);
    ensure(caveats.length <= MAX_CAVEATS, 'too many caveats');
    ensure(read().tag === 0, 'third-party caveats and extra fields are unsupported');
  }
  p = read();
  ensure(p.tag === 6 && p.value.length === 32 && pos === b.length, 'invalid macaroon signature or trailing data');
  return { version: 2, location, identifier, caveats, signature: p.value };
}
function mintMacaroon({ rootKey, identifier, location = '', caveats = [] }) {
  const key = bytes(rootKey, 'root key'), id = bytes(identifier, 'identifier');
  ensure(key.length > 0 && key.length <= 4096, 'root key length');
  let signature = hmac(hmac(Buffer.from('macaroons-key-generator'), key), id);
  const cs = caveats.map(c => bytes(c, 'caveat'));
  for (const c of cs) signature = hmac(signature, c);
  return encodeMacaroon({ version: 2, location, identifier: id, caveats: cs, signature });
}
function addFirstPartyCaveat(token, caveat) {
  const m = decodeMacaroon(token), c = bytes(caveat, 'caveat');
  m.caveats.push(c); m.signature = hmac(m.signature, c);
  return encodeMacaroon(m);
}
function verifyMacaroonIntegrity(token, rootKey) {
  const m = decodeMacaroon(token);
  const expected = decodeMacaroon(mintMacaroon({ rootKey, identifier: m.identifier, location: m.location, caveats: m.caveats })).signature;
  ensure(crypto.timingSafeEqual(m.signature, expected), 'macaroon signature invalid');
  return m; // Integrity alone is NOT authorization; caller must check every caveat.
}
function parsePolicy(m) {
  const base = Object.create(null), limits = [];
  for (const raw of m.caveats) {
    const c = utf8.decode(raw), match = /^([a-z][a-z0-9_]*) = ([\x21-\x7e]+)$/.exec(c);
    ensure(match, 'malformed capability caveat');
    const [, key, value] = match;
    if (key === 'limit') { limits.push(value); continue; }
    ensure(REQUIRED.includes(key), 'unknown capability caveat');
    ensure(!Object.hasOwn(base, key), 'duplicate critical capability caveat');
    base[key] = value;
  }
  ensure(REQUIRED.every(k => Object.hasOwn(base, k)), 'required capability caveat missing');
  ensure(base.profile === PROFILE && base.environment === 'isolated-test', 'unsupported capability profile or environment');
  ensure(HASH.test(base.holder) && HASH.test(base.profile_sha256) && HASH.test(base.body_sha256), 'invalid capability digest');
  ensure(NAME.test(base.audience) && NAME.test(base.operation), 'invalid capability audience or operation');
  const issuedAtMs = parseUint(base.issued_ms, 'issued_ms');
  let expiresAtMs = parseUint(base.expires_ms, 'expires_ms');
  let maxUses = parseUint(base.max_uses, 'max_uses'), maxBytes = parseUint(base.max_bytes, 'max_bytes');
  ensure(expiresAtMs > issuedAtMs && expiresAtMs - issuedAtMs <= MAX_DURATION_MS, 'capability duration exceeds limit');
  uint(maxUses, 'max_uses', 1, 1000); uint(maxBytes, 'max_bytes', 1, 16 * 1024 * 1024);
  for (const limit of limits) {
    const match = /^(expires_ms|max_uses|max_bytes):([0-9]+)$/.exec(limit);
    ensure(match, 'unknown attenuation restriction');
    const n = parseUint(match[2], match[1]);
    if (match[1] === 'expires_ms') { ensure(n > issuedAtMs && n < expiresAtMs, 'attenuation must shorten expiry'); expiresAtMs = n; }
    else if (match[1] === 'max_uses') { ensure(n >= 1 && n < maxUses, 'attenuation must reduce use budget'); maxUses = n; }
    else { ensure(n >= 1 && n < maxBytes, 'attenuation must reduce byte budget'); maxBytes = n; }
  }
  return { holderKeySha256: base.holder, audience: base.audience, profileSha256: base.profile_sha256,
    operation: base.operation, bodySha256: base.body_sha256, issuedAtMs, expiresAtMs, maxUses, maxBytes };
}
function mintTestCapability({ rootKey, identifier = crypto.randomBytes(32).toString('hex'), holderKeySha256,
  audience, profileSha256, operation, bodySha256, issuedAtMs, expiresAtMs, maxUses = 1, maxBytes = 8192 }) {
  ensure(bytes(rootKey, 'root key').length >= 32, 'capability root key must contain at least 32 bytes');
  ensure(typeof identifier === 'string' && NONCE.test(identifier.slice(0,32)) && HASH.test(identifier), 'capability identifier must be 32 random bytes in hex');
  ensure(typeof audience === 'string' && NAME.test(audience) && typeof operation === 'string' && NAME.test(operation), 'capability audience and operation required');
  ensure(typeof holderKeySha256 === 'string' && HASH.test(holderKeySha256) && typeof profileSha256 === 'string' && HASH.test(profileSha256) && typeof bodySha256 === 'string' && HASH.test(bodySha256), 'capability binding digests required');
  for (const [n,v] of Object.entries({ issuedAtMs, expiresAtMs, maxUses, maxBytes })) uint(v, n);
  const values = [PROFILE,'isolated-test',holderKeySha256,audience,profileSha256,operation,bodySha256,
    issuedAtMs,expiresAtMs,maxUses,maxBytes];
  const caveats = REQUIRED.map((k,i) => k + ' = ' + values[i]);
  const token = mintMacaroon({ rootKey, identifier, caveats });
  parsePolicy(decodeMacaroon(token));
  return token;
}
function attenuateCapability(token, restrictions) {
  ensure(plain(restrictions) && Object.keys(restrictions).length > 0 &&
    Object.keys(restrictions).every(k => ['expiresAtMs','maxUses','maxBytes'].includes(k)), 'unsupported attenuation request');
  let result = token; parsePolicy(decodeMacaroon(result));
  const names = { expiresAtMs: 'expires_ms', maxUses: 'max_uses', maxBytes: 'max_bytes' };
  for (const [key, value] of Object.entries(restrictions)) {
    uint(value, key); result = addFirstPartyCaveat(result, 'limit = ' + names[key] + ':' + value);
    parsePolicy(decodeMacaroon(result));
  }
  return result;
}
function checkPrivateDirectory(dir) {
  const s = fs.lstatSync(dir);
  ensure(s.isDirectory() && !s.isSymbolicLink() && !(s.mode & 0o077), 'replay directory must be private');
}
function syncDir(dir) { const fd = fs.openSync(dir, fs.constants.O_RDONLY); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
function newPrivateFile(file, data) {
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function initializeReplayState(stateDir) {
  if (!fs.existsSync(stateDir)) fs.mkdirSync(stateDir, { mode: 0o700 });
  checkPrivateDirectory(stateDir);
  newPrivateFile(path.join(stateDir, 'capability-state.json'), JSON.stringify({ schema: PROFILE + '.state', records: [] }) + '\n');
  syncDir(stateDir);
  return stateDir;
}
function readState(file) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const s = fs.fstatSync(fd);
    ensure(s.isFile() && s.nlink === 1 && !(s.mode & 0o077) && s.size <= MAX_STATE_BYTES, 'unsafe replay state');
    const state = JSON.parse(fs.readFileSync(fd, 'utf8'));
    ensure(exact(state, ['schema','records']) && state.schema === PROFILE + '.state' && Array.isArray(state.records) && state.records.length <= MAX_RECORDS, 'invalid replay state');
    const seen = new Set();
    for (const r of state.records) {
      ensure(exact(r, ['family','request','bytes','atMs']) && HASH.test(r.family) && HASH.test(r.request) && !seen.has(r.request), 'invalid replay record');
      uint(r.bytes, 'record bytes', 0, 16 * 1024 * 1024); uint(r.atMs, 'record time'); seen.add(r.request);
    }
    return state;
  } finally { fs.closeSync(fd); }
}
function consume(stateDir, family, context, policy, nowMs) {
  ensure(typeof stateDir === 'string' && stateDir.length > 0, 'durable replay state required');
  checkPrivateDirectory(stateDir);
  const lock = path.join(stateDir, 'capability-state.lock'), file = path.join(stateDir, 'capability-state.json');
  // Never steal an existing lock. A crash may require owner-reviewed recovery.
  const lockFd = fs.openSync(lock, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  let temp;
  try {
    const state = readState(file);
    ensure(state.records.length < MAX_RECORDS, 'replay journal capacity reached');
    const request = sha(context.holderKeySha256 + '\n' + context.audience + '\n' + context.requestNonce);
    ensure(!state.records.some(r => r.request === request), 'request replay refused');
    const used = state.records.filter(r => r.family === family);
    ensure(used.length < policy.maxUses, 'capability use budget exhausted');
    const bytesUsed = used.reduce((n,r) => n + r.bytes, 0);
    ensure(context.requestBytes <= policy.maxBytes - bytesUsed, 'capability byte budget exhausted');
    state.records.push({ family, request, bytes: context.requestBytes, atMs: nowMs });
    const data = JSON.stringify(state) + '\n';
    ensure(Buffer.byteLength(data) <= MAX_STATE_BYTES, 'replay journal size limit');
    temp = file + '.tmp-' + crypto.randomBytes(12).toString('hex');
    newPrivateFile(temp, data);
    fs.renameSync(temp, file); temp = undefined; syncDir(stateDir);
    return { uses: used.length + 1, bytes: bytesUsed + context.requestBytes };
  } finally {
    if (temp) fs.unlinkSync(temp);
    fs.closeSync(lockFd); fs.unlinkSync(lock); syncDir(stateDir);
  }
}
function verifyCapability({ token, rootKey, context, nowMs = Date.now(), stateDir }) {
  ensure(exact(context, ['holderKeySha256','audience','profileSha256','operation','bodySha256','requestNonce','requestBytes']), 'authenticated request context shape invalid');
  ensure(bytes(rootKey, 'root key').length >= 32, 'capability root key must contain at least 32 bytes');
  uint(nowMs, 'current time'); uint(context.requestBytes, 'request byte count', 0, 16 * 1024 * 1024);
  ensure(NONCE.test(context.requestNonce), 'request nonce invalid');
  const m = verifyMacaroonIntegrity(token, rootKey), policy = parsePolicy(m);
  ensure(HASH.test(utf8.decode(m.identifier)), 'invalid capability family identifier');
  for (const k of ['holderKeySha256','audience','profileSha256','operation','bodySha256']) {
    ensure(context[k] === policy[k], 'capability ' + k + ' mismatch');
  }
  ensure(nowMs >= policy.issuedAtMs && nowMs < policy.expiresAtMs, 'capability not yet valid or expired');
  const family = sha(m.identifier), consumed = consume(stateDir, family, context, policy, nowMs);
  return Object.freeze({ verified: true, testOnly: true, profile: PROFILE, familySha256: family,
    operation: policy.operation, expiresAtMs: policy.expiresAtMs, consumed,
    liveAdmission: false, paymentAuthorized: false, hardwareAttested: false });
}

function inspectReplayState(stateDir) {
  checkPrivateDirectory(stateDir);
  const state = readState(path.join(stateDir, 'capability-state.json'));
  return Object.freeze({ schema: state.schema, records: state.records.length, maxRecords: MAX_RECORDS });
}

module.exports = { PROFILE, MAX_DURATION_MS, mintMacaroon, encodeMacaroon, decodeMacaroon,
  addFirstPartyCaveat, verifyMacaroonIntegrity, mintTestCapability, attenuateCapability,
  initializeReplayState, verifyCapability, inspectReplayState };
