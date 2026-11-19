#!/usr/bin/env node
'use strict';
/**
 * Owner-paired direct TLS 1.3 transport for the existing conformance contract.
 * Mutual X.509 validation, exact certificate pins, Ed25519 application identity,
 * TLS exporter binding, strict framing, and persisted per-request owner policy.
 * Private test keys remain local. No discovery, public bind, shell, payment,
 * firmware, ACT endpoint, automatic enrollment, or manufacturer attestation.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const tls = require('node:tls');
const net = require('node:net');
const { spawnSync } = require('node:child_process');
const { performance } = require('node:perf_hooks');
const { TextDecoder } = require('node:util');
const fed = require('../live/federation-node.cjs');
const session = require('./session-adapter.cjs');
const handoff = require('./device-handoff.cjs');
const runtime = require('./runtime-profile.cjs');
const mac = require('./capability-macaroons.cjs');
const ledgers = require('./ledger-receipts.cjs');
const DOMAIN = 'MIKAYA-INTEROP-DIRECT/1\n';
const MAX_FRAME = 65536;
const MAX_STATE_FILE = 131072;
const MAX_LEDGER_BYTES = 8 * 1024 * 1024;
const HASH = /^[a-f0-9]{64}$/;
const ID = /^[a-f0-9]{32}$/;
const CAPS = ['compute.dot.v1', 'compute.sha256.v1'];
const PEER_FIELDS = ['schema', 'publicKey', 'fingerprint', 'profileSha256', 'tlsCertificatePem', 'tlsCertificateSha256', 'syntheticIdentity', 'hardwareAttested', 'productionAdmission', 'signature'];
const POLICY_FIELDS = ['schema', 'enabled', 'peerFingerprint', 'peerCertificateSha256', 'allowedCapabilities', 'maxRequestBytes', 'maxConnections', 'maxFramesPerConnection', 'maxConnectionBytes', 'idleTimeoutMs', 'maxConnectionMs'];
const TRANSPORT_FIELDS = ['schema', 'transport', 'holderFingerprint', 'workerFingerprint', 'holderCertificateSha256', 'workerCertificateSha256', 'channelBindingSha256', 'requestNonce', 'requestSha256', 'responseSha256', 'profileSha256', 'workerLedgerRecordSha256', 'issuedAtMs', 'hardwareAttested', 'productionAdmission', 'paymentAuthorized', 'signature'];
const utf8 = new TextDecoder('utf-8', { fatal: true });
const hash = x => crypto.createHash('sha256').update(x).digest('hex');
function ensure(ok, message) { if (!ok) throw new Error(message); }
function exact(value, fields) {
  return value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).sort().join('|') === [...fields].sort().join('|');
}
function safeDirectory(dir) {
  ensure(typeof dir === 'string' && path.isAbsolute(dir), 'absolute state directory required');
  const st = fs.lstatSync(dir);
  ensure(st.isDirectory() && !st.isSymbolicLink() && !(st.mode & 0o077), 'private state directory required');
  if (typeof process.getuid === 'function') ensure(st.uid === process.getuid(), 'state directory owner mismatch');
  return dir;
}
function readFile(file, maximum = MAX_STATE_FILE) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const st = fs.fstatSync(fd);
    ensure(st.isFile() && !(st.mode & 0o077) && st.size <= maximum, 'unsafe state file');
    if (typeof process.getuid === 'function') ensure(st.uid === process.getuid(), 'state file owner mismatch');
    const bytes = fs.readFileSync(fd);
    ensure(bytes.length <= maximum, 'state file grew beyond bound');
    return bytes;
  } finally { fs.closeSync(fd); }
}
function readJson(file) { return JSON.parse(utf8.decode(readFile(file))); }
function writeNew(file, value) {
  const bytes = typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value, null, 2) + '\n';
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function atomicJson(file, value) {
  // An existing policy must itself be a regular private file before replacement.
  readFile(file);
  const temp = file + '.tmp-' + crypto.randomBytes(16).toString('hex');
  try {
    writeNew(temp, value); fs.renameSync(temp, file);
    const fd = fs.openSync(path.dirname(file), fs.constants.O_RDONLY);
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } finally { if (fs.existsSync(temp)) fs.unlinkSync(temp); }
}
function transportDir(stateDir) { return path.join(safeDirectory(stateDir), 'direct-transport'); }
function sign(kind, value, privateKey) {
  return { ...value, signature: crypto.sign(null, Buffer.from(DOMAIN + kind + '\n' + fed.canonical(value)), privateKey).toString('base64') };
}
function verifySignature(kind, signed, publicKey) {
  ensure(typeof signed.signature === 'string' && /^[A-Za-z0-9+/]{86}==$/.test(signed.signature), 'invalid Ed25519 signature encoding');
  const { signature, ...value } = signed;
  const sig = Buffer.from(signature, 'base64');
  ensure(sig.length === 64 && sig.toString('base64') === signature && crypto.verify(null, Buffer.from(DOMAIN + kind + '\n' + fed.canonical(value)), publicKey, sig), 'direct identity or evidence signature refused');
}
function validatePeer(peer, nowMs = Date.now()) {
  session.boundedCanonical(peer, MAX_FRAME);
  ensure(exact(peer, PEER_FIELDS) && peer.schema === 'mikaya.interop.direct-peer.v1', 'direct peer schema refused');
  ensure(peer.syntheticIdentity === true && peer.hardwareAttested === false && peer.productionAdmission === false, 'direct peer scope refused');
  ensure(typeof peer.publicKey === 'string' && peer.publicKey.length <= 4096 && ['fingerprint','profileSha256','tlsCertificateSha256'].every(k => typeof peer[k] === 'string' && HASH.test(peer[k])), 'direct peer fields refused');
  const key = crypto.createPublicKey(peer.publicKey);
  ensure(key.asymmetricKeyType === 'ed25519' && fed.fp(key) === peer.fingerprint, 'direct peer application identity mismatch');
  ensure(typeof peer.tlsCertificatePem === 'string' && peer.tlsCertificatePem.length <= 8192, 'direct peer certificate too large');
  const cert = new crypto.X509Certificate(peer.tlsCertificatePem);
  ensure(cert.publicKey.asymmetricKeyType === 'ed25519' && cert.verify(cert.publicKey) && cert.checkHost('mikaya-interop.test') === 'mikaya-interop.test', 'direct peer certificate profile refused');
  ensure(hash(cert.raw) === peer.tlsCertificateSha256, 'direct peer certificate digest mismatch');
  ensure(Date.parse(cert.validFrom) <= nowMs && nowMs < Date.parse(cert.validTo), 'direct peer certificate expired or not yet valid');
  verifySignature('PEER', peer, key);
  return peer;
}
function loadIdentity(stateDir) {
  safeDirectory(stateDir);
  const saved = readJson(path.join(stateDir, 'synthetic-keys.json'));
  ensure(saved.schema === 'mikaya.interop.synthetic-keys.v1' && typeof saved.privateKey === 'string' && typeof saved.rootKeyHex === 'string' && HASH.test(saved.rootKeyHex), 'synthetic identity state refused');
  const privateKey = crypto.createPrivateKey(saved.privateKey);
  ensure(privateKey.asymmetricKeyType === 'ed25519', 'Ed25519 application key required');
  const profile = readJson(path.join(stateDir, 'runtime-profile.json'));
  runtime.validateRuntimeProfile(profile);
  ensure(session.profileDigest(profile) === saved.profileSha256, 'runtime profile changed');
  return { stateDir, privateKey, publicKey: crypto.createPublicKey(privateKey), rootKey: Buffer.from(saved.rootKeyHex, 'hex'), profile, profileSha256: saved.profileSha256, replayDir: path.join(stateDir, 'replay') };
}
function loadOwn(stateDir) {
  const own = loadIdentity(stateDir), dir = safeDirectory(transportDir(stateDir));
  const peer = validatePeer(readJson(path.join(dir, 'public-peer.json')));
  ensure(peer.fingerprint === fed.fp(own.publicKey) && peer.profileSha256 === own.profileSha256, 'local public identity changed');
  const key = readFile(path.join(dir, 'tls-private.pem'));
  ensure(new crypto.X509Certificate(peer.tlsCertificatePem).checkPrivateKey(crypto.createPrivateKey(key)), 'local TLS key and certificate mismatch');
  return { ...own, dir, peer, key, cert: peer.tlsCertificatePem };
}
function initialize(stateDir) {
  ensure(typeof stateDir === 'string' && path.isAbsolute(stateDir), 'absolute new state directory required');
  if (!fs.existsSync(stateDir)) handoff.execute('init', stateDir);
  const own = loadIdentity(stateDir), dir = transportDir(stateDir);
  fs.mkdirSync(dir, { mode: 0o700 });
  const pair = crypto.generateKeyPairSync('ed25519');
  writeNew(path.join(dir, 'tls-private.pem'), pair.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const conf = '[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN=mikaya-interop.test\n[ext]\nsubjectAltName=DNS:mikaya-interop.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\n';
  writeNew(path.join(dir, 'certificate.conf'), conf);
  const result = spawnSync('openssl', ['req', '-new', '-x509', '-key', path.join(dir, 'tls-private.pem'), '-out', path.join(dir, 'tls-public.pem'), '-days', '7', '-config', path.join(dir, 'certificate.conf')], { timeout: 10000, maxBuffer: 8192, windowsHide: true, encoding: 'utf8' });
  ensure(!result.error && result.status === 0 && !result.signal, 'OpenSSL certificate creation failed');
  fs.chmodSync(path.join(dir, 'tls-public.pem'), 0o600);
  const cert = readFile(path.join(dir, 'tls-public.pem')).toString('utf8');
  const peer = sign('PEER', { schema: 'mikaya.interop.direct-peer.v1', publicKey: own.publicKey.export({ type: 'spki', format: 'pem' }), fingerprint: fed.fp(own.publicKey), profileSha256: own.profileSha256, tlsCertificatePem: cert, tlsCertificateSha256: hash(new crypto.X509Certificate(cert).raw), syntheticIdentity: true, hardwareAttested: false, productionAdmission: false }, own.privateKey);
  validatePeer(peer);
  writeNew(path.join(dir, 'public-peer.json'), peer);
  writeNew(path.join(dir, 'events.jsonl'), '');
  return peer;
}
function defaultPolicy(peer) {
  return { schema: 'mikaya.interop.direct-policy.v1', enabled: true, peerFingerprint: peer.fingerprint, peerCertificateSha256: peer.tlsCertificateSha256, allowedCapabilities: [...CAPS], maxRequestBytes: 8192, maxConnections: 4, maxFramesPerConnection: 256, maxConnectionBytes: 1024 * 1024, idleTimeoutMs: 15000, maxConnectionMs: 120000 };
}
function validatePolicy(policy) {
  ensure(exact(policy, POLICY_FIELDS) && policy.schema === 'mikaya.interop.direct-policy.v1' && typeof policy.enabled === 'boolean', 'direct owner policy schema refused');
  ensure(typeof policy.peerFingerprint === 'string' && HASH.test(policy.peerFingerprint) && typeof policy.peerCertificateSha256 === 'string' && HASH.test(policy.peerCertificateSha256), 'direct owner pin fields refused');
  ensure(Array.isArray(policy.allowedCapabilities) && policy.allowedCapabilities.length > 0 && policy.allowedCapabilities.length <= 2 && new Set(policy.allowedCapabilities).size === policy.allowedCapabilities.length && policy.allowedCapabilities.every(x => CAPS.includes(x)), 'owner capability allowlist refused');
  for (const [name, min, max] of [['maxRequestBytes', 512, 8192], ['maxConnections', 1, 8], ['maxFramesPerConnection', 2, 256], ['maxConnectionBytes', 8192, 1024 * 1024], ['idleTimeoutMs', 1000, 30000], ['maxConnectionMs', 1000, 120000]]) ensure(Number.isSafeInteger(policy[name]) && policy[name] >= min && policy[name] <= max, 'owner limit refused: ' + name);
  return policy;
}
function pinPeer(stateDir, peer, distributionPolicy) {
  const own = loadOwn(stateDir); validatePeer(peer);
  ensure(own.peer.fingerprint !== peer.fingerprint && own.peer.tlsCertificateSha256 !== peer.tlsCertificateSha256, 'independent peer identities required');
  ledgers.validateDistributionPolicy(distributionPolicy);
  ensure(distributionPolicy.beneficiaries.every(b => [own.peer.fingerprint, peer.fingerprint].includes(b.fingerprint)), 'distribution policy must identify this exact pair');
  writeNew(path.join(own.dir, 'pinned-peer.json'), peer);
  writeNew(path.join(own.dir, 'owner-policy.json'), defaultPolicy(peer));
  writeNew(path.join(own.dir, 'distribution-policy.json'), distributionPolicy);
  const ledger = ledgers.initializeReceiptLedger({ ledgerDir: path.join(own.dir, 'receipt-ledger'), nodePrivateKey: own.privateKey, policy: distributionPolicy });
  return { schema: 'mikaya.interop.direct-pairing.v1', ownFingerprint: own.peer.fingerprint, peerFingerprint: peer.fingerprint, peerCertificateSha256: peer.tlsCertificateSha256, enabled: true, receiptLedgerCheckpoint: ledger.checkpoint, accountingUnit: ledgers.UNIT, paymentsAuthorized: false };
}
function loadAuthority(own, requireEnabled = true) {
  const peer = validatePeer(readJson(path.join(own.dir, 'pinned-peer.json')));
  const policy = validatePolicy(readJson(path.join(own.dir, 'owner-policy.json')));
  ensure(peer.fingerprint === policy.peerFingerprint && peer.tlsCertificateSha256 === policy.peerCertificateSha256, 'owner policy and peer pins disagree');
  if (requireEnabled) {
    ensure(policy.enabled, 'owner policy disabled');
    ensure(!fs.existsSync(path.join(own.dir, 'kill-switch')), 'owner kill switch active');
  }
  return { peer, policy };
}
function setEnabled(stateDir, enabled) {
  ensure(typeof enabled === 'boolean', 'boolean owner policy required');
  const own = loadOwn(stateDir), { policy } = loadAuthority(own, false);
  atomicJson(path.join(own.dir, 'owner-policy.json'), { ...policy, enabled });
  return { schema: 'mikaya.interop.direct-owner-switch.v1', enabled, restartRequiredWhenEnabling: true };
}
function safeAddress(host) {
  ensure(typeof host === 'string' && host.length <= 80, 'explicit private or loopback IP required');
  const family = net.isIP(host);
  if (family === 4) {
    const [a,b] = host.split('.').map(Number);
    ensure(a === 127 || a === 10 || a === 192 && b === 168 || a === 172 && b >= 16 && b <= 31 || a === 100 && b >= 64 && b <= 127, 'public or wildcard address refused');
  } else if (family === 6) ensure(host === '::1' || /^(?:fc|fd)[0-9a-f]{2}:/i.test(host), 'public, link-local or wildcard IPv6 refused');
  else throw new Error('literal private or loopback IP required');
  return host;
}
function checkPort(port, allowZero = false) { ensure(Number.isSafeInteger(port) && (allowZero && port === 0 || port >= 1024 && port <= 65535), 'unprivileged port required'); }
function bindingFor(socket) { return hash(socket.exportKeyingMaterial(32, 'MIKAYA-INTEROP-DIRECT/1')); }
function certificateHash(socket) { const raw = socket.getPeerCertificate().raw; ensure(Buffer.isBuffer(raw), 'TLS peer certificate missing'); return hash(raw); }
function authorizeSocket(socket, own, expectedPeer = null) {
  const { peer, policy } = loadAuthority(own);
  ensure(!expectedPeer || expectedPeer.fingerprint === peer.fingerprint && expectedPeer.tlsCertificateSha256 === peer.tlsCertificateSha256, 'owner pins changed during session');
  ensure(socket.authorized === true && socket.getProtocol() === 'TLSv1.3', 'authorized TLS 1.3 required');
  ensure(certificateHash(socket) === peer.tlsCertificateSha256, 'TLS certificate pin refused');
  return { peer, policy };
}
function frame(value) {
  const bytes = Buffer.from(session.boundedCanonical(value, MAX_FRAME)), header = Buffer.alloc(4);
  ensure(bytes.length > 0 && bytes.length <= MAX_FRAME, 'frame size refused'); header.writeUInt32BE(bytes.length);
  return Buffer.concat([header, bytes]);
}
function decoder(callback) {
  let pending = Buffer.alloc(0), expected = null;
  return chunk => {
    ensure(Buffer.isBuffer(chunk), 'binary TLS input required');
    pending = Buffer.concat([pending, chunk]);
    while (true) {
      if (expected === null) {
        if (pending.length < 4) break;
        expected = pending.readUInt32BE(0); pending = pending.subarray(4);
        ensure(expected > 0 && expected <= MAX_FRAME, 'frame size refused');
      }
      if (pending.length < expected) break;
      const raw = utf8.decode(pending.subarray(0, expected)), value = JSON.parse(raw);
      ensure(session.boundedCanonical(value, MAX_FRAME) === raw, 'noncanonical or duplicate-key frame refused');
      pending = pending.subarray(expected); expected = null;
      callback(value);
    }
    ensure(pending.length <= MAX_FRAME + 4, 'frame buffer limit exceeded');
  };
}
function readLedger(dir) {
  const raw = readFile(path.join(dir, 'events.jsonl'), MAX_LEDGER_BYTES).toString('utf8');
  ensure(raw === '' || raw.endsWith('\n'), 'partial local transport ledger');
  let previous = '0'.repeat(64), sequence = 0;
  for (const line of raw.split('\n').filter(Boolean)) {
    const row = JSON.parse(line);
    ensure(exact(row, ['seq', 'prev', 'event', 'hash']) && row.seq === ++sequence && row.prev === previous && hash(fed.canonical({ seq: row.seq, prev: row.prev, event: row.event })) === row.hash, 'local transport ledger integrity refused');
    previous = row.hash;
  }
  return { sequence, previous, bytes: Buffer.byteLength(raw) };
}
function appendEvent(dir, event) {
  const state = readLedger(dir); ensure(state.sequence < 20000, 'local transport ledger capacity reached');
  const body = { seq: state.sequence + 1, prev: state.previous, event: { atMs: Date.now(), ...event } };
  const row = { ...body, hash: hash(fed.canonical(body)) }, bytes = fed.canonical(row) + '\n';
  ensure(state.bytes + Buffer.byteLength(bytes) <= MAX_LEDGER_BYTES, 'local transport ledger size limit');
  const fd = fs.openSync(path.join(dir, 'events.jsonl'), fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  return row.hash;
}
function conformancePolicy(policy) { return { schema: 'mikaya.interop.conformance-policy.v1', enabled: policy.enabled, allowedCapabilities: policy.allowedCapabilities, maxRequestBytes: policy.maxRequestBytes }; }
function checkRequest(request, own, peer, policy) {
  const context = session.verifyRequest({ request, holderPublicKey: peer.publicKey, workerPublicKey: own.publicKey, maxBytes: policy.maxRequestBytes });
  ensure(policy.allowedCapabilities.includes(context.operation), 'operation excluded by owner policy');
  return context;
}
function recordReceipt(own, { request, response, evidence, holderPublicKey, workerPublicKey, profileSha256 }) {
  const policy = readJson(path.join(own.dir, 'distribution-policy.json'));
  return ledgers.appendReceipt({ ledgerDir: path.join(own.dir, 'receipt-ledger'), nodePrivateKey: own.privateKey, policy, receipt: { request, response, evidence }, holderPublicKey, workerPublicKey, profileSha256 });
}
function transportEvidence(own, peer, request, response, binding, workerLedger) {
  return sign('TRANSPORT_EVIDENCE', { schema: 'mikaya.interop.direct-evidence.v1', transport: 'TLSv1.3_MUTUAL_PINNED', holderFingerprint: peer.fingerprint, workerFingerprint: own.peer.fingerprint, holderCertificateSha256: peer.tlsCertificateSha256, workerCertificateSha256: own.peer.tlsCertificateSha256, channelBindingSha256: binding, requestNonce: request.auth.nonce, requestSha256: hash(session.boundedCanonical(request)), responseSha256: hash(session.boundedCanonical(response)), profileSha256: own.profileSha256, workerLedgerRecordSha256: hash(session.boundedCanonical(workerLedger)), issuedAtMs: response.auth.issuedAtMs, hardwareAttested: false, productionAdmission: false, paymentAuthorized: false }, own.privateKey);
}
function verifyTransportEvidence(evidence, { own, peer, request, response, binding, workerLedger, nowMs = Date.now() }) {
  session.boundedCanonical(evidence, MAX_FRAME);
  ensure(exact(evidence, TRANSPORT_FIELDS) && evidence.schema === 'mikaya.interop.direct-evidence.v1' && evidence.transport === 'TLSv1.3_MUTUAL_PINNED', 'transport evidence schema refused');
  ensure(evidence.hardwareAttested === false && evidence.productionAdmission === false && evidence.paymentAuthorized === false, 'transport evidence scope refused');
  ensure(evidence.holderFingerprint === own.fingerprint && evidence.workerFingerprint === peer.fingerprint && evidence.holderCertificateSha256 === own.tlsCertificateSha256 && evidence.workerCertificateSha256 === peer.tlsCertificateSha256, 'transport evidence peer binding refused');
  ensure(typeof binding === 'string' && HASH.test(binding) && evidence.channelBindingSha256 === binding && evidence.profileSha256 === peer.profileSha256, 'transport evidence channel or profile binding refused');
  ensure(evidence.requestNonce === request.auth.nonce && evidence.requestSha256 === hash(session.boundedCanonical(request)) && evidence.responseSha256 === hash(session.boundedCanonical(response)), 'transport evidence transcript binding refused');
  ensure(evidence.workerLedgerRecordSha256 === hash(session.boundedCanonical(workerLedger)), 'transport evidence ledger binding refused');
  ensure(Number.isSafeInteger(evidence.issuedAtMs) && evidence.issuedAtMs === response.auth.issuedAtMs && Math.abs(nowMs - evidence.issuedAtMs) <= 60000, 'transport evidence freshness refused');
  verifySignature('TRANSPORT_EVIDENCE', evidence, peer.publicKey);
  return true;
}
function verifyWorkerLedgerRecord(record, { policy, request, response, evidence, holderFingerprint, workerFingerprint, workerPublicKey, nowMs = Date.now() }) {
  session.boundedCanonical(record, MAX_FRAME);
  ensure(exact(record, ['recorded','index','entryHash','requestKey','receiptSha256','accounting','checkpoint','eventSpineDigest','paymentSettled','executionAuthorized']), 'worker ledger record schema refused');
  ensure(record.recorded === true && record.paymentSettled === false && record.executionAuthorized === false && Number.isSafeInteger(record.index) && record.index >= 1 && record.index < ledgers.MAX_ENTRIES, 'worker ledger record scope or index refused');
  ensure(['entryHash','requestKey','receiptSha256'].every(k => typeof record[k] === 'string' && HASH.test(record[k])), 'worker ledger digest fields refused');
  ensure(record.requestKey === hash(holderFingerprint + '\n' + workerFingerprint + '\n' + request.auth.nonce) && record.receiptSha256 === hash(session.boundedCanonical({ request, response, evidence }, MAX_FRAME)), 'worker ledger receipt binding refused');
  const accounting = ledgers.accountReceipt({ policy, capability: request.body.capability, holderFingerprint, workerFingerprint });
  ensure(hash(session.boundedCanonical(record.accounting)) === hash(session.boundedCanonical(accounting)), 'worker ledger accounting disagrees with owner policy');
  ledgers.verifyReceiptCheckpoint({ checkpoint: record.checkpoint, nodePublicKey: workerPublicKey });
  ensure(record.checkpoint.latestHash === record.entryHash && record.checkpoint.entries === record.index + 1 && record.checkpoint.policySha256 === accounting.policySha256 && record.checkpoint.ownerFingerprint === workerFingerprint, 'worker ledger checkpoint linkage refused');
  ensure(record.checkpoint.issuedAtMs >= response.auth.issuedAtMs && Math.abs(nowMs - record.checkpoint.issuedAtMs) <= 60000, 'worker ledger checkpoint freshness refused');
  ensure(exact(record.eventSpineDigest, ['kind','payloadSha256']) && record.eventSpineDigest.kind === 'FEDERATION_COMPUTE_OBSERVED' && record.eventSpineDigest.payloadSha256 === record.entryHash, 'worker ledger event digest refused');
  return true;
}
async function startServer({ stateDir, host, port }) {
  safeAddress(host); checkPort(port, true);
  const own = loadOwn(stateDir), authority = loadAuthority(own);
  readLedger(own.dir);
  const accountingPolicy = readJson(path.join(own.dir, 'distribution-policy.json'));
  ledgers.validateDistributionPolicy(accountingPolicy);
  const ledgerHead = ledgers.verifyReceiptLedger({ ledgerDir: path.join(own.dir, 'receipt-ledger'), nodePublicKey: own.publicKey });
  ensure(ledgerHead.policySha256 === hash(session.boundedCanonical(accountingPolicy)), 'signed ledger and current distribution policy disagree');
  // A corrupt/missing replay journal must fail before accepting a connection.
  mac.inspectReplayState(own.replayDir);
  const lock = path.join(own.dir, 'server.lock'), startedAtMs = Date.now();
  writeNew(lock, { schema: 'mikaya.interop.direct-server-lock.v1', pid: process.pid, startedAtMs, phase: 'STARTING' });
  const sockets = new Set(), socketMetadata = new WeakMap(); let closing = false, policyTimer;
  const server = tls.createServer({ key: own.key, cert: own.cert, ca: [authority.peer.tlsCertificatePem], requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', handshakeTimeout: 3000, sessionTimeout: 60 }, socket => {
    let authorized;
    try { authorized = authorizeSocket(socket, own, authority.peer); } catch { socket.destroy(); return; }
    sockets.add(socket); socket.setNoDelay(true); socket.setTimeout(authorized.policy.idleTimeoutMs, () => socket.destroy());
    const binding = bindingFor(socket); let frames = 0, bytesIn = 0, bytesOut = 0;
    const metadata = { startedAtMs: Date.now(), lastActivityMs: Date.now() }; socketMetadata.set(socket, metadata);
    const expiration = setTimeout(() => socket.destroy(), authorized.policy.maxConnectionMs); expiration.unref();
    socket.on('close', () => { sockets.delete(socket); clearTimeout(expiration); });
    socket.on('error', () => {});
    const send = value => {
      const buffer = frame(value); bytesOut += buffer.length;
      const current = authorizeSocket(socket, own, authorized.peer).policy;
      ensure(bytesOut <= current.maxConnectionBytes && socket.writableLength <= MAX_FRAME * 2, 'outbound connection budget exceeded');
      socket.write(buffer);
    };
    const consume = decoder(message => {
      const { peer, policy } = authorizeSocket(socket, own, authorized.peer);
      ensure(++frames <= policy.maxFramesPerConnection, 'connection frame limit exceeded');
      ensure(exact(message, message?.type === 'grant' ? ['id', 'type', 'channelBindingSha256', 'request'] : ['id', 'type', 'channelBindingSha256', 'request', 'token']) && typeof message.id === 'string' && ID.test(message.id) && ['grant', 'execute'].includes(message.type), 'direct message schema refused');
      ensure(message.channelBindingSha256 === binding, 'TLS channel binding refused');
      try {
        const context = checkRequest(message.request, own, peer, policy);
        if (message.type === 'grant') {
          const nowMs = Date.now();
          const token = mac.mintTestCapability({ rootKey: own.rootKey, holderKeySha256: context.holderKeySha256, audience: context.audience, profileSha256: own.profileSha256, operation: context.operation, bodySha256: context.bodySha256, issuedAtMs: nowMs, expiresAtMs: nowMs + 60000, maxUses: 1, maxBytes: policy.maxRequestBytes });
          appendEvent(own.dir, { type: 'CAPABILITY_GRANTED', requestNonce: context.requestNonce, holderFingerprint: peer.fingerprint, operation: context.operation, bodySha256: context.bodySha256 });
          send({ id: message.id, ok: true, channelBindingSha256: binding, result: { token, profileSha256: own.profileSha256 } });
        } else {
          ensure(typeof message.token === 'string' && message.token.length <= 32768, 'bounded capability token required');
          const accepted = session.acceptConformanceRequest({ request: message.request, token: message.token, rootKey: own.rootKey, holderPublicKey: peer.publicKey, workerPrivateKey: own.privateKey, profile: own.profile, stateDir: own.replayDir, policy: conformancePolicy(policy) });
          const workerLedger = recordReceipt(own, { request: message.request, response: accepted.response, evidence: accepted.evidence, holderPublicKey: peer.publicKey, workerPublicKey: own.publicKey, profileSha256: own.profileSha256 });
          const transport = transportEvidence(own, peer, message.request, accepted.response, binding, workerLedger);
          appendEvent(own.dir, { type: 'REQUEST_COMPLETED', requestNonce: context.requestNonce, holderFingerprint: peer.fingerprint, operation: context.operation, requestSha256: transport.requestSha256, responseSha256: transport.responseSha256, channelBindingSha256: binding });
          send({ id: message.id, ok: true, channelBindingSha256: binding, result: { response: accepted.response, evidence: accepted.evidence, transportEvidence: transport, workerLedger } });
        }
      } catch (error) {
        appendEvent(own.dir, { type: 'REQUEST_REFUSED', reason: String(error.message).slice(0, 160) });
        send({ id: message.id, ok: false, channelBindingSha256: binding, error: 'REFUSED: ' + String(error.message).slice(0, 160) });
      }
    });
    socket.on('data', chunk => {
      try {
        const current = authorizeSocket(socket, own, authorized.peer).policy;
        bytesIn += chunk.length; ensure(bytesIn <= current.maxConnectionBytes, 'inbound connection budget exceeded');
        ensure(Date.now() - metadata.startedAtMs <= current.maxConnectionMs, 'connection age limit exceeded');
        metadata.lastActivityMs = Date.now(); consume(chunk);
      } catch { socket.destroy(); }
    });
  });
  server.maxConnections = authority.policy.maxConnections;
  server.on('tlsClientError', () => {});
  const close = () => {
    if (closing) return; closing = true; clearInterval(policyTimer);
    for (const socket of sockets) socket.destroy();
    server.close();
  };
  server.on('close', () => { clearInterval(policyTimer); if (fs.existsSync(lock)) fs.unlinkSync(lock); });
  server.on('error', () => close());
  policyTimer = setInterval(() => {
    try {
      const next = loadAuthority(own); ensure(next.peer.fingerprint === authority.peer.fingerprint && next.peer.tlsCertificateSha256 === authority.peer.tlsCertificateSha256, 'peer pins changed');
      server.maxConnections = next.policy.maxConnections;
      let count = 0;
      for (const socket of sockets) {
        const metadata = socketMetadata.get(socket), nowMs = Date.now();
        if (++count > next.policy.maxConnections || nowMs - metadata.startedAtMs > next.policy.maxConnectionMs || nowMs - metadata.lastActivityMs > next.policy.idleTimeoutMs) socket.destroy();
      }
    }
    catch { close(); }
  }, 200); policyTimer.unref();
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen({ port, host, exclusive: true }, () => { server.off('error', reject); resolve(); }); });
    appendEvent(own.dir, { type: 'DIRECT_SERVER_STARTED', workerFingerprint: own.peer.fingerprint, peerFingerprint: authority.peer.fingerprint, protocol: 'TLSv1.3', port: server.address().port });
    atomicJson(lock, { schema: 'mikaya.interop.direct-server-lock.v1', pid: process.pid, startedAtMs, phase: 'READY', host, port: server.address().port });
    return { server, close, own: own.peer, peer: authority.peer, address: server.address() };
  } catch (error) { close(); if (fs.existsSync(lock)) fs.unlinkSync(lock); throw error; }
}
async function connect({ stateDir, host, port, timeoutMs = 10000 }) {
  safeAddress(host); checkPort(port); ensure(Number.isSafeInteger(timeoutMs) && timeoutMs >= 100 && timeoutMs <= 30000, 'client timeout refused');
  const own = loadOwn(stateDir), { peer, policy } = loadAuthority(own);
  const start = performance.now();
  const socket = tls.connect({ host, port, servername: 'mikaya-interop.test', key: own.key, cert: own.cert, ca: [peer.tlsCertificatePem], rejectUnauthorized: true, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', checkServerIdentity: (_name, cert) => cert.raw && hash(cert.raw) === peer.tlsCertificateSha256 ? undefined : new Error('TLS server certificate pin refused') });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('TLS connection deadline exceeded')); }, timeoutMs);
    socket.once('error', error => { clearTimeout(timer); reject(error); });
    socket.once('secureConnect', () => { clearTimeout(timer); try { authorizeSocket(socket, own, peer); resolve(); } catch (e) { socket.destroy(); reject(e); } });
  });
  const binding = bindingFor(socket), handshakeMs = performance.now() - start;
  const pending = new Map(); let stopped = false, received = 0, sent = 0;
  const fail = error => { if (stopped) return; stopped = true; for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(error); } pending.clear(); socket.destroy(); };
  socket.setNoDelay(true); socket.setTimeout(policy.idleTimeoutMs, () => fail(new Error('TLS session idle timeout')));
  socket.on('error', fail); socket.on('close', () => fail(new Error('TLS session closed')));
  const expiration = setTimeout(() => fail(new Error('TLS session age limit exceeded')), policy.maxConnectionMs); expiration.unref();
  socket.on('close', () => clearTimeout(expiration));
  const consume = decoder(message => {
    authorizeSocket(socket, own, peer);
    ensure(exact(message, message?.ok === true ? ['id', 'ok', 'channelBindingSha256', 'result'] : ['id', 'ok', 'channelBindingSha256', 'error']) && typeof message.id === 'string' && ID.test(message.id) && typeof message.ok === 'boolean' && message.channelBindingSha256 === binding, 'direct response envelope refused');
    const waiting = pending.get(message.id); ensure(waiting, 'unsolicited or repeated direct response');
    clearTimeout(waiting.timer); pending.delete(message.id);
    if (message.ok) waiting.resolve(message.result);
    else { ensure(typeof message.error === 'string' && message.error.length <= 200, 'unbounded direct error'); waiting.reject(new Error(message.error)); }
  });
  socket.on('data', chunk => { try { received += chunk.length; const current = authorizeSocket(socket, own, peer).policy; ensure(received <= current.maxConnectionBytes, 'response connection byte budget exceeded'); consume(chunk); } catch (e) { fail(e); } });
  const requestFrame = (type, request, token) => new Promise((resolve, reject) => {
    try {
      ensure(!stopped && !socket.destroyed, 'TLS session closed'); const current = authorizeSocket(socket, own, peer).policy;
      ensure(pending.size < 4, 'client request concurrency exceeded');
      const id = crypto.randomBytes(16).toString('hex');
      const message = { id, type, channelBindingSha256: binding, request, ...(type === 'execute' ? { token } : {}) }, bytes = frame(message);
      sent += bytes.length; ensure(sent <= current.maxConnectionBytes && socket.writableLength <= MAX_FRAME * 2, 'client connection byte budget exceeded');
      const timer = setTimeout(() => fail(new Error('direct request deadline exceeded')), timeoutMs);
      pending.set(id, { resolve, reject, timer }); socket.write(bytes);
    } catch (e) { reject(e); }
  });
  const perform = async (job, { checkReplay = false } = {}) => {
    const started = performance.now(), request = session.makeRequest({ holderPrivateKey: own.privateKey, workerPublicKey: peer.publicKey, job });
    const grant = await requestFrame('grant', request);
    ensure(exact(grant, ['token', 'profileSha256']) && typeof grant.token === 'string' && grant.profileSha256 === peer.profileSha256, 'grant profile binding refused');
    const result = await requestFrame('execute', request, grant.token);
    ensure(exact(result, ['response', 'evidence', 'transportEvidence', 'workerLedger']), 'direct result fields refused');
    const verified = session.verifyConformanceReceipt({ request, response: result.response, evidence: result.evidence, holderPublicKey: own.publicKey, workerPublicKey: peer.publicKey, profileSha256: peer.profileSha256 });
    verifyTransportEvidence(result.transportEvidence, { own: own.peer, peer, request, response: result.response, binding, workerLedger: result.workerLedger });
    verifyWorkerLedgerRecord(result.workerLedger, { policy: readJson(path.join(own.dir, 'distribution-policy.json')), request, response: result.response, evidence: result.evidence, holderFingerprint: own.peer.fingerprint, workerFingerprint: peer.fingerprint, workerPublicKey: peer.publicKey });
    const holderLedger = recordReceipt(own, { request, response: result.response, evidence: result.evidence, holderPublicKey: own.publicKey, workerPublicKey: peer.publicKey, profileSha256: peer.profileSha256 });
    let replayRefused = null;
    if (checkReplay) {
      try { await requestFrame('execute', request, grant.token); replayRefused = false; }
      catch (e) { ensure(/request replay refused/.test(e.message), 'replay check did not produce a verified replay refusal'); replayRefused = true; }
      ensure(replayRefused, 'completed request replay was accepted');
    }
    return { schema: 'mikaya.interop.direct-exchange.v1', verifiedAt: new Date().toISOString(), transport: 'TLSv1.3_MUTUAL_PINNED', negotiatedProtocol: socket.getProtocol(), cipher: socket.getCipher().standardName, own: own.peer, peer, request, response: result.response, evidence: result.evidence, transportEvidence: result.transportEvidence, workerLedger: result.workerLedger, holderLedger, verified, replayRefused, elapsedMs: performance.now() - started, handshakeMs, bytesSent: sent, bytesReceived: received, syntheticIdentities: true, hardwareAttested: false, productionAdmission: false, paymentsAuthorized: false };
  };
  return { perform, requestFrame, binding, own: own.peer, peer, handshakeMs, socket, close: () => fail(new Error('client closed')) };
}
function makeJob(capability, index = 0) {
  return { schema: 'mikaya.federation.job.v1', id: crypto.randomBytes(16).toString('hex'), capability, payload: capability === 'compute.dot.v1' ? { a: [1,2,3], b: [4,5,6] } : { challengeHex: 'a5'.repeat(32) } };
}
async function exercise(options) {
  const connection = await connect(options);
  try {
    const exchanges = [];
    for (const capability of CAPS) exchanges.push(await connection.perform(makeJob(capability), { checkReplay: true }));
    return { schema: 'mikaya.interop.direct-exercise.v1', performedAt: new Date().toISOString(), transport: 'TLSv1.3_MUTUAL_PINNED', exchanges, allVerified: exchanges.every(x => x.verified.evidenceVerified && x.replayRefused), hardwareAttested: false, productionAdmission: false };
  } finally { connection.close(); }
}
function summary(values) {
  const sorted = [...values].sort((a,b) => a-b);
  return { samples: values, minMs: sorted[0], medianMs: sorted[Math.floor(sorted.length / 2)], maxMs: sorted.at(-1), meanMs: values.reduce((a,b) => a+b, 0) / values.length };
}
async function benchmark(options, count = 10) {
  ensure(Number.isSafeInteger(count) && count >= 3 && count <= 20, 'benchmark count must be 3..20');
  // Alternate comparison order to reduce one-way order bias. These are tiny,
  // fixed authenticated jobs; this measures latency, not bulk link capacity.
  const fresh = [], persistent = [], receipts = [];
  const reuse = await connect(options);
  try {
    for (let i=0;i<count;i++) {
      for (const kind of i % 2 ? ['persistent','fresh'] : ['fresh','persistent']) {
        const started = performance.now(), client = kind === 'fresh' ? await connect(options) : reuse;
        try {
          const proof = await client.perform(makeJob('compute.sha256.v1', i));
          (kind === 'fresh' ? fresh : persistent).push(performance.now() - started);
          receipts.push({ kind, request: proof.request, response: proof.response, evidence: proof.evidence, transportEvidence: proof.transportEvidence, workerLedger: proof.workerLedger, holderLedger: proof.holderLedger });
        } finally { if (kind === 'fresh') client.close(); }
      }
    }
    const a = summary(fresh), b = summary(persistent);
    return { schema: 'mikaya.interop.direct-latency-benchmark.v1', performedAt: new Date().toISOString(), measurement: 'PAIRED_FIXED_32_BYTE_SHA256_JOB_LATENCY', countPerCondition: count, freshTlsEachJob: a, persistentTls: b, persistentConnectionSetupMs: reuse.handshakeMs, freshOverPersistentMedianRatio: a.medianMs / b.medianMs, persistentFasterInThisRun: b.medianMs < a.medianMs, own: reuse.own, peer: reuse.peer, receipts, bulkThroughputMeasured: false, independentHardwareAttestation: false };
  } finally { reuse.close(); }
}
async function main(args = process.argv.slice(2)) {
  const [command, stateDir, a, b, c, d, ...rest] = args;
  ensure(stateDir && rest.length === 0, 'usage: direct-transport.cjs init|pin|serve|exercise|benchmark|enable|disable|status ABSOLUTE_STATE ...');
  if (command === 'init') { ensure(!a, 'init takes state only'); return initialize(stateDir); }
  if (command === 'pin') { ensure(a && b && !c, 'pin requires public peer JSON and explicit nonmonetary distribution policy JSON'); return pinPeer(stateDir, JSON.parse(fs.readFileSync(a, 'utf8')), JSON.parse(fs.readFileSync(b, 'utf8'))); }
  if (command === 'enable' || command === 'disable') { ensure(!a, 'switch takes state only'); return setEnabled(stateDir, command === 'enable'); }
  if (command === 'status') { ensure(!a, 'status takes state only'); const own = loadOwn(stateDir), auth = loadAuthority(own, false); return { own: own.peer, peer: auth.peer, policy: auth.policy, killSwitch: fs.existsSync(path.join(own.dir, 'kill-switch')), localLedger: readLedger(own.dir), receiptLedger: ledgers.verifyReceiptLedger({ ledgerDir: path.join(own.dir, 'receipt-ledger'), nodePublicKey: own.publicKey }) }; }
  if (command === 'serve') {
    ensure(a && b && !c, 'serve requires IP and port'); checkPort(Number(b));
    const running = await startServer({ stateDir, host: a, port: Number(b) });
    process.stdout.write(JSON.stringify({ status: 'DIRECT_TLS_READY', protocol: 'TLSv1.3_MUTUAL_PINNED', address: running.address, ownFingerprint: running.own.fingerprint, peerFingerprint: running.peer.fingerprint }) + '\n');
    process.once('SIGTERM', running.close); process.once('SIGINT', running.close);
    return undefined;
  }
  if (command === 'exercise') { ensure(a && b && c && !d, 'exercise requires IP port new-output-file'); const result = await exercise({ stateDir, host: a, port: Number(b) }); writeNew(c, result); return { status: result.allVerified ? 'PASSED' : 'FAILED', output: c, exchanges: result.exchanges.length, replayRefused: result.exchanges.every(x => x.replayRefused) }; }
  if (command === 'benchmark') { ensure(a && b && c && d, 'benchmark requires IP port count new-output-file'); const result = await benchmark({ stateDir, host: a, port: Number(b) }, Number(c)); writeNew(d, result); return { status: 'MEASURED', output: d, freshMedianMs: result.freshTlsEachJob.medianMs, persistentMedianMs: result.persistentTls.medianMs, ratio: result.freshOverPersistentMedianRatio, persistentFasterInThisRun: result.persistentFasterInThisRun, bulkThroughputMeasured: false }; }
  throw new Error('unknown direct transport command');
}
if (require.main === module) main().then(result => { if (result !== undefined) process.stdout.write(JSON.stringify(result) + '\n'); }).catch(error => { process.stderr.write(JSON.stringify({ status: 'REFUSED', reason: String(error.message).slice(0,200) }) + '\n'); process.exitCode = 1; });
module.exports = { initialize, validatePeer, pinPeer, setEnabled, validatePolicy, loadOwn, loadAuthority, safeAddress, frame, decoder, startServer, connect, exercise, benchmark, verifyTransportEvidence, verifyWorkerLedgerRecord, makeJob, readLedger, main, MAX_FRAME };
