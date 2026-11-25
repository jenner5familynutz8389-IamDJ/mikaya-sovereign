#!/usr/bin/env node
'use strict';
/**
 * Explicit owner-invoked, offline, two-device conformance commands.
 * Creates NEW synthetic keys/state only. No service, network listener, live key
 * access, hardware attestation, wallet, installation or firmware operation.
 * Public packets can be carried between devices by the owner's chosen channel.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const session = require('./session-adapter.cjs');
const runtime = require('./runtime-profile.cjs');
const mac = require('./capability-macaroons.cjs');
const fed = require('../live/federation-node.cjs');
function ensure(ok, message) { if (!ok) throw new Error(message); }
function exactPacket(value, fields) {
  ensure(value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).sort().join('|') === [...fields].sort().join('|'), 'public packet schema refused');
  session.boundedCanonical(value, 65536);
}
const REQUEST_PACKET = ['request', 'holderPublicKey'];
const GRANT_PACKET = [...REQUEST_PACKET, 'token', 'workerPublicKey', 'profileSha256', 'environment'];
const RESPONSE_PACKET = [...GRANT_PACKET, 'response', 'evidence'];
function readJson(file, secret = false) {
  const st = fs.lstatSync(file);
  ensure(st.isFile() && !st.isSymbolicLink() && st.size <= 131072, 'unsafe or oversized input file');
  ensure(!secret || !(st.mode & 0o077), 'test key file permissions refused');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
function put(file, value) { fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 }); }
function load(stateDir) {
  const st = fs.lstatSync(stateDir);
  ensure(st.isDirectory() && !st.isSymbolicLink() && !(st.mode & 0o077), 'test state must be a private directory');
  const saved = readJson(path.join(stateDir, 'synthetic-keys.json'), true);
  ensure(saved.schema === 'mikaya.interop.synthetic-keys.v1', 'wrong test identity schema');
  const privateKey = crypto.createPrivateKey(saved.privateKey);
  ensure(privateKey.asymmetricKeyType === 'ed25519', 'wrong test key type');
  const publicKey = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' });
  const profile = readJson(path.join(stateDir, 'runtime-profile.json'));
  runtime.validateRuntimeProfile(profile);
  ensure(session.profileDigest(profile) === saved.profileSha256, 'stored test profile changed');
  ensure(/^[a-f0-9]{64}$/.test(saved.rootKeyHex), 'wrong test root key');
  return { privateKey, publicKey, profile, rootKey: Buffer.from(saved.rootKeyHex, 'hex'), stateDir: path.join(stateDir, 'replay') };
}
function init(stateDir) {
  ensure(path.isAbsolute(stateDir), 'use an absolute new test directory');
  fs.mkdirSync(stateDir, { mode: 0o700 });
  const key = crypto.generateKeyPairSync('ed25519');
  const publicKey = key.publicKey.export({ type: 'spki', format: 'pem' });
  const profile = runtime.collectRuntimeProfile();
  runtime.validateRuntimeProfile(profile);
  const profileSha256 = session.profileDigest(profile);
  put(path.join(stateDir, 'synthetic-keys.json'), { schema: 'mikaya.interop.synthetic-keys.v1', privateKey: key.privateKey.export({ type: 'pkcs8', format: 'pem' }), rootKeyHex: crypto.randomBytes(32).toString('hex'), profileSha256 });
  put(path.join(stateDir, 'runtime-profile.json'), profile);
  mac.initializeReplayState(path.join(stateDir, 'replay'));
  const result = { schema: 'mikaya.interop.public-test-identity.v1', publicKey, fingerprint: fed.fp(key.publicKey), profileSha256, nodeVersion: process.version, platform: process.platform, arch: process.arch, syntheticIdentity: true, hardwareAttested: false, productionAdmission: false };
  put(path.join(stateDir, 'public-identity.json'), result);
  return result;
}
function execute(command, stateDir, inputFile) {
  if (command === 'init') { ensure(!inputFile, 'init takes no packet'); return init(stateDir); }
  const own = load(stateDir);
  ensure(inputFile, 'a public input packet file is required');
  const input = readJson(inputFile);
  if (command === 'request') {
    exactPacket(input, ['workerPublicKey', 'job']);
    const request = session.makeRequest({ holderPrivateKey: own.privateKey, workerPublicKey: input.workerPublicKey, job: input.job });
    return { request, holderPublicKey: own.publicKey };
  }
  if (command === 'grant') {
    exactPacket(input, REQUEST_PACKET);
    const nowMs = Date.now();
    const ctx = session.verifyRequest({ request: input.request, holderPublicKey: input.holderPublicKey, workerPublicKey: own.publicKey, nowMs });
    const token = mac.mintTestCapability({ rootKey: own.rootKey, holderKeySha256: ctx.holderKeySha256, audience: ctx.audience, profileSha256: session.profileDigest(own.profile), operation: ctx.operation, bodySha256: ctx.bodySha256, issuedAtMs: nowMs, expiresAtMs: nowMs + 120000, maxUses: 1, maxBytes: 8192 });
    return { request: input.request, holderPublicKey: input.holderPublicKey, token, workerPublicKey: own.publicKey, profileSha256: session.profileDigest(own.profile), environment: 'isolated-test' };
  }
  if (command === 'respond') {
    exactPacket(input, GRANT_PACKET);
    ensure(input.environment === 'isolated-test' && input.profileSha256 === session.profileDigest(own.profile) && fed.fp(input.workerPublicKey) === fed.fp(own.publicKey), 'grant target profile or identity refused');
    const out = session.acceptConformanceRequest({ request: input.request, token: input.token, rootKey: own.rootKey, holderPublicKey: input.holderPublicKey, workerPrivateKey: own.privateKey, profile: own.profile, stateDir: own.stateDir, policy: session.conformancePolicy() });
    return { request: input.request, holderPublicKey: input.holderPublicKey, token: input.token, workerPublicKey: own.publicKey, profileSha256: session.profileDigest(own.profile), environment: 'isolated-test', response: out.response, evidence: out.evidence };
  }
  if (command === 'verify') {
    exactPacket(input, RESPONSE_PACKET);
    ensure(input.environment === 'isolated-test', 'packet environment refused');
    ensure(fed.fp(own.publicKey) === input.request.auth.from && fed.fp(input.holderPublicKey) === fed.fp(own.publicKey), 'receipt is for another test holder');
    const result = session.verifyConformanceReceipt({ request: input.request, response: input.response, evidence: input.evidence, holderPublicKey: own.publicKey, workerPublicKey: input.workerPublicKey, profileSha256: input.profileSha256 });
    return { schema: 'mikaya.interop.device-receipt-check.v1', verifiedAt: new Date().toISOString(), result, request: input.request, response: input.response, evidence: input.evidence, holderPublicKey: own.publicKey, workerPublicKey: input.workerPublicKey, targetProfileSha256: result.profileSha256, transport: 'OWNER_CARRIED_PUBLIC_TEST_PACKET', syntheticIdentities: true, hardwareAttested: false, productionAdmission: false };
  }
  throw new Error('unknown conformance command');
}
if (require.main === module) {
  try {
    const [command, stateDir, inputFile, ...rest] = process.argv.slice(2);
    ensure(['init', 'request', 'grant', 'respond', 'verify'].includes(command) && stateDir && rest.length === 0, 'usage: node device-handoff.cjs init|request|grant|respond|verify ABSOLUTE_TEST_STATE [PUBLIC_INPUT_JSON]');
    process.stdout.write(JSON.stringify(execute(command, stateDir, inputFile)) + '\n');
  } catch (err) {
    process.stderr.write(JSON.stringify({ status: 'REFUSED', reason: String(err.message).slice(0, 200) }) + '\n');
    process.exitCode = 1;
  }
}
module.exports = { execute };
