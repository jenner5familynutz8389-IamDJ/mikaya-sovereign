'use strict';
// Test-only stdio adapter around the CURRENT production module. No sockets.
// Identities are generated locally, synthetic, and removed on process exit.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const node = require('../../live/federation-node.cjs');
const DOMAIN = 'MIKAYA-INDEPENDENT-FEDERATION/1\n';
let root, dir, meta;

function initialized() { if (!meta) throw Error('initialize synthetic Node identity first'); }
function clean() { if (root) fs.rmSync(root, {recursive: true, force: true}); }
process.once('exit', clean);
process.once('SIGTERM', () => { clean(); process.exit(0); });

// signResponse is not exported by federation-node.cjs. This fixture signs its
// documented envelope with node:crypto; response verification and complete
// evidence verification below invoke the actual exported production verifiers.
function contractResponse({to, inReplyTo, body, issuedAtMs}) {
 initialized();
 const envelope = {schema: 'mikaya.federation.response.v1', from: meta.fingerprint,
  to, inReplyTo, bodySha256: node.sha(node.canonical(body)), issuedAtMs};
 return {...envelope, signature: crypto.sign(null,
  Buffer.from(DOMAIN + 'RES\n' + node.canonical(envelope)), node.loadNode(dir).privateKey).toString('base64')};
}

function dispatch(a) {
 if (a.op === 'describe') return {referenceOnly: true, runtime: process.version, pid: process.pid, transport: 'local-stdio-only'};
 if (a.op === 'canonical') {
  const canonical = node.canonical(a.value);
  return {canonical, utf8Hex: Buffer.from(canonical).toString('hex'), sha256: node.sha(canonical)};
 }
 if (a.op === 'fingerprint') {
  const key = crypto.createPublicKey(a.publicPem);
  return {publicPem: key.export({type: 'spki', format: 'pem'}), fingerprint: node.fp(a.publicPem)};
 }
 if (a.op === 'compute') return node.computeJob(a.job);
 if (a.op === 'verify-evidence') return node.verifyEvidence(a.proof);
 if (a.op === 'init') {
  if (meta) throw Error('reference identity already initialized');
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'mikaya-node-reference-'));
  fs.chmodSync(root, 0o700);
  dir = path.join(root, 'synthetic-node');
  meta = node.initNode(dir, 'LAB-PEER', 'synthetic-node-reference');
  return {referenceOnly: true, publicPem: fs.readFileSync(path.join(dir, 'identity-public.pem'), 'utf8'),
   fingerprint: meta.fingerprint, pid: process.pid, privateKeyExported: false};
 }
 initialized();
 if (a.op === 'pin') {
  const file = path.join(root, 'candidate-' + crypto.randomBytes(8).toString('hex') + '.pem');
  fs.writeFileSync(file, a.publicPem, {mode: 0o600, flag: 'wx'});
  try { return node.pinPeer(dir, file, 'MIKAYA', 'synthetic-python-reference', a.expectedFingerprint); }
  finally { fs.unlinkSync(file); }
 }
 if (a.op === 'revoke') return node.revokePeer(dir, a.fingerprint);
 if (a.op === 'sign-request') return node.signRequest({dir, to: a.to, method: a.method,
  route: a.route, body: a.body, nonce: a.nonce, issuedAtMs: a.issuedAtMs});
 if (a.op === 'verify-request') return node.verifyRequest({dir, auth: a.auth, method: a.method,
  route: a.route, body: a.body, nowMs: a.nowMs});
 if (a.op === 'sign-response') return contractResponse(a);
 if (a.op === 'verify-response') return node.verifyResponse({dir, auth: a.auth, body: a.body,
  to: a.expectedPeer, nonce: a.nonce, nowMs: a.nowMs});
 if (a.op === 'verify-receipt') {
  const expected = {schema: 'mikaya.federation.result.v1', jobId: a.job.id, capability: a.job.capability,
   workerFingerprint: a.expectedWorker, requestSha256: node.sha(node.canonical(a.job)), result: node.computeJob(a.job)};
  if (node.canonical(a.body) !== node.canonical(expected)) throw Error('peer computation receipt inconsistent');
  return true;
 }
 if (a.op === 'respond') {
  if (a.route !== '/v1/task') throw Error('reference responds only to bounded task fixtures');
  const peer = node.verifyRequest({dir, auth: a.auth, method: a.method, route: a.route, body: a.body, nowMs: a.nowMs});
  const body = node.acceptJob(dir, peer, a.body);
  return {body, auth: contractResponse({to: peer.fingerprint, inReplyTo: a.auth.nonce, body, issuedAtMs: a.nowMs})};
 }
 if (a.op === 'sign-domain-fixture') {
  if (!['REQ', 'RES', 'WRONG'].includes(a.domain)) throw Error('invalid test domain');
  return crypto.sign(null, Buffer.from(DOMAIN + a.domain + '\n' + node.canonical(a.envelope)),
   node.loadNode(dir).privateKey).toString('base64');
 }
 if (a.op === 'journal-valid') return node.verifyLocalJournal(dir);
 throw Error('unsupported Node fixture operation');
}

function receive(line) {
 let id = null, reply;
 try {
  if (line.length > 65536) throw Error('reference input exceeds 65536 bytes');
  const a = JSON.parse(line.toString('utf8'));
  if (Number.isSafeInteger(a?.id)) id = a.id;
  reply = {id, ok: true, result: dispatch(a)};
 } catch (error) {
  reply = {id, ok: false, error: String(error.message).slice(0, 180)};
 }
 process.stdout.write(JSON.stringify(reply) + '\n');
}
// JSON allows literal U+2028/U+2029 within strings. Frame strictly on LF bytes,
// not a text line helper that may treat those Unicode characters as delimiters.
let input = Buffer.alloc(0);
process.stdin.on('data', part => {
 input = Buffer.concat([input, part]);
 let lf;
 while ((lf = input.indexOf(10)) !== -1) {
  receive(input.subarray(0, lf));
  input = input.subarray(lf + 1);
 }
});
process.stdin.on('end', () => { if (input.length) receive(input); clean(); root = null; });
