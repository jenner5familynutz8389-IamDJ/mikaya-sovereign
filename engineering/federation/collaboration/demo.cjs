'use strict';
// Explicit, isolated software-identity laboratory. No existing node is edited.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {spawnSync} = require('node:child_process');
const assert = require('node:assert/strict');
const fed = require('../live/federation-node.cjs');
const gateway = require('./gateway-adapter.cjs');
const cap = require('./capability.cjs');
const protocol = require('./protocol.cjs');
const distribution = require('./distribution.cjs');
function write(file, value) { fs.writeFileSync(file, value, {flag: 'wx', mode: 0o600}); }
function openssl(args) {
  const run = spawnSync('openssl', args, {encoding: 'utf8', timeout: 20000, stdio: ['ignore', 'pipe', 'pipe']});
  if (run.status !== 0) throw Object.assign(new Error('OPENSSL_LAB_CERTIFICATE_FAILED'), {code: 'OPENSSL_LAB_CERTIFICATE_FAILED'});
}
function createLab(directory) {
  if (!path.isAbsolute(directory) || fs.realpathSync(path.dirname(directory)) !== path.dirname(directory)) throw Error('LAB_ABSOLUTE_NEW_DIRECTORY_REQUIRED');
  fs.mkdirSync(directory, {mode: 0o700});
  const pki = path.join(directory, 'pki'); fs.mkdirSync(pki, {mode: 0o700});
  const caKey = path.join(pki, 'lab-ca.key'), caCert = path.join(pki, 'lab-ca.crt');
  openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', caKey, '-out', caCert, '-days', '2', '-subj', '/CN=MIKAYA-Isolated-Lab-CA', '-addext', 'basicConstraints=critical,CA:TRUE']);
  const leafExtension = path.join(pki, 'leaf.ext');
  write(leafExtension, 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n');
  const aNode = path.join(directory, 'node-a'), bNode = path.join(directory, 'node-b');
  fed.initNode(aNode, 'MIKAYA', 'collaboration-lab-a'); fed.initNode(bNode, 'LAB-PEER', 'collaboration-lab-b');
  const a = fed.loadNode(aNode), b = fed.loadNode(bNode);
  fed.pinPeer(aNode, path.join(bNode, 'identity-public.pem'), 'LAB-PEER', b.meta.nodeId, b.meta.fingerprint);
  fed.pinPeer(bNode, path.join(aNode, 'identity-public.pem'), 'MIKAYA', a.meta.nodeId, a.meta.fingerprint);
  const tls = {};
  for (const name of ['a', 'b']) {
    const key = path.join(pki, name + '.key'), csr = path.join(pki, name + '.csr'), cert = path.join(pki, name + '.crt');
    openssl(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', csr, '-subj', '/CN=localhost']);
    openssl(['x509', '-req', '-in', csr, '-CA', caCert, '-CAkey', caKey, '-CAcreateserial', '-out', cert, '-days', '1', '-extfile', leafExtension]);
    fs.chmodSync(key, 0o600); fs.chmodSync(cert, 0o600);
    tls[name] = {certificate: cert, privateKey: key, caBundle: caCert};
  }
  fs.chmodSync(caKey, 0o600); fs.chmodSync(caCert, 0o600);
  const bytes = Buffer.alloc(131109); for (let i = 0; i < bytes.length; i++) bytes[i] = i % 251;
  const manifest = distribution.signManifest({bytes, artifactId: 'toybox-public-fixture', version: '1.0.0', sequence: 1,
    privateKey: a.privateKey, publicKey: a.publicKey.toString()});
  const digest = distribution.verifyManifest({manifest, publisherPublicKey: a.publicKey.toString(), expectedPublisher: a.meta.fingerprint}).manifestDigest;
  const sourcePath = path.join(directory, 'public-fixture.bytes'), manifestPath = path.join(directory, 'public-fixture.manifest.json');
  write(sourcePath, bytes); write(manifestPath, protocol.canonical(manifest));
  const resources = ['collaboration:self', 'toybox:transactions', 'receipt:transactions', 'broker:limitedcompute',
    'manifest:' + digest, ...manifest.chunks.map((_, i) => 'manifest:' + digest + ':chunk:' + i)].sort();
  const configurations = {};
  for (const [name, local, remote, remoteTls] of [['a', a, b, tls.b], ['b', b, a, tls.a]]) {
    configurations[name] = {schema: 'mikaya.act.gateway-config.v1', mode: 'lab', federationDirectory: local.dir,
      listen: {host: '127.0.0.1', port: 0}, tls: tls[name], policyVersion: 'collaboration-v1', issuerEpoch: 1, enabled: true,
      peers: {[remote.meta.fingerprint]: {enabled: true, tlsBinding: cap.keyBindingForCertificate(fs.readFileSync(remoteTls.certificate)),
        operations: gateway.OPS, resources, maxUses: 512, maxConcurrent: 2}}, brokerUrl: null,
      artifacts: name === 'a' ? [{manifestPath, sourcePath, manifestDigest: digest}] : []};
  }
  const aDirectory = path.join(directory, 'gateway-a'), bDirectory = path.join(directory, 'gateway-b');
  gateway.initialize({directory: aDirectory, config: configurations.a});
  gateway.initialize({directory: bDirectory, config: configurations.b});
  return {directory, aDirectory, bDirectory, a: fed.loadNode(aNode), b: fed.loadNode(bNode), configurations, manifest, digest, bytes, resources};
}
async function runDemo({directory}) {
  const lab = createLab(directory), startedAt = new Date().toISOString();
  const server = await gateway.startGateway({directory: lab.aDirectory});
  const url = 'https://127.0.0.1:' + server.address.port + '/';
  const client = gateway.createClient({directory: lab.bDirectory, peerFingerprint: lab.a.meta.fingerprint, url});
  const h1 = gateway.createClient({directory: lab.bDirectory, peerFingerprint: lab.a.meta.fingerprint, url, transport: 'http1'});
  const issued = Date.now();
  const token = gateway.grant({directory: lab.aDirectory, peerFingerprint: lab.b.meta.fingerprint,
    scopes: gateway.OPS, resources: lab.resources, uses: 256, ttlMs: 120000, nowMs: issued});
  const request = (operation, resource, payload, extra = {}) => protocol.makeRequest({node: lab.b, to: lab.a.meta.fingerprint,
    capability: token, operation, resource, payload, expiresAtMs: issued + 110000, ...extra});
  const checks = [];
  let receiver;
  try {
    const describe = await client.send(request('collaboration.describe.v1', 'collaboration:self', {}));
    assert.equal(describe.result.tls, 'TLSv1.3-mTLS'); checks.push('http2_mtls_signed_response');
    const tx = request('toybox.transaction.v1', 'toybox:transactions', {schema: 'mikaya.act.toybox-statement.v1', artifactDigest: lab.digest, statement: 'Record the approved public fixture digest.'});
    const first = await client.send(tx); assert.equal(first.receipt.state, 'completed');
    assert.equal(first.result.settlementAuthorized, false); checks.push('durable_toybox_receipt_without_payment_claim');
    const retry = request(tx.intent.operation, tx.intent.resource, tx.payload, {intent: tx.intent});
    const second = await client.send(retry); assert.equal(second.duplicate, true); assert.deepEqual(second.receipt, first.receipt); checks.push('same_intent_new_nonce_same_receipt');
    await assert.rejects(client.send(tx), /REQUEST_REPLAY_REFUSED/); checks.push('exact_attempt_replay_denied');
    const modified = {...tx.intent, payloadSha256: protocol.sha(protocol.canonical({...tx.payload, statement: 'changed'}))};
    await assert.rejects(client.send(request(tx.intent.operation, tx.intent.resource, {...tx.payload, statement: 'changed'}, {intent: modified})), /TRANSACTION_CONFLICT/); checks.push('changed_intent_conflict_denied');
    const broken = token.slice(0, -1) + (token.endsWith('A') ? 'B' : 'A');
    await assert.rejects(client.send(request('collaboration.describe.v1', 'collaboration:self', {}, {capability: broken}))); checks.push('tampered_capability_denied');
    const h1Result = await h1.send(request('collaboration.describe.v1', 'collaboration:self', {}));
    assert.equal(h1Result.result.tls, 'TLSv1.3-mTLS'); checks.push('http1_mtls_security_parity');
    const fetched = await client.send(request('artifact.manifest.read.v1', 'manifest:' + lab.digest, {}));
    assert.deepEqual(fetched.result.manifest, lab.manifest);
    const receiverDirectory = path.join(directory, 'receiver');
    const receiverOptions = {directory: receiverDirectory, manifest: lab.manifest, publisherPublicKey: lab.a.publicKey.toString(), expectedPublisher: lab.a.meta.fingerprint};
    receiver = distribution.createReceiver({...receiverOptions, initialize: true});
    let transferred = 0;
    const chunk0 = await client.send(request('artifact.chunk.read.v1', 'manifest:' + lab.digest + ':chunk:0', {}));
    receiver.acceptChunk({index: 0, bytes: chunk0.bytes}); transferred += chunk0.bytes.length;
    receiver.close(); receiver = distribution.createReceiver(receiverOptions);
    const resumed = receiver.status({});
    for (const index of resumed.missingChunks) {
      const chunk = await client.send(request('artifact.chunk.read.v1', 'manifest:' + lab.digest + ':chunk:' + index, {}));
      receiver.acceptChunk({index, bytes: chunk.bytes}); transferred += chunk.bytes.length;
    }
    const final = receiver.finalize({}); assert.equal(final.contentVerified, true); assert.equal(final.activationAuthorized, false);
    checks.push('signed_public_artifact_resumed_and_whole_digest_verified');
    const samples = {h2: [], http1: []};
    for (let i = 0; i < 30; i++) {
      for (const [label, connection] of (i % 2 ? [['http1', h1], ['h2', client]] : [['h2', client], ['http1', h1]])) {
        const begin = process.hrtime.bigint(); await connection.send(request('collaboration.describe.v1', 'collaboration:self', {}));
        samples[label].push(Number(process.hrtime.bigint() - begin) / 1e6);
      }
    }
    const summarize = rows => { const sorted = [...rows].sort((a, b) => a - b); return {samples: rows.length, medianMs: sorted[Math.floor(sorted.length / 2)], p95Ms: sorted[Math.ceil(sorted.length * 0.95) - 1]}; };
    const report = {schema: 'mikaya.act.collaboration-demo.v1', status: 'PASS', startedAt, completedAt: new Date().toISOString(),
      mode: 'LOCAL_TWO_INDEPENDENT_IDENTITIES_ONE_DEVICE', node: process.version, platform: process.platform, architecture: process.arch,
      checks, publicArtifact: {totalBytes: lab.bytes.length, reusedBytes: resumed.verifiedBytes, bytesTransferredTotal: transferred, contentVerified: true, activationAuthorized: false},
      transportScreening: {h2: summarize(samples.h2), http1: summarize(samples.http1), classification: '30_PAIRED_LOOPBACK_SCREENING_SAMPLES_NOT_A_NETWORK_SPEED_CLAIM'},
      actModelConnected: false, hardwareAttested: false, settlementEnabled: false};
    write(path.join(directory, 'acceptance-report.json'), JSON.stringify(report, null, 2) + '\n'); return report;
  } finally { if (receiver) receiver.close(); client.close(); h1.close(); await server.close(); }
}
module.exports = {createLab, runDemo};
