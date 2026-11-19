'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');
const { createLab } = require('../demo.cjs');
const gateway = require('../gateway-adapter.cjs');
const protocol = require('../protocol.cjs');
const distribution = require('../distribution.cjs');

test('collaboration gateway integration over real TLS 1.3 sockets', { timeout: 90000 }, async t => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'mikaya-gateway-integration-'));
  const lab = createLab(path.join(parent, 'isolated-lab'));
  let server = await gateway.startGateway({ directory: lab.aDirectory });
  let client, h1;
  const observed = [];
  function recordRequest(req) {
    observed.push({ socket: req.stream?.session || req.socket, protocol: req.socket.getProtocol(), authorized: req.socket.authorized,
      httpVersion: req.httpVersionMajor });
  }
  server.server.on('request', recordRequest);
  const origin = () => `https://127.0.0.1:${server.address.port}/`;
  const newClient = transport => gateway.createClient({ directory: lab.bDirectory,
    peerFingerprint: lab.a.meta.fingerprint, url: origin(), ...(transport ? { transport } : {}) });
  client = newClient(); h1 = newClient('http1');
  t.after(async () => {
    client?.close(); h1?.close(); await server?.close();
    fs.rmSync(parent, { recursive: true, force: true });
  });

  function config(directory) { return JSON.parse(fs.readFileSync(path.join(directory, 'config.json'), 'utf8')); }
  function saveConfig(directory, value) { fs.writeFileSync(path.join(directory, 'config.json'), protocol.canonical(value), { mode: 0o600 }); }
  function issue({ scopes = ['collaboration.describe.v1'], resources = ['collaboration:self'], uses = 10,
    ttlMs = 120000, nowMs = Date.now() } = {}) {
    const token = gateway.grant({ directory: lab.aDirectory, peerFingerprint: lab.b.meta.fingerprint,
      scopes, resources, uses, ttlMs, nowMs });
    return { token, expiresAtMs: nowMs + ttlMs - 1000 };
  }
  function request(grant, operation = 'collaboration.describe.v1', resource = 'collaboration:self', payload = {}, extra = {}) {
    return protocol.makeRequest({ node: lab.b, to: lab.a.meta.fingerprint, capability: grant.token,
      operation, resource, payload, expiresAtMs: grant.expiresAtMs, ...extra });
  }
  function statement(value = 'Record only the approved public artifact digest.') {
    return { schema: 'mikaya.act.toybox-statement.v1', artifactDigest: lab.digest, statement: value };
  }
  function rejectCode(promise, code) { return assert.rejects(promise, { code }); }

  await t.test('HTTP/2 and HTTP/1.1 both authenticate TLS 1.3 and verify signed replies', async () => {
    const grant = issue();
    const start = observed.length;
    const two = await client.send(request(grant));
    const one = await h1.send(request(grant));
    assert.equal(two.verified, true); assert.equal(one.verified, true);
    assert.equal(two.transport, 'h2'); assert.equal(one.transport, 'http1');
    assert.equal(two.result.tls, 'TLSv1.3-mTLS');
    assert.equal(one.result.tls, 'TLSv1.3-mTLS');
    assert.deepEqual(observed.slice(start).map(x => [x.protocol, x.authorized, x.httpVersion]),
      [['TLSv1.3', true, 2], ['TLSv1.3', true, 1]]);
    assert.equal(two.result.arbitraryExecution, false);
    assert.equal(two.result.settlementEnabled, false);
  });

  await t.test('TLS 1.2 and a TLS client without a certificate never reach HTTP dispatch', async () => {
    const c = config(lab.bDirectory), start = observed.length;
    async function rejectedHandshake(extra) {
      return new Promise((resolve, reject) => {
        const req = https.request(origin(), { method: 'POST', ca: fs.readFileSync(c.tls.caBundle),
          rejectUnauthorized: true, ...extra }, res => { res.resume(); reject(new Error('HTTP reached without required TLS authentication')); });
        req.on('error', resolve);
        req.setTimeout(2500, () => { req.destroy(); reject(new Error('TLS denial test timed out')); });
        req.end('{}');
      });
    }
    const old = await rejectedHandshake({ key: fs.readFileSync(c.tls.privateKey), cert: fs.readFileSync(c.tls.certificate),
      minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' });
    assert.match(old.code, /SSL|TLS|EPROTO|ECONNRESET/);
    const missing = await rejectedHandshake({ minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' });
    assert.match(missing.code, /SSL|TLS|EPROTO|ECONNRESET/);
    assert.equal(observed.length, start);
  });

  await t.test('a CA-valid client certificate with the wrong enrolled SPKI is rejected', async () => {
    const grant = issue(), original = config(lab.bDirectory);
    const changed = structuredClone(original);
    // Both certificates are signed by this isolated CA and have clientAuth;
    // the server certificate's key is not the enrolled LAB-PEER client key.
    changed.tls = structuredClone(config(lab.aDirectory).tls);
    let wrong;
    try {
      saveConfig(lab.bDirectory, changed);
      wrong = newClient();
      await rejectCode(wrong.send(request(grant)), 'PEER_POLICY_DENIED');
    } finally { wrong?.close(); saveConfig(lab.bDirectory, original); }
  });

  await t.test('wrong server SPKI pin blocks both transports before sending a request', async () => {
    const grant = issue(), original = config(lab.bDirectory);
    const changed = structuredClone(original);
    changed.peers[lab.a.meta.fingerprint].tlsBinding = config(lab.aDirectory).peers[lab.b.meta.fingerprint].tlsBinding;
    saveConfig(lab.bDirectory, changed);
    try {
      for (const transport of ['h2', 'http1']) {
        const count = observed.length, wrong = newClient(transport);
        try { await rejectCode(wrong.send(request(grant)), 'SERVER_PIN_DENIED'); }
        finally { wrong.close(); }
        assert.equal(observed.length, count, 'capability-bearing HTTP request must not be sent before the SPKI pin passes');
      }
    } finally { saveConfig(lab.bDirectory, original); }
  });

  await t.test('peer revocation is enforced on an already established HTTP/2 connection', async () => {
    const grant = issue();
    await client.send(request(grant));
    const socket = observed.at(-1).socket, original = config(lab.aDirectory);
    const revoked = structuredClone(original);
    revoked.peers[lab.b.meta.fingerprint].enabled = false;
    try {
      saveConfig(lab.aDirectory, revoked);
      await rejectCode(client.send(request(grant)), 'PEER_POLICY_DENIED');
      assert.equal(observed.at(-1).socket, socket, 'rejection must happen without relying on a new TLS handshake');
    } finally { saveConfig(lab.aDirectory, original); }
  });

  await t.test('issuer epoch revokes old tokens on the same socket; new epoch issuance succeeds', async () => {
    const old = issue();
    await client.send(request(old));
    const socket = observed.at(-1).socket, changed = config(lab.aDirectory);
    changed.issuerEpoch++;
    saveConfig(lab.aDirectory, changed);
    await rejectCode(client.send(request(old)), 'CAP_CONTEXT');
    assert.equal(observed.at(-1).socket, socket);
    const current = issue();
    assert.equal((await client.send(request(current))).verified, true);
    assert.equal(observed.at(-1).socket, socket);
    // Do not roll the epoch back during cleanup; subsequent grants use it.
  });

  await t.test('same-intent retry reuses the receipt; replay, conflict and new use are denied', async () => {
    const grant = issue({ scopes: ['toybox.transaction.v1'], resources: ['toybox:transactions'], uses: 1 });
    const firstRequest = request(grant, 'toybox.transaction.v1', 'toybox:transactions', statement());
    const first = await client.send(firstRequest);
    assert.equal(first.receipt.state, 'completed');
    assert.equal(first.result.paymentVerified, false);
    assert.equal(first.result.settlementAuthorized, false);
    assert.equal(first.result.executionAuthorized, false);
    await rejectCode(client.send(firstRequest), 'REQUEST_REPLAY_REFUSED');
    const retry = request(grant, firstRequest.intent.operation, firstRequest.intent.resource, firstRequest.payload,
      { intent: firstRequest.intent });
    const duplicate = await client.send(retry);
    assert.equal(duplicate.duplicate, true);
    assert.deepEqual(duplicate.receipt, first.receipt);
    const changedPayload = statement('The same transaction ID cannot name different content.');
    const conflictingIntent = { ...firstRequest.intent, payloadSha256: protocol.sha(protocol.canonical(changedPayload)) };
    await rejectCode(client.send(request(grant, 'toybox.transaction.v1', 'toybox:transactions', changedPayload,
      { intent: conflictingIntent })), 'TRANSACTION_CONFLICT');
    await rejectCode(client.send(request(grant, 'toybox.transaction.v1', 'toybox:transactions', statement('A new transaction.'))), 'GRANT_EXHAUSTED');
  });

  await t.test('concurrent distinct transactions cannot overspend a one-use grant', async () => {
    const grant = issue({ scopes: ['toybox.transaction.v1'], resources: ['toybox:transactions'], uses: 1 });
    const results = await Promise.allSettled([
      client.send(request(grant, 'toybox.transaction.v1', 'toybox:transactions', statement('First racing intent.'))),
      client.send(request(grant, 'toybox.transaction.v1', 'toybox:transactions', statement('Second racing intent.'))),
    ]);
    assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    const rejected = results.find(r => r.status === 'rejected');
    assert.equal(rejected.reason.code, 'GRANT_EXHAUSTED');
  });

  await t.test('current scope removal, wrong resource semantics and expired tokens fail', async () => {
    const grant = issue(), original = config(lab.aDirectory);
    const narrowed = structuredClone(original);
    narrowed.peers[lab.b.meta.fingerprint].operations = narrowed.peers[lab.b.meta.fingerprint].operations.filter(x => x !== 'collaboration.describe.v1');
    try {
      saveConfig(lab.aDirectory, narrowed);
      await rejectCode(client.send(request(grant)), 'OPERATION_POLICY_DENIED');
    } finally { saveConfig(lab.aDirectory, original); }
    const wrongResource = issue({ resources: ['toybox:transactions'] });
    await rejectCode(client.send(request(wrongResource, 'collaboration.describe.v1', 'toybox:transactions')), 'RESOURCE_SEMANTICS_DENIED');
    const expired = issue({ nowMs: Date.now() - 10000, ttlMs: 1000 });
    await rejectCode(client.send(request(expired, 'collaboration.describe.v1', 'collaboration:self', {},
      { expiresAtMs: Date.now() + 1000 })), 'CAP_TIME');
  });

  await t.test('original broker remains disabled and a capability cannot enable ACT compute', async () => {
    const state = gateway.status(lab.aDirectory);
    assert.equal(state.legacyBrokerConfigured, false);
    assert.equal(state.arbitraryExecution, false);
    assert.equal(state.settlementEnabled, false);
    const grant = issue({ scopes: ['federation.broker.v1'], resources: ['broker:limitedcompute'], uses: 1 });
    await rejectCode(client.send(request(grant, 'federation.broker.v1', 'broker:limitedcompute', {})), 'EXISTING_BROKER_NOT_CONFIGURED');
    assert.equal(gateway.status(lab.aDirectory).legacyBrokerConfigured, false);
  });

  await t.test('signed binary chunk delivery resumes a real verified receiver', async () => {
    const resources = [distribution.manifestResource(lab.digest), ...lab.manifest.chunks.map((_, index) => distribution.chunkResource(lab.digest, index))];
    const grant = issue({ scopes: ['artifact.chunk.read.v1', 'artifact.manifest.read.v1'], resources, uses: 8 });
    const fetched = await client.send(request(grant, 'artifact.manifest.read.v1', distribution.manifestResource(lab.digest)));
    assert.deepEqual(fetched.result.manifest, lab.manifest);
    const verified = distribution.verifyManifest({ manifest: fetched.result.manifest, publisherPublicKey: lab.a.publicKey.toString(),
      expectedPublisher: lab.a.meta.fingerprint, expectedManifestDigest: lab.digest });
    assert.equal(verified.manifestDigest, lab.digest);
    const receiverOptions = { directory: path.join(lab.directory, 'integration-receiver'), manifest: fetched.result.manifest,
      publisherPublicKey: lab.a.publicKey.toString(), expectedPublisher: lab.a.meta.fingerprint };
    let receiver = distribution.createReceiver({ ...receiverOptions, initialize: true });
    try {
      const first = await client.send(request(grant, 'artifact.chunk.read.v1', distribution.chunkResource(lab.digest, 0)));
      assert.equal(first.verified, true); assert.equal(first.bytes.length, 65536);
      assert.equal(first.result.sha256, protocol.sha(first.bytes));
      assert.equal(first.result.activationAuthorized, false);
      receiver.acceptChunk({ index: 0, bytes: first.bytes }); receiver.close();
      receiver = distribution.createReceiver(receiverOptions);
      const resumed = receiver.status();
      assert.equal(resumed.verifiedBytes, 65536); assert.deepEqual(resumed.missingChunks, [1, 2]);
      let remaining = 0;
      for (const index of resumed.missingChunks) {
        const connection = index === 1 ? h1 : client;
        const chunk = await connection.send(request(grant, 'artifact.chunk.read.v1', distribution.chunkResource(lab.digest, index)));
        remaining += chunk.bytes.length;
        receiver.acceptChunk({ index, bytes: chunk.bytes });
      }
      assert.equal(remaining, 65573);
      const complete = receiver.finalize();
      assert.equal(complete.contentVerified, true); assert.equal(complete.activationAuthorized, false);
      assert.deepEqual(fs.readFileSync(complete.path), lab.bytes);
    } finally { receiver.close(); }
  });

  await t.test('altered allowlisted artifact bytes fail before binary delivery', async () => {
    const grant = issue({ scopes: ['artifact.chunk.read.v1'], resources: [distribution.chunkResource(lab.digest, 0)], uses: 1 });
    const record = config(lab.aDirectory).artifacts[0], original = fs.readFileSync(record.sourcePath);
    const changed = Buffer.from(original); changed[changed.length - 1] ^= 1;
    try {
      fs.writeFileSync(record.sourcePath, changed);
      await rejectCode(client.send(request(grant, 'artifact.chunk.read.v1', distribution.chunkResource(lab.digest, 0))), 'DISTRIBUTION_SOURCE_CHANGED');
    } finally { fs.writeFileSync(record.sourcePath, original); }
  });

  await t.test('telemetry keeps transport/security evidence without capability or statement bodies', async () => {
    const grant = issue({ scopes: ['toybox.transaction.v1'], resources: ['toybox:transactions'], uses: 1 });
    const marker = 'PRIVATE-PAYLOAD-MUST-NOT-APPEAR-IN-SECURITY-TELEMETRY';
    await client.send(request(grant, 'toybox.transaction.v1', 'toybox:transactions', statement(marker)));
    const raw = fs.readFileSync(path.join(lab.aDirectory, 'runtime/state.json'), 'utf8');
    assert.ok(!raw.includes(grant.token)); assert.ok(!raw.includes(marker));
    const events = JSON.parse(raw).payload.events.map(x => x.event);
    assert.ok(events.some(x => x.transport === 'h2-TLS1.3-mTLS'));
    assert.ok(events.some(x => x.transport === 'http1.1-TLS1.3-mTLS'));
    assert.ok(events.some(x => x.code === 'REQUEST_REPLAY_REFUSED'));
    assert.ok(events.some(x => x.code === 'CAP_CONTEXT'));
    assert.ok(events.some(x => x.code === 'DISTRIBUTION_SOURCE_CHANGED'));
  });

  await t.test('nonce rejection and completed transaction receipts survive gateway restart', async () => {
    const grant = issue({ scopes: ['toybox.transaction.v1'], resources: ['toybox:transactions'], uses: 1 });
    const original = request(grant, 'toybox.transaction.v1', 'toybox:transactions', statement('Survive a controlled gateway restart.'));
    const first = await client.send(original);
    client.close(); h1.close(); await server.close();
    server = await gateway.startGateway({ directory: lab.aDirectory });
    server.server.on('request', recordRequest);
    client = newClient(); h1 = newClient('http1');
    await rejectCode(client.send(original), 'REQUEST_REPLAY_REFUSED');
    const repeated = await client.send(request(grant, original.intent.operation, original.intent.resource, original.payload,
      { intent: original.intent }));
    assert.equal(repeated.duplicate, true); assert.deepEqual(repeated.receipt, first.receipt);
  });

  await t.test('signed peer clock prepares safe attempts on both transports without granting authority', async () => {
    const grant = issue();
    await rejectCode(client.send(request(grant, 'collaboration.describe.v1', 'collaboration:self', {},
      {nowMs: Date.now() + 20000})), 'ATTEMPT_INVALID_OR_EXPIRED');
    for (const connection of [client, h1]) {
      const sample = await connection.synchronize();
      assert.ok(sample.rttMs <= 2000);
      assert.equal(sample.signedResponse.body.sender, lab.a.meta.fingerprint);
      assert.equal(sample.signedResponse.body.recipient, lab.b.meta.fingerprint);
      assert.equal(await connection.synchronize(), sample, 'a fresh sample is reused');
      const prepared = await connection.prepareRequest({capability: grant.token,
        operation: 'collaboration.describe.v1', resource: 'collaboration:self', payload: {},
        expiresAtMs: grant.expiresAtMs, nowMs: Date.now() + 20000});
      assert.ok(Math.abs(prepared.attempt.issuedAtMs - Date.now()) < 2000);
      const result = await connection.send(prepared);
      assert.equal(result.verified, true);
      assert.equal(result.signedResponse.auth.inReplyTo, prepared.attempt.nonce);
      assert.deepEqual(protocol.verifyResponse({response: result.signedResponse, request: prepared,
        publicKey: lab.a.publicKey}), result.signedResponse.body);
      const noAuthority = await connection.prepareRequest({capability: 'not-a-capability',
        operation: 'collaboration.describe.v1', resource: 'collaboration:self', payload: {}, expiresAtMs: grant.expiresAtMs});
      await assert.rejects(connection.send(noAuthority), error => error.code.startsWith('CAP_'));
    }
    const original = config(lab.aDirectory), revoked = structuredClone(original);
    revoked.peers[lab.b.meta.fingerprint].enabled = false;
    try {
      saveConfig(lab.aDirectory, revoked);
      await rejectCode(client.synchronize({force: true}), 'CLOCK_HANDSHAKE_DENIED');
    } finally {saveConfig(lab.aDirectory, original);}
  });
});
