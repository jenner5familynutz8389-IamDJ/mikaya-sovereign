#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const http2 = require('node:http2');
const https = require('node:https');
const fed = require('../live/federation-node.cjs');
const cap = require('./capability.cjs');
const protocol = require('./protocol.cjs');
const clock = require('./session-clock.cjs');
const {performance} = require('node:perf_hooks');
const {canonical, sha, exact, fail} = protocol;
const {createJournal} = require('./transaction-journal.cjs');
const {createArtifactPolicy} = require('./artifact-policy.cjs');
const {createRuntimeState, safeBytes} = require('./runtime-state.cjs');
const OPS = Object.freeze(['artifact.chunk.read.v1', 'artifact.manifest.read.v1', 'artifact.metadata.verify.v1',
  'collaboration.describe.v1', 'federation.broker.v1', 'receipt.read.v1', 'toybox.transaction.v1']);
const CONTROL_LIMIT = 8192;
const RESPONSE_LIMIT = 32768;
const localHost = x => x === '127.0.0.1' || x === '::1';
function privateHost(host) {
  if (localHost(host)) return true;
  const family = require('node:net').isIP(host);
  if (family === 6) return /^(fc|fd)[0-9a-f]{2}:/i.test(host);
  if (family !== 4) return false;
  const a = host.split('.').map(Number);
  return a[0] === 10 || (a[0] === 192 && a[1] === 168) || (a[0] === 172 && a[1] >= 16 && a[1] <= 31) || (a[0] === 100 && a[1] >= 64 && a[1] <= 127);
}
const publicRead = file => safeBytes(file, 100000, false);
const privateJSON = file => JSON.parse(safeBytes(file).toString('utf8'));
function privateWrite(file, bytes) { fs.writeFileSync(file, bytes, {flag: 'wx', mode: 0o600}); }
function validateConfig(c) {
  if (!exact(c, ['schema', 'mode', 'federationDirectory', 'listen', 'tls', 'policyVersion', 'issuerEpoch', 'enabled', 'peers', 'brokerUrl', 'artifacts']) ||
      c.schema !== 'mikaya.act.gateway-config.v1' || !['lab', 'production'].includes(c.mode) || typeof c.enabled !== 'boolean' ||
      c.policyVersion !== 'collaboration-v1' || !Number.isSafeInteger(c.issuerEpoch) || c.issuerEpoch < 0 ||
      !exact(c.listen, ['host', 'port']) || typeof c.listen.host !== 'string' || !privateHost(c.listen.host) ||
      !Number.isSafeInteger(c.listen.port) || c.listen.port > 65535 || c.listen.port < (c.mode === 'lab' && localHost(c.listen.host) ? 0 : 1024) ||
      !exact(c.tls, ['certificate', 'privateKey', 'caBundle']) || !c.peers || Object.getPrototypeOf(c.peers) !== Object.prototype ||
      Object.keys(c.peers).length > 16 || !Array.isArray(c.artifacts) || c.artifacts.length > 16) fail('CONFIG_INVALID');
  if (!path.isAbsolute(c.federationDirectory)) fail('IDENTITY_PATH_INVALID');
  const node = fed.loadNode(c.federationDirectory), tlsKey = safeBytes(c.tls.privateKey);
  const certificate = publicRead(c.tls.certificate), caBundle = publicRead(c.tls.caBundle);
  const cert = new crypto.X509Certificate(certificate);
  if (!cert.checkPrivateKey(crypto.createPrivateKey(tlsKey))) fail('TLS_KEY_MISMATCH');
  if (Date.now() >= Date.parse(cert.validTo) || Date.now() < Date.parse(cert.validFrom)) fail('TLS_CERT_EXPIRED');
  const bindings = new Set();
  for (const [fp, peer] of Object.entries(c.peers)) {
    if (!/^[0-9a-f]{64}$/.test(fp) || fp === node.meta.fingerprint || !node.peers[fp] ||
        !exact(peer, ['enabled', 'tlsBinding', 'operations', 'resources', 'maxUses', 'maxConcurrent']) ||
        typeof peer.enabled !== 'boolean' || !/^sha256:[0-9a-f]{64}$/.test(peer.tlsBinding) || bindings.has(peer.tlsBinding) ||
        !Array.isArray(peer.operations) || !peer.operations.length || peer.operations.some(op => !OPS.includes(op)) ||
        !Array.isArray(peer.resources) || !peer.resources.length || peer.resources.length > 64 ||
        peer.resources.some(r => typeof r !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$/.test(r)) ||
        !Number.isSafeInteger(peer.maxUses) || peer.maxUses < 1 || peer.maxUses > 2048 ||
        !Number.isSafeInteger(peer.maxConcurrent) || peer.maxConcurrent < 1 || peer.maxConcurrent > 4) fail('PEER_CONFIG_INVALID');
    const key = publicRead(path.join(c.federationDirectory, 'trust', fp + '.pem'));
    if (fed.fp(key) !== fp) fail('PEER_IDENTITY_MISMATCH');
    bindings.add(peer.tlsBinding);
  }
  if (c.brokerUrl !== null) {
    const url = new URL(c.brokerUrl);
    if (url.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(url.hostname) || url.username || url.password ||
        url.pathname !== '/' || url.search || url.hash || !url.port || Number(url.port) === c.listen.port) fail('BROKER_MUST_BE_EXISTING_LOOPBACK');
  }
  for (const artifact of c.artifacts) {
    if (!exact(artifact, ['manifestPath', 'sourcePath', 'manifestDigest']) || !/^[0-9a-f]{64}$/.test(artifact.manifestDigest) ||
        !path.isAbsolute(artifact.manifestPath) || !path.isAbsolute(artifact.sourcePath)) fail('ARTIFACT_CONFIG_INVALID');
  }
  return {config: c, node, tls: {key: tlsKey, cert: certificate, ca: caBundle}};
}
function load(directory) {
  if (!path.isAbsolute(directory) || fs.realpathSync(directory) !== directory) fail('STATE_PATH_UNSAFE');
  const s = fs.lstatSync(directory);
  if (!s.isDirectory() || s.isSymbolicLink() || (s.mode & 0o077)) fail('STATE_DIRECTORY_UNSAFE');
  const value = validateConfig(privateJSON(path.join(directory, 'config.json')));
  value.rootKey = safeBytes(path.join(directory, 'capability-root.key'), 64);
  if (value.rootKey.length !== 32) fail('CAPABILITY_KEY_INVALID');
  return value;
}
function initialize({directory, config}) {
  if (!path.isAbsolute(directory) || fs.realpathSync(path.dirname(directory)) !== path.dirname(directory)) fail('STATE_PATH_UNSAFE');
  validateConfig(config);
  fs.mkdirSync(directory, {mode: 0o700});
  privateWrite(path.join(directory, 'config.json'), canonical(config));
  privateWrite(path.join(directory, 'capability-root.key'), crypto.randomBytes(32));
  createJournal({directory: path.join(directory, 'transactions'), initialize: true}).close();
  createArtifactPolicy({directory: path.join(directory, 'artifact-policy'), initialize: true}).close();
  createRuntimeState({directory: path.join(directory, 'runtime'), initialize: true}).close();
  return {status: 'INITIALIZED_STOPPED', directory, federationFingerprint: fed.loadNode(config.federationDirectory).meta.fingerprint};
}
function grant({directory, peerFingerprint, scopes, resources, uses = 1, ttlMs = 60000, nowMs = Date.now()}) {
  const {config, node, rootKey} = load(directory), p = config.peers[peerFingerprint];
  if (!config.enabled || !p?.enabled || !node.peers[peerFingerprint]?.enabled ||
      !Array.isArray(scopes) || !scopes.length || scopes.some(s => !p.operations.includes(s)) ||
      !Array.isArray(resources) || !resources.length || resources.some(r => !p.resources.includes(r)) ||
      !Number.isSafeInteger(uses) || uses < 1 || uses > p.maxUses || !Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > 120000) fail('GRANT_POLICY_DENIED');
  return cap.issue({rootKey, nowMs, claims: {schema: cap.SCHEMA, version: cap.VERSION,
    issuer: node.meta.fingerprint, issuerKeyId: 'collaboration-root-v1', audience: node.meta.fingerprint,
    peer: peerFingerprint, keyBinding: p.tlsBinding, grantId: crypto.randomUUID(), issuerEpoch: config.issuerEpoch,
    policyVersion: config.policyVersion, scopes: [...new Set(scopes)].sort(), resources: [...new Set(resources)].sort(),
    notBeforeMs: nowMs, expiresAtMs: nowMs + ttlMs, limits: {uses, maxBytes: CONTROL_LIMIT, maxConcurrent: p.maxConcurrent}}});
}
function status(directory) {
  const {config, node} = load(directory);
  return {schema: 'mikaya.act.gateway-status.v1', configured: true, enabled: config.enabled, mode: config.mode,
    identity: node.meta.fingerprint, owner: node.meta.owner, listen: config.listen, policyVersion: config.policyVersion,
    issuerEpoch: config.issuerEpoch, peers: Object.entries(config.peers).map(([fingerprint, p]) => ({fingerprint, enabled: p.enabled && node.peers[fingerprint]?.enabled === true})),
    writerLeasePresent: fs.existsSync(path.join(directory, 'transactions', 'writer.lock')),
    legacyBrokerConfigured: config.brokerUrl !== null, actAdmission: 'EXISTING_BROKER_GATES_REQUIRED', arbitraryExecution: false, settlementEnabled: false};
}
function peerForSocket(current, socket) {
  if (!socket?.authorized || socket.getProtocol() !== 'TLSv1.3') fail('AUTHENTICATED_TLS13_REQUIRED');
  const cert = socket.getPeerCertificate(true);
  if (!cert?.raw) fail('CLIENT_CERTIFICATE_REQUIRED');
  const currentCertificate = new crypto.X509Certificate(cert.raw);
  if (Date.now() < Date.parse(currentCertificate.validFrom) || Date.now() >= Date.parse(currentCertificate.validTo)) fail('CLIENT_CERTIFICATE_EXPIRED');
  const binding = cap.keyBindingForCertificate(cert.raw);
  const entry = Object.entries(current.config.peers).find(([, p]) => p.tlsBinding === binding);
  if (!current.config.enabled || !entry || !entry[1].enabled || current.node.peers[entry[0]]?.enabled !== true) fail('PEER_POLICY_DENIED');
  return {...entry[1], fingerprint: entry[0], publicKey: publicRead(path.join(current.config.federationDirectory, 'trust', entry[0] + '.pem'))};
}
function readBody(req) { return new Promise((resolve, reject) => {
  let size = 0, parts = [], finished = false;
  const finish = (error, value) => { if (finished) return; finished = true; clearTimeout(timer); error ? reject(error) : resolve(value); };
  const timer = setTimeout(() => { finish(Object.assign(new Error('BODY_TIMEOUT'), {code: 'BODY_TIMEOUT'})); req.destroy(); }, 5000);
  if (req.headers['content-type'] !== 'application/json' || (req.headers['content-length'] !== undefined &&
      (!/^[0-9]+$/.test(req.headers['content-length']) || Number(req.headers['content-length']) > CONTROL_LIMIT))) {
    finish(Object.assign(new Error('BODY_HEADERS_REFUSED'), {code: 'BODY_HEADERS_REFUSED'})); return;
  }
  req.on('data', b => { size += b.length; if (size > CONTROL_LIMIT) { finish(Object.assign(new Error('MESSAGE_TOO_LARGE'), {code: 'MESSAGE_TOO_LARGE'})); req.destroy(); } else parts.push(b); });
  req.on('end', () => finish(null, Buffer.concat(parts)));
  req.on('error', () => finish(Object.assign(new Error('BODY_INTERRUPTED'), {code: 'BODY_INTERRUPTED'})));
  req.on('aborted', () => finish(Object.assign(new Error('BODY_INTERRUPTED'), {code: 'BODY_INTERRUPTED'})));
}); }
function artifactFor(current, resource) {
  const match = /^manifest:([0-9a-f]{64})(?::chunk:([0-9]{1,2}))?$/.exec(resource);
  if (!match) fail('ARTIFACT_RESOURCE_INVALID');
  const a = current.config.artifacts.find(x => x.manifestDigest === match[1]);
  if (!a) fail('ARTIFACT_NOT_PUBLISHED');
  const manifest = privateJSON(a.manifestPath), distribution = require('./distribution.cjs');
  distribution.verifyManifest({manifest, publisherPublicKey: current.node.publicKey.toString(), expectedPublisher: current.node.meta.fingerprint, expectedManifestDigest: match[1]});
  return {manifest, record: a, index: match[2] === undefined ? null : Number(match[2]), distribution};
}
async function startGateway({directory}) {
  const initial = load(directory);
  const journal = createJournal({directory: path.join(directory, 'transactions')});
  let artifacts, runtime;
  try { artifacts = createArtifactPolicy({directory: path.join(directory, 'artifact-policy')}); runtime = createRuntimeState({directory: path.join(directory, 'runtime')}); }
  catch (e) { journal.close(); if (artifacts) artifacts.close(); throw e; }
  const active = new Map(), sessions = new Set(), connections = new Set();
  let totalActive = 0, closed = false;
  const server = http2.createSecureServer({...initial.tls, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
    requestCert: true, rejectUnauthorized: true, allowHTTP1: true, maxSessionMemory: 8,
    settings: {maxConcurrentStreams: 4, maxHeaderListSize: 8192}, maxHeaderListPairs: 24});
  server.maxConnections = 16;
  server.requestTimeout = 7000;
  server.headersTimeout = 5000;
  server.keepAliveTimeout = 10000;
  server.on('connection', s => { connections.add(s); s.on('close', () => connections.delete(s)); });
  server.on('session', s => { sessions.add(s); s.setTimeout(15000, () => s.close()); s.on('error', () => {}); s.on('close', () => sessions.delete(s)); });
  server.on('tlsClientError', () => { try { runtime.audit({decision: 'deny', code: 'TLS_HANDSHAKE_DENIED'}); } catch {} });
  server.on('error', () => {});
  server.on('request', async (req, res) => {
    let peer, request, reserved = false, counted = false, countedPeerFingerprint, trustedRequest = false;
    const send = (code, body, extra = {}) => {
      if (res.destroyed || res.writableEnded || res.headersSent) return;
      const bytes = Buffer.isBuffer(body) ? body : Buffer.from(canonical(body));
      if (bytes.length > (Buffer.isBuffer(body) ? 65536 : RESPONSE_LIMIT)) return send(503, {error: 'RESPONSE_TOO_LARGE'});
      res.writeHead(code, {'content-type': Buffer.isBuffer(body) ? 'application/octet-stream' : 'application/json', 'content-length': bytes.length, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...extra}); res.end(bytes);
    };
    try {
      if (req.method !== 'POST' || !['/v1/collaboration', '/v1/session'].includes(req.url)) fail('ROUTE_REFUSED');
      let current = load(directory); peer = peerForSocket(current, req.socket);
      if (totalActive >= 8 || (active.get(peer.fingerprint) || 0) >= peer.maxConcurrent) fail('CONCURRENCY_EXHAUSTED');
      totalActive++; active.set(peer.fingerprint, (active.get(peer.fingerprint) || 0) + 1); counted = true; countedPeerFingerprint = peer.fingerprint;
      const bytes = await readBody(req); request = protocol.parseCanonical(bytes);
      current = load(directory); peer = peerForSocket(current, req.socket);
      if (peer.fingerprint !== countedPeerFingerprint) fail('PEER_BINDING_CHANGED');
      if (req.url === '/v1/session') {
        clock.verifyChallenge({challenge: request, node: current.node, peer});
        runtime.nonceOnce({peer: peer.fingerprint, nonce: request.body.nonce, issuedAtMs: Date.now()});
        runtime.audit({decision: 'allow', code: 'PEER_CLOCK_CHALLENGE', peer: peer.fingerprint});
        // A signed time sample confers no capability and touches no business journal.
        return send(200, clock.signClockResponse({node: current.node, challenge: request}));
      }
      protocol.verifyRequest({request, node: current.node, peer});
      trustedRequest = true;
      const i = request.intent;
      if (i.policyVersion !== current.config.policyVersion || !peer.operations.includes(i.operation) || !peer.resources.includes(i.resource)) fail('OPERATION_POLICY_DENIED');
      const fixedResource = {'collaboration.describe.v1': 'collaboration:self', 'toybox.transaction.v1': 'toybox:transactions',
        'receipt.read.v1': 'receipt:transactions', 'federation.broker.v1': 'broker:limitedcompute'}[i.operation];
      if (fixedResource && i.resource !== fixedResource) fail('RESOURCE_SEMANTICS_DENIED');
      const verifyCap = state => cap.verify(request.capability, {rootKey: state.rootKey, channelAuthenticated: true,
        issuer: state.node.meta.fingerprint, issuerKeyId: 'collaboration-root-v1', audience: state.node.meta.fingerprint,
        peer: peer.fingerprint, keyBinding: peer.tlsBinding, issuerEpoch: state.config.issuerEpoch,
        policyVersion: state.config.policyVersion, operation: i.operation, resource: i.resource, requestBytes: bytes.length, nowMs: Date.now()});
      const verified = verifyCap(current);
      if (i.expiresAtMs > verified.expiresAtMs) fail('INTENT_OUTLIVES_CAPABILITY');
      if ((active.get(peer.fingerprint) || 0) > verified.claims.limits.maxConcurrent) fail('CAP_CONCURRENCY_EXHAUSTED');
      runtime.nonceOnce({peer: peer.fingerprint, nonce: request.attempt.nonce, issuedAtMs: request.attempt.issuedAtMs});
      runtime.audit({decision: 'allow', code: 'AUTHORIZATION_ACCEPTED', peer: peer.fingerprint, transactionId: i.transactionId,
        operation: i.operation, intentSha256: sha(canonical(i)), transport: req.httpVersionMajor === 2 ? 'h2-TLS1.3-mTLS' : 'http1.1-TLS1.3-mTLS'});
      const grantId = sha(canonical([current.node.meta.fingerprint, current.config.issuerEpoch, verified.grantId]));
      const accepted = journal.accept({intent: i, grantId, usageLimit: verified.grantUsageLimit,
        effectiveUsageLimit: verified.usageLimit, expiresAtMs: verified.expiresAtMs});
      if (accepted.duplicate) return send(200, protocol.signResponse({node: current.node, request, body: {duplicate: true, receipt: accepted.receipt}}));
      reserved = true;
      current = load(directory); peer = peerForSocket(current, req.socket); verifyCap(current);
      if (!peer.operations.includes(i.operation) || !peer.resources.includes(i.resource) || Date.now() >= i.expiresAtMs) fail('CURRENT_POLICY_DENIED');
      let result, binary = null;
      switch (i.operation) {
        case 'collaboration.describe.v1':
          if (!exact(request.payload, [])) fail('DESCRIBE_PAYLOAD_INVALID');
          result = {schema: 'mikaya.act.interface.v1', operations: peer.operations, transport: ['h2', 'http/1.1'], tls: 'TLSv1.3-mTLS',
            maximumControlBytes: CONTROL_LIMIT, maximumChunkBytes: 65536, actAdmission: 'EXISTING_BROKER_GATES_REQUIRED', arbitraryExecution: false, settlementEnabled: false}; break;
        case 'toybox.transaction.v1':
          if (!exact(request.payload, ['schema', 'artifactDigest', 'statement']) || request.payload.schema !== 'mikaya.act.toybox-statement.v1' ||
              !/^[0-9a-f]{64}$/.test(request.payload.artifactDigest) || typeof request.payload.statement !== 'string' || Buffer.byteLength(request.payload.statement) > 1024) fail('TOYBOX_PAYLOAD_INVALID');
          result = {schema: 'mikaya.act.toybox-accepted.v1', artifactDigest: request.payload.artifactDigest, statementSha256: sha(request.payload.statement),
            recorded: true, blockchainVerified: false, paymentVerified: false, settlementAuthorized: false, executionAuthorized: false}; break;
        case 'receipt.read.v1':
          if (!exact(request.payload, ['operation', 'transactionId'])) fail('RECEIPT_QUERY_INVALID');
          result = {receipt: journal.get({sender: peer.fingerprint, ...request.payload})}; break;
        case 'artifact.metadata.verify.v1': {
          const p = request.payload;
          if (!exact(p, ['manifest', 'release', 'artifactId']) || i.resource !== 'manifest:' + sha(canonical(p.manifest))) fail('MANIFEST_SCOPE_INVALID');
          result = artifacts.verifyAndRecord({manifest: p.manifest, release: p.release, publisherPublicKey: peer.publicKey.toString(),
            expectedPublisher: peer.fingerprint, expectedManifestDigest: sha(canonical(p.manifest)), expectedArtifactId: p.artifactId}); break;
        }
        case 'artifact.manifest.read.v1': {
          if (!exact(request.payload, [])) fail('MANIFEST_PAYLOAD_INVALID'); const a = artifactFor(current, i.resource);
          if (a.index !== null) fail('MANIFEST_RESOURCE_INVALID'); result = {manifest: a.manifest}; break;
        }
        case 'artifact.chunk.read.v1': {
          if (!exact(request.payload, [])) fail('CHUNK_PAYLOAD_INVALID'); const a = artifactFor(current, i.resource);
          if (a.index === null) fail('CHUNK_RESOURCE_INVALID');
          binary = a.distribution.readChunk(safeBytes(a.record.sourcePath, 1048576), a.manifest, a.index);
          result = {manifestDigest: a.record.manifestDigest, index: a.index, length: binary.length, sha256: sha(binary), activationAuthorized: false}; break;
        }
        case 'federation.broker.v1':
          if (!current.config.brokerUrl) fail('EXISTING_BROKER_NOT_CONFIGURED');
          if (!exact(request.payload, ['auth', 'body']) || request.payload.auth?.from !== peer.fingerprint ||
              request.payload.auth?.to !== current.node.meta.fingerprint || request.payload.auth?.route !== '/v1/task') fail('LEGACY_ENVELOPE_BINDING_INVALID');
          fed.computeJob(request.payload.body);
          result = await fed.rawPost(current.config.brokerUrl + 'v1/task', request.payload); break;
        default: fail('OPERATION_NOT_IMPLEMENTED');
      }
      // A current policy check accompanies the committed receipt too. A changed
      // policy after a legacy forward means uncertainty, never a fabricated undo.
      current = load(directory); peer = peerForSocket(current, req.socket); verifyCap(current);
      if (peer.fingerprint !== countedPeerFingerprint || !peer.operations.includes(i.operation) || !peer.resources.includes(i.resource)) fail('CURRENT_POLICY_DENIED');
      const completed = journal.complete({...i, result}); reserved = false;
      runtime.audit({decision: 'allow', code: 'TRANSACTION_COMPLETED', peer: peer.fingerprint, transactionId: i.transactionId, operation: i.operation, intentSha256: sha(canonical(i))});
      const response = protocol.signResponse({node: current.node, request, body: {duplicate: false, receipt: completed.receipt, result}});
      if (binary) return send(200, binary, {'x-mikaya-receipt': Buffer.from(canonical(response)).toString('base64url')});
      send(200, response);
    } catch (e) {
      const code = /^[A-Z0-9_]{1,64}$/.test(e.code || '') ? e.code : 'REQUEST_DENIED';
      if (reserved && request) { try { journal.markUncertain({...request.intent, reason: code}); } catch {} }
      let securityEventDigest = null;
      try { securityEventDigest = runtime.audit({decision: reserved ? 'hold' : 'deny', code, peer: peer?.fingerprint || null,
        transactionId: trustedRequest ? request?.intent?.transactionId : null, operation: trustedRequest ? request?.intent?.operation : null}); } catch {}
      let denial = {error: code};
      if (trustedRequest) {
        try { denial = protocol.signResponse({node: load(directory).node, request,
          body: {error: code, accepted: reserved ? 'UNCERTAIN' : false, securityEventDigest}}); } catch {}
      }
      send(code.includes('CONCURRENCY') ? 429 : reserved ? 503 : 403, denial);
    } finally { if (counted) { totalActive--; active.set(countedPeerFingerprint, (active.get(countedPeerFingerprint) || 1) - 1); } }
  });
  runtime.audit({decision: 'startup', code: 'GATEWAY_STARTED'});
  try { await new Promise((resolve, reject) => { server.once('error', reject); server.listen(initial.config.listen.port, initial.config.listen.host, resolve); }); }
  catch (e) { journal.close(); artifacts.close(); runtime.close(); throw e; }
  async function close() {
    if (closed) return; closed = true;
    for (const s of sessions) s.close();
    await new Promise(resolve => {
      const timer = setTimeout(() => { for (const s of connections) s.destroy(); }, 7000);
      server.close(() => { clearTimeout(timer); resolve(); });
      for (const s of connections) if (!totalActive) s.destroy();
    });
    try { runtime.audit({decision: 'shutdown', code: 'GATEWAY_STOPPED'}); } finally { runtime.close(); artifacts.close(); journal.close(); }
  }
  return {server, address: server.address(), close};
}

function createClient({directory, peerFingerprint, url, transport = 'h2'}) {
  const initial = load(directory), p = initial.config.peers[peerFingerprint];
  if (!p?.enabled || !initial.node.peers[peerFingerprint]?.enabled) fail('OUTBOUND_PEER_DENIED');
  const u = new URL(url);
  if (u.protocol !== 'https:' || u.username || u.password || u.pathname !== '/' || u.search || u.hash) fail('HTTPS_ORIGIN_REQUIRED');
  const tlsOptions = {...initial.tls, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', rejectUnauthorized: true};
  let session, agent, calibration, synchronization;
  if (transport === 'h2') { session = http2.connect(u.origin, tlsOptions); session.on('error', () => {}); }
  else if (transport === 'http1') agent = new https.Agent({...tlsOptions, keepAlive: true, maxSockets: 1});
  else fail('TRANSPORT_INVALID');
  const peerKey = publicRead(path.join(initial.config.federationDirectory, 'trust', peerFingerprint + '.pem'));
  function validateSocket(socket) {
    const current = load(directory);
    const remoteCert = new crypto.X509Certificate(socket.getPeerCertificate(true).raw);
    if (!current.config.enabled || !current.config.peers[peerFingerprint]?.enabled || !current.node.peers[peerFingerprint]?.enabled ||
        !socket.authorized || socket.getProtocol() !== 'TLSv1.3' || Date.now() < Date.parse(remoteCert.validFrom) || Date.now() >= Date.parse(remoteCert.validTo) ||
        cap.keyBindingForCertificate(remoteCert.raw) !== current.config.peers[peerFingerprint].tlsBinding) fail('SERVER_PIN_DENIED');
  }
  async function exchange(route, message) {
    const bytes = Buffer.from(canonical(message)); if (bytes.length > CONTROL_LIMIT) fail('MESSAGE_TOO_LARGE');
    return new Promise((resolve, reject) => {
      let stream, responseHeaders, parts = [], size = 0, settled = false;
      const timer = setTimeout(() => { if (stream) stream.destroy(); finish(Object.assign(new Error('RESPONSE_TIMEOUT'), {code: 'RESPONSE_TIMEOUT'})); }, 7000);
      function finish(error, value) { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : resolve(value); }
      function collect(readable, headers, statusCode) {
        responseHeaders = headers;
        readable.on('data', b => { size += b.length; if (size > 65536) { readable.destroy(); finish(Object.assign(new Error('RESPONSE_TOO_LARGE'), {code: 'RESPONSE_TOO_LARGE'})); } else parts.push(b); });
        readable.on('end', () => finish(null, {statusCode, headers: responseHeaders, bytes: Buffer.concat(parts)}));
        readable.on('error', () => finish(Object.assign(new Error('RESPONSE_INTERRUPTED'), {code: 'RESPONSE_INTERRUPTED'})));
      }
      function h2send() {
        try {
          validateSocket(session.socket);
          stream = session.request({':method': 'POST', ':path': route, 'content-type': 'application/json', 'content-length': bytes.length});
          stream.on('response', headers => collect(stream, headers, headers[':status']));
          stream.on('error', () => finish(Object.assign(new Error('TRANSPORT_ERROR'), {code: 'TRANSPORT_ERROR'})));
          stream.end(bytes);
        } catch (e) { finish(e); }
      }
      if (session) {
        if (session.destroyed || session.closed) return finish(Object.assign(new Error('SESSION_CLOSED'), {code: 'SESSION_CLOSED'}));
        if (session.connecting) { session.once('connect', h2send); session.once('error', () => finish(Object.assign(new Error('TLS_CONNECT_FAILED'), {code: 'TLS_CONNECT_FAILED'}))); }
        else h2send();
      } else {
        stream = https.request(new URL(route, u), {agent, method: 'POST', headers: {'content-type': 'application/json', 'content-length': bytes.length}}, res => {
          try { validateSocket(res.socket); collect(res, res.headers, res.statusCode); } catch (e) { res.destroy(); finish(e); }
        });
        // Authenticate the pinned server before writing a capability or payload.
        stream.on('socket', socket => {
          const write = () => { try { validateSocket(socket); stream.end(bytes); } catch (e) { stream.destroy(); finish(e); } };
          if (socket.connecting) socket.once('secureConnect', write); else write();
        });
        stream.on('error', () => finish(Object.assign(new Error('TLS_CONNECT_FAILED'), {code: 'TLS_CONNECT_FAILED'})));
      }
    });
  }
  async function synchronize({force = false} = {}) {
    if (calibration && !force) {
      try { clock.peerNow(calibration, performance.now() + 7000); return calibration; } catch {}
    }
    if (synchronization) return synchronization;
    synchronization = (async () => {
      const challenge = clock.makeChallenge({node: initial.node, to: peerFingerprint});
      const startMonoMs = performance.now();
      const response = await exchange('/v1/session', challenge), endMonoMs = performance.now();
      if (response.statusCode !== 200) fail('CLOCK_HANDSHAKE_DENIED');
      calibration = clock.verifyClockResponse({response: protocol.parseCanonical(response.bytes, RESPONSE_LIMIT),
        challenge, publicKey: peerKey, startMonoMs, endMonoMs});
      return calibration;
    })();
    try { return await synchronization; } finally { synchronization = undefined; }
  }
  async function prepareRequest(options) {
    await synchronize();
    return protocol.makeRequest({...options, node: initial.node, to: peerFingerprint, nowMs: clock.peerNow(calibration)});
  }
  const responseTime = () => calibration ? clock.peerNow(calibration) : Date.now();
  async function send(request) {
    if (request.intent.sender !== initial.node.meta.fingerprint || request.intent.recipient !== peerFingerprint) fail('OUTBOUND_INTENT_DENIED');
    const response = await exchange('/v1/collaboration', request);
    if (response.statusCode !== 200) {
      let error, signedRejection;
      try {
        const parsed = protocol.parseCanonical(response.bytes, RESPONSE_LIMIT);
        if (parsed.auth) { error = protocol.verifyResponse({response: parsed, request, publicKey: peerKey, nowMs: responseTime()}).error; signedRejection = parsed; }
        else error = parsed.error;
      } catch { fail('REMOTE_REJECTION_INVALID'); }
      const code = error && /^[A-Z0-9_]{1,64}$/.test(error) ? error : 'REMOTE_REQUEST_DENIED';
      const denied = new Error(code); denied.code = code; if (signedRejection) denied.signedRejection = signedRejection; throw denied;
    }
    const latest = load(directory);
    if (!latest.config.enabled || !latest.config.peers[peerFingerprint]?.enabled || !latest.node.peers[peerFingerprint]?.enabled ||
        latest.config.peers[peerFingerprint].tlsBinding !== p.tlsBinding) fail('SERVER_PIN_DENIED');
    const binary = response.headers['content-type'] === 'application/octet-stream';
    const signed = binary ? protocol.parseCanonical(Buffer.from(response.headers['x-mikaya-receipt'] || '', 'base64url'), RESPONSE_LIMIT) : protocol.parseCanonical(response.bytes, RESPONSE_LIMIT);
    const body = protocol.verifyResponse({response: signed, request, publicKey: peerKey, nowMs: responseTime()});
    if (body.receipt?.resultSha256 && body.result && body.receipt.resultSha256 !== sha(canonical(body.result))) fail('RECEIPT_RESULT_MISMATCH');
    if (binary && (body.result?.sha256 !== sha(response.bytes) || body.result.length !== response.bytes.length)) fail('BINARY_RECEIPT_MISMATCH');
    return {verified: true, transport, signedResponse: signed, ...body, ...(binary ? {bytes: response.bytes} : {})};
  }
  return {send, prepareRequest, synchronize, peerNow: () => clock.peerNow(calibration), close: () => { if (session) session.destroy(); if (agent) agent.destroy(); }};
}
function options(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!/^--[a-z-]+$/.test(argv[i]) || argv[i + 1] === undefined || Object.hasOwn(result, argv[i].slice(2))) fail('CLI_ARGUMENT_INVALID');
    result[argv[i].slice(2)] = argv[i + 1];
  }
  return result;
}
async function main(argv = process.argv.slice(2)) {
  const [verb, ...rest] = argv;
  if (verb === 'preflight') { process.exitCode = await require('./android-preflight.cjs').runCli(rest); return; }
  const o = options(rest);
  if (verb === 'demo') return console.log(JSON.stringify(await require('./demo.cjs').runDemo({directory: o.directory}), null, 2));
  if (verb === 'init') return console.log(JSON.stringify(initialize({directory: o.directory, config: privateJSON(o.config)}), null, 2));
  if (verb === 'status') return console.log(JSON.stringify(status(o.directory), null, 2));
  if (verb === 'grant') {
    const token = grant({directory: o.directory, peerFingerprint: o.peer, scopes: o.scopes?.split(','), resources: o.resources?.split(','), uses: Number(o.uses || 1), ttlMs: Number(o['ttl-ms'] || 60000)});
    privateWrite(o.output, token + '\n'); return console.log(JSON.stringify({status: 'GRANT_WRITTEN', output: o.output}));
  }
  if (verb === 'serve') {
    const runtime = await startGateway({directory: o.directory});
    console.log(JSON.stringify({status: 'COLLABORATION_READY', address: runtime.address, tls: 'TLSv1.3-mTLS'}));
    const stop = () => runtime.close().then(() => process.exit(0), () => process.exit(2));
    process.once('SIGINT', stop); process.once('SIGTERM', stop); return;
  }
  if (verb === 'request') {
    const descriptor = privateJSON(o.request), node = load(o.directory).node;
    if (!exact(descriptor, ['peer', 'url', 'capabilityFile', 'operation', 'resource', 'payload', 'transactionId', 'expiresAtMs'])) fail('REQUEST_DESCRIPTOR_INVALID');
    const capability = safeBytes(descriptor.capabilityFile, 4097).toString().trim();
    const client = createClient({directory: o.directory, peerFingerprint: descriptor.peer, url: descriptor.url, transport: o.transport || 'h2'});
    try {
      const request = await client.prepareRequest({node, to: descriptor.peer, capability, ...descriptor});
      const response = await client.send(request);
      if (response.bytes) {
        if (!o.output) fail('BINARY_OUTPUT_REQUIRED'); privateWrite(o.output, response.bytes); delete response.bytes; response.output = o.output;
      }
      console.log(JSON.stringify(response, null, 2));
    } finally { client.close(); } return;
  }
  fail('USAGE_PREFLIGHT_DEMO_INIT_STATUS_GRANT_SERVE_REQUEST');
}
module.exports = {OPS, CONTROL_LIMIT, load, validateConfig, initialize, grant, status, startGateway, createClient, main};
if (require.main === module) main().catch(e => { console.error(e.code || 'COLLABORATION_COMMAND_FAILED'); process.exitCode = 1; });
