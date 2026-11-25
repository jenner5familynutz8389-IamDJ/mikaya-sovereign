'use strict';
// Archival verification only. Does not change frozen source, execute a suite,
// contact a device/network, load private keys, or grant new request freshness.
const fs = require('node:fs'), path = require('node:path'), os = require('node:os');
const crypto = require('node:crypto'), assert = require('node:assert/strict');
assert(process.argv.length === 4 && process.argv[2].trim() && process.argv[3].trim(),
  'Usage: node verify-public-evidence.cjs EVIDENCE_ROOT REPO_ROOT');
const ROOT = path.resolve(process.argv[2]);
const REPO = path.resolve(process.argv[3]);
assert(fs.statSync(ROOT).isDirectory() && fs.statSync(REPO).isDirectory(),
  'EVIDENCE_ROOT and REPO_ROOT must both be directories');
const EXPECTED_SOURCE = '76310862197a799269ea6aa9a2c8374538eb0ecabfa2ee74b91742e310c7ed31';
const EXPECTED_TESTS = 137;
const WORKSPACE_DIR = path.join(ROOT, 'workspace-final-137');
assert.match(EXPECTED_SOURCE, /^[a-f0-9]{64}$/);
assert(Number.isSafeInteger(EXPECTED_TESTS) && EXPECTED_TESTS > 0 && EXPECTED_TESTS < 10000);
const session = require(path.join(REPO, 'engineering/federation/interop/session-adapter.cjs'));
const direct = require(path.join(REPO, 'engineering/federation/interop/direct-transport.cjs'));
const ledgers = require(path.join(REPO, 'engineering/federation/interop/ledger-receipts.cjs'));
const service = require(path.join(REPO, 'engineering/federation/interop/service-control.cjs'));
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
function canonical(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  assert(value && Object.getPrototypeOf(value) === Object.prototype, 'noncanonical signed object');
  return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}
const jsonHash = value => sha(canonical(value));
const read = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const fingerprint = key => sha(crypto.createPublicKey(key).export({ type: 'spki', format: 'pem' }));
const uniqueSignatures = new Set();
function verifySignature(object, kind, key, domain) {
  const { signature, ...body } = object;
  assert.match(signature, /^[A-Za-z0-9+/]{86}==$/);
  const bytes = Buffer.from(signature, 'base64'); assert.equal(bytes.toString('base64'), signature);
  assert(crypto.verify(null, Buffer.from(domain + kind + '\n' + canonical(body)), key, bytes), 'independent signature failure: ' + kind);
  uniqueSignatures.add(domain + kind + ':' + signature + ':' + fingerprint(key));
}
function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => {
    assert(!e.isSymbolicLink(), 'evidence symlink refused');
    const file = path.join(dir, e.name); return e.isDirectory() ? walk(file) : [file];
  });
}
function inventory(dir) {
  return walk(dir).map(file => {
    const raw = fs.readFileSync(file, 'utf8');
    assert(!/-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/.test(raw), 'private key material found in evidence artifact: ' + path.basename(file));
    const value = file.endsWith('.json') ? JSON.parse(raw) : null;
    function inspect(x) {
      if (!x || typeof x !== 'object') return;
      for (const [k,v] of Object.entries(x)) {
        assert(!(['privateKey','rootKeyHex','tlsPrivateKey','access_token','password','token'].includes(k) && typeof v === 'string' && v.length), 'private credential field found in evidence artifact: ' + path.basename(file));
        inspect(v);
      }
    }
    inspect(value);
    return { file, value };
  });
}
function one(items, predicate, description) {
  const found = items.filter(predicate); assert.equal(found.length, 1, description + ': expected exactly one, got ' + found.length); return found[0];
}
function uniqueArtifacts(items) {
  const seen = new Set();
  return [...items].sort((a,b)=>a.file.length-b.file.length).filter(item => {
    const hash=sha(fs.readFileSync(item.file));if(seen.has(hash))return false;seen.add(hash);return true;
  });
}
const report = { schema: 'mikaya.interop.final-independent-verification.v1', verifiedAt: new Date().toISOString(),
  status: 'PASS', testedSourceSetSha256: EXPECTED_SOURCE, method: 'Independent artifact/TAP/source hashing, independent node:crypto signature checks, source contract/ledger verification and deduplicated reconciliation. No test suites or device commands rerun.',
  acceptance: [], deployedIdentities: [], directExchanges: [], benchmarks: [], ledgerVerification: [], serviceObservations: [], ownerLifecycle: [], hardwareObservations: [] };
function acceptance(name, item) {
  const a = item.value, dir = path.dirname(item.file);
  assert.equal(a.status, 'PASS'); assert.equal(a.sourceSetSha256, EXPECTED_SOURCE); assert.equal(a.sourceStable, true);
  assert.deepEqual(a.failureReasons, []); assert.equal(a.process.exitCode, 0); assert.equal(a.process.signal, null); assert.equal(a.process.terminationReason, null);
  const tap = fs.readFileSync(path.join(dir, 'test-results.tap'), 'utf8'), counts = {};
  for (const key of ['tests', 'suites', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
    const matches = [...tap.matchAll(new RegExp('^# ' + key + ' (\\d+)$', 'gm'))]; assert.equal(matches.length, 1); counts[key] = Number(matches[0][1]);
  }
  assert.deepEqual(counts, a.tap.counts); assert.equal(counts.tests, EXPECTED_TESTS); assert.equal(counts.pass, EXPECTED_TESTS);
  for (const key of ['fail', 'cancelled', 'skipped', 'todo']) assert.equal(counts[key], 0);
  for (const artifact of a.artifacts) {
    assert.equal(path.basename(artifact.name), artifact.name); const bytes = fs.readFileSync(path.join(dir, artifact.name));
    assert.equal(bytes.length, artifact.bytes); assert.equal(sha(bytes), artifact.sha256);
  }
  const before = read(path.join(dir, 'source-manifest.json')), after = read(path.join(dir, 'source-manifest-after.json'));
  assert.deepEqual(before, after); assert.equal(sha(JSON.stringify(before.files)), EXPECTED_SOURCE);
  for (const source of before.files) {
    assert(!path.isAbsolute(source.path) && !source.path.split('/').includes('..'));
    const bytes = fs.readFileSync(path.join(REPO, source.path)); assert.equal(bytes.length, source.bytes); assert.equal(sha(bytes), source.sha256);
  }
  assert.equal(a.runtimeComparison.outcome, 'MATCH');
  const profile = read(path.join(dir, 'runtime-profile.json'));
  report.acceptance.push({ environment: name, startedAt: a.startedAt, finishedAt: a.finishedAt, durationMs: a.durationMs, counts,
    verifiedArtifactCount: a.artifacts.length, verifiedSourceFileCount: before.files.length, sourceSetSha256: a.sourceSetSha256,
    runtime: Object.fromEntries(['runtime.nodeVersion','runtime.platform','runtime.arch'].map(k => [k, profile.facts[k]?.value])),
    acceptanceRecordSha256: sha(fs.readFileSync(item.file)), tapSha256: sha(tap), scope: a.TEST_SCOPE });
}
const workspaceItems = inventory(WORKSPACE_DIR);
acceptance('workspace', one(workspaceItems, x => x.value?.schema === 'mikaya.interop.executed-acceptance.v1', 'workspace acceptance'));
const devices = {};
for (const name of ['f110', 'motorola']) {
  const dir = path.join(ROOT, name + '-ready-evidence'), items = inventory(dir);
  acceptance(name, one(items, x => x.value?.schema === 'mikaya.interop.executed-acceptance.v1' && x.file === path.join(dir,'acceptance','acceptance.json'), name + ' final acceptance'));
  const peerItem = one(items, x => x.value?.schema === 'mikaya.interop.direct-peer.v1' && x.file === path.join(dir,'public-peer.json'), name + ' own public peer');
  const peer = peerItem.value;
  verifySignature(peer, 'PEER', peer.publicKey, 'MIKAYA-INTEROP-DIRECT/1\n');
  assert.equal(fingerprint(peer.publicKey), peer.fingerprint);
  const cert = new crypto.X509Certificate(peer.tlsCertificatePem);
  assert.equal(sha(cert.raw), peer.tlsCertificateSha256); assert(cert.verify(cert.publicKey)); assert.equal(cert.checkHost('mikaya-interop.test'), 'mikaya-interop.test');
  const matchingProfiles = items.filter(x => x.value?.schema === 'mikaya.interop.runtime-profile.v1' && jsonHash(x.value) === peer.profileSha256);
  assert(matchingProfiles.length > 0, name + ' actual saved deployment profile missing');
  const policyItems = items.filter(x => x.value?.schema === 'mikaya.interop.distribution-policy.v1' && x.file === path.join(dir,'distribution-policy.json'));
  assert(policyItems.length > 0, 'explicit distribution policy missing');
  const policy = policyItems[0].value; ledgers.validateDistributionPolicy(policy);
  for (const item of policyItems) assert.equal(jsonHash(item.value), jsonHash(policy));
  const rowItems = items.filter(x => x.value?.schema === 'mikaya.interop.receipt-ledger-entry.v1' && path.dirname(x.file) === path.join(dir,'receipt-ledger')).sort((a,b) => a.value.index - b.value.index);
  assert(rowItems.length > 0, name + ' public receipt ledger missing');
  const ledgerId = rowItems[0].value.ledgerId; assert(rowItems.every(x => x.value.ledgerId === ledgerId));
  devices[name] = { name, dir, items, peer, policy, profile:matchingProfiles[0].value, rows: rowItems.map(x => x.value), rowItems, checkpointCandidates: [] };
  report.deployedIdentities.push({ device: name, fingerprint: peer.fingerprint, certificateSha256: peer.tlsCertificateSha256, profileSha256: peer.profileSha256,
    certificateValidFrom: new Date(cert.validFrom).toISOString(), certificateValidUntil: new Date(cert.validTo).toISOString(),
    actualSavedProfileDigestMatched: true, peerManifestSignatureVerified: true, certificateSelfSignatureVerified: true, hardwareAttested: false });
}
assert.notEqual(devices.f110.peer.fingerprint, devices.motorola.peer.fingerprint);
assert.equal(jsonHash(devices.f110.policy), jsonHash(devices.motorola.policy));
const proofWork = new Map(), allTimestampDeltas = [];
function verifyRecord(record, receipt, owner, holder, worker, nowMs) {
  ledgers.verifyReceiptCheckpoint({ checkpoint: record.checkpoint, nodePublicKey: owner.peer.publicKey });
  verifySignature(record.checkpoint, 'CHECKPOINT', owner.peer.publicKey, 'MIKAYA-INTEROP-RECEIPT-LEDGER/1\n');
  assert.equal(record.recorded, true); assert.equal(record.paymentSettled, false); assert.equal(record.executionAuthorized, false);
  assert.equal(record.receiptSha256, jsonHash(receipt));
  const requestKey = sha(holder.peer.fingerprint + '\n' + worker.peer.fingerprint + '\n' + receipt.request.auth.nonce);
  assert.equal(record.requestKey, requestKey); assert.equal(record.checkpoint.entries, record.index + 1); assert.equal(record.checkpoint.latestHash, record.entryHash);
  assert.equal(record.checkpoint.ownerFingerprint, owner.peer.fingerprint); assert.equal(record.checkpoint.policySha256, jsonHash(owner.policy));
  assert.deepEqual(record.accounting, ledgers.accountReceipt({ policy: owner.policy, capability: receipt.request.body.capability, holderFingerprint: holder.peer.fingerprint, workerFingerprint: worker.peer.fingerprint }));
  const row = owner.rows[record.index]; assert(row, 'recorded checkpoint entry missing from saved ledger');
  assert.equal(row.entryHash, record.entryHash); assert.equal(row.ledgerId, record.checkpoint.ledgerId); assert.equal(row.payload.requestKey, requestKey); assert.equal(row.payload.receiptSha256, record.receiptSha256);
  assert.equal(row.recordedAtMs, record.checkpoint.issuedAtMs);
  session.verifyConformanceReceipt({ ...receipt, holderPublicKey: holder.peer.publicKey, workerPublicKey: worker.peer.publicKey, profileSha256: worker.peer.profileSha256, nowMs: record.checkpoint.issuedAtMs });
  if (owner === worker) owner.checkpointCandidates.push(record.checkpoint);
}
function verifyProof(proof, holder, worker, fallbackTime) {
  if (proof.own) assert.equal(jsonHash(proof.own), jsonHash(holder.peer));
  if (proof.peer) assert.equal(jsonHash(proof.peer), jsonHash(worker.peer));
  const receipt = { request: proof.request, response: proof.response, evidence: proof.evidence };
  const nowMs = proof.verifiedAt ? Date.parse(proof.verifiedAt) : proof.holderLedger.checkpoint.issuedAtMs;
  assert(Number.isSafeInteger(nowMs));
  direct.validatePeer(holder.peer, nowMs); direct.validatePeer(worker.peer, nowMs);
  verifySignature(proof.request.auth, 'REQ', holder.peer.publicKey, 'MIKAYA-INDEPENDENT-FEDERATION/1\n');
  verifySignature(proof.response.auth, 'RES', worker.peer.publicKey, 'MIKAYA-INDEPENDENT-FEDERATION/1\n');
  verifySignature(proof.evidence, 'EVIDENCE', worker.peer.publicKey, 'MIKAYA-INTEROP-CONFORMANCE/1\n');
  verifySignature(proof.transportEvidence, 'TRANSPORT_EVIDENCE', worker.peer.publicKey, 'MIKAYA-INTEROP-DIRECT/1\n');
  assert.equal(jsonHash(proof.request.body), proof.request.auth.bodySha256);
  assert.equal(jsonHash(proof.response.body), proof.response.auth.bodySha256);
  assert.equal(jsonHash(proof.request), proof.evidence.requestSha256); assert.equal(jsonHash(proof.response), proof.evidence.responseSha256);
  assert.equal(proof.evidence.profileSha256, worker.peer.profileSha256);
  const job = proof.request.body;
  const expected = job.capability === 'compute.dot.v1' ? job.payload.a.reduce((n,v,i) => n + v*job.payload.b[i], 0) : sha(Buffer.from(job.payload.challengeHex, 'hex'));
  assert.equal(proof.response.body.result, expected);
  const verified = session.verifyConformanceReceipt({ ...receipt, holderPublicKey: holder.peer.publicKey, workerPublicKey: worker.peer.publicKey, profileSha256: worker.peer.profileSha256, nowMs });
  const binding = proof.transportEvidence.channelBindingSha256;
  direct.verifyTransportEvidence(proof.transportEvidence, { own: holder.peer, peer: worker.peer, request: proof.request, response: proof.response, binding, workerLedger: proof.workerLedger, nowMs });
  direct.verifyWorkerLedgerRecord(proof.workerLedger, { policy: holder.policy, ...receipt, holderFingerprint: holder.peer.fingerprint, workerFingerprint: worker.peer.fingerprint, workerPublicKey: worker.peer.publicKey, nowMs });
  verifyRecord(proof.workerLedger, receipt, worker, holder, worker, nowMs); verifyRecord(proof.holderLedger, receipt, holder, holder, worker, nowMs);
  const key = proof.workerLedger.requestKey, old = proofWork.get(key); if (old) assert.equal(old, jsonHash(receipt)); proofWork.set(key, jsonHash(receipt));
  const signedDelta = proof.response.auth.issuedAtMs - proof.request.auth.issuedAtMs;
  assert(Math.abs(signedDelta) <= 10000); allTimestampDeltas.push({ holder: holder.name, worker: worker.name, signedDeltaMs: signedDelta });
  if (proof.verified) assert.deepEqual(proof.verified, verified);
  return { capability: job.capability, result: expected, signedTimestampDeltaMs: signedDelta, recordedVerificationAt: new Date(nowMs).toISOString(), requestKey: key, channelBindingSha256: binding, profileBindingVerified: true, signedWorkerAndHolderCheckpointsVerified: true, bothActualLedgerEntriesMatched: true };
}
function stats(values) { const sorted=[...values].sort((a,b)=>a-b); return { minMs: sorted[0], medianMs: sorted[Math.floor(sorted.length/2)], maxMs: sorted.at(-1), meanMs: values.reduce((a,b)=>a+b,0)/values.length }; }
for (const holder of Object.values(devices)) {
  const worker = devices[holder.name === 'f110' ? 'motorola' : 'f110'];
  const lifecycleFile=path.join(holder.dir,'owner-control-live-final.json'), lifecycle=read(lifecycleFile);
  assert.equal(lifecycle.schema,'mikaya.interop.owner-control-live-test.v1');assert.equal(lifecycle.status,'PASS');assert.equal(lifecycle.testedSourceSetSha256,EXPECTED_SOURCE);assert.equal(lifecycle.listenerClosedAfterKill,true);
  assert.deepEqual(lifecycle.steps.map(x=>x.command),['status','kill','resume-while-killed','start-while-killed','clear-kill','resume-while-disabled','explicit-owner-start']);
  const controlSteps=[];
  for(const step of lifecycle.steps){
    const r=step.result;
    if(step.command==='start-while-killed'){
      assert.equal(step.exitCode,1);const refusal=JSON.parse(r.refusal);assert.equal(refusal.status,'REFUSED');assert.match(refusal.reason,/owner kill switch active/);
      controlSteps.push({command:step.command,exitCode:step.exitCode,killEnforcementRefusalVerified:true});continue;
    }
    assert.equal(step.exitCode,0);assert.equal(r.sourceCurrent,true);
    const running=step.command==='status'||step.command==='explicit-owner-start';
    const killed=step.command==='kill'||step.command==='resume-while-killed';
    assert.equal(r.running,running);assert.equal(r.enabled,running);assert.equal(r.killSwitch,killed);
    if(running){assert.equal(r.worker?.phase,'READY');assert.equal(r.worker?.state,'MATCH');assert.equal(r.supervisor?.state,'MATCH');}
    if(step.command.startsWith('resume-while-'))assert.equal(r.status,'OWNER_DISABLED');
    controlSteps.push({command:step.command,exitCode:step.exitCode,recordedRunning:r.running,recordedEnabled:r.enabled,recordedKillSwitch:r.killSwitch,recordedWorkerReady:r.worker?.phase==='READY'});
  }
  const readyFile=path.join(holder.dir,'final-ready-status.json'),ready=read(readyFile);
  assert.equal(ready.schema,'mikaya.interop.service-status.v1');assert.equal(ready.running,true);assert.equal(ready.enabled,true);assert.equal(ready.killSwitch,false);assert.equal(ready.sourceCurrent,true);assert.equal(ready.policyError,null);
  assert.equal(ready.worker?.phase,'READY');assert.equal(ready.worker?.state,'MATCH');assert.equal(ready.supervisor?.state,'MATCH');
  assert.equal(ready.testedSourceSetSha256,EXPECTED_SOURCE);assert.equal(ready.postOwnerRestartTrafficVerified,true);
  assert.equal(ready.sourceSetSha256,sha(JSON.stringify(service.sources())));
  assert.equal(ready.ownFingerprint,holder.peer.fingerprint);assert.equal(ready.peerFingerprint,worker.peer.fingerprint);
  const installedFile=path.join(holder.dir,'owner-controls.json'),installed=read(installedFile);
  assert.equal(installed.schema,'mikaya.interop.installed-owner-controls.v2');assert.equal(installed.command,'mikaya-interop');
  assert.equal(installed.loginHookInstalled,true);assert.equal(installed.rebootExecuted,false);assert.equal(installed.currentServiceRunning,true);assert.equal(installed.sourceCurrent,true);
  assert.match(installed.wrapperSha256,/^[a-f0-9]{64}$/);assert.match(installed.cliSha256,/^[a-f0-9]{64}$/);
  report.ownerLifecycle.push({device:holder.name,status:'PASS',artifact:path.relative(ROOT,lifecycleFile),artifactSha256:sha(fs.readFileSync(lifecycleFile)),startedAt:lifecycle.startedAt,finishedAt:lifecycle.finishedAt,
    testedSourceSetSha256:lifecycle.testedSourceSetSha256,listenerClosureAfterKillRecorded:true,steps:controlSteps,
    finalReady:{checkedAt:ready.checkedAt,running:true,workerPhase:'READY',postOwnerRestartTrafficRecorded:true,serviceInventoryMatchesFrozenSource:true,artifactSha256:sha(fs.readFileSync(readyFile))},
    installedControls:{command:installed.command,loginHookInstalled:installed.loginHookInstalled,bootHookInstalled:installed.bootHookInstalled,rebootExecuted:false,wrapperSha256AsRecorded:installed.wrapperSha256,cliSha256AsRecorded:installed.cliSha256,artifactSha256:sha(fs.readFileSync(installedFile))},
    evidenceClass:'RETAINED_OPERATOR_DEVICE_CONTROL_RECORDS_NOT_HARDWARE_ATTESTATION'});
  const hardwareFile=path.join(holder.dir,'hardware-integrity-observation.json'),hardware=read(hardwareFile);
  assert.equal(hardware.schema,'mikaya.interop.hardware-integrity-observation.v1');assert.equal(hardware.hardwareAttestationVerified,false);assert.equal(hardware.identifiesHuman,false);assert.equal(hardware.provesWalletAuthority,false);
  const allowed=['ro.product.model','ro.product.manufacturer','ro.product.board','ro.soc.model','ro.build.version.release','ro.build.version.sdk','ro.build.version.security_patch','ro.boot.verifiedbootstate','ro.boot.vbmeta.device_state','ro.boot.flash.locked','ro.boot.veritymode'];
  assert.deepEqual(Object.keys(hardware.properties).sort(),[...allowed].sort());
  const overlaps={'ro.product.model':'android.model','ro.product.board':'android.board','ro.soc.model':'android.soc','ro.build.version.release':'android.release','ro.build.version.sdk':'android.sdk','ro.build.version.security_patch':'android.securityPatch'};
  for(const [property,fact] of Object.entries(overlaps))if(hardware.properties[property].status==='observed'&&holder.profile.facts[fact]?.status==='observed')assert.equal(String(hardware.properties[property].value),String(holder.profile.facts[fact].value));
  report.hardwareObservations.push({device:holder.name,observedAt:hardware.observedAt,artifactSha256:sha(fs.readFileSync(hardwareFile)),evidenceClass:'UNSIGNED_ANDROID_GETPROP_SOFTWARE_OBSERVATION',properties:hardware.properties,overlappingFactsMatchSignedRuntimeProfile:true,hardwareAttestationVerified:false,identifiesHuman:false,provesWalletAuthority:false});
  for (const item of holder.items) {
    const snapshots=[];
    function collect(value) {
      if(!value||typeof value!=='object')return;
      if(value.schema==='mikaya.interop.service-status.v1'){
        assert.equal(typeof value.running,'boolean');assert.equal(typeof value.enabled,'boolean');assert.equal(typeof value.killSwitch,'boolean');
        assert(Number.isFinite(Date.parse(value.checkedAt)));
        if(value.running){assert.equal(value.enabled,true);assert.equal(value.killSwitch,false);if(value.worker?.phase!==undefined)assert.equal(value.worker.phase,'READY');assert.equal(value.worker?.state,'MATCH');assert.equal(value.supervisor?.state,'MATCH');}
        snapshots.push({checkedAt:value.checkedAt,recordedRunning:value.running,recordedEnabled:value.enabled,recordedKillSwitch:value.killSwitch,recordedWorkerPhase:value.worker?.phase||null,recordedSourceCurrent:value.sourceCurrent===true,metadataErrorPresent:!!value.policyError});
      }
      for(const child of Object.values(value))collect(child);
    }
    collect(item.value);
    if(snapshots.length)report.serviceObservations.push({device:holder.name,artifact:path.relative(ROOT,item.file),artifactSha256:sha(fs.readFileSync(item.file)),classification:'RETAINED_OPERATOR_PROCESS_OBSERVATIONS_NOT_CRYPTOGRAPHIC_PROCESS_ATTESTATION',snapshots});
  }
  const exercises = uniqueArtifacts(holder.items.filter(x => x.value?.schema === 'mikaya.interop.direct-exercise.v1')); assert(exercises.length > 0, 'physical direct exercise missing');
  for (const item of exercises) {
    const proof = item.value; assert.equal(proof.allVerified, true); assert.equal(proof.exchanges.length, 2);
    const exchanges = proof.exchanges.map(x => { assert.equal(x.replayRefused, true); assert.equal(x.negotiatedProtocol, 'TLSv1.3'); assert.equal(x.cipher, 'TLS_AES_256_GCM_SHA384'); return verifyProof(x, holder, worker); });
    report.directExchanges.push({ direction: holder.name + ' -> ' + worker.name + ' -> ' + holder.name, operatorRouteLabel: path.basename(item.file).includes('-overlay')?'OWNER_OVERLAY':path.basename(item.file).includes('-lan')?'OWNER_LAN':'UNSPECIFIED', artifact: path.relative(ROOT,item.file), artifactSha256:sha(fs.readFileSync(item.file)), transport:'TLSv1.3_MUTUAL_PINNED', cipher:'TLS_AES_256_GCM_SHA384', capturedReplayRefusal:true, exchanges });
  }
  for (const item of uniqueArtifacts(holder.items.filter(x => x.value?.schema === 'mikaya.interop.direct-latency-benchmark.v1'))) {
    const b = item.value; assert.equal(jsonHash(b.own),jsonHash(holder.peer)); assert.equal(jsonHash(b.peer),jsonHash(worker.peer));
    const count=b.countPerCondition; assert(Number.isInteger(count)&&count>=3&&count<=20); assert.equal(b.receipts.length,count*2);
    for (const condition of ['freshTlsEachJob','persistentTls']) {
      const s=b[condition]; assert.equal(s.samples.length,count); assert(s.samples.every(x=>Number.isFinite(x)&&x>=0));
      for(const [k,v] of Object.entries(stats(s.samples))) assert.equal(s[k],v);
    }
    assert.equal(b.receipts.filter(x=>x.kind==='fresh').length,count); assert.equal(b.receipts.filter(x=>x.kind==='persistent').length,count);
    for(const proof of b.receipts) verifyProof(proof,holder,worker);
    assert.equal(b.freshOverPersistentMedianRatio,b.freshTlsEachJob.medianMs/b.persistentTls.medianMs);
    assert.equal(b.persistentFasterInThisRun,b.persistentTls.medianMs<b.freshTlsEachJob.medianMs);
    report.benchmarks.push({ direction:holder.name+' -> '+worker.name,operatorRouteLabel:path.basename(item.file).includes('-overlay')?'OWNER_OVERLAY':path.basename(item.file).includes('-lan')?'OWNER_LAN':'UNSPECIFIED',artifact:path.relative(ROOT,item.file),artifactSha256:sha(fs.readFileSync(item.file)),sampleCountPerCondition:count,freshTlsEachJob:stats(b.freshTlsEachJob.samples),persistentTls:stats(b.persistentTls.samples),freshOverPersistentMedianRatio:b.freshOverPersistentMedianRatio,persistentFasterInThisRun:b.persistentFasterInThisRun,signedReceiptsVerified:b.receipts.length,bulkThroughputMeasured:false });
  }
}
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-public-ledger-verification-'));
try {
  const inputs=[];
  for(const device of Object.values(devices)){
    const ledgerDir=path.join(temp,device.name);fs.mkdirSync(ledgerDir,{mode:0o700});
    for(const item of device.rowItems){
      const row=item.value;
      const {signature,entryHash,...body}=row;
      assert.equal(entryHash,sha('MIKAYA-INTEROP-RECEIPT-LEDGER/1\nHASH\n'+canonical(body)));
      verifySignature({entryHash,signature},'ENTRY',device.peer.publicKey,'MIKAYA-INTEROP-RECEIPT-LEDGER/1\n');
      if(row.kind==='VERIFIED_COMPUTE_RECEIPT'){
        const p=row.payload;
        verifySignature(p.receipt.request.auth,'REQ',p.holderPublicKey,'MIKAYA-INDEPENDENT-FEDERATION/1\n');
        verifySignature(p.receipt.response.auth,'RES',p.workerPublicKey,'MIKAYA-INDEPENDENT-FEDERATION/1\n');
        verifySignature(p.receipt.evidence,'EVIDENCE',p.workerPublicKey,'MIKAYA-INTEROP-CONFORMANCE/1\n');
      }
      const name=String(row.index).padStart(6,'0')+'.json';fs.writeFileSync(path.join(ledgerDir,name),fs.readFileSync(item.file),{mode:0o600,flag:'wx'});
    }
    assert(device.checkpointCandidates.length>0,'counterparty-retained checkpoint missing');
    const expectedCheckpoint=device.checkpointCandidates.sort((a,b)=>b.entries-a.entries)[0];
    const input={ledgerDir,nodePublicKey:device.peer.publicKey,expectedCheckpoint};inputs.push(input);
    const result=ledgers.verifyReceiptLedger(input);
    report.ledgerVerification.push({device:device.name,...result,counterpartyRetainedCheckpointEntries:expectedCheckpoint.entries});
  }
  report.reconciliation=ledgers.reconcileReceiptLedgers({ledgers:inputs});
}finally{fs.rmSync(temp,{recursive:true,force:true});}
report.uniqueProofWorkReceipts=proofWork.size;report.uniqueSignedEnvelopesIndependentlyVerified=uniqueSignatures.size;
assert([...proofWork.keys()].every(k=>report.reconciliation.matchedRequestKeys.includes(k)), 'a saved network proof is missing from bilateral ledger reconciliation');
report.additionalLedgerOnlyWorkReceipts=report.reconciliation.matchedRequestKeys.filter(k=>!proofWork.has(k)).length;
report.timestampPolicy={maxSignedTimestampDeltaMs:10000,maxLocalFreshnessMs:60000,observed:allTimestampDeltas,
  minimumSignedDeltaMs:Math.min(...allTimestampDeltas.map(x=>x.signedDeltaMs)),maximumSignedDeltaMs:Math.max(...allTimestampDeltas.map(x=>x.signedDeltaMs)),clockOffsetVerified:false,
  explanation:'Signed response minus signed request includes device clock disagreement and processing/transport elapsed time. These deltas are not an independently attested clock offset. Archival verification uses original captured holder or signed ledger-record timestamps and does not renew expired requests.'};
report.evidenceLimits=[
  'Acceptance TAP, runtime observations, service lifecycle and latency timings are retained operator/device records, not manufacturer hardware attestation.',
  'Independent Ed25519 verification establishes key possession and integrity of saved signed requests, results, profiles, transport statements and ledger checkpoints.',
  'Saved transport evidence binds the recorded TLS exporter digest. An offline verifier cannot reconstruct a live TLS exporter or independently observe the original socket.',
  'Replay refusals are captured authenticated-channel observations; the successful work receipt itself is not a separate signed refusal.',
  'Benchmark comparison covers paired fixed32-byte SHA256 job latency including verification/accounting; it is not bulk bandwidth, a general hardware speed ranking or an ACT hardware benchmark.',
  'Overlay/LAN are operator-supplied route labels. These captures occurred at different times and under different accumulated ledger state; the audit does not attribute differences between captures to route, hardware or optimization causality.',
  'Installed login/boot hooks were recorded; no reboot was executed. Wrapper/CLI hashes are installation-record observations, not byte comparisons against separately supplied wrapper source.',
  'Android ro.boot.veritymode describes dm-verity state; it is not an independently collected SELinux getenforce result.',
  'Public ledger snapshots are copied byte-for-byte into private temporary verification directories; this does not independently attest original handset filesystem modes.',
  'Joint nonmonetary accounting deduplicates matching receipts; payment settlement, mining reward, firmware changes and ACT production admission are not inferred.'
];
const out=path.join(ROOT,'reproduced-independent-verification.json');
fs.writeFileSync(out,JSON.stringify(report,null,2)+'\n',{mode:0o600});
console.log(JSON.stringify({output:path.basename(out),status:report.status,acceptance:report.acceptance.map(x=>({environment:x.environment,tests:x.counts.tests,pass:x.counts.pass})),directDirections:report.directExchanges.length,uniqueWork:proofWork.size,matchedLedgerReceipts:report.reconciliation.matchedReceipts,unmatchedLedgerRecords:report.reconciliation.unmatchedRecords.length,uniqueSignedEnvelopes:uniqueSignatures.size,timestampDeltaRangeMs:[report.timestampPolicy.minimumSignedDeltaMs,report.timestampPolicy.maximumSignedDeltaMs],benchmarks:report.benchmarks.map(x=>({direction:x.direction,freshMedianMs:x.freshTlsEachJob.medianMs,persistentMedianMs:x.persistentTls.medianMs,ratio:x.freshOverPersistentMedianRatio}))},null,2));
