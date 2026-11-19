'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const ledger = require('../ledger-receipts.cjs');
const session = require('../session-adapter.cjs');
const mac = require('../capability-macaroons.cjs');
const fed = require('../../live/federation-node.cjs');
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mikaya-receipt-ledger-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const holder = crypto.generateKeyPairSync('ed25519'), worker = crypto.generateKeyPairSync('ed25519');
  const nowMs = Date.now(), holderFp = fed.fp(holder.publicKey), workerFp = fed.fp(worker.publicKey);
  const profile = { schema: 'mikaya.interop.synthetic-profile.v1', synthetic: true, platform: 'node' };
  const profileSha256 = session.profileDigest(profile), rootKey = crypto.randomBytes(32), stateDir = path.join(dir, 'capability-state');
  mac.initializeReplayState(stateDir);
  const policy = { schema: 'mikaya.interop.distribution-policy.v1', policyId: 'explicit-test-accounting', unit: ledger.UNIT,
    rates: [{ capability: 'compute.dot.v1', creditUnits: 7 }, { capability: 'compute.sha256.v1', creditUnits: 3 }],
    beneficiaries: [{ fingerprint: holderFp, basisPoints: 3333 }, { fingerprint: workerFp, basisPoints: 6667 }] };
  function receipt(capability = 'compute.dot.v1', time = nowMs) {
    const job = { schema: 'mikaya.federation.job.v1', id: crypto.randomBytes(16).toString('hex'), capability, payload: capability === 'compute.dot.v1' ? { a: [1, 2, 3], b: [4, 5, 6] } : { challengeHex: 'a5'.repeat(32) } };
    const request = session.makeRequest({ holderPrivateKey: holder.privateKey, workerPublicKey: worker.publicKey, job, nowMs: time });
    const token = mac.mintTestCapability({ rootKey, holderKeySha256: holderFp, audience: workerFp, profileSha256, operation: capability, bodySha256: request.auth.bodySha256, issuedAtMs: time, expiresAtMs: time + 60000, maxUses: 1, maxBytes: 8192 });
    const { response, evidence } = session.acceptConformanceRequest({ request, token, rootKey, holderPublicKey: holder.publicKey, workerPrivateKey: worker.privateKey, profile, stateDir, policy: session.conformancePolicy(), nowMs: time });
    return { request, response, evidence };
  }
  const ledgerDir = path.join(dir, 'holder-ledger');
  const genesis = ledger.initializeReceiptLedger({ ledgerDir, nodePrivateKey: holder.privateKey, policy, nowMs: nowMs - 1 });
  const args = { ledgerDir, nodePrivateKey: holder.privateKey, policy, holderPublicKey: holder.publicKey, workerPublicKey: worker.publicKey, profileSha256, nowMs };
  return { dir, holder, worker, holderFp, workerFp, profileSha256, policy, nowMs, ledgerDir, genesis, receipt, args };
}
function copy(value) { return JSON.parse(JSON.stringify(value)); }
function rewrite(file, mutate) { const row = JSON.parse(fs.readFileSync(file, 'utf8')); mutate(row); fs.writeFileSync(file, fed.canonical(row) + '\n'); }
test('both participants retain separate signed ledgers with identical accounting for verified work', t => {
  const f = fixture(t), receipt = f.receipt();
  const a = ledger.appendReceipt({ ...f.args, receipt });
  const other = path.join(f.dir, 'worker-ledger');
  ledger.initializeReceiptLedger({ ledgerDir: other, nodePrivateKey: f.worker.privateKey, policy: f.policy, nowMs: f.nowMs - 1 });
  const b = ledger.appendReceipt({ ...f.args, ledgerDir: other, nodePrivateKey: f.worker.privateKey, receipt });
  assert.deepEqual(a.accounting, b.accounting); assert.notEqual(a.entryHash, b.entryHash);
  assert.notEqual(a.checkpoint.ledgerId, b.checkpoint.ledgerId);
  for (const [dir, key, result] of [[f.ledgerDir, f.holder.publicKey, a], [other, f.worker.publicKey, b]]) {
    const verified = ledger.verifyReceiptLedger({ ledgerDir: dir, nodePublicKey: key, expectedCheckpoint: result.checkpoint });
    assert.equal(verified.entries, 2); assert.equal(verified.receipts, 1); assert.equal(verified.rollbackAnchored, true);
    assert.equal(verified.totals.reduce((n, x) => n + x.units, 0), 7);
    assert.equal(verified.paymentSettled, false); assert.equal(verified.miningReward, false);
    assert.equal(verified.executionAuthorized, false); assert.equal(verified.bitcoinTransaction, false);
    assert.equal(fs.statSync(path.join(dir, '000001.json')).mode & 0o077, 0);
  }
  assert.deepEqual(a.eventSpineDigest, { kind: 'FEDERATION_COMPUTE_OBSERVED', payloadSha256: a.entryHash });
});
test('altered computation or profile evidence is refused without adding an entry', t => {
  const f = fixture(t), good = f.receipt();
  for (const mutate of [r => { r.response.body.result = 999; }, r => { r.request.body.payload.a[0] = 99; }, r => { r.evidence.profileSha256 = 'f'.repeat(64); }, r => { r.evidence.signature = 'A'.repeat(86) + '=='; }]) {
    const receipt = copy(good); mutate(receipt);
    assert.throws(() => ledger.appendReceipt({ ...f.args, receipt }));
    assert.equal(ledger.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey }).entries, 1);
  }
  assert.throws(() => ledger.appendReceipt({ ...f.args, receipt: { ...good, paymentSettled: true } }), /fields/);
});
test('replay is refused after a fresh module load and cannot double accounting', t => {
  const f = fixture(t), receipt = f.receipt(); ledger.appendReceipt({ ...f.args, receipt });
  delete require.cache[require.resolve('../ledger-receipts.cjs')];
  const fresh = require('../ledger-receipts.cjs');
  assert.throws(() => fresh.appendReceipt({ ...f.args, receipt }), /replay/);
  const result = fresh.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey });
  assert.equal(result.receipts, 1); assert.equal(result.totals.reduce((n, x) => n + x.units, 0), 7);
});
test('different accepted jobs accumulate exact integer totals without monetary claims', t => {
  const f = fixture(t); ledger.appendReceipt({ ...f.args, receipt: f.receipt() });
  ledger.appendReceipt({ ...f.args, receipt: f.receipt('compute.sha256.v1', f.nowMs + 1), nowMs: f.nowMs + 1 });
  const result = ledger.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey, expectedCheckpoint: f.genesis.checkpoint });
  assert.equal(result.receipts, 2); assert.equal(result.totals.reduce((n, x) => n + x.units, 0), 10); assert.equal(result.unit, 'NONMONETARY_COMPUTE_UNIT');
});
test('cross-node reconciliation counts matching work once and excludes unmatched local records', t => {
  const f = fixture(t), first = f.receipt(), other = path.join(f.dir, 'worker-ledger');
  ledger.initializeReceiptLedger({ ledgerDir: other, nodePrivateKey: f.worker.privateKey, policy: f.policy, nowMs: f.nowMs - 1 });
  const a = ledger.appendReceipt({ ...f.args, receipt: first });
  const b = ledger.appendReceipt({ ...f.args, ledgerDir: other, nodePrivateKey: f.worker.privateKey, receipt: first });
  ledger.appendReceipt({ ...f.args, receipt: f.receipt('compute.sha256.v1', f.nowMs + 1), nowMs: f.nowMs + 1 });
  const result = ledger.reconcileReceiptLedgers({ ledgers: [
    { ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey, expectedCheckpoint: a.checkpoint },
    { ledgerDir: other, nodePublicKey: f.worker.publicKey, expectedCheckpoint: b.checkpoint }
  ] });
  assert.equal(result.matchedReceipts, 1); assert.equal(result.unmatchedRecords.length, 1); assert.equal(result.allReceiptsAgreed, false);
  assert.equal(result.allocations.reduce((n, x) => n + x.units, 0), 7);
  assert.equal(result.paymentSettled, false); assert.equal(result.executionAuthorized, false);
  assert.throws(() => ledger.reconcileReceiptLedgers({ ledgers: [{ ledgerDir: other, nodePublicKey: f.worker.publicKey }, { ledgerDir: other, nodePublicKey: f.worker.publicKey }] }), /independent/);
});
test('reconciliation rejects differing validly signed results for the same request', t => {
  const f = fixture(t), receipt = f.receipt(), other = path.join(f.dir, 'worker-ledger');
  ledger.initializeReceiptLedger({ ledgerDir: other, nodePrivateKey: f.worker.privateKey, policy: f.policy, nowMs: f.nowMs - 1 });
  ledger.appendReceipt({ ...f.args, receipt });
  const changed = copy(receipt); changed.response.auth.issuedAtMs++;
  const sign = (kind, value, prefix) => {
    const { signature, ...body } = value;
    return { ...body, signature: crypto.sign(null, Buffer.from(prefix + kind + '\n' + fed.canonical(body)), f.worker.privateKey).toString('base64') };
  };
  changed.response.auth = sign('RES', changed.response.auth, 'MIKAYA-INDEPENDENT-FEDERATION/1\n');
  changed.evidence.issuedAtMs++;
  changed.evidence.responseSha256 = fed.sha(fed.canonical(changed.response));
  changed.evidence = sign('EVIDENCE', changed.evidence, 'MIKAYA-INTEROP-CONFORMANCE/1\n');
  ledger.appendReceipt({ ...f.args, ledgerDir: other, nodePrivateKey: f.worker.privateKey, receipt: changed });
  assert.throws(() => ledger.reconcileReceiptLedgers({ ledgers: [
    { ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey }, { ledgerDir: other, nodePublicKey: f.worker.publicKey }
  ] }), /conflicting/);
});
test('distribution uses deterministic remainder allocation and conserves every unit', t => {
  const f = fixture(t), policy = copy(f.policy); policy.rates[0].creditUnits = 1;
  policy.beneficiaries.forEach(x => { x.basisPoints = 5000; });
  const args = { policy, capability: 'compute.dot.v1', holderFingerprint: f.holderFp, workerFingerprint: f.workerFp };
  const a = ledger.accountReceipt(args), b = ledger.accountReceipt({ ...args, policy: { ...policy, beneficiaries: [...policy.beneficiaries].reverse() } });
  assert.deepEqual(a.allocations, b.allocations);
  assert.equal(a.allocations[0].units, 1); assert.equal(a.allocations[1].units, 0);
  policy.rates[0].creditUnits = 1000000000;
  assert.equal(ledger.accountReceipt(args).allocations.reduce((n, x) => n + x.units, 0), 1000000000);
});
test('policy rejects monetary labels, unknown fields, duplicate beneficiaries and invalid shares', t => {
  const f = fixture(t);
  for (const mutate of [p => { p.unit = 'BTC-LN-msat'; }, p => { p.settlementVerified = true; }, p => { p.beneficiaries[1].fingerprint = p.beneficiaries[0].fingerprint; }, p => { p.beneficiaries[0].basisPoints = 5000; }, p => { p.rates[0].creditUnits = 1.5; }, p => { p.rates.push(p.rates[0]); }, p => { p.rates[0].capability = 'wallet.pay'; }]) {
    const policy = copy(f.policy); mutate(policy); assert.throws(() => ledger.validateDistributionPolicy(policy));
  }
});
test('signed genesis binds immutable policy and excludes unauthorized participants', t => {
  const f = fixture(t), receipt = f.receipt(), policy = copy(f.policy); policy.rates[0].creditUnits++;
  assert.throws(() => ledger.appendReceipt({ ...f.args, receipt, policy }), /policy changed/);
  const other = crypto.generateKeyPairSync('ed25519');
  assert.throws(() => ledger.appendReceipt({ ...f.args, receipt, nodePrivateKey: other.privateKey }), /owner must participate/);
  const excluded = copy(f.policy); excluded.beneficiaries[1].fingerprint = fed.fp(other.publicKey);
  assert.throws(() => ledger.appendReceipt({ ...f.args, receipt, policy: excluded }), /participants excluded/);
});
test('retained signed checkpoint detects deletion of the latest receipt', t => {
  const f = fixture(t), result = ledger.appendReceipt({ ...f.args, receipt: f.receipt() });
  fs.unlinkSync(path.join(f.ledgerDir, '000001.json'));
  // A syntactically intact prefix alone cannot prove that no tail was removed.
  assert.equal(ledger.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey }).rollbackAnchored, false);
  assert.throws(() => ledger.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey, expectedCheckpoint: result.checkpoint }), /rollback|checkpoint/);
});
test('checkpoint corruption and wrong ledger identity fail closed', t => {
  const f = fixture(t), result = ledger.appendReceipt({ ...f.args, receipt: f.receipt() });
  const changed = { ...result.checkpoint, latestHash: '0'.repeat(64) };
  assert.throws(() => ledger.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey, expectedCheckpoint: changed }), /signature/);
  assert.throws(() => ledger.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.worker.publicKey }), /identity/);
});
test('public checkpoint verifier validates signature without asserting access to remote history', t => {
  const f = fixture(t), { checkpoint } = ledger.appendReceipt({ ...f.args, receipt: f.receipt() });
  const verified = ledger.verifyReceiptCheckpoint({ checkpoint, nodePublicKey: f.holder.publicKey });
  assert.equal(verified.verified, true); assert.equal(verified.entries, 2);
  assert.equal(verified.localLedgerConsistencyVerified, false); assert.equal(verified.paymentSettled, false);
  assert.throws(() => ledger.verifyReceiptCheckpoint({ checkpoint, nodePublicKey: f.worker.publicKey }), /owner/);
  for (const mutate of [c => { c.entries = 0; }, c => { c.entries = 1025; }, c => { c.issuedAtMs = -1; }, c => { c.latestHash = ['a'.repeat(64)]; }, c => { c.policySha256 = 'x'; }, c => { c.paymentSettled = true; }]) {
    const changed = copy(checkpoint); mutate(changed);
    assert.throws(() => ledger.verifyReceiptCheckpoint({ checkpoint: changed, nodePublicKey: f.holder.publicKey }));
  }
});
test('altered chain entries cannot be repaired by rehashing without the owner signature', t => {
  const f = fixture(t); ledger.appendReceipt({ ...f.args, receipt: f.receipt() });
  rewrite(path.join(f.ledgerDir, '000001.json'), row => {
    row.payload.accounting.allocations[0].units++;
    const { signature, entryHash, ...body } = row;
    row.entryHash = fed.sha('MIKAYA-INTEROP-RECEIPT-LEDGER/1\nHASH\n' + fed.canonical(body));
  });
  assert.throws(() => ledger.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey }), /signature/);
  assert.throws(() => ledger.appendReceipt({ ...f.args, receipt: f.receipt('compute.sha256.v1') }), /signature/);
});
test('sequence gaps and noncanonical persisted JSON are rejected', t => {
  const f = fixture(t); ledger.appendReceipt({ ...f.args, receipt: f.receipt() });
  const file = path.join(f.ledgerDir, '000001.json');
  fs.renameSync(file, path.join(f.ledgerDir, '000002.json'));
  assert.throws(() => ledger.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey }), /sequence/);
  fs.renameSync(path.join(f.ledgerDir, '000002.json'), file);
  fs.writeFileSync(file, JSON.stringify(JSON.parse(fs.readFileSync(file)), null, 2) + '\n');
  assert.throws(() => ledger.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey }), /noncanonical/);
});
test('missing ledger, unsafe permissions, symlink and outstanding lock do not initialize implicitly', t => {
  const f = fixture(t), receipt = f.receipt();
  assert.throws(() => ledger.appendReceipt({ ...f.args, ledgerDir: path.join(f.dir, 'missing'), receipt }), /ENOENT/);
  fs.chmodSync(f.ledgerDir, 0o755);
  assert.throws(() => ledger.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey }), /private/);
  fs.chmodSync(f.ledgerDir, 0o700);
  const link = path.join(f.dir, 'link'); fs.symlinkSync(f.ledgerDir, link);
  assert.throws(() => ledger.verifyReceiptLedger({ ledgerDir: link, nodePublicKey: f.holder.publicKey }), /private/);
  fs.writeFileSync(path.join(f.ledgerDir, '.append.lock'), '', { mode: 0o600 });
  assert.throws(() => ledger.appendReceipt({ ...f.args, receipt }), /EEXIST/);
  assert.throws(() => ledger.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey }), /lock/);
});
test('expired work cannot be appended now and ledger record time cannot roll back', t => {
  const f = fixture(t), receipt = f.receipt();
  assert.throws(() => ledger.appendReceipt({ ...f.args, receipt, nowMs: f.nowMs + 60001 }), /expired/);
  ledger.appendReceipt({ ...f.args, receipt, nowMs: f.nowMs + 1 });
  assert.throws(() => ledger.appendReceipt({ ...f.args, receipt: f.receipt('compute.sha256.v1'), nowMs: f.nowMs }), /clock rollback/);
});
test('two actual processes cannot append the same receipt twice', async t => {
  const f = fixture(t), receipt = f.receipt();
  const input = path.join(f.dir, 'process-input.json');
  fs.writeFileSync(input, JSON.stringify({ ...f.args, receipt, nodePrivateKey: f.holder.privateKey.export({ type: 'pkcs8', format: 'pem' }), holderPublicKey: f.holder.publicKey.export({ type: 'spki', format: 'pem' }), workerPublicKey: f.worker.publicKey.export({ type: 'spki', format: 'pem' }) }), { mode: 0o600 });
  const program = "const fs=require('node:fs');try{require(process.argv[1]).appendReceipt(JSON.parse(fs.readFileSync(process.argv[2],'utf8')));process.stdout.write('RECORDED');}catch(e){process.stderr.write(e.message);process.exitCode=2;}";
  const run = () => new Promise(resolve => {
    const child = spawn(process.execPath, ['-e', program, require.resolve('../ledger-receipts.cjs'), input], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = ''; child.stdout.on('data', x => { out += x; }); child.stderr.on('data', x => { err += x; });
    child.on('error', e => resolve({ code: -1, err: e.message })); child.on('close', code => resolve({ code, out, err }));
  });
  const results = await Promise.all([run(), run()]);
  assert.equal(results.filter(x => x.code === 0 && x.out === 'RECORDED').length, 1);
  assert.equal(results.filter(x => x.code === 2 && /EEXIST|replay/.test(x.err)).length, 1);
  assert.equal(ledger.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey }).receipts, 1);
});
test('initialization and append work when Android denies every hard-link operation', t => {
  const originalLink = fs.linkSync; let calls = 0;
  fs.linkSync = () => { calls++; throw Object.assign(new Error('Android app hard links denied'), { code: 'EACCES' }); };
  try {
    const f = fixture(t), record = ledger.appendReceipt({ ...f.args, receipt: f.receipt() });
    assert.equal(ledger.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey, expectedCheckpoint: record.checkpoint }).receipts, 1);
    assert.equal(calls, 0);
  } finally { fs.linkSync = originalLink; }
});
test('partial final-path write remains present, unaccepted and impossible to overwrite on retry', t => {
  const f = fixture(t), receipt = f.receipt(), target = path.join(f.ledgerDir, '000001.json');
  const originalOpen = fs.openSync, originalWrite = fs.writeFileSync; let targetFd = null;
  fs.openSync = (...args) => { const fd = originalOpen(...args); if (args[0] === target && (args[1] & fs.constants.O_CREAT)) targetFd = fd; return fd; };
  fs.writeFileSync = (fd, data, ...rest) => {
    if (fd === targetFd) {
      originalWrite(fd, Buffer.from(data).subarray(0, 37));
      throw Object.assign(new Error('injected partial receipt write'), { code: 'EIO' });
    }
    return originalWrite(fd, data, ...rest);
  };
  try { assert.throws(() => ledger.appendReceipt({ ...f.args, receipt }), /injected partial/); }
  finally { fs.openSync = originalOpen; fs.writeFileSync = originalWrite; }
  const before = fs.readFileSync(target);
  assert.equal(before.length, 37); assert.equal(fs.existsSync(path.join(f.ledgerDir, '.append.lock')), true);
  assert.throws(() => ledger.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey }), /lock/);
  assert.throws(() => ledger.appendReceipt({ ...f.args, receipt }), /EEXIST/);
  assert.deepEqual(fs.readFileSync(target), before);
  // Even explicit removal of the lock cannot make incomplete JSON valid or
  // permit a fresh append over the preserved record.
  fs.unlinkSync(path.join(f.ledgerDir, '.append.lock'));
  assert.throws(() => ledger.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey }));
  assert.throws(() => ledger.appendReceipt({ ...f.args, receipt }));
  assert.deepEqual(fs.readFileSync(target), before);
});
test('entry fsync failure retains a lock even when its complete signed bytes are visible', t => {
  const f = fixture(t), receipt = f.receipt(), target = path.join(f.ledgerDir, '000001.json');
  const originalOpen = fs.openSync, originalSync = fs.fsyncSync; let targetFd = null;
  fs.openSync = (...args) => { const fd = originalOpen(...args); if (args[0] === target && (args[1] & fs.constants.O_CREAT)) targetFd = fd; return fd; };
  fs.fsyncSync = fd => {
    if (fd === targetFd) throw Object.assign(new Error('injected receipt fsync failure'), { code: 'EIO' });
    return originalSync(fd);
  };
  try { assert.throws(() => ledger.appendReceipt({ ...f.args, receipt }), /injected receipt fsync/); }
  finally { fs.openSync = originalOpen; fs.fsyncSync = originalSync; }
  const before = fs.readFileSync(target); assert.equal(JSON.parse(before).kind, 'VERIFIED_COMPUTE_RECEIPT');
  assert.equal(fs.existsSync(path.join(f.ledgerDir, '.append.lock')), true);
  assert.throws(() => ledger.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey }), /lock/);
  assert.throws(() => ledger.appendReceipt({ ...f.args, receipt }), /EEXIST/);
  assert.deepEqual(fs.readFileSync(target), before);
});
test('an unexpected final-path file is never overwritten during exclusive append', t => {
  const f = fixture(t), receipt = f.receipt(), target = path.join(f.ledgerDir, '000001.json');
  const originalOpen = fs.openSync; let injected = false;
  const sentinel = Buffer.from('OWNER_REVIEW_REQUIRED\n');
  fs.openSync = (...args) => {
    if (!injected && args[0] === target && (args[1] & fs.constants.O_CREAT)) {
      injected = true;
      const fd = originalOpen(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      try { fs.writeFileSync(fd, sentinel); } finally { fs.closeSync(fd); }
    }
    return originalOpen(...args);
  };
  try { assert.throws(() => ledger.appendReceipt({ ...f.args, receipt }), /EEXIST/); }
  finally { fs.openSync = originalOpen; }
  assert.equal(injected, true); assert.deepEqual(fs.readFileSync(target), sentinel);
  assert.equal(fs.existsSync(path.join(f.ledgerDir, '.append.lock')), true);
  assert.throws(() => ledger.verifyReceiptLedger({ ledgerDir: f.ledgerDir, nodePublicKey: f.holder.publicKey }), /lock/);
  assert.throws(() => ledger.appendReceipt({ ...f.args, receipt }), /EEXIST/);
  assert.deepEqual(fs.readFileSync(target), sentinel);
});
