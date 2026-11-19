'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {createJournal, validateIntent, sha} = require('../transaction-journal.cjs');
const modulePath = require.resolve('../transaction-journal.cjs');
const A = 'a'.repeat(64), B = 'b'.repeat(64);

function fixture(t) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'mikaya-journal-test-'));
  const directory = path.join(parent, 'journal');
  t.after(() => fs.rmSync(parent, {recursive: true, force: true}));
  return {parent, directory};
}
function intent(id = 'transaction-1', change = {}) {
  return {schema: 'mikaya.act.transaction-intent.v1', transactionId: id, sender: A, recipient: B,
    operation: 'evidence.ingest.v1', resource: 'evidence:fixture', payloadSha256: sha('fixture'),
    policyVersion: 'policy-1', expiresAtMs: 50000, ...change};
}
function acceptance(value = intent(), change = {}) {
  return {intent: value, grantId: 'root-grant-1', usageLimit: 2, expiresAtMs: 40000, nowMs: 1000, ...change};
}
function key(value = intent()) { return {sender: value.sender, operation: value.operation, transactionId: value.transactionId}; }

test('initialization is explicit and missing existing state is never reconstructed', t => {
  const {directory} = fixture(t);
  assert.throws(() => createJournal({directory}), /ENOENT/);
  const journal = createJournal({directory, initialize: true}); journal.close();
  assert.throws(() => createJournal({directory, initialize: true}), /STATE_INITIALIZATION_REFUSED/);
  fs.unlinkSync(path.join(directory, 'state.json'));
  assert.throws(() => createJournal({directory}), /ENOENT/);
  assert.equal(fs.existsSync(path.join(directory, 'state.json')), false);
});

test('durable acceptance, result and identical retry survive reopening without a second use', t => {
  const {directory} = fixture(t);
  let journal = createJournal({directory, initialize: true});
  const first = journal.accept(acceptance(intent(), {usageLimit: 1}));
  assert.equal(first.duplicate, false);
  assert.equal(journal.accept(acceptance(intent(), {usageLimit: 1, nowMs: 1001})).duplicate, true);
  const completed = journal.complete({...key(), result: {accepted: true}, nowMs: 1002});
  journal.close();
  journal = createJournal({directory});
  assert.deepEqual(journal.get(key()), completed.receipt);
  const retry = journal.accept(acceptance(intent(), {usageLimit: 1, nowMs: 1003}));
  assert.equal(retry.duplicate, true);
  assert.deepEqual(retry.receipt, completed.receipt);
  assert.throws(() => journal.accept(acceptance(intent('transaction-2'), {usageLimit: 1, nowMs: 1004})), /GRANT_EXHAUSTED/);
  journal.close();
});

test('same id with a different immutable intent conflicts while sender namespaces remain distinct', t => {
  const {directory} = fixture(t), journal = createJournal({directory, initialize: true});
  journal.accept(acceptance());
  assert.throws(() => journal.accept(acceptance(intent('transaction-1', {payloadSha256: sha('changed')}))), /TRANSACTION_CONFLICT/);
  const second = journal.accept(acceptance(intent('transaction-1', {sender: B, recipient: A}), {grantId: 'other-root'}));
  assert.equal(second.duplicate, false);
  journal.close();
});

test('fresh authentication metadata cannot accidentally become transaction intent', () => {
  const digest = validateIntent(intent());
  assert.equal(validateIntent(JSON.parse(JSON.stringify(intent()))), digest);
  for (const field of ['nonce', 'issuedAtMs', 'sessionId', 'signature']) {
    assert.throws(() => validateIntent({...intent(), [field]: 'new-attempt'}), /INTENT_INVALID/);
  }
});

test('attenuated descendants consume the same root budget and cannot reopen exhausted grants', t => {
  const {directory} = fixture(t), journal = createJournal({directory, initialize: true});
  journal.accept(acceptance(intent('one'), {effectiveUsageLimit: 1}));
  assert.throws(() => journal.accept(acceptance(intent('two'), {effectiveUsageLimit: 1})), /GRANT_EXHAUSTED/);
  journal.accept(acceptance(intent('two'), {effectiveUsageLimit: 2}));
  assert.throws(() => journal.accept(acceptance(intent('three'))), /GRANT_EXHAUSTED/);
  assert.equal(journal.accept(acceptance(intent('one'), {effectiveUsageLimit: 1})).duplicate, true);
  const stored = JSON.parse(fs.readFileSync(path.join(directory, 'state.json')));
  assert.equal(stored.payload.quotas[0].used, 2);
  assert.equal(stored.payload.transactions.length, 2);
  journal.close();
});

test('root budget changes and invalid descendant budgets are rejected', t => {
  const {directory} = fixture(t), journal = createJournal({directory, initialize: true});
  journal.accept(acceptance());
  assert.throws(() => journal.accept(acceptance(intent('two'), {usageLimit: 3})), /GRANT_BUDGET_CHANGED/);
  assert.throws(() => journal.accept(acceptance(intent('two'), {effectiveUsageLimit: 3})), /GRANT_OR_INTENT_INVALID/);
  assert.equal(journal.get(key(intent('two'))), null);
  journal.close();
});

test('expiry and clock rollback fail before another durable acceptance', t => {
  const {directory} = fixture(t), journal = createJournal({directory, initialize: true});
  journal.accept(acceptance());
  assert.throws(() => journal.accept(acceptance(intent('two'), {nowMs: 999})), /CLOCK_ROLLBACK_HOLD/);
  assert.throws(() => journal.accept(acceptance(intent('two'), {expiresAtMs: 1000})), /GRANT_OR_INTENT_INVALID/);
  assert.throws(() => journal.accept(acceptance(intent('two', {expiresAtMs: 1000}))), /GRANT_OR_INTENT_INVALID/);
  assert.equal(journal.get(key(intent('two'))), null);
  journal.close();
});

test('a concurrent process cannot acquire the current writer lease', t => {
  const {directory} = fixture(t), journal = createJournal({directory, initialize: true});
  const run = spawnSync(process.execPath, ['-e',
    'try { require(process.argv[1]).createJournal({directory:process.argv[2]}); process.exit(1); } catch(e) { process.stdout.write(e.code || e.message); }',
    modulePath, directory], {encoding: 'utf8', timeout: 3000});
  assert.equal(run.status, 0);
  assert.match(run.stdout, /WRITER_LEASE_HOLD/);
  assert.equal(journal.get(key()), null);
  journal.close();
});

test('process exit without close leaves an uncertain writer lease and preserves accepted state', t => {
  const {directory} = fixture(t);
  const run = spawnSync(process.execPath, ['-e',
    'const j=require(process.argv[1]).createJournal({directory:process.argv[2],initialize:true}); j.accept(JSON.parse(process.argv[3]));',
    modulePath, directory, JSON.stringify(acceptance())], {encoding: 'utf8', timeout: 3000});
  assert.equal(run.status, 0, run.stderr);
  const before = fs.readFileSync(path.join(directory, 'state.json'));
  assert.throws(() => createJournal({directory}), /WRITER_LEASE_HOLD/);
  assert.deepEqual(fs.readFileSync(path.join(directory, 'state.json')), before);
  assert.equal(JSON.parse(before).payload.transactions.length, 1);
});

test('changed state bytes are detected before reading receipts or accepting new work', t => {
  const {directory} = fixture(t), journal = createJournal({directory, initialize: true});
  journal.accept(acceptance());
  const file = path.join(directory, 'state.json');
  const state = JSON.parse(fs.readFileSync(file)); state.payload.quotas[0].limit = 8;
  fs.writeFileSync(file, JSON.stringify(state));
  assert.throws(() => journal.get(key()), /STATE_INTEGRITY_HOLD/);
  assert.throws(() => journal.accept(acceptance(intent('two'))), /STATE_INTEGRITY_HOLD/);
  journal.close();
});

test('symlink, hard-link and world-readable state files fail closed', t => {
  for (const mode of ['symlink', 'hardlink', 'permissions']) {
    const {directory, parent} = fixture(t), journal = createJournal({directory, initialize: true});
    const file = path.join(directory, 'state.json'), target = path.join(parent, 'preserved.json');
    if (mode === 'symlink') { fs.renameSync(file, target); fs.symlinkSync(target, file); }
    else if (mode === 'hardlink') {
      const original = fs.readFileSync(file);
      try {
        fs.linkSync(file, target);
      } catch (error) {
        if (process.platform !== 'android' || !['EACCES', 'EPERM'].includes(error.code)) throw error;
        assert.throws(() => fs.lstatSync(target), {code: 'ENOENT'});
        assert.deepEqual(fs.readFileSync(file), original);
        assert.equal(fs.lstatSync(file).nlink, 1);
        assert.doesNotThrow(() => journal.get(key()));
        t.diagnostic(`Native Android kernel blocked hard-link fixture creation (${error.code}); destination absent and source unchanged. Runtime hard-link rejection is exercised when fixture creation is permitted.`);
        journal.close();
        continue;
      }
    }
    else fs.chmodSync(file, 0o644);
    assert.throws(() => journal.get(key()), /STATE_FILE_UNSAFE/);
    journal.close();
  }
});

test('FIFO state is refused without blocking', {timeout: 3000}, t => {
  const {directory} = fixture(t), journal = createJournal({directory, initialize: true});
  const file = path.join(directory, 'state.json'); fs.unlinkSync(file);
  const made = spawnSync('mkfifo', ['-m', '600', file], {encoding: 'utf8', timeout: 1000});
  assert.equal(made.status, 0, made.stderr);
  assert.throws(() => journal.get(key()), /STATE_FILE_UNSAFE/);
  journal.close();
});

test('symlink directory and symlink ancestor are refused', t => {
  const {parent, directory} = fixture(t), actual = path.join(parent, 'actual');
  fs.mkdirSync(actual, {mode: 0o700}); fs.symlinkSync(actual, directory);
  assert.throws(() => createJournal({directory}), /STATE_DIRECTORY_UNSAFE/);
  assert.throws(() => createJournal({directory: path.join(directory, 'child'), initialize: true}), /STATE_PARENT_UNSAFE/);
});

test('replaced writer lease is preserved instead of deleted by the original owner', t => {
  const {directory} = fixture(t), journal = createJournal({directory, initialize: true});
  const lock = path.join(directory, 'writer.lock'); fs.writeFileSync(lock, 'replacement');
  assert.throws(() => journal.close(), /WRITER_LEASE_CHANGED_HOLD/);
  assert.equal(fs.readFileSync(lock, 'utf8'), 'replacement');
});

test('failed rename returns uncertain HOLD, preserves evidence and cannot consume twice', t => {
  const {directory} = fixture(t), journal = createJournal({directory, initialize: true});
  const before = fs.readFileSync(path.join(directory, 'state.json'));
  const original = fs.renameSync;
  fs.renameSync = () => { const error = new Error('simulated I/O failure'); error.code = 'EIO'; throw error; };
  try { assert.throws(() => journal.accept(acceptance()), /DURABILITY_UNCERTAIN_HOLD/); }
  finally { fs.renameSync = original; }
  assert.deepEqual(fs.readFileSync(path.join(directory, 'state.json')), before);
  assert.ok(fs.readdirSync(directory).some(name => name.endsWith('.tmp')));
  assert.throws(() => journal.accept(acceptance()), /DURABILITY_UNCERTAIN_HOLD/);
  assert.throws(() => journal.close(), /DURABILITY_UNCERTAIN_HOLD/);
  assert.throws(() => createJournal({directory}), /WRITER_LEASE_HOLD/);
});

test('failed directory fsync after rename never reports an accepted receipt', t => {
  const {directory} = fixture(t), journal = createJournal({directory, initialize: true});
  const original = fs.fsyncSync; let count = 0;
  fs.fsyncSync = fd => { count++; if (count === 2) throw new Error('simulated durability failure'); return original(fd); };
  try { assert.throws(() => journal.accept(acceptance()), /DURABILITY_UNCERTAIN_HOLD/); }
  finally { fs.fsyncSync = original; }
  const after = JSON.parse(fs.readFileSync(path.join(directory, 'state.json')));
  assert.equal(after.payload.quotas[0].used, 1);
  assert.throws(() => journal.close(), /DURABILITY_UNCERTAIN_HOLD/);
  assert.throws(() => createJournal({directory}), /WRITER_LEASE_HOLD/);
});

test('completed results are digest-bound and uncertain effects cannot be blindly completed', t => {
  const {directory} = fixture(t), journal = createJournal({directory, initialize: true});
  journal.accept(acceptance());
  const completed = journal.complete({...key(), result: {ok: true}, nowMs: 1001});
  assert.equal(journal.complete({...key(), result: {ok: true}, nowMs: 1002}).duplicate, true);
  assert.throws(() => journal.complete({...key(), result: {ok: false}, nowMs: 1002}), /TRANSACTION_STATE_HOLD/);
  journal.accept(acceptance(intent('two'), {nowMs: 1003}));
  const uncertain = journal.markUncertain({...key(intent('two')), reason: 'downstream_outcome_unknown', nowMs: 1004});
  assert.equal(uncertain.receipt.state, 'uncertain');
  assert.throws(() => journal.complete({...key(intent('two')), result: {ok: true}, nowMs: 1005}), /TRANSACTION_STATE_HOLD/);
  completed.receipt.state = 'accepted';
  assert.equal(journal.get(key()).state, 'completed');
  journal.close();
});

test('result contents are not persisted and malformed or oversized results do not change state', t => {
  const {directory} = fixture(t), journal = createJournal({directory, initialize: true});
  journal.accept(acceptance());
  assert.throws(() => journal.complete({...key(), result: 'x'.repeat(8193), nowMs: 1001}), /RESULT_TOO_LARGE/);
  assert.throws(() => journal.complete({...key(), result: {x: Infinity}, nowMs: 1001}), /JSON_VALUE_REFUSED/);
  const secret = 'fixture-value-must-not-be-stored';
  journal.complete({...key(), result: {secret}, nowMs: 1002});
  assert.equal(fs.readFileSync(path.join(directory, 'state.json'), 'utf8').includes(secret), false);
  journal.close();
});
