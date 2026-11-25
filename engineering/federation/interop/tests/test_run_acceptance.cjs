'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const acceptance = require('../run-acceptance.cjs');

function tap({ pass = 1, fail = 0, cancelled = 0, skipped = 0, todo = 0 } = {}) {
  return `TAP version 13\n${fail || cancelled ? 'not ok' : 'ok'} 1 - actual fixture\n1..1\n# tests 1\n# suites 0\n# pass ${pass}\n# fail ${fail}\n# cancelled ${cancelled}\n# skipped ${skipped}\n# todo ${todo}\n# duration_ms 1.2\n`;
}
function reasons(text, overrides = {}) {
  return acceptance.acceptanceReasons({ parsed: acceptance.parseTap(text),
    processResult: { exitCode: 0, signal: null, reason: null },
    comparison: { outcome: 'MATCH' }, sourceStable: true, ...overrides });
}

test('acceptance requires a completed TAP plan and every actual counter rather than a success substring', () => {
  assert.deepEqual(reasons(tap()), []);
  for (const damaged of [
    'PASS 100 tests',
    tap().replace('# skipped 0\n', ''),
    tap() + '# tests 1\n',
    tap().replace('1..1', '1..2'),
    tap().replace('ok 1', 'ok 2'),
    tap().replace('TAP version 13\n', ''),
    tap() + 'Bail out! incomplete\n'
  ]) assert.ok(reasons(damaged).includes('test_results_incomplete_or_invalid'));
});

test('failed, cancelled, skipped and todo tests cannot produce acceptance even on process exit zero', () => {
  for (const [field, reason] of [['fail', 'tests_failed'], ['cancelled', 'tests_cancelled'], ['skipped', 'tests_skipped'], ['todo', 'tests_todo']]) {
    assert.ok(reasons(tap({ pass: 0, [field]: 1 })).includes(reason));
  }
  assert.ok(reasons(tap().replace('ok 1', 'not ok 1')).includes('test_results_incomplete_or_invalid'));
  assert.ok(reasons(tap(), { processResult: { exitCode: 1, signal: null, reason: null } }).includes('test_process_failed'));
});

test('a green TAP transcript cannot override changed source, unknown runtime or forced termination', () => {
  assert.ok(reasons(tap(), { sourceStable: false }).includes('test_source_changed_or_unverified'));
  assert.ok(reasons(tap(), { comparison: { outcome: 'UNKNOWN' } }).includes('portable_runtime_profile_not_matched'));
  assert.ok(reasons(tap(), { processResult: { exitCode: null, signal: 'SIGKILL', reason: 'test_process_timeout' } }).includes('test_process_timeout'));
});

test('evidence output must be a new private directory and an existing directory or symlink is refused', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'interop-acceptance-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const output = path.join(root, 'new-evidence');
  assert.equal(acceptance.createOutputDirectory(output), output);
  assert.equal(fs.statSync(output).mode & 0o077, 0);
  assert.throws(() => acceptance.createOutputDirectory(output));
  assert.throws(() => acceptance.createOutputDirectory('relative-output'));
  if (process.platform !== 'win32') {
    const link = path.join(root, 'link'); fs.symlinkSync(output, link);
    assert.throws(() => acceptance.createOutputDirectory(link));
  }
});

test('source inventory binds runtime tests and fixtures plus fixed live dependencies and excludes documentation', () => {
  const inventory = acceptance.sourceInventory();
  const paths = inventory.files.map(f => f.path);
  for (const required of [
    'engineering/federation/interop/runtime-profile.cjs',
    'engineering/federation/interop/native-reference.py',
    'engineering/federation/interop/fixtures/canonical-vectors.json',
    'engineering/federation/interop/profiles/portable-node22.json',
    'engineering/federation/live/federation-node.cjs',
    'engineering/federation/live/security-tollbooth.cjs',
    'engineering/federation/live/act-backend-compat.cjs'
  ]) assert.ok(paths.includes(required), required);
  assert.equal(paths.some(p => p.endsWith('.md') || /\/(?:reports|evidence|docs)\//.test(p)), false);
  assert.match(inventory.sourceSetSha256, /^[a-f0-9]{64}$/);
  const files = acceptance.testFilesFromInventory(inventory);
  assert.ok(files.every(p => /^engineering\/federation\/interop\/tests\/[^/]+\.cjs$/.test(p)));
});
