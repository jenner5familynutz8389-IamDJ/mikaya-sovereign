#!/usr/bin/env node
'use strict';

/** Execute the current isolated interop suite and retain inspectable evidence. */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const runtime = require('./runtime-profile.cjs');
const REPO_ROOT = path.resolve(__dirname, '../../..');
const RELATIVE_ROOT = 'engineering/federation/interop';
const TEST_TIMEOUT_MS = 180000;
const MAX_TEST_OUTPUT_BYTES = 8 * 1024 * 1024;
const MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024;
const DEPENDENCIES = Object.freeze([
  'engineering/federation/live/federation-node.cjs',
  'engineering/federation/live/security-tollbooth.cjs',
  'engineering/federation/live/act-backend-compat.cjs'
]);
const TEST_SCOPE = Object.freeze({
  classification: 'ISOLATED_LOCAL_INTEROPERABILITY_CONFORMANCE',
  identities: 'NEW_SYNTHETIC_TEST_IDENTITIES_ONLY',
  communication: 'LOCAL_SUBPROCESS_PIPES_LOOPBACK_MUTUAL_TLS_AND_OWNER_CARRIED_PACKET_FIXTURES',
  localServiceLifecycleExecuted: true,
  directPhysicalNetworkExchangeIncluded: false,
  actHardwareTested: false,
  actEndpointCalled: false,
  hardwareAttested: false,
  productionAdmission: false,
  paymentsAuthorized: false,
  firmwareOperations: false,
  distributedReplayProtectionProven: false
});
const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');
function ensure(ok, message) { if (!ok) throw new Error(message); }
function jsonBytes(value) { return Buffer.from(JSON.stringify(value, null, 2) + '\n'); }

function createOutputDirectory(output) {
  ensure(typeof output === 'string' && path.isAbsolute(output), 'output must be an absolute new directory');
  const requested = path.resolve(output), parent = fs.realpathSync(path.dirname(requested));
  ensure(fs.statSync(parent).isDirectory(), 'output parent must already exist');
  // Android commonly aliases /data/data to /data/user/0. Resolve the existing
  // parent once, then create the new final component exclusively beneath it.
  const actual = path.join(parent, path.basename(requested));
  fs.mkdirSync(actual, { mode: 0o700 });
  const st = fs.lstatSync(actual);
  ensure(st.isDirectory() && !st.isSymbolicLink() && !(st.mode & 0o077), 'output directory must enforce private permissions');
  if (typeof process.getuid === 'function') ensure(st.uid === process.getuid(), 'output directory owner mismatch');
  return actual;
}

function writeEvidence(output, name, data) {
  ensure(/^[a-z0-9][a-z0-9.-]{0,79}$/.test(name), 'invalid evidence filename');
  const bytes = Buffer.isBuffer(data) ? data : typeof data === 'string' ? Buffer.from(data) : jsonBytes(data);
  const file = path.join(output, name), fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  return { name, bytes: bytes.length, sha256: sha256(bytes) };
}

function boundedSourceRead(file) {
  ensure(!fs.lstatSync(file).isSymbolicLink(), 'source symlink refused');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const st = fs.fstatSync(fd);
    ensure(st.isFile() && st.size <= MAX_SOURCE_FILE_BYTES, 'source file is not a bounded regular file');
    const buffer = Buffer.alloc(MAX_SOURCE_FILE_BYTES + 1);
    let used = 0;
    while (used < buffer.length) {
      const n = fs.readSync(fd, buffer, used, buffer.length - used, null);
      if (!n) break;
      used += n;
    }
    ensure(used <= MAX_SOURCE_FILE_BYTES, 'source file grew beyond size limit');
    return buffer.subarray(0, used);
  } finally { fs.closeSync(fd); }
}

function sourceInventory() {
  const selected = [];
  function add(relative) {
    ensure(selected.length < 512, 'too many source files');
    const raw = boundedSourceRead(path.join(REPO_ROOT, relative));
    selected.push({ path: relative.split(path.sep).join('/'), bytes: raw.length, sha256: sha256(raw) });
  }
  // No generated reports or documentation are included. A README edit does
  // not change the tested source identity; a fixture, profile or test edit does.
  for (const entry of fs.readdirSync(__dirname, { withFileTypes: true })) {
    if (/\.(?:cjs|py)$/.test(entry.name)) add(`${RELATIVE_ROOT}/${entry.name}`);
  }
  const excluded = /^(?:evidence|reports?|results?|artifacts?|outputs?|node_modules|__pycache__|\.git)$/i;
  function walk(relative, group) {
    const directory = path.join(REPO_ROOT, relative), st = fs.lstatSync(directory);
    ensure(st.isDirectory() && !st.isSymbolicLink(), 'source directory symlink refused');
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.name.startsWith('.') || excluded.test(entry.name)) continue;
      const next = `${relative}/${entry.name}`;
      if (entry.isSymbolicLink()) throw new Error('source symlink refused');
      if (entry.isDirectory()) { walk(next, group); continue; }
      const wanted = group === 'profiles' ? /\.json$/ : /\.(?:cjs|py|json)$/;
      if (wanted.test(entry.name)) add(next);
    }
  }
  for (const group of ['tests', 'fixtures', 'profiles']) walk(`${RELATIVE_ROOT}/${group}`, group);
  for (const dependency of DEPENDENCIES) add(dependency);
  selected.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  ensure(new Set(selected.map(x => x.path)).size === selected.length, 'duplicate source entry');
  return { schema: 'mikaya.interop.executed-source-manifest.v1',
    digestDefinition: 'SHA256 of UTF8 JSON.stringify(files) in the recorded order',
    sourceSetSha256: sha256(JSON.stringify(selected)), files: selected };
}

function testFilesFromInventory(inventory) {
  const prefix = `${RELATIVE_ROOT}/tests/`;
  const tests = inventory.files.map(x => x.path).filter(p => p.startsWith(prefix) &&
    /^[A-Za-z0-9][A-Za-z0-9_.-]*\.cjs$/.test(p.slice(prefix.length)));
  ensure(tests.length > 0 && tests.length <= 100, 'missing or excessive acceptance test files');
  return tests;
}

function parseTap(text) {
  const errors = [], counts = {}, names = ['tests', 'suites', 'pass', 'fail', 'cancelled', 'skipped', 'todo'];
  if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_TEST_OUTPUT_BYTES) return { valid: false, errors: ['tap_invalid_or_too_large'], counts: null, plan: null };
  if (!/^TAP version 13\r?$/m.test(text)) errors.push('tap_header_missing');
  for (const name of names) {
    const rows = [...text.matchAll(new RegExp(`^# ${name} (\\d+)\\r?$`, 'gm'))];
    if (rows.length !== 1 || !Number.isSafeInteger(Number(rows[0]?.[1])) || Number(rows[0]?.[1]) > 1000000) errors.push(`tap_${name}_count_missing_or_ambiguous`);
    else counts[name] = Number(rows[0][1]);
  }
  const plans = [...text.matchAll(/^1\.\.(\d+)(?:\s+#.*)?\r?$/gm)];
  const plan = plans.length === 1 ? Number(plans[0][1]) : null;
  if (!Number.isSafeInteger(plan) || plan < 1 || plan > 1000000) errors.push('tap_plan_missing_or_invalid');
  const cases = [...text.matchAll(/^(ok|not ok)\s+(\d+)(?:[^\r\n]*)\r?$/gm)];
  if (plan !== null && cases.length !== plan) errors.push('tap_plan_case_count_mismatch');
  if (cases.some((row, index) => Number(row[2]) !== index + 1)) errors.push('tap_case_sequence_invalid');
  if (/^Bail out!/im.test(text)) errors.push('tap_bailout');
  if (cases.some(row => row[1] === 'not ok') && counts.fail === 0 && counts.cancelled === 0) errors.push('tap_failure_counter_inconsistent');
  if (cases.some(row => /#\s*(?:SKIP|TODO)\b/i.test(row[0])) && counts.skipped === 0 && counts.todo === 0) errors.push('tap_nonexecution_counter_inconsistent');
  if (counts.tests === 0) errors.push('tap_no_tests_executed');
  return { valid: errors.length === 0, errors, counts: names.every(n => Object.hasOwn(counts, n)) ? counts : null, plan };
}

function acceptanceReasons({ parsed, processResult, comparison, sourceStable }) {
  const reasons = [];
  if (processResult.reason) reasons.push(processResult.reason);
  if (processResult.exitCode !== 0 || processResult.signal) reasons.push('test_process_failed');
  if (!parsed.valid || !parsed.counts) reasons.push('test_results_incomplete_or_invalid');
  const c = parsed.counts;
  if (c) {
    if (c.fail) reasons.push('tests_failed');
    if (c.cancelled) reasons.push('tests_cancelled');
    if (c.skipped) reasons.push('tests_skipped');
    if (c.todo) reasons.push('tests_todo');
    if (c.tests < 1 || c.pass !== c.tests) reasons.push('not_all_tests_passed');
  }
  if (comparison?.outcome !== 'MATCH') reasons.push('portable_runtime_profile_not_matched');
  if (sourceStable !== true) reasons.push('test_source_changed_or_unverified');
  return [...new Set(reasons)];
}

function runTestProcess(testFiles) {
  const args = ['--test', '--test-concurrency=1', '--test-reporter=tap', ...testFiles];
  return new Promise(resolve => {
    const stdout = [], stderr = [];
    let bytes = 0, reason = null, finished = false, timer, grace, child;
    const finish = (exitCode, signal) => {
      if (finished) return;
      finished = true; clearTimeout(timer); clearTimeout(grace);
      resolve({ stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8'),
        exitCode: Number.isInteger(exitCode) ? exitCode : null, signal: signal || null, reason, args });
    };
    const stop = why => {
      if (reason) return;
      reason = why;
      try {
        if (process.platform !== 'win32' && Number.isInteger(child?.pid) && child.pid > 1) process.kill(-child.pid, 'SIGKILL');
        else child?.kill('SIGKILL');
      } catch { try { child?.kill('SIGKILL'); } catch { } }
      // Preserve bounded partial evidence even if a descendant holds a pipe.
      grace = setTimeout(() => finish(null, 'SIGKILL'), 2000);
    };
    const consume = (chunks, data) => {
      const remaining = MAX_TEST_OUTPUT_BYTES - bytes;
      if (remaining > 0) chunks.push(data.subarray(0, remaining));
      bytes += data.length;
      if (bytes > MAX_TEST_OUTPUT_BYTES) stop('test_output_limit');
    };
    const env = { ...process.env };
    delete env.NODE_OPTIONS; delete env.NODE_TEST_CONTEXT; delete env.NODE_V8_COVERAGE;
    try {
      child = spawn(process.execPath, args, { cwd: REPO_ROOT, shell: false,
        stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, detached: process.platform !== 'win32', env });
    } catch { reason = 'test_process_spawn_failed'; finish(null, null); return; }
    child.stdout.on('data', data => consume(stdout, data));
    child.stderr.on('data', data => consume(stderr, data));
    child.once('error', () => { reason = 'test_process_spawn_failed'; finish(null, null); });
    child.once('close', finish);
    timer = setTimeout(() => stop('test_process_timeout'), TEST_TIMEOUT_MS);
  });
}

async function runAcceptance(outputPath) {
  const output = createOutputDirectory(outputPath), started = Date.now(), artifacts = [];
  const startedAt = new Date(started).toISOString();
  artifacts.push(writeEvidence(output, 'acceptance-start.json', { schema: 'mikaya.interop.acceptance-start.v1', startedAt, TEST_SCOPE }));
  let inventory = null, after = null, profile = null, comparison = null, tests = [], setupError = null;
  let processResult = { stdout: '', stderr: '', exitCode: null, signal: null, reason: 'tests_not_started', args: [] };
  try {
    inventory = sourceInventory();
    artifacts.push(writeEvidence(output, 'source-manifest.json', inventory));
    profile = runtime.collectRuntimeProfile();
    runtime.validateRuntimeProfile(profile);
    artifacts.push(writeEvidence(output, 'runtime-profile.json', profile));
    const expected = JSON.parse(boundedSourceRead(path.join(__dirname, 'profiles/portable-node22.json')).toString('utf8'));
    comparison = runtime.compareRuntimeProfile(profile, expected);
    artifacts.push(writeEvidence(output, 'runtime-comparison.json', comparison));
    tests = testFilesFromInventory(inventory);
    processResult = await runTestProcess(tests);
  } catch { setupError = 'acceptance_setup_or_collection_failed'; }
  artifacts.push(writeEvidence(output, 'test-results.tap', processResult.stdout));
  artifacts.push(writeEvidence(output, 'test-stderr.log', processResult.stderr));
  try { after = sourceInventory(); artifacts.push(writeEvidence(output, 'source-manifest-after.json', after)); }
  catch { setupError = setupError || 'source_manifest_after_unavailable'; }
  const parsed = parseTap(processResult.stdout), sourceStable = !!inventory && !!after && inventory.sourceSetSha256 === after.sourceSetSha256;
  const reasons = acceptanceReasons({ parsed, processResult, comparison, sourceStable });
  if (setupError) reasons.unshift(setupError);
  const finishedAt = new Date().toISOString();
  const result = { schema: 'mikaya.interop.executed-acceptance.v1', status: reasons.length ? 'FAIL' : 'PASS',
    startedAt, finishedAt, durationMs: Math.max(0, Date.now() - started), TEST_SCOPE,
    executedTestFiles: tests, testCommand: { executable: 'process.execPath', args: processResult.args, cwd: 'repository_root' },
    limits: { testTimeoutMs: TEST_TIMEOUT_MS, combinedTestOutputBytes: MAX_TEST_OUTPUT_BYTES },
    process: { exitCode: processResult.exitCode, signal: processResult.signal, terminationReason: processResult.reason },
    tap: parsed, runtimeComparison: comparison, sourceStable,
    sourceSetSha256: inventory?.sourceSetSha256 || null, failureReasons: reasons, artifacts };
  writeEvidence(output, 'acceptance.json', result);
  return { output, result };
}

async function main(args = process.argv.slice(2)) {
  ensure(args.length === 2 && args[0] === '--output', 'usage: run-acceptance.cjs --output ABSOLUTE_NEW_DIRECTORY');
  const { output, result } = await runAcceptance(args[1]);
  process.stdout.write(JSON.stringify({ status: result.status, output, tests: result.tap.counts,
    sourceStable: result.sourceStable, failureReasons: result.failureReasons, TEST_SCOPE }) + '\n');
  if (result.status !== 'PASS') process.exitCode = 1;
}

module.exports = { runAcceptance, parseTap, acceptanceReasons, createOutputDirectory,
  sourceInventory, testFilesFromInventory, TEST_SCOPE, TEST_TIMEOUT_MS, MAX_TEST_OUTPUT_BYTES };
if (require.main === module) main().catch(() => {
  process.stderr.write('{"status":"REFUSED","reason":"Use an absolute new output directory with an existing private-capable parent"}\n');
  process.exitCode = 1;
});
