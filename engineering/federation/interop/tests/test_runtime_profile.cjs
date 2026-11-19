'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const runtime = require('../runtime-profile.cjs');
const profileDir = path.join(__dirname, '..', 'profiles');
const portable = JSON.parse(fs.readFileSync(path.join(profileDir, 'portable-node22.json'), 'utf8'));
const clone = x => JSON.parse(JSON.stringify(x));
const fixedTime = () => 1795060800000;
const fakeHost = () => ({ nodeVersion: '26.13.1', platform: 'android', arch: 'arm64',
  endianness: 'LE', kernelRelease: '5.15.197-android13', machine: 'aarch64',
  cpuModel: 'ARMv8 Processor', statMode: '644', ed25519: true, sha256: true });
const unavailable = () => ({ ok: false, reason: 'not_found_in_fixed_paths' });
function report(probe = unavailable, overrides = {}) {
  return runtime.collectRuntimeProfile({ probe, snapshot: fakeHost,
    readCpuInfo: () => ({ ok: false, reason: 'cpuinfo_unavailable' }), clock: fixedTime, ...overrides });
}
function utilityProbe(id) {
  if (id.startsWith('android.')) return { ok: true, stdout: ({
    'android.sdk': '35', 'android.model': 'F110 Pro', 'android.board': 'e393_qc_f10_w_6835_v0',
    'android.soc': 'MT6835', 'android.release': '15', 'android.manufacturer': 'FOSSiBOT'
  })[id] || '' };
  const [provider, ...parts] = id.split('.'), operation = parts.join('.');
  if (!['busybox', 'toybox'].includes(provider)) return unavailable();
  if (operation === 'applets') return { ok: true, stdout: 'sh sha256sum date stat base64 timeout\n' };
  if (operation === 'version') return { ok: true, stdout: provider === 'busybox' ? 'BusyBox v1.36.1 multi-call binary\n' : 'toybox 0.8.12-android\n' };
  if (operation === 'sha256.stdin') return { ok: true, stdout: crypto.createHash('sha256').update(runtime.probeSpec(id).input).digest('hex') + '  -\n' };
  if (operation === 'date.epoch') return { ok: true, stdout: '1970-01-01T00:00:00Z\n' };
  if (operation === 'stat.mode') return { ok: true, stdout: '644\n' };
  return unavailable();
}

test('unavailable probes remain unknown and never invent Pixel, AVF, root, slot or safe temporary storage', () => {
  const out = report();
  runtime.validateRuntimeProfile(out);
  for (const fact of ['android.model', 'android.sdk', 'cpu.features', 'virtualization.avf',
    'privilege.rootAvailable', 'boot.slot', 'filesystem.safeTemporaryDirectory']) {
    assert.equal(out.facts[fact].status, 'unknown', fact);
    assert.equal(Object.hasOwn(out.facts[fact], 'value'), false);
  }
  assert.equal(JSON.stringify(out).includes('Pixel'), false);
  assert.equal(out.hardwareAttested, false);
  assert.equal(out.peerEnrolled, false);
});

test('both BusyBox and Toybox must pass real stdin hash, UTC date and stat semantics independently', () => {
  const out = report(utilityProbe);
  runtime.validateRuntimeProfile(out);
  for (const provider of ['busybox', 'toybox']) {
    for (const operation of ['sha256.stdin', 'date.epoch', 'stat.mode']) {
      assert.deepEqual(out.facts[`utility.${provider}.${operation}`], {
        status: 'observed', value: true, evidence: `fixed.${provider}.${operation}`
      });
    }
  }
  assert.equal(out.facts['android.sdk'].value, 35);
  assert.equal(out.facts['android.model'].value, 'F110 Pro');
  assert.equal(out.facts['utility.busybox.version'].value, '1.36.1');
  assert.equal(out.facts['utility.toybox.version'].value, '0.8.12-android');
});

test('listing an applet is insufficient when its output violates the required semantics', () => {
  const out = report(id => id === 'busybox.sha256.stdin' ? { ok: true, stdout: 'f'.repeat(64) + '  -\n' } :
    id === 'toybox.stat.mode' ? { ok: true, stdout: '777\n' } : utilityProbe(id));
  assert.equal(out.facts['utility.busybox.applet.sha256sum'].value, true);
  assert.equal(out.facts['utility.busybox.sha256.stdin'].value, false);
  assert.equal(out.facts['utility.toybox.stat.mode'].value, false);
  assert.equal(out.facts['utility.toybox.sha256.stdin'].value, true);
});

test('missing applets are false while failed execution and missing provider are unknown', () => {
  const out = report(id => id === 'busybox.applets' ? { ok: true, stdout: 'sh stat\n' } :
    id === 'busybox.stat.mode' ? { ok: false, reason: 'probe_timeout' } : unavailable());
  assert.equal(out.facts['utility.busybox.applet.sha256sum'].value, false);
  assert.equal(out.facts['utility.busybox.sha256.stdin'].value, false);
  assert.equal(out.facts['utility.busybox.stat.mode'].status, 'unknown');
  assert.equal(out.facts['utility.toybox.present'].status, 'unknown');
});

test('fixed system Toybox is found without PATH and subprocesses cannot receive shell commands', () => {
  const calls = [];
  const probe = runtime.createProbeExecutor({ clock: fixedTime,
    isExecutable: p => p === '/system/bin/toybox',
    spawn: (binary, args, options) => { calls.push({ binary, args, options }); return { status: 0, stdout: 'sh date stat sha256sum\n' }; }
  });
  assert.equal(probe('toybox.applets').ok, true);
  assert.equal(calls[0].binary, '/system/bin/toybox');
  assert.equal(calls[0].options.shell, false);
  assert.equal(calls[0].options.timeout, runtime.PROBE_TIMEOUT_MS);
  assert.equal(calls[0].options.maxBuffer, runtime.MAX_OUTPUT_BYTES);
  assert.deepEqual(calls[0].args, []);
  assert.throws(() => probe('toybox.sh -c curl attacker'), /unknown fixed probe/);
  assert.throws(() => runtime.probeSpec('android.serial'), /unknown fixed probe/);
  assert.equal(calls.length, 1);
});

test('SHA256 is tested with a fixed stdin fixture and never with private input or a shell pipe', () => {
  let captured;
  const probe = runtime.createProbeExecutor({ clock: fixedTime,
    isExecutable: p => p === '/data/data/com.termux/files/usr/bin/busybox',
    spawn: (binary, args, options) => { captured = { binary, args, options }; return { status: 0, stdout: '' }; }
  });
  probe('busybox.sha256.stdin');
  assert.deepEqual(captured.args, ['sha256sum']);
  assert.equal(captured.options.input, 'MIKAYA local utility compatibility fixture v1\n');
  assert.equal(captured.options.shell, false);
  assert.equal(Object.hasOwn(captured.options.env, 'LD_PRELOAD'), false);
});

test('overall deadline, output cap, timeouts and exceptions fail closed without raw diagnostics', () => {
  let now = 0, calls = 0;
  const expired = runtime.createProbeExecutor({ clock: () => now, isExecutable: () => true,
    spawn: () => { calls++; return { status: 0, stdout: '' }; } });
  now = runtime.TOTAL_PROBE_BUDGET_MS;
  assert.deepEqual(expired('toybox.applets'), { ok: false, reason: 'probe_budget_exhausted' });
  assert.equal(calls, 0);
  for (const result of [
    { status: 0, stdout: 'x'.repeat(runtime.MAX_OUTPUT_BYTES + 1) },
    { error: { code: 'ETIMEDOUT', message: 'sensitive diagnostic' }, stderr: 'private material' },
    { status: 1, stdout: 'private material', stderr: 'private material' }
  ]) {
    const p = runtime.createProbeExecutor({ clock: fixedTime, isExecutable: () => true, spawn: () => result });
    const out = p('busybox.applets');
    assert.equal(out.ok, false);
    assert.equal(JSON.stringify(out).includes('private'), false);
    assert.equal(JSON.stringify(out).includes('sensitive'), false);
  }
});

test('property output and CPU text cannot inject identifiers, credentials, multiline payloads or unbounded data', () => {
  const out = report(id => id === 'android.model' ? { ok: true, stdout: 'F110 Pro\npassword=NOT_FOR_REPORT\n' } :
    id === 'android.board' ? { ok: true, stdout: 'https://10.20.30.40/private' } :
    id === 'android.soc' ? { ok: true, stdout: 'x'.repeat(8193) } : unavailable(), {
    readCpuInfo: () => ({ ok: true, text: 'Serial: DO_NOT_PUBLISH\nFeatures: fp asimd aes\n' })
  });
  const raw = JSON.stringify(out);
  for (const secret of ['NOT_FOR_REPORT', '10.20.30.40', 'DO_NOT_PUBLISH']) assert.equal(raw.includes(secret), false);
  for (const key of ['android.model', 'android.board', 'android.soc']) assert.equal(out.facts[key].status, 'unknown');
  assert.deepEqual(out.facts['cpu.features'].value, ['aes', 'fp', 'neon']);
});

test('CPU capabilities use intersection across reported cores and normalize ARM feature names', () => {
  const flags = runtime.parseCpuFeatures('processor: 0\nFeatures: fp asimd asimddp i8mm aes\n\nprocessor: 1\nFeatures: fp asimd asimddp aes\n');
  assert.deepEqual(flags, ['aes', 'dotprod', 'fp', 'neon']);
  assert.equal(flags.includes('i8mm'), false);
  assert.equal(runtime.parseCpuFeatures('Hardware: Tensor G5'), null);
  assert.equal(runtime.parseCpuFeatures('x'.repeat(65537)), null);
});

test('portable protocol eligibility does not require ACT hardware or utility suites', () => {
  const out = runtime.compareRuntimeProfile(report(), portable);
  assert.equal(out.outcome, 'MATCH');
  assert.equal(out.hardwareAttested, false);
  assert.equal(out.authorizationGranted, false);
  assert.equal(out.peerEnrolled, false);
  assert.equal(out.compatibilityScope, 'DECLARED_CHECKS_ONLY');
});

test('Node version and crypto failures prevent a portable profile match', () => {
  const out = report(unavailable, { snapshot: () => ({ ...fakeHost(), nodeVersion: '20.19.0', ed25519: false }) });
  const result = runtime.compareRuntimeProfile(out, portable);
  assert.equal(result.outcome, 'MISMATCH');
  assert.equal(result.checks.find(x => x.id === 'node22').outcome, 'MISMATCH');
  assert.equal(result.checks.find(x => x.id === 'ed25519').outcome, 'MISMATCH');
});

test('required unknown differs from mismatch, while optional unknown cannot masquerade as measured success', () => {
  const p = clone(portable);
  p.checks.push({ id: 'hardware-observation', fact: 'android.model', operator: 'contains', expected: 'Pixel 8', required: true });
  assert.equal(runtime.compareRuntimeProfile(report(), p).outcome, 'UNKNOWN');
  p.checks.at(-1).required = false;
  const result = runtime.compareRuntimeProfile(report(), p);
  assert.equal(result.outcome, 'MATCH');
  assert.equal(result.checks.at(-1).outcome, 'UNKNOWN');
  assert.equal(result.checks.at(-1).actual, null);
});

test('F110 observations mismatch the ACT Pixel source reference without rewriting either identity', () => {
  const p = JSON.parse(fs.readFileSync(path.join(profileDir, 'act-pixel8-source.json'), 'utf8'));
  const out = report(utilityProbe), result = runtime.compareRuntimeProfile(out, p);
  assert.equal(result.outcome, 'MISMATCH');
  assert.equal(result.sourceDeclaredOnly, true);
  assert.equal(result.profilePurpose, 'source-hardware-reference');
  assert.equal(out.facts['android.model'].value, 'F110 Pro');
  assert.equal(result.checks.find(c => c.id === 'root-unprobed').outcome, 'UNKNOWN');
});

test('expected-profile parser rejects code, unpinned sources, unknown facts, bad types and vacuous policies', () => {
  for (const change of [
    p => { p.command = 'curl remote'; },
    p => { p.sourceDeclaredOnly = false; },
    p => { p.sources[0].url = 'https://github.com/owner/repo/blob/main/README.md'; },
    p => { p.sources[0].url += '?token=private'; },
    p => { p.checks[0].fact = 'android.serial'; },
    p => { p.checks[0].operator = 'eval'; },
    p => { p.checks[0].expected = 22.5; },
    p => { p.checks[0].expected = '22'; },
    p => { p.checks.push(clone(p.checks[0])); },
    p => { p.checks.forEach(c => { c.required = false; }); }
  ]) { const p = clone(portable); change(p); assert.throws(() => runtime.validateExpectedProfile(p)); }
});

test('runtime validation refuses invented attestation, undeclared fields, floats and non-public observations', () => {
  for (const change of [
    p => { p.hardwareAttested = true; },
    p => { p.authorizationGranted = true; },
    p => { p.facts['android.serial'] = { status: 'observed', value: 'private-id', evidence: 'getprop' }; },
    p => { p.facts['runtime.nodeMajor'].value = 26.5; },
    p => { p.facts['android.model'] = { status: 'observed', value: 'http://10.0.0.2/private', evidence: 'getprop' }; },
    p => { p.facts['android.model'] = { status: 'unknown', reason: 'failed', evidence: 'getprop', raw: 'secret' }; }
  ]) { const p = report(); change(p); assert.throws(() => runtime.validateRuntimeProfile(p)); }
});

test('all checked-in expected profiles are strict source-declared references with pinned evidence', () => {
  const files = fs.readdirSync(profileDir).filter(x => x.endsWith('.json'));
  assert.equal(files.length >= 4, true);
  for (const file of files) runtime.validateExpectedProfile(JSON.parse(fs.readFileSync(path.join(profileDir, file), 'utf8')));
});
