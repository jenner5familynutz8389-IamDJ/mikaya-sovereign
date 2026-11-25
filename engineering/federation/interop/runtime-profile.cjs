#!/usr/bin/env node
'use strict';

/**
 * Bounded local compatibility observations. No network, shell, privilege,
 * device-management or service operations. A report is NOT an attestation.
 * BusyBox and Android Toybox here mean utility providers, not the separate
 * MIKAYA historical Bitcoin observation module named Toybox.
 */
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const REPORT_SCHEMA = 'mikaya.interop.runtime-profile.v1';
const EXPECTED_SCHEMA = 'mikaya.interop.expected-runtime-profile.v1';
const PROBE_TIMEOUT_MS = 750;
const TOTAL_PROBE_BUDGET_MS = 10000;
const MAX_OUTPUT_BYTES = 8192;
const MAX_CPUINFO_BYTES = 65536;
const MAX_PROFILE_BYTES = 65536;
const FIXTURE = 'MIKAYA local utility compatibility fixture v1\n';
const FIXTURE_SHA256 = crypto.createHash('sha256').update(FIXTURE).digest('hex');
const APPLETS = Object.freeze(['sh', 'sha256sum', 'date', 'stat', 'base64', 'timeout']);
const PROVIDERS = Object.freeze(['busybox', 'toybox']);
const PROPERTY_KEYS = Object.freeze({
  'android.sdk': 'ro.build.version.sdk',
  'android.release': 'ro.build.version.release',
  'android.model': 'ro.product.model',
  'android.manufacturer': 'ro.product.manufacturer',
  'android.board': 'ro.product.board',
  'android.hardware': 'ro.hardware',
  'android.soc': 'ro.soc.model',
  'android.buildId': 'ro.build.id',
  'android.buildIncremental': 'ro.build.version.incremental',
  'android.securityPatch': 'ro.build.version.security_patch',
  'android.vendorSecurityPatch': 'ro.vendor.build.security_patch'
});
// Fixed absolute paths deliberately ignore PATH, including empty/current-dir
// entries. In particular, Android's Toybox may exist outside Termux's PATH.
const EXECUTABLES = Object.freeze({
  getprop: Object.freeze(['/system/bin/getprop']),
  busybox: Object.freeze([
    '/data/data/com.termux/files/usr/bin/busybox', '/system/bin/busybox',
    '/system/xbin/busybox', '/usr/bin/busybox', '/bin/busybox',
    '/usr/local/bin/busybox'
  ]),
  toybox: Object.freeze([
    '/system/bin/toybox', '/data/data/com.termux/files/usr/bin/toybox',
    '/usr/bin/toybox', '/bin/toybox', '/usr/local/bin/toybox'
  ])
});
const FEATURE_NAMES = new Set([
  'fp', 'asimd', 'neon', 'aes', 'pmull', 'sha1', 'sha2', 'crc32', 'atomics',
  'fphp', 'asimdhp', 'asimddp', 'dotprod', 'i8mm', 'sve', 'sve2', 'svei8mm',
  'bf16', 'svebf16', 'lrcpc', 'ilrcpc', 'bti', 'paca', 'pacg', 'ssse3',
  'sse', 'sse2', 'sse3', 'sse4_1', 'sse4_2', 'avx', 'avx2', 'avx512f',
  'avx512bw', 'avx512vl', 'fma', 'sha_ni', 'bmi1', 'bmi2'
]);
const FACT_NAMES = new Set([
  'runtime.nodeVersion', 'runtime.nodeMajor', 'runtime.platform', 'runtime.arch',
  'runtime.endianness', 'system.kernelRelease', 'system.machine', 'cpu.model',
  'cpu.features', 'crypto.sha256', 'crypto.ed25519', ...Object.keys(PROPERTY_KEYS),
  'privilege.rootAvailable', 'boot.slot', 'virtualization.avf',
  'filesystem.safeTemporaryDirectory', 'gpu.renderer',
  ...PROVIDERS.flatMap(p => [
    `utility.${p}.present`, `utility.${p}.version`,
    `utility.${p}.sha256.stdin`, `utility.${p}.date.epoch`,
    `utility.${p}.stat.mode`, ...APPLETS.map(a => `utility.${p}.applet.${a}`)
  ])
]);

function plain(x) {
  return x !== null && typeof x === 'object' && !Array.isArray(x) &&
    Object.getPrototypeOf(x) === Object.prototype;
}
function exact(x, keys) {
  return plain(x) && Object.keys(x).sort().join('|') === [...keys].sort().join('|');
}
function ensure(ok, message) { if (!ok) throw new Error(message); }
function safeText(value, max = 160) {
  if (typeof value !== 'string') return null;
  const s = value.trim();
  if (!s || s.length > max || !/^[A-Za-z0-9][A-Za-z0-9 _().+:/#-]*$/.test(s)) return null;
  // No raw paths, URLs, addresses, credentials, or multiline probe output.
  if (s.includes('://') || /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(s) ||
      /(?:private.?key|password|bearer|secret|token\s*[:=])/i.test(s)) return null;
  return s;
}
function observed(value, evidence) { return { status: 'observed', value, evidence }; }
function unknown(reason, evidence) { return { status: 'unknown', reason, evidence }; }
function valueFact(value, evidence) {
  const text = safeText(value);
  return text === null ? unknown('missing_or_invalid_value', evidence) : observed(text, evidence);
}

/** A small, closed probe vocabulary: callers cannot supply shell text or flags. */
function probeSpec(id) {
  if (Object.hasOwn(PROPERTY_KEYS, id)) {
    return { provider: 'getprop', args: [PROPERTY_KEYS[id]], input: '' };
  }
  for (const p of PROVIDERS) {
    const prefix = `${p}.`;
    if (!id.startsWith(prefix)) continue;
    const operation = id.slice(prefix.length);
    if (operation === 'applets') return { provider: p, args: p === 'busybox' ? ['--list'] : [], input: '' };
    if (operation === 'version') return { provider: p, args: [p === 'busybox' ? '--help' : '--version'], input: '' };
    if (operation === 'sha256.stdin') return { provider: p, args: ['sha256sum'], input: FIXTURE };
    if (operation === 'date.epoch') return { provider: p, args: ['date', '-u', '-d', '@0', '+%Y-%m-%dT%H:%M:%SZ'], input: '' };
    if (operation === 'stat.mode') return { provider: p, args: ['stat', '-c', '%a', __filename], input: '' };
  }
  throw new Error('unknown fixed probe');
}

function executableFile(file) {
  try { fs.accessSync(file, fs.constants.X_OK); return fs.statSync(file).isFile(); }
  catch { return false; }
}

/** Injected primitives are for unit tests; the CLI never exposes them. */
function createProbeExecutor({ spawn = spawnSync, isExecutable = executableFile, clock = Date.now } = {}) {
  const started = clock();
  const located = new Map();
  return function runProbe(id) {
    const spec = probeSpec(id);
    if (clock() - started >= TOTAL_PROBE_BUDGET_MS) return { ok: false, reason: 'probe_budget_exhausted' };
    if (!located.has(spec.provider)) located.set(spec.provider, EXECUTABLES[spec.provider].find(isExecutable) || null);
    const binary = located.get(spec.provider);
    if (!binary) return { ok: false, reason: 'not_found_in_fixed_paths' };
    const remaining = TOTAL_PROBE_BUDGET_MS - (clock() - started);
    if (remaining <= 0) return { ok: false, reason: 'probe_budget_exhausted' };
    let result;
    try {
      result = spawn(binary, spec.args, {
        shell: false, encoding: 'utf8', input: spec.input,
        timeout: Math.max(1, Math.min(PROBE_TIMEOUT_MS, remaining)),
        killSignal: 'SIGKILL', maxBuffer: MAX_OUTPUT_BYTES,
        windowsHide: true, env: { PATH: '/system/bin:/usr/bin:/bin', LC_ALL: 'C', LANG: 'C' }
      });
    } catch { return { ok: false, reason: 'execution_failed' }; }
    if (result?.error || result?.signal) {
      return { ok: false, reason: result?.error?.code === 'ETIMEDOUT' ? 'probe_timeout' : 'execution_or_output_limit' };
    }
    if (result?.status !== 0) return { ok: false, reason: 'probe_not_supported_or_failed' };
    if (typeof result.stdout !== 'string' || Buffer.byteLength(result.stdout) > MAX_OUTPUT_BYTES) {
      return { ok: false, reason: 'execution_or_output_limit' };
    }
    return { ok: true, stdout: result.stdout };
  };
}

function readBoundedCpuInfo() {
  let fd;
  try {
    fd = fs.openSync('/proc/cpuinfo', fs.constants.O_RDONLY);
    const buffer = Buffer.alloc(MAX_CPUINFO_BYTES + 1);
    let used = 0;
    while (used < buffer.length) {
      const n = fs.readSync(fd, buffer, used, buffer.length - used, null);
      if (!n) break;
      used += n;
    }
    if (used > MAX_CPUINFO_BYTES) return { ok: false, reason: 'cpuinfo_too_large' };
    return { ok: true, text: buffer.subarray(0, used).toString('utf8') };
  } catch { return { ok: false, reason: 'cpuinfo_unavailable' }; }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}

function parseCpuFeatures(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_CPUINFO_BYTES) return null;
  const rows = text.split(/\r?\n/).filter(line => /^\s*(?:flags|features)\s*:/i.test(line));
  if (!rows.length) return null;
  const sets = rows.map(line => new Set(line.slice(line.indexOf(':') + 1).trim().split(/\s+/)
    .filter(name => FEATURE_NAMES.has(name.toLowerCase()))
    .map(name => ({ asimd: 'neon', asimddp: 'dotprod' }[name.toLowerCase()] || name.toLowerCase()))));
  // Require the feature on every reported CPU; a union is unsafe on mixed cores.
  return [...sets[0]].filter(name => sets.every(set => set.has(name))).sort();
}

function nativeSnapshot() {
  let model = null, machine = null, kernelRelease = null, endianness = null, statMode = null;
  try { model = os.cpus()[0]?.model || null; } catch { }
  try { machine = os.machine(); } catch { }
  try { kernelRelease = os.release(); } catch { }
  try { endianness = os.endianness(); } catch { }
  try { statMode = (fs.statSync(__filename).mode & 0o7777).toString(8); } catch { }
  let ed25519 = false, sha256 = false;
  try { sha256 = crypto.createHash('sha256').update('abc').digest('hex') === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'; } catch { }
  try {
    const keys = crypto.generateKeyPairSync('ed25519');
    const data = Buffer.from(FIXTURE);
    ed25519 = crypto.verify(null, data, keys.publicKey, crypto.sign(null, data, keys.privateKey));
    // Keys are temporary in-memory test fixtures, never returned or written.
  } catch { }
  return { nodeVersion: process.versions.node, platform: process.platform, arch: process.arch,
    endianness, kernelRelease, machine, cpuModel: model, statMode, ed25519, sha256 };
}

function collectRuntimeProfile({ probe = createProbeExecutor(), snapshot = nativeSnapshot,
  readCpuInfo = readBoundedCpuInfo, clock = Date.now } = {}) {
  const host = snapshot();
  const facts = {};
  facts['runtime.nodeVersion'] = valueFact(host.nodeVersion, 'node.process.versions');
  const major = typeof host.nodeVersion === 'string' && /^(\d+)\.\d+\.\d+(?:[-+].*)?$/.exec(host.nodeVersion);
  facts['runtime.nodeMajor'] = major && Number.isSafeInteger(Number(major[1])) ?
    observed(Number(major[1]), 'node.process.versions') : unknown('invalid_node_version', 'node.process.versions');
  for (const [key, value, evidence] of [
    ['runtime.platform', host.platform, 'node.process.platform'],
    ['runtime.arch', host.arch, 'node.process.arch'],
    ['runtime.endianness', host.endianness, 'node.os.endianness'],
    ['system.kernelRelease', host.kernelRelease, 'node.os.release'],
    ['system.machine', host.machine, 'node.os.machine'],
    ['cpu.model', host.cpuModel, 'node.os.cpus']
  ]) facts[key] = valueFact(value, evidence);
  for (const name of ['ed25519', 'sha256']) facts[`crypto.${name}`] =
    typeof host[name] === 'boolean' ? observed(host[name], 'in_memory_known_input_self_check') : unknown('self_check_unavailable', 'node.crypto');

  let cpu;
  try { cpu = readCpuInfo(); } catch { cpu = { ok: false }; }
  const features = cpu?.ok ? parseCpuFeatures(cpu.text) : null;
  facts['cpu.features'] = features === null ? unknown('cpu_features_unavailable_or_incomplete', 'proc.cpuinfo.flags_only') :
    observed(features, 'proc.cpuinfo.reported_cpu_intersection');

  function checkedProbe(id) {
    let out;
    try { out = probe(id); } catch { return { ok: false, reason: 'probe_failed' }; }
    if (!out?.ok) {
      const reason = new Set(['probe_budget_exhausted', 'not_found_in_fixed_paths', 'execution_failed',
        'probe_timeout', 'execution_or_output_limit', 'probe_not_supported_or_failed']);
      return { ok: false, reason: reason.has(out?.reason) ? out.reason : 'probe_failed' };
    }
    if (typeof out.stdout !== 'string' || Buffer.byteLength(out.stdout) > MAX_OUTPUT_BYTES) return { ok: false, reason: 'execution_or_output_limit' };
    return { ok: true, stdout: out.stdout };
  }

  for (const [key, property] of Object.entries(PROPERTY_KEYS)) {
    const out = checkedProbe(key), evidence = `android.getprop.${property}`;
    if (!out.ok) facts[key] = unknown(out.reason, evidence);
    else if (key === 'android.sdk') {
      const s = out.stdout.trim();
      facts[key] = /^\d{1,3}$/.test(s) && Number(s) > 0 && Number(s) < 100 ?
        observed(Number(s), evidence) : unknown('property_missing_or_invalid', evidence);
    } else facts[key] = valueFact(out.stdout, evidence);
  }

  for (const provider of PROVIDERS) {
    const prefix = `utility.${provider}`;
    const listing = checkedProbe(`${provider}.applets`);
    if (!listing.ok) {
      for (const key of FACT_NAMES) if (key.startsWith(`${prefix}.`)) facts[key] = unknown(listing.reason, `fixed.${provider}.probe`);
      continue;
    }
    // Store only the selected applet booleans, never the complete/raw listing.
    const listed = new Set(listing.stdout.trim().split(/\s+/).filter(x => /^[a-z0-9_+.[\]-]{1,48}$/.test(x)));
    facts[`${prefix}.present`] = observed(true, `fixed.${provider}.applet_listing`);
    for (const applet of APPLETS) facts[`${prefix}.applet.${applet}`] = observed(listed.has(applet), `fixed.${provider}.applet_listing`);
    const version = checkedProbe(`${provider}.version`);
    const match = version.ok && new RegExp(`${provider}\\s+v?(\\d+\\.\\d+(?:\\.\\d+)?(?:[-+.][A-Za-z0-9_.-]+)?)`, 'i').exec(version.stdout);
    facts[`${prefix}.version`] = match ? valueFact(match[1], `fixed.${provider}.version`) : unknown('version_not_reported', `fixed.${provider}.version`);
    for (const [operation, applet] of [['sha256.stdin', 'sha256sum'], ['date.epoch', 'date'], ['stat.mode', 'stat']]) {
      const evidence = `fixed.${provider}.${operation}`;
      if (!listed.has(applet)) { facts[`${prefix}.${operation}`] = observed(false, evidence); continue; }
      const out = checkedProbe(`${provider}.${operation}`);
      if (!out.ok) { facts[`${prefix}.${operation}`] = unknown(out.reason, evidence); continue; }
      let passed;
      if (operation === 'sha256.stdin') passed = new RegExp(`^${FIXTURE_SHA256}\\s+[-]$`).test(out.stdout.trim());
      if (operation === 'date.epoch') passed = out.stdout.trim() === '1970-01-01T00:00:00Z';
      if (operation === 'stat.mode') {
        if (typeof host.statMode !== 'string' || !/^[0-7]{1,4}$/.test(host.statMode)) {
          facts[`${prefix}.${operation}`] = unknown('node_stat_reference_unavailable', evidence); continue;
        }
        passed = /^[0-7]{1,4}$/.test(out.stdout.trim()) && parseInt(out.stdout.trim(), 8) === parseInt(host.statMode, 8);
      }
      facts[`${prefix}.${operation}`] = observed(passed, evidence);
    }
  }

  for (const key of ['privilege.rootAvailable', 'boot.slot', 'virtualization.avf', 'filesystem.safeTemporaryDirectory', 'gpu.renderer']) {
    facts[key] = unknown('not_probed', 'excluded_from_read_only_runtime_scope');
  }
  return {
    schema: REPORT_SCHEMA, collectedAt: new Date(clock()).toISOString(),
    evidenceClass: 'LOCAL_SOFTWARE_OBSERVATION_NOT_ATTESTATION',
    hardwareAttested: false, authorizationGranted: false, peerEnrolled: false,
    facts
  };
}

function scalar(value) {
  return typeof value === 'boolean' || (typeof value === 'number' && Number.isSafeInteger(value)) ||
    (typeof value === 'string' && safeText(value) !== null);
}
function boundedValue(value) {
  return scalar(value) || (Array.isArray(value) && value.length <= 64 && value.every(x => typeof x === 'string' && safeText(x, 64) !== null));
}
function validateExpectedProfile(profile) {
  ensure(exact(profile, ['schema', 'id', 'label', 'purpose', 'sourceDeclaredOnly', 'sources', 'checks']) &&
    profile.schema === EXPECTED_SCHEMA && profile.sourceDeclaredOnly === true, 'invalid expected-profile schema');
  ensure(typeof profile.id === 'string' && /^[a-z0-9][a-z0-9-]{0,63}$/.test(profile.id) && safeText(profile.label) !== null,
    'invalid expected-profile identity');
  ensure(['protocol-runtime', 'source-hardware-reference', 'utility-compatibility'].includes(profile.purpose), 'invalid expected-profile purpose');
  ensure(Array.isArray(profile.sources) && profile.sources.length > 0 && profile.sources.length <= 8, 'invalid expected-profile sources');
  for (const source of profile.sources) {
    ensure(exact(source, ['url', 'description']) && typeof source.url === 'string' && source.url.length <= 512 && safeText(source.description) !== null,
      'invalid source reference');
    let u;
    try { u = new URL(source.url); } catch { throw new Error('invalid source URL'); }
    ensure(u.protocol === 'https:' && !u.username && !u.password && !u.search && !u.hash && u.hostname === 'github.com' &&
      /^\/[^/]+\/[^/]+\/blob\/[a-f0-9]{40}\//.test(u.pathname), 'source must be a public commit-pinned GitHub file URL');
  }
  ensure(Array.isArray(profile.checks) && profile.checks.length > 0 && profile.checks.length <= 64, 'invalid profile check count');
  const ids = new Set();
  for (const check of profile.checks) {
    ensure(exact(check, ['id', 'fact', 'operator', 'expected', 'required']) && typeof check.id === 'string' &&
      /^[a-z0-9][a-z0-9-]{0,63}$/.test(check.id) && !ids.has(check.id), 'invalid or duplicate profile check');
    ids.add(check.id);
    ensure(FACT_NAMES.has(check.fact) && typeof check.required === 'boolean', 'unknown fact or invalid required flag');
    ensure(['eq', 'gte', 'oneOf', 'includesAll', 'prefix', 'contains'].includes(check.operator), 'unsupported comparison operator');
    ensure(boundedValue(check.expected), 'invalid expected value');
    if (check.operator === 'gte') ensure(typeof check.expected === 'number', 'gte requires an integer');
    if (['oneOf', 'includesAll'].includes(check.operator)) ensure(Array.isArray(check.expected) && check.expected.length > 0, 'set comparison requires values');
    if (['prefix', 'contains'].includes(check.operator)) ensure(typeof check.expected === 'string', 'text comparison requires text');
    if (check.operator === 'eq') ensure(scalar(check.expected), 'eq requires a scalar');
  }
  ensure(profile.checks.some(check => check.required), 'at least one required check is necessary');
  return profile;
}

function validateRuntimeProfile(report) {
  ensure(exact(report, ['schema', 'collectedAt', 'evidenceClass', 'hardwareAttested', 'authorizationGranted', 'peerEnrolled', 'facts']) &&
    report.schema === REPORT_SCHEMA && report.evidenceClass === 'LOCAL_SOFTWARE_OBSERVATION_NOT_ATTESTATION' &&
    report.hardwareAttested === false && report.authorizationGranted === false && report.peerEnrolled === false &&
    typeof report.collectedAt === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(report.collectedAt) &&
    Number.isFinite(Date.parse(report.collectedAt)) && plain(report.facts) && Object.keys(report.facts).length <= FACT_NAMES.size,
  'invalid runtime-profile schema');
  for (const [key, fact] of Object.entries(report.facts)) {
    ensure(FACT_NAMES.has(key), 'unknown runtime fact');
    const known = fact?.status === 'observed';
    ensure(exact(fact, known ? ['status', 'value', 'evidence'] : ['status', 'reason', 'evidence']) &&
      (known ? boundedValue(fact.value) : fact.status === 'unknown' && typeof fact.reason === 'string' && /^[a-z0-9_]{1,80}$/.test(fact.reason)) &&
      typeof fact.evidence === 'string' && /^[A-Za-z0-9_.-]{1,120}$/.test(fact.evidence), 'invalid runtime fact value');
  }
  return report;
}

function compareRuntimeProfile(report, profile) {
  validateRuntimeProfile(report);
  validateExpectedProfile(profile);
  const checks = profile.checks.map(check => {
    const fact = report.facts[check.fact];
    if (!fact || fact.status !== 'observed') return { ...check, outcome: 'UNKNOWN', actual: null, reason: fact?.reason || 'fact_missing' };
    const actual = fact.value, expected = check.expected;
    let matches = false;
    if (check.operator === 'eq') matches = actual === expected;
    if (check.operator === 'gte') matches = typeof actual === 'number' && actual >= expected;
    if (check.operator === 'oneOf') matches = expected.includes(actual);
    if (check.operator === 'includesAll') matches = Array.isArray(actual) && expected.every(x => actual.includes(x));
    if (check.operator === 'prefix') matches = typeof actual === 'string' && actual.startsWith(expected);
    if (check.operator === 'contains') matches = typeof actual === 'string' && actual.includes(expected);
    return { ...check, outcome: matches ? 'MATCH' : 'MISMATCH', actual, reason: matches ? 'declared_check_satisfied' : 'declared_check_not_satisfied' };
  });
  const required = checks.filter(c => c.required);
  const outcome = required.some(c => c.outcome === 'MISMATCH') ? 'MISMATCH' :
    required.some(c => c.outcome === 'UNKNOWN') ? 'UNKNOWN' : 'MATCH';
  return { schema: 'mikaya.interop.runtime-comparison.v1', profileId: profile.id, profilePurpose: profile.purpose,
    sourceDeclaredOnly: true, outcome, checks, compatibilityScope: 'DECLARED_CHECKS_ONLY',
    hardwareAttested: false, authorizationGranted: false, peerEnrolled: false };
}

function readExpectedProfile(file) {
  let fd;
  try {
    // The opened descriptor is the object validated and read, preventing a
    // path replacement between a metadata check and the JSON read.
    ensure(!fs.lstatSync(file).isSymbolicLink(), 'expected profile cannot be a symlink');
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const st = fs.fstatSync(fd);
    ensure(st.isFile() && st.size <= MAX_PROFILE_BYTES, 'expected profile must be a bounded regular file');
    const buffer = Buffer.alloc(MAX_PROFILE_BYTES + 1);
    let used = 0;
    while (used < buffer.length) {
      const n = fs.readSync(fd, buffer, used, buffer.length - used, null);
      if (!n) break;
      used += n;
    }
    ensure(used <= MAX_PROFILE_BYTES, 'expected profile too large');
    return validateExpectedProfile(JSON.parse(buffer.subarray(0, used).toString('utf8')));
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}

function main(args = process.argv.slice(2)) {
  ensure(args.length === 1 && args[0] === 'collect' || args.length === 3 && args[0] === 'collect' && args[1] === '--expected',
    'usage: runtime-profile.cjs collect [--expected profile.json]');
  // Reject malformed expected profiles before invoking even a local probe.
  const expected = args.length === 3 ? readExpectedProfile(args[2]) : null;
  const runtime = collectRuntimeProfile();
  validateRuntimeProfile(runtime);
  const comparison = expected ? compareRuntimeProfile(runtime, expected) : null;
  process.stdout.write(JSON.stringify(comparison ? { runtime, comparison } : runtime, null, 2) + '\n');
  if (comparison && comparison.outcome !== 'MATCH') process.exitCode = 2;
}

module.exports = { collectRuntimeProfile, compareRuntimeProfile, validateExpectedProfile,
  validateRuntimeProfile, parseCpuFeatures, probeSpec, createProbeExecutor, main,
  REPORT_SCHEMA, EXPECTED_SCHEMA, PROBE_TIMEOUT_MS, TOTAL_PROBE_BUDGET_MS, MAX_OUTPUT_BYTES };

if (require.main === module) {
  try { main(); }
  catch { process.stderr.write('{"error":"runtime_profile_refused","detail":"Invalid arguments, expected profile, or bounded local observation"}\n'); process.exitCode = 1; }
}
