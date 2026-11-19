'use strict';

// These tests use fixture property readers and temporary host directories.
// Passing them does not establish execution, attestation, or admission on a phone.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { inspectAndroid, PROPERTIES } = require('../android-preflight.cjs');

const installerSource = path.resolve(__dirname, '../install-termux.sh');
const hash = data => crypto.createHash('sha256').update(data).digest('hex');
const F110 = {
  'ro.product.model': 'F110 Pro',
  'ro.product.board': 'e393_qc_f10_w_6835_v0',
  'ro.board.platform': 'mt6835',
  'ro.build.version.release': '15',
  'ro.build.version.sdk': '35',
  'ro.product.cpu.abilist': 'arm64-v8a,armeabi-v7a,armeabi',
  'ro.product.cpu.abi': 'arm64-v8a',
};
const MOTOROLA = {
  ...F110,
  'ro.product.model': 'moto g power 5G - 2023',
  'ro.product.board': 'devonn',
  'ro.board.platform': 'mt6855',
  'ro.build.version.release': '14',
  'ro.build.version.sdk': '34',
};
function preflight(properties = F110, overrides = {}) {
  return inspectAndroid({
    propertyReader: property => properties[property] || '',
    fsProbe: file => ({ exists: !!file, readable: !!file, type: file ? 'directory' : null, error: null }),
    nodeVersion: '26.13.1', runtimeArch: 'arm64', runtimePlatform: 'android',
    environment: { PREFIX: '/fixture/termux/usr', HOME: '/fixture/termux/home' },
    sourceRoot: '/fixture/source', generatedAt: '2026-11-19T00:00:00.000Z',
    ...overrides,
  });
}

test('fixture F110 reports separate actual board properties and makes no attestation claim', () => {
  const result = preflight();
  assert.equal(result.device.productBoard, 'e393_qc_f10_w_6835_v0');
  assert.equal(result.device.boardPlatform, 'mt6835');
  assert.equal(result.device.profile.classification, 'documented-profile-match');
  assert.equal(result.compatibility.sourceRuntimeUsable, true);
  assert.equal(result.evidenceKind, 'fixture-or-injected-observation');
  assert.deepEqual(result.mutations, { files: false, keys: false, services: false, network: false });
  assert.equal(result.boundaries.hardwareAttestation, false);
  assert.equal(result.boundaries.ownerAuthorization, false);
  assert.equal(result.boundaries.collaborationAdmission, 'NOT_EVALUATED');
  assert.equal(result.boundaries.existingEvidencePort, 4188);
});

test('fixture Motorola never conflates product board devonn with platform mt6855', () => {
  const result = preflight(MOTOROLA);
  assert.equal(result.device.productBoard, 'devonn');
  assert.equal(result.device.boardPlatform, 'mt6855');
  assert.equal(result.device.apiLevel, 34);
  assert.equal(result.device.profile.id, 'moto-g-power-5g-2023');
  assert.equal(result.device.profile.classification, 'documented-profile-match');
});

test('unknown fixture hardware stays unreviewed with its original identifiers', () => {
  const result = preflight({ ...F110, 'ro.product.model': 'Unreviewed phone', 'ro.product.board': 'other-board', 'ro.board.platform': 'other-platform' });
  assert.equal(result.device.model, 'Unreviewed phone');
  assert.equal(result.device.productBoard, 'other-board');
  assert.equal(result.device.boardPlatform, 'other-platform');
  assert.equal(result.device.profile.id, null);
  assert.equal(result.device.profile.classification, 'unreviewed');
  assert.equal(result.compatibility.profileReviewNeeded, true);
});

test('known model with mismatching fixture board requires review instead of substitution', () => {
  const result = preflight({ ...MOTOROLA, 'ro.product.board': 'mt6855' });
  assert.equal(result.device.productBoard, 'mt6855');
  assert.equal(result.device.profile.classification, 'requires-review');
  assert.deepEqual(result.device.profile.differingFields, ['productBoard']);
});

test('missing fixture board platform is null and cannot pass profile review', () => {
  const result = preflight({ ...F110, 'ro.board.platform': '' });
  assert.equal(result.device.boardPlatform, null);
  assert.equal(result.compatibility.profileReviewNeeded, true);
});

test('property command failures yield bounded errors and no guessed fixture identity', () => {
  const seen = [];
  const result = preflight({}, { propertyReader: name => { seen.push(name); const e = new Error('private stderr must not appear'); e.code = 'ENOENT'; throw e; } });
  assert.deepEqual(seen.sort(), Object.values(PROPERTIES).sort());
  assert.equal(result.device.model, null);
  assert.equal(result.device.apiLevel, null);
  assert.equal(result.propertyErrors.length, Object.keys(PROPERTIES).length);
  assert.equal(JSON.stringify(result).includes('private stderr'), false);
  assert.ok(result.compatibility.blockers.includes('ANDROID_IDENTITY_PROPERTIES_UNAVAILABLE'));
});

test('fixture Node versions below 22 fail compatibility and Node 22 passes', () => {
  assert.ok(preflight(F110, { nodeVersion: '20.19.0' }).compatibility.blockers.includes('NODE_22_OR_NEWER_REQUIRED'));
  assert.equal(preflight(F110, { nodeVersion: '22.0.0' }).compatibility.sourceRuntimeUsable, true);
  assert.ok(preflight(F110, { nodeVersion: 'invalid' }).compatibility.blockers.includes('NODE_22_OR_NEWER_REQUIRED'));
});

test('fixture arm64 hardware with a 32-bit runtime remains blocked', () => {
  const result = preflight(F110, { runtimeArch: 'arm' });
  assert.ok(result.compatibility.blockers.includes('ARM64_RUNTIME_AND_ABI_REQUIRED'));
});

test('fixture unknown Android API is retained and requires an explicit compatibility test', () => {
  const result = preflight({ ...F110, 'ro.build.version.sdk': '36' });
  assert.equal(result.device.apiLevel, 36);
  assert.ok(result.compatibility.blockers.includes('ANDROID_API_REQUIRES_COMPATIBILITY_TEST'));
});

test('fixture primary ABI is used only when abilist is unavailable', () => {
  const result = preflight({ ...F110, 'ro.product.cpu.abilist': '' });
  assert.deepEqual(result.device.abiList, ['arm64-v8a']);
});

test('fixture nonabsolute prefix is rejected without inventing a Termux location', () => {
  const result = preflight(F110, { environment: { PREFIX: 'relative', HOME: '/fixture/home' } });
  assert.equal(result.paths.find(x => x.name === 'termux-prefix').path, null);
  assert.ok(result.compatibility.blockers.includes('ABSOLUTE_TERMUX_PREFIX_REQUIRED'));
});

test('fixture control characters in system properties are not emitted as device identities', () => {
  const result = preflight({ ...F110, 'ro.product.model': 'F110 Pro\nforged' });
  assert.equal(result.device.model, null);
  assert.ok(result.propertyErrors.some(x => x.property === 'ro.product.model'));
});

function installationFixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mikaya-delivery-fixture-'));
  const source = path.join(directory, "source with ' quote");
  const prefix = path.join(directory, "prefix with ' quote");
  const userHome = path.join(directory, 'home');
  const caller = path.join(directory, 'unrelated-cwd');
  const relativeInstaller = 'engineering/federation/collaboration/install-termux.sh';
  const relativeEntrypoint = 'engineering/federation/collaboration/gateway-adapter.cjs';
  const installer = path.join(source, relativeInstaller);
  const entrypoint = path.join(source, relativeEntrypoint);
  for (const item of [path.dirname(installer), path.join(prefix, 'bin'), path.join(prefix, 'lib'), userHome, caller]) fs.mkdirSync(item, { recursive: true, mode: 0o700 });
  fs.copyFileSync(installerSource, installer);
  fs.writeFileSync(entrypoint, `'use strict';process.stdout.write(JSON.stringify({fixture:true,version:1,args:process.argv.slice(2),cwd:process.cwd(),nodeOptions:process.env.NODE_OPTIONS||null})+'\\n');\n`);
  const sentinelState = path.join(userHome, 'existing-owner-key.fixture');
  const evidenceCommand = path.join(prefix, 'bin/mikaya-local-evidence');
  const serviceMarker = path.join(prefix, 'var/service/mikaya-mobile-evidence/down');
  fs.mkdirSync(path.dirname(serviceMarker), { recursive: true, mode: 0o700 });
  fs.writeFileSync(sentinelState, 'fixture-existing-key-do-not-replace');
  fs.writeFileSync(evidenceCommand, 'fixture-existing-evidence-command-do-not-replace');
  fs.writeFileSync(serviceMarker, 'fixture-default-down');
  const retained = [sentinelState, evidenceCommand, serviceMarker].map(file => ({ file, digest: hash(fs.readFileSync(file)) }));
  t.after(() => {
    try {
      for (const item of retained) assert.equal(hash(fs.readFileSync(item.file)), item.digest, `Existing fixture changed: ${item.file}`);
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  });
  let manifestCounter = 0;
  function writeManifest(mutator) {
    const value = { schema: 'mikaya.collaboration.source-manifest.v1', entrypoint: relativeEntrypoint, files: [relativeEntrypoint, relativeInstaller].map(file => ({ path: file, sha256: hash(fs.readFileSync(path.join(source, file))) })) };
    if (mutator) mutator(value);
    const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
    const file = path.join(directory, `manifest-${manifestCounter++}.json`);
    fs.writeFileSync(file, bytes);
    return { file, digest: hash(bytes), value };
  }
  const manifest = writeManifest();
  const env = { ...process.env, PREFIX: prefix, HOME: userHome, PATH: `${path.dirname(process.execPath)}:${process.env.PATH || ''}` };
  function invoke(args, extra = {}) {
    return spawnSync('bash', [installer, ...args], { cwd: caller, env, encoding: 'utf8', timeout: 15000, ...extra });
  }
  function manifestArgs(mode = '--install', m = manifest) { return [mode, '--manifest', m.file, '--manifest-sha256', m.digest]; }
  function install(m = manifest) {
    const result = invoke(manifestArgs('--install', m));
    assert.equal(result.status, 0, result.stderr || result.error?.message);
    return JSON.parse(result.stdout);
  }
  const root = path.join(prefix, 'lib/mikaya-collaboration');
  const command = path.join(prefix, 'bin/mikaya-collaboration');
  return { directory, source, prefix, userHome, caller, installer, entrypoint, relativeEntrypoint, root, command, env, manifest, invoke, install, manifestArgs, writeManifest };
}

test('host installer fixture --check verifies hashes without creating installation or state', t => {
  const f = installationFixture(t);
  const result = f.invoke(f.manifestArgs('--check'));
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).readOnly, true);
  assert.equal(fs.existsSync(f.root), false);
  assert.equal(fs.existsSync(f.command), false);
});

test('host installer fixture creates a fixed-path command usable from any cwd with quoted paths', t => {
  const f = installationFixture(t);
  const receipt = f.install();
  assert.equal(receipt.stateInitialized, false);
  assert.equal(receipt.servicesStarted, false);
  assert.equal(receipt.ownerKeysTouched, false);
  assert.equal(receipt.signaturesVerified, false);
  const execution = spawnSync(f.command, ['status', '--directory', '/fixture/absolute-state'], { cwd: '/', env: f.env, encoding: 'utf8', timeout: 10000 });
  assert.equal(execution.status, 0, execution.stderr);
  const body = JSON.parse(execution.stdout);
  assert.equal(body.fixture, true);
  assert.equal(body.cwd, '/');
  assert.deepEqual(body.args, ['status', '--directory', '/fixture/absolute-state']);
  assert.equal(body.nodeOptions, null);
  assert.equal(fs.statSync(f.command).mode & 0o777, 0o700);
});

test('host installer fixture can reinstall identical source without reinitializing state', t => {
  const f = installationFixture(t);
  const first = f.install();
  const second = f.install();
  assert.equal(first.manifestSha256, second.manifestSha256);
  assert.equal(fs.readdirSync(path.join(f.root, 'releases')).length, 1);
  const status = f.invoke(['--status']);
  assert.equal(status.status, 0, status.stderr);
  assert.equal(JSON.parse(status.stdout).integrityChecked, true);
});

test('host installer fixture rejects an incorrect manifest hash before all writes', t => {
  const f = installationFixture(t);
  const result = f.invoke(['--install', '--manifest', f.manifest.file, '--manifest-sha256', '0'.repeat(64)]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Manifest SHA-256/);
  assert.equal(fs.existsSync(f.root), false);
});

test('host installer fixture rejects modified source bytes before creating a release', t => {
  const f = installationFixture(t);
  fs.appendFileSync(f.entrypoint, '\n// changed\n');
  const result = f.invoke(f.manifestArgs());
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Source SHA-256 mismatch/);
  assert.equal(fs.existsSync(f.root), false);
});

test('host installer fixture refuses path traversal in an otherwise hash-matched manifest', t => {
  const f = installationFixture(t);
  const invalid = f.writeManifest(value => { value.files.push({ path: '../existing-owner-key.fixture', sha256: '0'.repeat(64) }); });
  const result = f.invoke(f.manifestArgs('--install', invalid));
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Unsafe manifest source path/);
  assert.equal(fs.existsSync(f.root), false);
});

test('host installer fixture refuses symlink source files even when target bytes match', t => {
  const f = installationFixture(t);
  const outside = path.join(f.directory, 'outside.cjs');
  fs.renameSync(f.entrypoint, outside);
  fs.symlinkSync(outside, f.entrypoint);
  const result = f.invoke(f.manifestArgs());
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /regular file/);
  assert.equal(fs.existsSync(f.root), false);
});

test('host installer fixture preserves an unrelated command and refuses adoption', t => {
  const f = installationFixture(t);
  const bytes = Buffer.from('unrelated owner command\n');
  fs.writeFileSync(f.command, bytes);
  const result = f.invoke(f.manifestArgs());
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unrelated or modified command/);
  assert.deepEqual(fs.readFileSync(f.command), bytes);
  assert.equal(fs.existsSync(f.root), false);
});

test('host installer fixture never adopts or clears an existing unowned installation directory', t => {
  const f = installationFixture(t);
  fs.mkdirSync(f.root);
  const bytes = Buffer.from('owner-state-must-survive\n');
  const existing = path.join(f.root, 'state.json');
  fs.writeFileSync(existing, bytes);
  const result = f.invoke(f.manifestArgs());
  assert.notEqual(result.status, 0);
  assert.deepEqual(fs.readFileSync(existing), bytes);
  assert.equal(fs.existsSync(path.join(f.root, 'releases')), false);
});

test('host installed command fixture refuses source tampering before executing entrypoint', t => {
  const f = installationFixture(t);
  f.install();
  const installed = path.join(f.root, 'releases', f.manifest.digest, 'source', f.relativeEntrypoint);
  fs.chmodSync(installed, 0o600);
  fs.appendFileSync(installed, '// tampered\n');
  const result = spawnSync(f.command, ['status'], { cwd: f.caller, env: f.env, encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /SOURCE_CHANGED/);
  assert.equal(result.stdout, '');
});

test('host installed command fixture refuses an unlisted installed source file', t => {
  const f = installationFixture(t);
  f.install();
  fs.writeFileSync(path.join(f.root, 'releases', f.manifest.digest, 'source', 'unlisted.cjs'), 'throw Error("must not run")');
  const result = spawnSync(f.command, ['status'], { cwd: f.caller, env: f.env, encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /UNLISTED_SOURCE/);
});

test('host installer fixture rolls back only the command and retains both source releases', t => {
  const f = installationFixture(t);
  f.install();
  fs.writeFileSync(f.entrypoint, `'use strict';process.stdout.write(JSON.stringify({fixture:true,version:2})+'\\n');\n`);
  const second = f.writeManifest();
  f.install(second);
  const before = spawnSync(f.command, [], { env: f.env, encoding: 'utf8' });
  assert.equal(JSON.parse(before.stdout).version, 2);
  const rollback = f.invoke(['--rollback', '--release', f.manifest.digest]);
  assert.equal(rollback.status, 0, rollback.stderr);
  const after = spawnSync(f.command, [], { env: f.env, encoding: 'utf8' });
  assert.equal(JSON.parse(after.stdout).version, 1);
  assert.equal(fs.readdirSync(path.join(f.root, 'releases')).length, 2);
});

test('host installer fixture removes only its command and retains release and receipt', t => {
  const f = installationFixture(t);
  f.install();
  const result = f.invoke(['--remove-command']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.existsSync(f.command), false);
  assert.equal(fs.existsSync(path.join(f.root, 'releases', f.manifest.digest, 'manifest.json')), true);
  assert.equal(fs.existsSync(path.join(f.root, 'current.json')), true);
  const status = f.invoke(['--status']);
  assert.equal(status.status, 0, status.stderr);
  assert.equal(JSON.parse(status.stdout).commandPresent, false);
  assert.equal(JSON.parse(status.stdout).sourceInstalled, true);
});

test('host installer fixture refuses removal of a command changed since installation', t => {
  const f = installationFixture(t);
  f.install();
  const bytes = Buffer.from('owner-edited-command\n');
  fs.writeFileSync(f.command, bytes);
  const result = f.invoke(['--remove-command']);
  assert.notEqual(result.status, 0);
  assert.deepEqual(fs.readFileSync(f.command), bytes);
});

test('host installer fixture never steals or clears an existing installation lock', t => {
  const f = installationFixture(t);
  f.install();
  const lock = path.join(f.root, '.install-lock');
  fs.mkdirSync(lock);
  const sentinel = path.join(lock, 'owner.fixture');
  fs.writeFileSync(sentinel, 'other-installer-fixture');
  const result = f.invoke(f.manifestArgs());
  assert.notEqual(result.status, 0);
  assert.equal(fs.readFileSync(sentinel, 'utf8'), 'other-installer-fixture');
});

test('host installer fixture rejects reset, force, state initialization, and autostart switches', t => {
  const f = installationFixture(t);
  for (const argument of ['--reset', '--force', '--init', '--start', '--autostart']) {
    const result = f.invoke([...f.manifestArgs(), argument]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Unknown installer argument/);
  }
  assert.equal(fs.existsSync(f.root), false);
});
