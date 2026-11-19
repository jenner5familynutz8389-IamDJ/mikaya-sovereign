#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
umask 077
unset NODE_OPTIONS NODE_PATH

# Explicit source installation only. No pkg, su, sudo, service, boot, or network
# commands are invoked. Invoke with bash on a host fixture or a Termux device.
MIKAYA_NODE_BIN="$(command -v node || true)"
if [[ -z "$MIKAYA_NODE_BIN" ]]; then
  printf '%s\n' 'Node.js 22 or newer must already be installed.' >&2
  exit 2
fi

"$MIKAYA_NODE_BIN" - "${BASH_SOURCE[0]}" "$@" <<'MIKAYA_INSTALL_NODE'
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const SCHEMA = 'mikaya.collaboration.source-manifest.v1';
const OWNER_SCHEMA = 'mikaya.collaboration.source-installation.v1';
const CURRENT_SCHEMA = 'mikaya.collaboration.installed-command.v1';
const PREFIX_MARKER = '# mikaya-collaboration managed wrapper v1';
const MODES = new Set(['--check', '--install', '--status', '--rollback', '--remove-command']);
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES = 64 * 1024 * 1024;
let heldLock = null;
let stagedDirectory = null;

function fail(message) { throw new Error(message); }
function hash(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function exists(file) { try { fs.lstatSync(file); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } }
function statRegular(file, maxBytes = MAX_FILE_BYTES) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) fail(`Expected a regular file: ${file}`);
  if (stat.size > maxBytes) fail(`File exceeds the size limit: ${file}`);
  return stat;
}
function readRegular(file, maxBytes) { statRegular(file, maxBytes); return fs.readFileSync(file); }
function parseJson(bytes, label) {
  try { return JSON.parse(bytes.toString('utf8')); }
  catch { fail(`Invalid JSON in ${label}`); }
}
function assertDirectory(directory) {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`Expected a real directory: ${directory}`);
}
function ensureDirectory(directory) {
  if (!exists(directory)) fs.mkdirSync(directory, { mode: 0o700 });
  assertDirectory(directory);
}
function atomicWrite(file, bytes, mode) {
  if (exists(file)) statRegular(file, MAX_MANIFEST_BYTES);
  const temp = `${file}.tmp-${crypto.randomBytes(12).toString('hex')}`;
  try {
    fs.writeFileSync(temp, bytes, { flag: 'wx', mode });
    const fd = fs.openSync(temp, 'r');
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(temp, file);
  } finally { if (exists(temp)) fs.unlinkSync(temp); }
}
function relativeSourcePath(value) {
  if (typeof value !== 'string' || !value || value.length > 512 || /[\x00-\x1f\x7f\\]/.test(value)) fail('Invalid manifest source path');
  if (path.posix.isAbsolute(value) || value.split('/').some(part => !part || part === '.' || part === '..')) fail(`Unsafe manifest source path: ${value}`);
  if (value.split('/').some(part => ['.git', 'node_modules', '.ssh', '.gnupg'].includes(part))) fail(`Non-source directory in manifest: ${value}`);
  return value;
}
function inspectManifest(bytes, expectedHash) {
  if (!/^[a-f0-9]{64}$/.test(expectedHash || '')) fail('An explicit lowercase 64-character --manifest-sha256 is required');
  if (hash(bytes) !== expectedHash) fail('Manifest SHA-256 does not match the independently supplied expected value');
  const manifest = parseJson(bytes, 'source manifest');
  if (!manifest || manifest.schema !== SCHEMA || !Array.isArray(manifest.files)) fail(`Manifest schema must be ${SCHEMA}`);
  if (!manifest.files.length || manifest.files.length > 512) fail('Manifest must contain between 1 and 512 source files');
  const seen = new Set();
  for (const file of manifest.files) {
    if (!file || typeof file !== 'object') fail('Invalid manifest file record');
    relativeSourcePath(file.path);
    if (seen.has(file.path)) fail(`Duplicate manifest source path: ${file.path}`);
    seen.add(file.path);
    if (!/^[a-f0-9]{64}$/.test(file.sha256 || '')) fail(`Invalid source SHA-256: ${file.path}`);
  }
  relativeSourcePath(manifest.entrypoint);
  if (!manifest.entrypoint.startsWith('engineering/federation/collaboration/') || !manifest.entrypoint.endsWith('.cjs')) fail('Entrypoint must be a collaboration .cjs source file');
  if (!seen.has(manifest.entrypoint)) fail('Entrypoint is not covered by the manifest');
  return manifest;
}
function sourceFile(root, relative) {
  const parts = relativeSourcePath(relative).split('/');
  let current = root;
  for (let index = 0; index < parts.length; index++) {
    current = path.join(current, parts[index]);
    if (index + 1 < parts.length) assertDirectory(current);
    else statRegular(current);
  }
  return current;
}
function readAndVerifySources(root, manifest) {
  const sources = [];
  let totalBytes = 0;
  for (const file of manifest.files) {
    const source = sourceFile(root, file.path);
    const bytes = readRegular(source);
    totalBytes += bytes.length;
    if (totalBytes > MAX_TOTAL_BYTES) fail('Manifest source files exceed the total size limit');
    if (hash(bytes) !== file.sha256) fail(`Source SHA-256 mismatch: ${file.path}`);
    sources.push({ ...file, bytes });
  }
  return { sources, totalBytes };
}
function assertExactSourceInventory(root, manifest) {
  const expected = new Set(manifest.files.map(file => file.path));
  function walk(directory, relative = '') {
    assertDirectory(directory);
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const entryRelative = relative ? `${relative}/${entry.name}` : entry.name;
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(full, entryRelative);
      else if (entry.isFile() && expected.has(entryRelative)) expected.delete(entryRelative);
      else fail(`Unlisted or unsafe installed source entry: ${entryRelative}`);
    }
  }
  walk(root);
  if (expected.size) fail('Installed source inventory is incomplete');
}
function verifyRelease(root, releaseHash) {
  if (!/^[a-f0-9]{64}$/.test(releaseHash || '')) fail('Invalid release SHA-256');
  const directory = path.join(root, 'releases', releaseHash);
  assertDirectory(path.join(root, 'releases'));
  assertDirectory(directory);
  const manifestBytes = readRegular(path.join(directory, 'manifest.json'), MAX_MANIFEST_BYTES);
  const manifest = inspectManifest(manifestBytes, releaseHash);
  const sourceRoot = path.join(directory, 'source');
  assertDirectory(sourceRoot);
  readAndVerifySources(sourceRoot, manifest);
  assertExactSourceInventory(sourceRoot, manifest);
  return { directory, manifest, sourceRoot };
}
function checkOwnedRoot(root, prefix) {
  if (!exists(root)) return false;
  assertDirectory(root);
  const marker = parseJson(readRegular(path.join(root, 'installation.json'), MAX_MANIFEST_BYTES), 'installation marker');
  if (marker.schema !== OWNER_SCHEMA || marker.prefix !== prefix) fail('Existing installation directory is not owned by this installer and prefix');
  return true;
}
function readCurrent(root) {
  const file = path.join(root, 'current.json');
  if (!exists(file)) return null;
  const current = parseJson(readRegular(file, MAX_MANIFEST_BYTES), 'current command receipt');
  if (!current || current.schema !== CURRENT_SCHEMA || !/^[a-f0-9]{64}$/.test(current.wrapperSha256 || '')) fail('Invalid installed command receipt');
  return current;
}
function checkCommandOwnership(command, current) {
  if (!exists(command)) return null;
  const bytes = readRegular(command, MAX_MANIFEST_BYTES);
  if (!current || hash(bytes) !== current.wrapperSha256 || !bytes.toString('utf8').includes(PREFIX_MARKER)) fail('Refusing to replace or remove an unrelated or modified command');
  return bytes;
}
function shellQuote(value) { return `'${String(value).replace(/'/g, `'\\''`)}'`; }
function runtimeVerifier(sourceRoot, releaseHash, manifestFile) {
  // This verifier is embedded in the fixed-path wrapper so a later accidental
  // source edit cannot silently become the executable release. Its digest is
  // itself retained in current.json. This is integrity checking, not a signature.
  return `const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');` +
    `const root=${JSON.stringify(sourceRoot)},manifestFile=${JSON.stringify(manifestFile)},expected=${JSON.stringify(releaseHash)};` +
    `const digest=b=>crypto.createHash('sha256').update(b).digest('hex');` +
    `const regular=p=>{const s=fs.lstatSync(p);if(!s.isFile()||s.isSymbolicLink()||s.size>${MAX_FILE_BYTES})throw Error('SOURCE_FILE_UNSAFE');};` +
    `try{if(Number(process.versions.node.split('.')[0])<22)throw Error('NODE_22_REQUIRED');` +
    `regular(manifestFile);const raw=fs.readFileSync(manifestFile);if(digest(raw)!==expected)throw Error('MANIFEST_CHANGED');` +
    `const m=JSON.parse(raw);if(m.schema!==${JSON.stringify(SCHEMA)}||!Array.isArray(m.files))throw Error('MANIFEST_INVALID');` +
    `const paths=new Set();for(const f of m.files){if(typeof f.path!=='string'||f.path.split('/').some(p=>!p||p==='.'||p==='..')||f.path.includes('\\\\')||paths.has(f.path))throw Error('SOURCE_PATH_UNSAFE');paths.add(f.path);` +
    `let p=root;const parts=f.path.split('/');for(let i=0;i<parts.length;i++){p=path.join(p,parts[i]);if(i<parts.length-1){const s=fs.lstatSync(p);if(!s.isDirectory()||s.isSymbolicLink())throw Error('SOURCE_DIRECTORY_UNSAFE');}}` +
    `regular(p);if(digest(fs.readFileSync(p))!==f.sha256)throw Error('SOURCE_CHANGED');}` +
    `const walk=(p,r='')=>{const s=fs.lstatSync(p);if(!s.isDirectory()||s.isSymbolicLink())throw Error('SOURCE_DIRECTORY_UNSAFE');for(const d of fs.readdirSync(p,{withFileTypes:true})){const rel=r?r+'/'+d.name:d.name;if(d.isDirectory())walk(path.join(p,d.name),rel);else if(d.isFile()&&paths.has(rel))paths.delete(rel);else throw Error('UNLISTED_SOURCE');}};walk(root);if(paths.size)throw Error('SOURCE_MISSING');` +
    `}catch(e){process.stderr.write('MIKAYA_COLLABORATION_SOURCE_HOLD: '+e.message+'\\n');process.exit(2);}`;
}
function activate(root, prefix, releaseHash, nodeExecutable) {
  const release = verifyRelease(root, releaseHash);
  const command = path.join(prefix, 'bin', 'mikaya-collaboration');
  const oldCurrent = readCurrent(root);
  const oldBytes = checkCommandOwnership(command, oldCurrent);
  const shell = exists('/system/bin/sh') ? '/system/bin/sh' : '/bin/sh';
  statRegular(fs.realpathSync(shell));
  const entrypoint = path.join(release.sourceRoot, release.manifest.entrypoint);
  const verifier = runtimeVerifier(release.sourceRoot, releaseHash, path.join(release.directory, 'manifest.json'));
  const bytes = Buffer.from(`#!${shell}\n${PREFIX_MARKER}\n# Source delivery only; execution requires an explicit CLI verb.\nunset NODE_OPTIONS NODE_PATH\n${shellQuote(nodeExecutable)} -e ${shellQuote(verifier)} || exit $?\nexec ${shellQuote(nodeExecutable)} ${shellQuote(entrypoint)} "$@"\n`);
  const current = {
    schema: CURRENT_SCHEMA, manifestSha256: releaseHash,
    entrypoint, nodeExecutable, wrapperSha256: hash(bytes),
    activatedAt: new Date().toISOString(),
    previousManifestSha256: oldCurrent ? oldCurrent.manifestSha256 : null,
    stateInitialized: false, servicesStarted: false,
  };
  atomicWrite(command, bytes, 0o700);
  try { atomicWrite(path.join(root, 'current.json'), `${JSON.stringify(current, null, 2)}\n`, 0o600); }
  catch (error) {
    if (oldBytes) atomicWrite(command, oldBytes, 0o700);
    else if (exists(command) && hash(readRegular(command)) === hash(bytes)) fs.unlinkSync(command);
    throw error;
  }
  return { command, ...current };
}
function usage() {
  process.stdout.write(`MIKAYA collaboration source installer (Node 22+)\n\n` +
    `  bash /absolute/path/install-termux.sh --check --manifest /absolute/manifest.json --manifest-sha256 SHA256\n` +
    `  bash /absolute/path/install-termux.sh --install --manifest /absolute/manifest.json --manifest-sha256 SHA256\n` +
    `  bash /absolute/path/install-termux.sh --status\n` +
    `  bash /absolute/path/install-termux.sh --rollback --release PREVIOUS_MANIFEST_SHA256\n` +
    `  bash /absolute/path/install-termux.sh --remove-command\n\n` +
    `PREFIX supplies the existing Termux prefix; --prefix /absolute/prefix overrides it.\n` +
    `Source root is derived from this script's real location, never from the working directory.\n` +
    `No state initialization, owner-key changes, packages, firmware, services, network, or boot activation.\n`);
}

try {
  const installerPath = fs.realpathSync(process.argv[2]);
  const args = process.argv.slice(3);
  if (!args.length || args.includes('--help')) { usage(); process.exitCode = 0; }
  else {
    if (Number(process.versions.node.split('.')[0]) < 22) fail('Node.js 22 or newer is required');
    const options = {};
    let mode = null;
    for (let index = 0; index < args.length; index++) {
      const argument = args[index];
      if (MODES.has(argument)) {
        if (mode) fail('Choose exactly one installer mode');
        mode = argument;
      } else if (['--manifest', '--manifest-sha256', '--prefix', '--release'].includes(argument)) {
        if (Object.hasOwn(options, argument) || !args[index + 1] || args[index + 1].startsWith('--')) fail(`A single value is required for ${argument}`);
        options[argument] = args[++index];
      } else fail(`Unknown installer argument: ${argument}`);
    }
    if (!mode) fail('An explicit installer mode is required');
    const requestedPrefix = options['--prefix'] || process.env.PREFIX;
    if (!requestedPrefix || !path.isAbsolute(requestedPrefix) || /[\x00-\x1f\x7f]/.test(requestedPrefix)) fail('PREFIX or --prefix must name an existing absolute prefix');
    const prefix = fs.realpathSync(requestedPrefix);
    assertDirectory(prefix);
    assertDirectory(path.join(prefix, 'bin'));
    assertDirectory(path.join(prefix, 'lib'));
    const root = path.join(prefix, 'lib', 'mikaya-collaboration');
    const command = path.join(prefix, 'bin', 'mikaya-collaboration');
    const sourceRoot = path.resolve(path.dirname(installerPath), '../../..');
    const nodeExecutable = fs.realpathSync(process.execPath);
    let manifest;
    let manifestBytes;
    let bundle;
    if (mode === '--check' || mode === '--install') {
      if (!options['--manifest'] || !path.isAbsolute(options['--manifest'])) fail('--manifest must be an absolute path');
      manifestBytes = readRegular(options['--manifest'], MAX_MANIFEST_BYTES);
      manifest = inspectManifest(manifestBytes, options['--manifest-sha256']);
      bundle = readAndVerifySources(sourceRoot, manifest);
    } else if (options['--manifest'] || options['--manifest-sha256']) fail('Manifest arguments apply only to --check and --install');
    if (mode !== '--rollback' && options['--release']) fail('--release applies only to --rollback');
    if (mode === '--check') {
      const owned = checkOwnedRoot(root, prefix);
      checkCommandOwnership(command, owned ? readCurrent(root) : null);
      process.stdout.write(`${JSON.stringify({ ok: true, mode, manifestSha256: options['--manifest-sha256'], sourceRoot, prefix, fileCount: bundle.sources.length, totalBytes: bundle.totalBytes, readOnly: true, signaturesVerified: false }, null, 2)}\n`);
    } else if (mode === '--status') {
      const owned = checkOwnedRoot(root, prefix);
      const current = owned ? readCurrent(root) : null;
      if (current) verifyRelease(root, current.manifestSha256);
      const commandBytes = checkCommandOwnership(command, current);
      process.stdout.write(`${JSON.stringify({ ok: true, mode, sourceInstalled: !!current, commandPresent: !!commandBytes, integrityChecked: !!current, current, readOnly: true }, null, 2)}\n`);
    } else {
      // Validate existing ownership before making any change. Never adopt an
      // arbitrary preexisting directory, key file, state directory, or command.
      const alreadyOwned = checkOwnedRoot(root, prefix);
      checkCommandOwnership(command, alreadyOwned ? readCurrent(root) : null);
      if (!alreadyOwned) {
        if (mode !== '--install') fail('There is no managed source installation');
        fs.mkdirSync(root, { mode: 0o700 });
        atomicWrite(path.join(root, 'installation.json'), `${JSON.stringify({ schema: OWNER_SCHEMA, prefix, createdAt: new Date().toISOString(), scope: 'versioned-source-and-command-only' }, null, 2)}\n`, 0o600);
      }
      const lock = path.join(root, '.install-lock');
      fs.mkdirSync(lock, { mode: 0o700 });
      heldLock = lock;
      ensureDirectory(path.join(root, 'releases'));
      if (mode === '--remove-command') {
        const current = readCurrent(root);
        const commandBytes = checkCommandOwnership(command, current);
        if (commandBytes) fs.unlinkSync(command);
        process.stdout.write(`${JSON.stringify({ ok: true, mode, commandRemoved: !!commandBytes, releasesPreserved: true, stateTouched: false, servicesStopped: false }, null, 2)}\n`);
      } else {
        const releaseHash = mode === '--rollback' ? options['--release'] : options['--manifest-sha256'];
        if (!/^[a-f0-9]{64}$/.test(releaseHash || '')) fail('A valid release SHA-256 is required');
        const releaseDirectory = path.join(root, 'releases', releaseHash);
        if (mode === '--install' && !exists(releaseDirectory)) {
          stagedDirectory = path.join(root, `staging-${crypto.randomBytes(16).toString('hex')}`);
          fs.mkdirSync(stagedDirectory, { mode: 0o700 });
          const stagedSource = path.join(stagedDirectory, 'source');
          fs.mkdirSync(stagedSource, { mode: 0o700 });
          for (const file of bundle.sources) {
            const destination = path.join(stagedSource, file.path);
            fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
            fs.writeFileSync(destination, file.bytes, { flag: 'wx', mode: file.path.endsWith('.sh') ? 0o500 : 0o400 });
          }
          fs.writeFileSync(path.join(stagedDirectory, 'manifest.json'), manifestBytes, { flag: 'wx', mode: 0o400 });
          assertExactSourceInventory(stagedSource, manifest);
          readAndVerifySources(stagedSource, manifest);
          fs.renameSync(stagedDirectory, releaseDirectory);
          stagedDirectory = null;
        }
        const activation = activate(root, prefix, releaseHash, nodeExecutable);
        process.stdout.write(`${JSON.stringify({ ok: true, mode, ...activation, ownerKeysTouched: false, existingEvidencePort: 4188, signaturesVerified: false }, null, 2)}\n`);
      }
    }
  }
} catch (error) {
  process.stderr.write(`${JSON.stringify({ ok: false, error: error.message })}\n`);
  process.exitCode = 1;
} finally {
  // Only paths created by this invocation are removed. Existing releases,
  // collaboration runtime state, ledgers, certificates, and keys are untouched.
  if (stagedDirectory && exists(stagedDirectory)) fs.rmSync(stagedDirectory, { recursive: true, force: false });
  if (heldLock && exists(heldLock)) fs.rmdirSync(heldLock);
}
MIKAYA_INSTALL_NODE
