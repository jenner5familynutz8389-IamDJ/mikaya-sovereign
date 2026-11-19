#!/usr/bin/env node
'use strict';
/** Owner-local lifecycle for the pinned direct transport. No shell or root. */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
// Emergency stop must load even if transport source/dependencies are damaged.
function transport() { return require('./direct-transport.cjs'); }
const ENTRY = path.resolve(__dirname, 'direct-transport.cjs');
const SELF = path.resolve(__filename);
const FILES = ['service-control.cjs', 'direct-transport.cjs', 'capability-macaroons.cjs',
  'device-handoff.cjs', 'runtime-profile.cjs', 'session-adapter.cjs', 'ledger-receipts.cjs',
  '../live/federation-node.cjs', '../live/security-tollbooth.cjs', '../live/act-backend-compat.cjs'];
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
function ensure(ok, why) { if (!ok) throw new Error(why); }
function digest(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function privateDir(dir) {
  ensure(path.isAbsolute(dir), 'absolute state path required');
  const s = fs.lstatSync(dir);
  ensure(s.isDirectory() && !s.isSymbolicLink() && !(s.mode & 0o077), 'private state directory required');
  ensure(s.uid === process.getuid(), 'state ownership mismatch');
}
function directory(stateDir) { privateDir(stateDir); const d = path.join(stateDir, 'direct-transport'); privateDir(d); return d; }
function read(file) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const s = fs.fstatSync(fd);
    ensure(s.isFile() && s.uid === process.getuid() && !(s.mode & 0o077) && s.size <= 131072, 'unsafe service file');
    return JSON.parse(fs.readFileSync(fd, 'utf8'));
  } finally { fs.closeSync(fd); }
}
function write(file, value, exclusive = false) {
  const temporary = file + '.tmp-' + crypto.randomBytes(12).toString('hex');
  if (fs.existsSync(file)) { ensure(!exclusive, 'service configuration already exists'); read(file); }
  const target = exclusive ? file : temporary;
  const fd = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value) + '\n'); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  if (!exclusive) fs.renameSync(temporary, file);
  const parent = fs.openSync(path.dirname(file), fs.constants.O_RDONLY);
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
}
function sources() {
  return FILES.map(relative => {
    const file = path.resolve(__dirname, relative), s = fs.lstatSync(file);
    ensure(s.isFile() && !s.isSymbolicLink() && !(s.mode & 0o022) && s.size <= 1024 * 1024, 'unsafe executable source');
    const bytes = fs.readFileSync(file);
    return { relative, bytes: bytes.length, sha256: digest(bytes) };
  });
}
function loadConfig(stateDir, verifySources = true) {
  const cfg = read(path.join(directory(stateDir), 'service-config.json'));
  ensure(cfg.schema === 'mikaya.interop.service-config.v1' && cfg.stateDir === stateDir && cfg.entry === ENTRY && cfg.controller === SELF, 'service configuration target mismatch');
  transport().safeAddress(cfg.host);
  ensure(Number.isSafeInteger(cfg.port) && cfg.port >= 1024 && cfg.port <= 65535, 'unprivileged service port required');
  ensure(Array.isArray(cfg.sources) && cfg.sources.length === FILES.length, 'service source inventory missing');
  if (verifySources) ensure(JSON.stringify(cfg.sources) === JSON.stringify(sources()), 'service executable source changed; explicit reinstall required');
  return cfg;
}
function matchesProcessArguments(args, expected, executable = process.execPath, platform = process.platform) {
  if (!Array.isArray(args) || args[0] !== executable) return false;
  // Some Termux/Node launchers expose the executable twice in procfs argv.
  // Accept only that exact observed Android form, never arbitrary prefixes.
  const offset = platform === 'android' && args[1] === executable ? 2 : 1;
  return args.length === expected.length + offset && args.slice(offset).every((arg, i) => arg === expected[i]);
}
function processState(pid, expected) {
  if (!Number.isSafeInteger(pid) || pid <= 1) return 'INVALID';
  try {
    const raw = fs.readFileSync('/proc/' + pid + '/cmdline');
    if (raw.length > 16384) return 'OTHER_PROCESS';
    const args = raw.toString('utf8').split('\0').filter(Boolean);
    return matchesProcessArguments(args, expected) ? 'MATCH' : 'OTHER_PROCESS';
  } catch (e) { return e.code === 'ENOENT' || e.code === 'ESRCH' ? 'ABSENT' : 'UNKNOWN'; }
}
function processRecord(dir, kind, stateDir, cfg) {
  const supervisor = kind === 'supervisor';
  try {
    const row = read(path.join(dir, supervisor ? 'supervisor.json' : 'server.lock'));
    ensure(row !== null && typeof row === 'object' && !Array.isArray(row) &&
      row.schema === (supervisor ? 'mikaya.interop.supervisor.v1' : 'mikaya.interop.direct-server-lock.v1') &&
      Number.isSafeInteger(row.pid) && row.pid > 1, kind + ' metadata schema or PID invalid');
    if (supervisor) {
      ensure(typeof row.startedAt === 'string' && Number.isFinite(Date.parse(row.startedAt)), 'supervisor metadata start time invalid');
      return { pid: row.pid, state: processState(row.pid, [SELF, '_run', stateDir]), startedAt: row.startedAt };
    }
    ensure(Number.isSafeInteger(row.startedAtMs) && row.startedAtMs >= 0 && ['STARTING','READY'].includes(row.phase), 'worker metadata phase or time invalid');
    if (row.phase === 'READY' && cfg) ensure(row.host === cfg.host && row.port === cfg.port, 'worker metadata listener differs from current configuration');
    return { pid: row.pid, state: cfg ? processState(row.pid, [ENTRY, 'serve', stateDir, cfg.host, String(cfg.port)]) : 'UNKNOWN', phase: row.phase };
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    // Exclusive-create metadata is briefly visible before its complete write.
    // Unknown is neither absence nor ownership: polling may wait for completion,
    // but startup/stop must not infer permission to spawn or signal a process.
    return { state: 'UNKNOWN', ...(supervisor ? {} : { phase: 'UNKNOWN' }), metadataError: String(e.message).slice(0,160) };
  }
}
function inspect(stateDir) {
  const dir = directory(stateDir), cfg = loadConfig(stateDir, false);
  // Lifecycle inspection and emergency stop must remain usable after certificate
  // expiry or source drift. They need no private signing key or network access.
  const own = read(path.join(dir, 'public-peer.json'));
  let policy = null, policyError = null, sourceCurrent = false;
  try { policy = transport().validatePolicy(read(path.join(dir, 'owner-policy.json'))); }
  catch (e) { policyError = String(e.message).slice(0,160); }
  try { sourceCurrent = JSON.stringify(cfg.sources) === JSON.stringify(sources()); } catch {}
  const supervisor = processRecord(dir, 'supervisor', stateDir, cfg);
  const worker = processRecord(dir, 'worker', stateDir, cfg);
  const killSwitch = fs.existsSync(path.join(dir, 'kill-switch'));
  return { schema: 'mikaya.interop.service-status.v1', checkedAt: new Date().toISOString(),
    enabled: policy?.enabled === true, killSwitch, supervisor, worker, sourceCurrent, policyError,
    running: policy?.enabled === true && !killSwitch && supervisor?.state === 'MATCH' && worker?.state === 'MATCH' && worker.phase === 'READY',
    host: cfg.host, port: cfg.port, ownFingerprint: own.fingerprint, peerFingerprint: policy?.peerFingerprint || null,
    sourceSetSha256: digest(JSON.stringify(cfg.sources)), hardwareAttested: false, productionAdmission: false, paymentsAuthorized: false };
}
function install(stateDir, host, port) {
  const dir = directory(stateDir); transport().safeAddress(host);
  ensure(Number.isSafeInteger(port) && port >= 1024 && port <= 65535, 'unprivileged service port required');
  const own = transport().loadOwn(stateDir); transport().loadAuthority(own, false);
  write(path.join(dir, 'service-config.json'), { schema: 'mikaya.interop.service-config.v1', stateDir,
    entry: ENTRY, controller: SELF, host, port, sources: sources(), installedAt: new Date().toISOString() }, true);
  return inspect(stateDir);
}
function cleanupStale(stateDir, cfg) {
  const dir = directory(stateDir), lock = path.join(dir, 'server.lock');
  if (!fs.existsSync(lock)) return;
  const data = read(lock), state = processState(data.pid, [ENTRY, 'serve', stateDir, cfg.host, String(cfg.port)]);
  ensure(state === 'ABSENT' || state === 'OTHER_PROCESS', 'existing service lock is live or cannot be verified');
  // A reboot may reuse the PID. Never signal that unrelated process.
  fs.unlinkSync(lock);
}
async function supervise(stateDir) {
  const cfg = loadConfig(stateDir), dir = directory(stateDir), record = path.join(dir, 'supervisor.json');
  if (fs.existsSync(record)) {
    const prior = read(record), state = processState(prior.pid, [SELF, '_run', stateDir]);
    ensure(state === 'ABSENT' || state === 'OTHER_PROCESS', 'supervisor already active or inaccessible');
    fs.unlinkSync(record);
  }
  write(record, { schema: 'mikaya.interop.supervisor.v1', pid: process.pid, startedAt: new Date().toISOString() }, true);
  let stopping = false, child = null, crashes = 0;
  const stop = () => { stopping = true; if (child && child.exitCode === null) child.kill('SIGTERM'); };
  process.once('SIGTERM', stop); process.once('SIGINT', stop);
  try {
    while (!stopping) {
      loadConfig(stateDir);
      const own = transport().loadOwn(stateDir); transport().loadAuthority(own);
      cleanupStale(stateDir, cfg);
      const began = Date.now();
      child = spawn(process.execPath, [ENTRY, 'serve', stateDir, cfg.host, String(cfg.port)], { stdio: 'ignore', shell: false });
      await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
      child = null;
      if (stopping) break;
      // Explicit policy disable/kill exits here and is never automatically undone.
      transport().loadAuthority(transport().loadOwn(stateDir));
      crashes = Date.now() - began > 60000 ? 0 : crashes + 1;
      ensure(crashes <= 3, 'service restart budget exhausted');
      await delay(Math.min(1000 * (crashes + 1), 5000));
    }
  } finally {
    stop();
    try { if (read(record).pid === process.pid) fs.unlinkSync(record); } catch {}
  }
}
async function start(stateDir) {
  const cfg = loadConfig(stateDir), dir = directory(stateDir), previous = inspect(stateDir);
  if (previous.running) return previous;
  ensure(!previous.killSwitch, 'owner kill switch active; explicit clear-kill is required before start');
  for (const [name, row] of [['supervisor', previous.supervisor], ['worker', previous.worker]]) {
    ensure(row?.state !== 'UNKNOWN', name + ' metadata or process identity unknown; duplicate start refused');
    ensure(row?.state !== 'MATCH', name + ' still active');
  }
  transport().setEnabled(stateDir, true);
  const log = path.join(dir, 'supervisor-error.log');
  const fd = fs.openSync(log, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW, 0o600);
  const st = fs.fstatSync(fd);
  ensure(st.isFile() && !(st.mode & 0o077) && st.uid === process.getuid() && st.size < 65536, 'service error log requires owner review');
  const child = spawn(process.execPath, [SELF, '_run', stateDir], { detached: true, stdio: ['ignore', 'ignore', fd], shell: false });
  fs.closeSync(fd);
  await new Promise((resolve, reject) => { child.once('spawn', resolve); child.once('error', reject); });
  child.unref();
  for (let i = 0; i < 80; i++) {
    await delay(100);
    const status = inspect(stateDir);
    if (status.running) return status;
    if (processState(child.pid, [SELF, '_run', stateDir]) === 'ABSENT') break;
  }
  throw new Error('service did not reach a running process state; inspect private supervisor-error.log');
}
async function stop(stateDir, kill = false) {
  const dir = directory(stateDir), marker = path.join(dir, 'kill-switch'), alreadyKilled = fs.existsSync(marker);
  // Place the deny marker BEFORE parsing any certificate, config or policy.
  // The running worker checks this independently and drops active sessions.
  if (!alreadyKilled) write(marker, { enabledAt: new Date().toISOString() }, true);
  let policyDisabled = false, cfg = null;
  try {
    const file = path.join(dir, 'owner-policy.json'), policy = transport().validatePolicy(read(file));
    write(file, { ...policy, enabled: false });
    policyDisabled = true;
  } catch { /* Preserve corrupt policy for diagnosis; the deny marker remains. */ }
  try { cfg = loadConfig(stateDir, false); } catch {}
  function records() {
    return { supervisor: processRecord(dir, 'supervisor', stateDir, cfg), worker: processRecord(dir, 'worker', stateDir, cfg) };
  }
  const initial = records();
  for (const row of [initial.supervisor, initial.worker]) {
    if (row?.state === 'MATCH') { try { process.kill(row.pid, 'SIGTERM'); } catch (e) { if (e.code !== 'ESRCH') throw e; } }
  }
  for (let i = 0; i < 50; i++) {
    await delay(100);
    const current = records();
    if (![current.supervisor?.state, current.worker?.state].some(s => s === 'MATCH' || s === 'UNKNOWN')) {
      if (cfg) cleanupStale(stateDir, cfg);
      if (!kill && !alreadyKilled && policyDisabled) fs.unlinkSync(marker);
      try { return inspect(stateDir); }
      catch (e) { return { schema: 'mikaya.interop.service-stop.v1', checkedAt: new Date().toISOString(), running: false,
        enabled: false, killSwitch: fs.existsSync(marker), processStopVerified: true, metadataError: String(e.message).slice(0,160) }; }
    }
  }
  throw new Error('owner deny marker installed; process stop could not be verified; no unverified process was killed');
}
function clearKill(stateDir) {
  const dir = directory(stateDir), status = inspect(stateDir);
  ensure(!status.enabled && !status.running, 'disable service before clearing kill switch');
  ensure(![status.supervisor?.state, status.worker?.state].some(s => s === 'MATCH' || s === 'UNKNOWN'), 'process state must be verified stopped before clearing kill switch');
  const file = path.join(dir, 'kill-switch');
  if (fs.existsSync(file)) {
    const s = fs.lstatSync(file);
    ensure(s.isFile() && !s.isSymbolicLink() && s.uid === process.getuid() && !(s.mode & 0o077), 'unsafe kill marker');
    fs.unlinkSync(file);
  }
  return inspect(stateDir);
}
async function main(args = process.argv.slice(2)) {
  ensure(process.platform === 'linux' || process.platform === 'android', 'service lifecycle requires Linux or Android procfs');
  const [cmd, stateDir, host, port, ...rest] = args;
  ensure(stateDir && rest.length === 0, 'usage: service-control.cjs install|start|resume|stop|kill|clear-kill|status ABS_STATE [BIND_IP PORT]');
  if (cmd === 'install') { ensure(host && port, 'install requires private bind address and port'); return install(stateDir, host, Number(port)); }
  ensure(!host && !port, 'unexpected service arguments');
  if (cmd === 'start') return start(stateDir);
  if (cmd === 'resume') {
    const current = inspect(stateDir);
    if (!current.enabled || current.killSwitch || current.policyError) return { ...current, status: 'OWNER_DISABLED' };
    return start(stateDir);
  }
  if (cmd === 'stop' || cmd === 'kill') return stop(stateDir, cmd === 'kill');
  if (cmd === 'clear-kill') return clearKill(stateDir);
  if (cmd === 'status') return inspect(stateDir);
  if (cmd === '_run') { await supervise(stateDir); return undefined; }
  throw new Error('unknown service command');
}
if (require.main === module) main().then(result => { if (result !== undefined) console.log(JSON.stringify(result)); }).catch(e => { console.error(JSON.stringify({ status: 'REFUSED', reason: String(e.message).slice(0,200) })); process.exitCode = 1; });
module.exports = { install, start, stop, clearKill, inspect, processState, matchesProcessArguments, loadConfig, sources, main };
