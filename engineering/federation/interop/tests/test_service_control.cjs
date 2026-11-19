'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawnSync } = require('node:child_process');
const direct = require('../direct-transport.cjs');
const control = require('../service-control.cjs');

test('process ownership recognizes the observed Android duplicated executable and rejects other prefixes', () => {
  const exe = '/data/data/com.termux/files/usr/bin/node', expected = ['/owner/service.cjs', '_run', '/owner/state'];
  assert.equal(control.matchesProcessArguments([exe, ...expected], expected, exe, 'android'), true);
  assert.equal(control.matchesProcessArguments([exe, exe, ...expected], expected, exe, 'android'), true);
  assert.equal(control.matchesProcessArguments([exe, exe, ...expected], expected, exe, 'linux'), false);
  assert.equal(control.matchesProcessArguments([exe, '/other/node', ...expected], expected, exe, 'android'), false);
  assert.equal(control.matchesProcessArguments(['/other/node', ...expected], expected, exe, 'android'), false);
  assert.equal(control.matchesProcessArguments([exe, exe, ...expected, '--extra'], expected, exe, 'android'), false);
  assert.equal(control.matchesProcessArguments([exe, exe, expected[0], expected[1], '/other/state'], expected, exe, 'android'), false);
});

async function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mikaya-service-'));
  fs.chmodSync(root, 0o700);
  const a = path.join(root, 'a'), b = path.join(root, 'b');
  const A = direct.initialize(a), B = direct.initialize(b);
  const policy = { schema: 'mikaya.interop.distribution-policy.v1', policyId: 'explicit-service-test',
    unit: 'NONMONETARY_COMPUTE_UNIT', rates: [{ capability: 'compute.dot.v1', creditUnits: 1000 }, { capability: 'compute.sha256.v1', creditUnits: 1000 }],
    beneficiaries: [{ fingerprint: A.fingerprint, basisPoints: 5000 }, { fingerprint: B.fingerprint, basisPoints: 5000 }] };
  direct.pinPeer(a, B, policy); direct.pinPeer(b, A, policy);
  const reservation = net.createServer();
  await new Promise(resolve => reservation.listen({ host: '127.0.0.1', port: 0 }, resolve));
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  control.install(b, '127.0.0.1', port);
  t.after(async () => { try { await control.stop(b, true); } finally { fs.rmSync(root, { recursive: true, force: true }); } });
  return { root, a, b, A, B, port, dir: path.join(b, 'direct-transport') };
}

test('deployed supervisor serves authenticated work, starts idempotently, and stops persistently', async t => {
  const f = await fixture(t), initial = await control.start(f.b);
  assert.equal(initial.running, true); assert.equal(initial.sourceCurrent, true);
  const second = await control.start(f.b);
  assert.equal(second.supervisor.pid, initial.supervisor.pid);
  assert.equal((await direct.exercise({ stateDir: f.a, host: '127.0.0.1', port: f.port })).allVerified, true);
  const stopped = await control.stop(f.b);
  assert.equal(stopped.running, false); assert.equal(stopped.enabled, false);
  await assert.rejects(direct.connect({ stateDir: f.a, host: '127.0.0.1', port: f.port, timeoutMs: 1000 }));
  assert.equal((await control.main(['resume', f.b])).status, 'OWNER_DISABLED');
});

test('kill terminates active service and requires explicit clear then start', async t => {
  const f = await fixture(t); await control.start(f.b);
  const client = await direct.connect({ stateDir: f.a, host: '127.0.0.1', port: f.port });
  t.after(() => client.close());
  const killed = await control.stop(f.b, true);
  assert.equal(killed.killSwitch, true); assert.equal(killed.running, false);
  await assert.rejects(client.perform(direct.makeJob('compute.dot.v1')));
  await assert.rejects(control.start(f.b), /kill switch active/);
  const cleared = control.clearKill(f.b);
  assert.equal(cleared.killSwitch, false); assert.equal(cleared.enabled, false);
  assert.equal((await control.start(f.b)).running, true);
});

test('source inventory drift prevents startup but cannot disable the emergency stop control', async t => {
  const f = await fixture(t); await control.start(f.b);
  const file = path.join(f.dir, 'service-config.json'), cfg = JSON.parse(fs.readFileSync(file));
  cfg.sources[0].sha256 = '0'.repeat(64); fs.writeFileSync(file, JSON.stringify(cfg));
  assert.equal(control.inspect(f.b).sourceCurrent, false);
  await assert.rejects(control.start(f.b), /source changed/);
  const result = await control.stop(f.b, true);
  assert.equal(result.running, false); assert.equal(result.killSwitch, true);
});

test('damaged owner policy still permits emergency stop without silently repairing it', async t => {
  const f = await fixture(t); await control.start(f.b);
  const file = path.join(f.dir, 'owner-policy.json'); fs.writeFileSync(file, '{broken');
  const result = await control.stop(f.b, true);
  assert.equal(result.running, false); assert.equal(result.killSwitch, true);
  assert.equal(fs.readFileSync(file, 'utf8'), '{broken');
});

test('damaged or expired public certificate does not prevent local stop', async t => {
  const f = await fixture(t); await control.start(f.b);
  const file = path.join(f.dir, 'public-peer.json'), peer = JSON.parse(fs.readFileSync(file));
  peer.tlsCertificatePem = 'expired-or-damaged-certificate'; fs.writeFileSync(file, JSON.stringify(peer));
  assert.throws(() => direct.loadOwn(f.b));
  assert.equal((await control.stop(f.b, true)).running, false);
});

test('malformed public identity cannot block the emergency deny marker or process stop', async t => {
  const f = await fixture(t); await control.start(f.b);
  fs.writeFileSync(path.join(f.dir, 'public-peer.json'), '{broken');
  const result = await control.stop(f.b, true);
  assert.equal(result.running, false); assert.equal(result.killSwitch, true);
  assert.equal(result.processStopVerified, true);
});

test('malformed service configuration cannot block stopping the identified supervisor', async t => {
  const f = await fixture(t); await control.start(f.b);
  fs.writeFileSync(path.join(f.dir, 'service-config.json'), '{broken');
  const result = await control.stop(f.b, true);
  assert.equal(result.running, false); assert.equal(result.killSwitch, true);
  assert.equal(result.processStopVerified, true);
});

test('emergency kill loads and stops work even when the transport dependency has a syntax error', async t => {
  const f = await fixture(t); await control.start(f.b);
  const damaged = path.join(f.root, 'damaged-controller'); fs.mkdirSync(damaged, { mode: 0o700 });
  const controller = path.join(damaged, 'service-control.cjs');
  fs.copyFileSync(require.resolve('../service-control.cjs'), controller);
  fs.writeFileSync(path.join(damaged, 'direct-transport.cjs'), 'this is invalid JavaScript }');
  const run = spawnSync(process.execPath, [controller, 'kill', f.b], { encoding: 'utf8', timeout: 8000, maxBuffer: 8192 });
  assert.equal(run.status, 0, run.stderr); const result = JSON.parse(run.stdout);
  assert.equal(result.running, false); assert.equal(result.killSwitch, true);
  assert.equal(result.processStopVerified, true);
});

test('stale PID lock recovery never signals an unrelated live process', async t => {
  const f = await fixture(t);
  fs.writeFileSync(path.join(f.dir, 'server.lock'), JSON.stringify({ pid: process.pid }), { mode: 0o600, flag: 'wx' });
  assert.equal(control.inspect(f.b).worker.state, 'OTHER_PROCESS');
  assert.equal((await control.start(f.b)).running, true);
  assert.equal(process.kill(process.pid, 0), true);
  assert.equal(control.processState(process.pid, ['/a/different/program']), 'OTHER_PROCESS');
});

test('occupied network port cannot be reported as a ready service', async t => {
  const f = await fixture(t), occupied = net.createServer();
  await new Promise(resolve => occupied.listen({ host: '127.0.0.1', port: f.port }, resolve));
  t.after(() => new Promise(resolve => occupied.close(resolve)));
  await assert.rejects(control.start(f.b), /did not reach a running/);
  assert.equal(control.inspect(f.b).running, false);
});
