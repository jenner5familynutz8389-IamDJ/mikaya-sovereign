'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const cli = path.resolve(__dirname, '../device-handoff.cjs');
function invoke(command, dir, input, expectedExit = 0) {
  const args = [cli, command, dir];
  let file;
  if (input) {
    file = path.join(path.dirname(dir), 'packet-' + Math.random().toString(16).slice(2) + '.json');
    fs.writeFileSync(file, JSON.stringify(input), { mode: 0o600, flag: 'wx' });
    args.push(file);
  }
  const r = cp.spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 15000, maxBuffer: 262144 });
  if (file) fs.unlinkSync(file);
  assert.equal(r.status, expectedExit, r.stderr || String(r.error || ''));
  return JSON.parse((expectedExit ? r.stderr : r.stdout).trim());
}
test('separate processes complete both directions with no secret keys in public packets', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mikaya-public-handoff-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const aDir = path.join(root, 'a'), bDir = path.join(root, 'b');
  const a = invoke('init', aDir), b = invoke('init', bDir);
  assert.notEqual(a.fingerprint, b.fingerprint);
  for (const [holder, worker, workerPublic] of [[aDir, bDir, b], [bDir, aDir, a]]) {
    const job = { schema: 'mikaya.federation.job.v1', id: '1234567890abcdef1234567890abcdef', capability: 'compute.dot.v1', payload: { a: [1, 2, 3], b: [4, 5, 6] } };
    const request = invoke('request', holder, { workerPublicKey: workerPublic.publicKey, job });
    const grant = invoke('grant', worker, request);
    const response = invoke('respond', worker, grant);
    const verified = invoke('verify', holder, response);
    assert.equal(verified.result.verified, true);
    assert.equal(verified.result.evidenceVerified, true);
    assert.equal(verified.targetProfileSha256, workerPublic.profileSha256);
    assert.equal(verified.result.result, 32);
    assert.equal(verified.hardwareAttested, false);
    assert.equal(verified.productionAdmission, false);
    assert.doesNotMatch(JSON.stringify([a, b, request, grant, response, verified]), /PRIVATE KEY|rootKeyHex/);
    assert.match(invoke('respond', worker, grant, 1).reason, /replay|nonce|consumed/);
  }
  assert.match(invoke('init', aDir, null, 1).reason, /EEXIST/);
});
test('public handoff rejects substituted profile evidence and unknown packet fields', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mikaya-handoff-evidence-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const aDir = path.join(root, 'a'), bDir = path.join(root, 'b');
  invoke('init', aDir); const b = invoke('init', bDir);
  const job = { schema: 'mikaya.federation.job.v1', id: 'abcdef1234567890abcdef1234567890', capability: 'compute.sha256.v1', payload: { challengeHex: 'a'.repeat(64) } };
  assert.match(invoke('request', aDir, { workerPublicKey: b.publicKey, job, unexpected: true }, 1).reason, /packet schema/);
  const request = invoke('request', aDir, { workerPublicKey: b.publicKey, job });
  assert.match(invoke('grant', bDir, { ...request, unexpected: true }, 1).reason, /packet schema/);
  const grant = invoke('grant', bDir, request);
  assert.match(invoke('respond', bDir, { ...grant, unexpected: true }, 1).reason, /packet schema/);
  assert.match(invoke('respond', bDir, { ...grant, profileSha256: 'f'.repeat(64) }, 1).reason, /profile/);
  const response = invoke('respond', bDir, grant);
  assert.match(invoke('verify', aDir, { ...response, profileSha256: 'f'.repeat(64) }, 1).reason, /profile binding/);
  assert.match(invoke('verify', aDir, { ...response, profileSha256: 'f'.repeat(64), evidence: { ...response.evidence, profileSha256: 'f'.repeat(64) } }, 1).reason, /signature/);
  assert.match(invoke('verify', aDir, { ...response, evidence: { ...response.evidence, hardwareAttested: true } }, 1).reason, /security limits/);
  assert.match(invoke('verify', aDir, { ...response, unexpected: true }, 1).reason, /packet schema/);
  assert.equal(invoke('verify', aDir, response).result.evidenceVerified, true);
});
test('a modified stored profile and relaxed key permissions stop the handoff', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mikaya-handoff-guards-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = path.join(root, 'one');
  invoke('init', dir);
  const keyFile = path.join(dir, 'synthetic-keys.json');
  fs.chmodSync(keyFile, 0o644);
  assert.match(invoke('request', dir, {}, 1).reason, /permissions/);
  fs.chmodSync(keyFile, 0o600);
  const profilePath = path.join(dir, 'runtime-profile.json');
  const profile = JSON.parse(fs.readFileSync(profilePath, 'utf8'));
  profile.collectedAt = '2000-01-01T00:00:00.000Z';
  fs.writeFileSync(profilePath, JSON.stringify(profile));
  assert.match(invoke('request', dir, {}, 1).reason, /profile/);
});
