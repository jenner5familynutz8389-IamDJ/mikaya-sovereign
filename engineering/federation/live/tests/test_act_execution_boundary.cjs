'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const fed = require('../federation-node.cjs');

function fixture(t, localOwner = 'MIKAYA', peerOwner = 'ACT-OMEGA') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mikaya-act-boundary-'));
  const dir = path.join(root, 'local'), remoteDir = path.join(root, 'remote');
  const local = fed.initNode(dir, localOwner, 'local-test');
  const remote = fed.initNode(remoteDir, peerOwner, 'remote-test');
  fed.pinPeer(dir, path.join(remoteDir, 'identity-public.pem'), peerOwner, remote.nodeId, remote.fingerprint);
  fed.pinPeer(remoteDir, path.join(dir, 'identity-public.pem'), localOwner, local.nodeId, local.fingerprint);
  const servers = [];
  t.after(async () => {
    for (const server of servers) await new Promise(resolve => server.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  });
  return { root, dir, remoteDir, local, remote, servers };
}
function job() {
  return { schema: 'mikaya.federation.job.v1', id: crypto.randomBytes(16).toString('hex'),
    capability: 'compute.dot.v1', payload: { a: [2, 3], b: [5, 7] } };
}
async function start(s) {
  const port = await new Promise((resolve, reject) => {
    const reservation = net.createServer();
    reservation.once('error', reject);
    reservation.listen(0, '127.0.0.1', () => {
      const value = reservation.address().port;
      reservation.close(() => resolve(value));
    });
  });
  const server = fed.startServer(s.dir, port);
  s.servers.push(server);
  await new Promise((resolve, reject) => { server.once('listening', resolve); server.once('error', reject); });
  return 'http://127.0.0.1:' + port;
}
function envelope(s, body, route = '/v1/task') {
  return { auth: fed.signRequest({ dir: s.remoteDir, to: s.local.fingerprint, method: 'POST', route, body }), body };
}

test('HTTP direct node refuses signed pinned ACT compute without owner-reviewed broker admission', async t => {
  const s = fixture(t), url = await start(s);
  const response = await fed.rawPost(url + '/v1/task', envelope(s, job()));
  assert.equal(response.status, 422, 'pinning ACT is identity verification, not compute authorization');
  assert.equal(response.json.error, 'owner_policy_or_capability_denied');
  assert.deepEqual(fs.readdirSync(path.join(s.dir, 'jobs')), []);
  assert.equal(fs.existsSync(path.join(s.dir, 'journal.jsonl')), false);
});

test('shared acceptance derives the ACT role from its current pin, not caller metadata', t => {
  const s = fixture(t);
  assert.throws(() => fed.acceptJob(s.dir, { fingerprint:s.remote.fingerprint, owner:'MOTOROLA',
    capabilities:['compute.dot.v1'], verified:true }, job()), /owner-reviewed broker/);
  assert.deepEqual(fs.readdirSync(path.join(s.dir,'jobs')), []);
});

test('shared acceptance rechecks revocation and current peer capability after verification', t => {
  const s = fixture(t,'MIKAYA','MOTOROLA'), body = job(), signed = envelope(s,body);
  const peer = fed.verifyRequest({dir:s.dir,auth:signed.auth,body,method:'POST',route:'/v1/task'});
  const file = path.join(s.dir,'peers.json'), peers = JSON.parse(fs.readFileSync(file,'utf8'));
  peers[s.remote.fingerprint].capabilities = ['compute.sha256.v1'];
  fs.writeFileSync(file,JSON.stringify(peers)+'\n');
  assert.throws(() => fed.acceptJob(s.dir,peer,body), /capability/);
  fed.revokePeer(s.dir,s.remote.fingerprint);
  assert.throws(() => fed.acceptJob(s.dir,peer,body), /enabled peer pin/);
  assert.deepEqual(fs.readdirSync(path.join(s.dir,'jobs')), []);
});

test('shared acceptance honors the owner kill switch without writing a job', t => {
  const s = fixture(t,'MIKAYA','MOTOROLA'), file=path.join(s.dir,'policy.json');
  const policy=JSON.parse(fs.readFileSync(file,'utf8'));policy.enabled=false;
  fs.writeFileSync(file,JSON.stringify(policy)+'\n');
  assert.throws(() => fed.acceptJob(s.dir,{fingerprint:s.remote.fingerprint,capabilities:['compute.dot.v1']},job()), /policy/);
  assert.deepEqual(fs.readdirSync(path.join(s.dir,'jobs')), []);
});

test('existing signed MIKAYA to Motorola and Motorola to MIKAYA jobs retain independent receipts', async t => {
  for(const [localOwner,peerOwner] of [['MIKAYA','MOTOROLA'],['MOTOROLA','MIKAYA']]) {
    const s=fixture(t,localOwner,peerOwner),url=await start(s),body=job();
    const result=await fed.clientCall({dir:s.remoteDir,url,expectedPeer:s.local.fingerprint,route:'/v1/task',body});
    assert.equal(result.verified,true);assert.equal(result.body.result,31);
    assert.equal(result.body.workerFingerprint,s.local.fingerprint);
    assert.equal(fed.verifyLocalJournal(s.dir),true);
  }
});
