'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const {spawn} = require('node:child_process');
const node = require('../federation-node.cjs');
const entry = path.resolve(__dirname, '../federation-node.cjs');

function setup(t) {
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-fed-test-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const a=path.join(root,'MIKAYA');const b=path.join(root,'LAB-PEER');
 const A=node.initNode(a,'MIKAYA','f110-lab');
 const B=node.initNode(b,'LAB-PEER','lab-opposite');
 return {root,a,b,A,B};
}
function pair({a,b,A,B}) {
 node.pinPeer(a,path.join(b,'identity-public.pem'),'LAB-PEER','lab-opposite',B.fingerprint);
 node.pinPeer(b,path.join(a,'identity-public.pem'),'MIKAYA','f110-lab',A.fingerprint);
}
function dot(a,b){return {schema:'mikaya.federation.job.v1',id:crypto.randomBytes(16).toString('hex'),capability:'compute.dot.v1',payload:{a,b}};}
function openPort(){return new Promise((resolve,reject)=>{const s=net.createServer();s.once('error',reject);s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});}
function startChild(dir,port){
 return new Promise((resolve,reject)=>{
  const proc=spawn(process.execPath,[entry,'serve',dir,String(port)],{stdio:['ignore','pipe','pipe']});
  let stdout='',stderr='',ready=false;
  const timeout=setTimeout(()=>{proc.kill();reject(Error('child start timeout '+stderr));},4000);
  proc.stdout.on('data',ch=>{stdout+=ch;if(!ready&&stdout.includes('FEDERATION_READY')){ready=true;clearTimeout(timeout);resolve(proc);}});
  proc.stderr.on('data',ch=>stderr+=ch);
  proc.once('exit',code=>{if(!ready){clearTimeout(timeout);reject(Error('child failed '+code+' '+stderr));}});
 });
}
function closeChild(proc){return new Promise(resolve=>{if(proc.exitCode!==null||proc.signalCode!==null)return resolve();proc.once('exit',resolve);proc.kill('SIGTERM');setTimeout(()=>{if(proc.exitCode===null)proc.kill('SIGKILL');resolve();},1500).unref();});}

test('separate persistent Ed25519 identities and private key permissions',t=>{
 const {a,b,A,B}=setup(t);
 assert.notEqual(A.fingerprint,B.fingerprint);
 assert.equal(fs.statSync(path.join(a,'identity-private.pem')).mode&0o777,0o600);
 assert.equal(fs.statSync(a).mode&0o777,0o700);
 assert.notEqual(fs.readFileSync(path.join(a,'identity-private.pem'),'utf8'),fs.readFileSync(path.join(b,'identity-private.pem'),'utf8'));
 assert.throws(()=>node.initNode(a,'MIKAYA','f110-lab'),/already|exists|refus/i);
});

test('peer pin must match explicit independent fingerprint',t=>{
 const s=setup(t);
 assert.throws(()=>node.pinPeer(s.a,path.join(s.b,'identity-public.pem'),'LAB-PEER','lab-opposite','0'.repeat(64)),/fingerprint|mismatch/i);
 pair(s);
 const info=node.loadNode(s.a);
 assert.equal(info.peers[s.B.fingerprint].owner,'LAB-PEER');
 assert.ok(!JSON.stringify(info.peers).includes('PRIVATE KEY'));
});

test('signed requests bind method path bytes recipient and one-use nonce persistently',t=>{
 const s=setup(t);pair(s);
 const body={schema:'mikaya.federation.hello.v1',owner:'MIKAYA',nodeId:'f110-lab',capabilities:['compute.dot.v1','compute.sha256.v1'],platform:{os:'android',androidApi:35,arch:'aarch64'}};
 const sig=node.signRequest({dir:s.a,to:s.B.fingerprint,method:'POST',route:'/v1/hello',body,nonce:'1'.repeat(32)});
 assert.equal(node.verifyRequest({dir:s.b,auth:sig,method:'POST',route:'/v1/hello',body}).fingerprint,s.A.fingerprint);
 assert.throws(()=>node.verifyRequest({dir:s.b,auth:sig,method:'POST',route:'/v1/hello',body}),/replay/i);
 assert.throws(()=>node.verifyRequest({dir:s.b,auth:sig,method:'POST',route:'/v1/task',body}),/signature|route|path/i);
 assert.throws(()=>node.verifyRequest({dir:s.b,auth:sig,method:'POST',route:'/v1/hello',body:{...body,owner:'ACT-OMEGA'}}),/signature|hash|mismatch/i);
 assert.throws(()=>node.verifyRequest({dir:s.a,auth:sig,method:'POST',route:'/v1/hello',body}),/recipient|target/i);
});

test('unknown signer and expired signed request fail closed',t=>{
 const s=setup(t);pair(s);
 const body={schema:'mikaya.federation.hello.v1',owner:'MIKAYA',nodeId:'f110-lab',capabilities:['compute.dot.v1'],platform:{os:'android',androidApi:35,arch:'aarch64'}};
 const bad=node.signRequest({dir:s.a,to:s.B.fingerprint,method:'POST',route:'/v1/hello',body,issuedAtMs:Date.now()-180000});
 assert.throws(()=>node.verifyRequest({dir:s.b,auth:bad,method:'POST',route:'/v1/hello',body}),/expired/i);
 const unknown=node.initNode(path.join(s.root,'OTHER'),'MIKAYA','other-node');
 const unsigned={schema:'mikaya.federation.request.v1',from:unknown.fingerprint,to:s.B.fingerprint,method:'POST',route:'/v1/hello',bodySha256:node.sha(node.canonical(body)),nonce:'f'.repeat(32),issuedAtMs:Date.now()};
 const otherKey=fs.readFileSync(path.join(s.root,'OTHER','identity-private.pem'));
 const forged={...unsigned,signature:crypto.sign(null,Buffer.from('MIKAYA-INDEPENDENT-FEDERATION/1\nREQ\n'+node.canonical(unsigned)),otherKey).toString('base64')};
 assert.notEqual(unknown.fingerprint,s.A.fingerprint);
 assert.throws(()=>node.verifyRequest({dir:s.b,auth:forged,method:'POST',route:'/v1/hello',body}),/unknown|untrusted/i);
});

test('compute is bounded, deterministic, verifiable, and never executes code',()=>{
 assert.equal(node.computeJob(dot([1,2,3],[4,5,6])),32);
 const challenge='1'.repeat(64);
 const job={schema:'mikaya.federation.job.v1',id:'a'.repeat(32),capability:'compute.sha256.v1',payload:{challengeHex:challenge}};
 assert.equal(node.computeJob(job),crypto.createHash('sha256').update(Buffer.from(challenge,'hex')).digest('hex'));
 for(const attack of [
  {...job,capability:'shell.exec'},
  {...job,payload:{...job.payload,seedPhrase:'exfiltrate'}},
  {...job,payload:{text:'private key'}},
  {...dot([1001],[1])},
  {...dot([1],[2,3])},
  {...dot(Array(18).fill(1),Array(18).fill(2))}
 ])assert.throws(()=>node.computeJob(attack));
});

test('remote cleartext HTTP refused, HTTPS allowed for externally authenticated peers',()=>{
 for(const x of ['http://example.com:8000','http://100.101.22.10:8000','http://[2001:db8::1]:8000','file:///tmp/x'])
  assert.throws(()=>node.validateUrl(x),/TLS|loopback|protocol/i);
 assert.equal(node.validateUrl('http://127.0.0.1:42841').protocol,'http:');
 assert.equal(node.validateUrl('https://act.example.org').protocol,'https:');
});

test('a revoked peer is denied without changing its identity',t=>{
 const s=setup(t);pair(s);
 const body={schema:'mikaya.federation.hello.v1',owner:'MIKAYA',nodeId:'f110-lab',capabilities:['compute.dot.v1'],platform:{os:'android',androidApi:35,arch:'aarch64'}};
 node.revokePeer(s.b,s.A.fingerprint);
 const sig=node.signRequest({dir:s.a,to:s.B.fingerprint,method:'POST',route:'/v1/hello',body});
 assert.throws(()=>node.verifyRequest({dir:s.b,auth:sig,method:'POST',route:'/v1/hello',body}),/revoked|disabled/i);
});

test('LIVE two separate node processes exchange signed hello and both compute on loopback',async t=>{
 const s=setup(t);pair(s);
 const pa=await openPort(),pb=await openPort();
 const p1=await startChild(s.a,pa);t.after(()=>closeChild(p1));
 const p2=await startChild(s.b,pb);t.after(()=>closeChild(p2));
 const ha=await node.clientCall({dir:s.a,url:'http://127.0.0.1:'+pb,expectedPeer:s.B.fingerprint,route:'/v1/hello',body:node.makeHello(s.a)});
 const hb=await node.clientCall({dir:s.b,url:'http://127.0.0.1:'+pa,expectedPeer:s.A.fingerprint,route:'/v1/hello',body:node.makeHello(s.b)});
 assert.equal(ha.body.owner,'LAB-PEER');assert.equal(hb.body.owner,'MIKAYA');
 const j1=dot([2,3,4],[5,6,7]),j2=dot([10,-5],[3,4]);
 const ra=await node.clientCall({dir:s.a,url:'http://127.0.0.1:'+pb,expectedPeer:s.B.fingerprint,route:'/v1/task',body:j1});
 const rb=await node.clientCall({dir:s.b,url:'http://127.0.0.1:'+pa,expectedPeer:s.A.fingerprint,route:'/v1/task',body:j2});
 assert.equal(ra.body.result,56);assert.equal(rb.body.result,10);
 assert.equal(ra.body.workerFingerprint,s.B.fingerprint);assert.equal(rb.body.workerFingerprint,s.A.fingerprint);
 assert.equal(ra.verified,true);assert.equal(rb.verified,true);
 const collective=node.combineResults([ra,rb]);
 assert.match(collective.combinedSha256,/^[a-f0-9]{64}$/);
 assert.equal(collective.participants,2);
 assert.equal(node.verifyLocalJournal(s.a),true);
 assert.equal(node.verifyLocalJournal(s.b),true);
 // Unknown jobs are never forwarded to code execution or firmware.
 await assert.rejects(()=>node.clientCall({dir:s.a,url:'http://127.0.0.1:'+pb,expectedPeer:s.B.fingerprint,route:'/v1/task',body:{...j1,id:crypto.randomBytes(16).toString('hex'),capability:'firmware.flash'}}));
});

test('replay refusal holds across server restarts and journal data remains owned locally',async t=>{
 const s=setup(t);pair(s);
 const port=await openPort();let proc=await startChild(s.b,port);
 t.after(()=>closeChild(proc));
 const body=node.makeHello(s.a),auth=node.signRequest({dir:s.a,to:s.B.fingerprint,method:'POST',route:'/v1/hello',body,nonce:'b'.repeat(32)});
 const first=await node.rawPost('http://127.0.0.1:'+port+'/v1/hello',{auth,body});
 assert.equal(first.status,200);
 const second=await node.rawPost('http://127.0.0.1:'+port+'/v1/hello',{auth,body});
 assert.equal(second.status,401);
 await closeChild(proc);proc=await startChild(s.b,port);
 const third=await node.rawPost('http://127.0.0.1:'+port+'/v1/hello',{auth,body});
 assert.equal(third.status,401);
 assert.equal(node.verifyLocalJournal(s.b),true);
 assert.equal(fs.readFileSync(path.join(s.b,'journal.jsonl'),'utf8').includes('identity-private'),false);
});

test('offline independent evidence verifier checks both owner signatures and recomputed work',async t=>{
 const s=setup(t);pair(s);
 const pa=await openPort(),pb=await openPort();const p1=await startChild(s.a,pa),p2=await startChild(s.b,pb);
 t.after(()=>closeChild(p1));t.after(()=>closeChild(p2));
 const j1=dot([7,11],[2,3]),j2=dot([-4,5],[2,8]);
 const ra=await node.clientCall({dir:s.a,url:'http://127.0.0.1:'+pb,expectedPeer:s.B.fingerprint,route:'/v1/task',body:j1});
 const rb=await node.clientCall({dir:s.b,url:'http://127.0.0.1:'+pa,expectedPeer:s.A.fingerprint,route:'/v1/task',body:j2});
 const evidence=node.buildEvidence({a:s.a,b:s.b,exchanges:[ra,rb],mode:'LOCAL_TWO_PROCESSES_ONE_DEVICE'});
 const audit=node.verifyEvidence(evidence);
 assert.equal(audit.valid,true);assert.equal(audit.jobs,2);assert.equal(audit.participants,2);
 assert.match(audit.combinedSha256,/^[a-f0-9]{64}$/);
 const corrupted=structuredClone(evidence);corrupted.exchanges[0].body.result++;
 assert.throws(()=>node.verifyEvidence(corrupted),/signature|digest|evidence|result/i);
 const forged=structuredClone(evidence);forged.publicKeys[s.B.fingerprint]=forged.publicKeys[s.A.fingerprint];
 assert.throws(()=>node.verifyEvidence(forged),/fingerprint|key/i);
 assert.ok(!JSON.stringify(evidence).includes('PRIVATE KEY'));
});

test('local journal tampering blocks new entries instead of silently continuing',t=>{
 const s=setup(t);pair(s);
 const body=node.makeHello(s.a),auth=node.signRequest({dir:s.a,to:s.B.fingerprint,method:'POST',route:'/v1/hello',body});
 const peer=node.verifyRequest({dir:s.b,auth,method:'POST',route:'/v1/hello',body});
 const job=dot([1],[2]);node.acceptJob(s.b,peer,job);
 assert.equal(node.verifyLocalJournal(s.b),true);
 const journal=path.join(s.b,'journal.jsonl');
 fs.writeFileSync(journal,fs.readFileSync(journal,'utf8').replace('job-completed','job-modified'));
 assert.equal(node.verifyLocalJournal(s.b),false);
 assert.throws(()=>node.acceptJob(s.b,peer,dot([3],[4])),/journal.*corrupt/i);
});


test('Motorola is a separately identifiable Android 14 peer, never ACT-Omega impersonation', t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'moto-fed-test-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const moto=node.initNode(path.join(root,'motorola'),'MOTOROLA','motorola-2023');
 assert.equal(moto.owner,'MOTOROLA');
 assert.equal(moto.platform.os,'android');
 assert.equal(moto.platform.androidApi,34);
 assert.notEqual(moto.owner,'ACT-OMEGA');
});

test('public-only two-physical-node evidence can be verified without collecting a private key',async t=>{
 const s=setup(t);pair(s);
 const pa=await openPort(),pb=await openPort();
 const first=await startChild(s.a,pa),second=await startChild(s.b,pb);
 t.after(()=>closeChild(first));t.after(()=>closeChild(second));
 const j1=dot([3,5],[7,11]),j2=dot([2,-4],[6,1]);
 const x=await node.clientCall({dir:s.a,url:'http://127.0.0.1:'+pb,expectedPeer:s.B.fingerprint,route:'/v1/task',body:j1});
 const y=await node.clientCall({dir:s.b,url:'http://127.0.0.1:'+pa,expectedPeer:s.A.fingerprint,route:'/v1/task',body:j2});
 const publicKeys={
  [s.A.fingerprint]:fs.readFileSync(path.join(s.a,'identity-public.pem'),'utf8'),
  [s.B.fingerprint]:fs.readFileSync(path.join(s.b,'identity-public.pem'),'utf8')
 };
 const proof=node.buildPublicEvidence({publicKeys,exchanges:[x,y],mode:'TWO_PHYSICAL_ANDROID_DEVICES_DIRECT_TLS'});
 const checked=node.verifyEvidence(proof);
 assert.equal(checked.valid,true);assert.equal(checked.jobs,2);
 assert.equal(JSON.stringify(proof).includes('PRIVATE KEY'),false);
 assert.throws(()=>node.buildPublicEvidence({publicKeys,exchanges:[x,y],mode:'anything-goes'}),/mode|evidence/);
 const bad=structuredClone(proof);bad.exchanges[0].body.result=999;
 assert.throws(()=>node.verifyEvidence(bad),/signature|digest|result|mismatch/i);
});
