'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),net=require('node:net');
const crypto=require('node:crypto');
const fed=require('../federation-node.cjs'),broker=require('../federation-broker.cjs');
const SHA=x=>crypto.createHash('sha256').update(x).digest('hex');
const job=(cap='compute.dot.v1')=>({schema:'mikaya.federation.job.v1',id:crypto.randomBytes(16).toString('hex'),capability:cap,payload:{a:[1,3],b:[4,5]}});
function setup(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-broker-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const g=path.join(root,'gateway'),w=path.join(root,'worker'),p=path.join(root,'peer');
 const G=fed.initNode(g,'MIKAYA','f110-test'),W=fed.initNode(w,'MOTOROLA','moto-test'),P=fed.initNode(p,'LAB-PEER','peer-synthetic');
 fed.pinPeer(g,path.join(w,'identity-public.pem'),'MOTOROLA','moto-test',W.fingerprint);
 fed.pinPeer(w,path.join(g,'identity-public.pem'),'MIKAYA','f110-test',G.fingerprint);
 fed.pinPeer(g,path.join(p,'identity-public.pem'),'LAB-PEER','peer-synthetic',P.fingerprint);
 fed.pinPeer(p,path.join(g,'identity-public.pem'),'MIKAYA','f110-test',G.fingerprint);
 return {root,g,w,p,G,W,P};
}
const openPort=()=>new Promise(resolve=>{const s=net.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
const waitServer=s=>new Promise(resolve=>s.listening?resolve():s.once('listening',resolve));
const closeServer=s=>new Promise(resolve=>s.close(resolve));
function policy(s,url){return {schema:'mikaya.federation.broker-policy.v1',enabled:true,testOnly:true,allowedUpstream:{[s.P.fingerprint]:['compute.dot.v1']},downstream:{fingerprint:s.W.fingerprint,url},maxRequestsInFlight:1};}
function save(s,value){const file=path.join(s.g,'broker-policy.json');fs.writeFileSync(file,JSON.stringify(value)+'\n',{mode:0o600});return file;}
test('broker refuses unpinned routes, unsafe target URLs, and unauthorized scope',async t=>{
 const s=setup(t),u='http://127.0.0.1:34567/';
 assert.equal(broker.validatePolicy(policy(s,u),fed.loadNode(s.g)).testOnly,true);
 assert.throws(()=>broker.validatePolicy({...policy(s,u),downstream:{fingerprint:s.W.fingerprint,url:'http://192.168.0.172:43829/'}},fed.loadNode(s.g)),/TLS|url|transport/i);
 assert.throws(()=>broker.validatePolicy({...policy(s,u),downstream:{fingerprint:'f'.repeat(64),url:u}},fed.loadNode(s.g)),/pinned|downstream/i);
 assert.throws(()=>broker.validatePolicy({...policy(s,u),allowedUpstream:{[s.P.fingerprint]:['shell.exec']}},fed.loadNode(s.g)),/capability|scope/i);
});
test('signed third-peer request reaches separate internal worker and returns two signed receipts',async t=>{
 const s=setup(t),workerPort=await openPort(),brokerPort=await openPort();
 const worker=fed.startServer(s.w,workerPort);t.after(()=>closeServer(worker));await waitServer(worker);
 const policyFile=save(s,policy(s,'http://127.0.0.1:'+workerPort+'/'));
 const gw=broker.startBroker({dir:s.g,policyFile,port:brokerPort});t.after(()=>closeServer(gw));await waitServer(gw);
 const response=await broker.callBroker({dir:s.p,url:'http://127.0.0.1:'+brokerPort+'/',expectedGateway:s.G.fingerprint,
   expectedWorkerPublicKey:fs.readFileSync(path.join(s.w,'identity-public.pem')),job:job()});
 assert.equal(response.verified,true);
 assert.equal(response.result,19);
 assert.equal(response.proof.gatewayFingerprint,s.G.fingerprint);
 assert.equal(response.proof.workerFingerprint,s.W.fingerprint);
 assert.equal(response.proof.paymentStatus,'UNPAID_TEST_ONLY');
 assert.equal(fed.verifyLocalJournal(s.w),true);
});
test('unpaid broker cannot route forbidden capability and wrong peer cannot join',async t=>{
 const s=setup(t),workerPort=await openPort(),brokerPort=await openPort();
 const worker=fed.startServer(s.w,workerPort);t.after(()=>closeServer(worker));await waitServer(worker);
 const pol=save(s,policy(s,'http://127.0.0.1:'+workerPort+'/'));
 const gw=broker.startBroker({dir:s.g,policyFile:pol,port:brokerPort});t.after(()=>closeServer(gw));await waitServer(gw);
 const invalid=job('compute.sha256.v1');invalid.payload={challengeHex:'0'.repeat(64)};
 await assert.rejects(()=>broker.callBroker({dir:s.p,url:'http://127.0.0.1:'+brokerPort+'/',expectedGateway:s.G.fingerprint,
  expectedWorkerPublicKey:fs.readFileSync(path.join(s.w,'identity-public.pem')),job:invalid}),/403|policy|denied|refused/i);
 const unknown=path.join(s.root,'unknown');const U=fed.initNode(unknown,'ACT-OMEGA','unverified-act');
 assert.throws(()=>fed.signRequest({dir:unknown,to:s.G.fingerprint,method:'POST',route:'/v1/task',body:job()}),/untrusted|pinned|outbound/i);
});
test('broker rejects forged relay reply and cannot transform a hash into payment',async t=>{
 const s=setup(t);const fake={schema:'mikaya.federation.relay-result.v1',gatewayFingerprint:s.G.fingerprint,workerFingerprint:s.W.fingerprint,paymentStatus:'SETTLED'};
 assert.throws(()=>broker.verifyRelayedResult({proof:fake,job:job(),gatewayPublicKey:fs.readFileSync(path.join(s.g,'identity-public.pem')),workerPublicKey:fs.readFileSync(path.join(s.w,'identity-public.pem')),upstreamFingerprint:s.P.fingerprint}),/schema|payment|result|receipt/i);
});
test('broker policy disabling and revoked upstream deny even valid signed messages',async t=>{
 const s=setup(t),workerPort=await openPort(),brokerPort=await openPort();
 const worker=fed.startServer(s.w,workerPort);t.after(()=>closeServer(worker));await waitServer(worker);
 const pol=save(s,{...policy(s,'http://127.0.0.1:'+workerPort+'/'),enabled:false});
 const gw=broker.startBroker({dir:s.g,policyFile:pol,port:brokerPort});t.after(()=>closeServer(gw));await waitServer(gw);
 await assert.rejects(()=>broker.callBroker({dir:s.p,url:'http://127.0.0.1:'+brokerPort+'/',expectedGateway:s.G.fingerprint,
  expectedWorkerPublicKey:fs.readFileSync(path.join(s.w,'identity-public.pem')),job:job()}),/403|disabled|refused/i);
});
test('a disabled broker never advertises itself as ready for routing',async t=>{
 const s=setup(t),port=await openPort();
 const pol=save(s,{...policy(s,'http://127.0.0.1:34567/'),enabled:false});
 const gw=broker.startBroker({dir:s.g,policyFile:pol,port});t.after(()=>closeServer(gw));await waitServer(gw);
 const res=await fetch('http://127.0.0.1:'+port+'/v1/broker-health');
 assert.equal(res.status,200);
 const body=await res.json();
 assert.equal(body.status,'held');
 assert.equal(body.routingEnabled,false);
 assert.equal(body.paymentEnabled,false);
});
test('broker cannot be bound off-loopback without transport encryption',t=>{
 const s=setup(t),pol=save(s,policy(s,'http://127.0.0.1:34567/'));
 assert.throws(()=>broker.startBroker({dir:s.g,policyFile:pol,port:43830,host:'0.0.0.0'}),/TLS/i);
});
test('disabled broker can purge all temporary upstream peers and still health-check as held',async t=>{
 const s=setup(t),port=await openPort();fed.revokePeer(s.g,s.P.fingerprint);
 const pol=save(s,{...policy(s,'http://127.0.0.1:34567/'),enabled:false,allowedUpstream:{}});
 const gw=broker.startBroker({dir:s.g,policyFile:pol,port});t.after(()=>closeServer(gw));await waitServer(gw);
 const response=await fetch('http://127.0.0.1:'+port+'/v1/broker-health');
 assert.equal(response.status,200);const body=await response.json();
 assert.equal(body.status,'held');assert.equal(body.routingEnabled,false);
});