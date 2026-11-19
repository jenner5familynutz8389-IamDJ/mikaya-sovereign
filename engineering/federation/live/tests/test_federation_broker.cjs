'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),net=require('node:net');
const crypto=require('node:crypto');
const {spawn}=require('node:child_process');
const fed=require('../federation-node.cjs'),broker=require('../federation-broker.cjs');
const tollbooth=require('../security-tollbooth.cjs');
const nodeEntry=path.resolve(__dirname,'../federation-node.cjs');
const SHA=x=>crypto.createHash('sha256').update(x).digest('hex');
const job=(cap='compute.dot.v1')=>({schema:'mikaya.federation.job.v1',id:crypto.randomBytes(16).toString('hex'),capability:cap,payload:{a:[1,3],b:[4,5]}});
function setup(t){
 // These fixtures use only loopback. The sandbox cannot enumerate interfaces;
 // supply the known test interface without bypassing the downstream guard.
 t.mock.method(os,'networkInterfaces',()=>({lo:[{address:'127.0.0.1',family:'IPv4',internal:true}]}));
 tollbooth.configure(); // Fresh default request budget for each independent case.
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-broker-')),cleanup=[];
 t.after(async()=>{
  try{for(const close of cleanup.reverse())await close();}
  finally{fs.rmSync(root,{recursive:true,force:true});}
 });
 const g=path.join(root,'gateway'),w=path.join(root,'worker'),p=path.join(root,'peer');
 const G=fed.initNode(g,'MIKAYA','f110-test'),W=fed.initNode(w,'MOTOROLA','moto-test'),P=fed.initNode(p,'LAB-PEER','peer-synthetic');
 fed.pinPeer(g,path.join(w,'identity-public.pem'),'MOTOROLA','moto-test',W.fingerprint);
 fed.pinPeer(w,path.join(g,'identity-public.pem'),'MIKAYA','f110-test',G.fingerprint);
 fed.pinPeer(g,path.join(p,'identity-public.pem'),'LAB-PEER','peer-synthetic',P.fingerprint);
 fed.pinPeer(p,path.join(g,'identity-public.pem'),'MIKAYA','f110-test',G.fingerprint);
 return {root,g,w,p,G,W,P,cleanup};
}
const openPort=()=>new Promise((resolve,reject)=>{const s=net.createServer();s.once('error',reject);s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
const waitServer=s=>new Promise((resolve,reject)=>{if(s.listening)return resolve();s.once('error',reject);s.once('listening',resolve);});
const closeServer=s=>new Promise(resolve=>s.close(resolve));
function closeChild(proc){return new Promise(resolve=>{
 if(!proc.pid||proc.exitCode!==null||proc.signalCode!==null)return resolve();
 const timeout=setTimeout(()=>proc.kill('SIGKILL'),1500);
 proc.once('exit',()=>{clearTimeout(timeout);resolve();});proc.kill('SIGTERM');
});}
async function startWorker(s,port){
 // A separate process owns the independent worker runtime and request budget.
 const proc=spawn(process.execPath,[nodeEntry,'serve',s.w,String(port),'127.0.0.1'],{stdio:['ignore','pipe','pipe']});
 s.cleanup.push(()=>closeChild(proc));
 await new Promise((resolve,reject)=>{
  let stdout='',stderr='',settled=false;
  const finish=error=>{if(settled)return;settled=true;clearTimeout(timeout);error?reject(error):resolve();};
  const timeout=setTimeout(()=>{proc.kill('SIGTERM');finish(Error('worker startup timed out '+stderr));},4000);
  proc.once('error',finish);
  proc.stdout.on('data',chunk=>{stdout=(stdout+chunk).slice(-8192);if(stdout.includes('FEDERATION_READY '))finish();});
  proc.stderr.on('data',chunk=>{stderr=(stderr+chunk).slice(-8192);});
  proc.once('exit',code=>finish(Error('worker exited before readiness '+code+' '+stderr)));
 });
 return proc;
}
function policy(s,url){return {schema:'mikaya.federation.broker-policy.v1',enabled:true,testOnly:true,allowedUpstream:{[s.P.fingerprint]:['compute.dot.v1']},downstream:{fingerprint:s.W.fingerprint,url},maxRequestsInFlight:1};}
function save(s,value){const file=path.join(s.g,'broker-policy.json');fs.writeFileSync(file,JSON.stringify(value)+'\n',{mode:0o600});return file;}
test('broker refuses unpinned routes, unsafe target URLs, and unauthorized scope',async t=>{
 const s=setup(t),u='http://127.0.0.1:34567/';
 assert.equal(broker.validatePolicy(policy(s,u),fed.loadNode(s.g)).testOnly,true);
 assert.throws(()=>broker.validatePolicy({...policy(s,u),downstream:{fingerprint:s.W.fingerprint,url:'http://192.0.2.123:43829/'}},fed.loadNode(s.g)),/TLS|url|transport/i);
 assert.throws(()=>broker.validatePolicy({...policy(s,u),downstream:{fingerprint:'f'.repeat(64),url:u}},fed.loadNode(s.g)),/pinned|downstream/i);
 assert.throws(()=>broker.validatePolicy({...policy(s,u),allowedUpstream:{[s.P.fingerprint]:['shell.exec']}},fed.loadNode(s.g)),/capability|scope/i);
});
test('signed third-peer request reaches separate internal worker and returns two signed receipts',async t=>{
 const s=setup(t),workerPort=await openPort();
 await startWorker(s,workerPort);const brokerPort=await openPort();
 const policyFile=save(s,policy(s,'http://127.0.0.1:'+workerPort+'/'));
 const gw=broker.startBroker({dir:s.g,policyFile,port:brokerPort});s.cleanup.push(()=>closeServer(gw));await waitServer(gw);
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
 const s=setup(t),workerPort=await openPort();
 await startWorker(s,workerPort);const brokerPort=await openPort();
 const pol=save(s,policy(s,'http://127.0.0.1:'+workerPort+'/'));
 const gw=broker.startBroker({dir:s.g,policyFile:pol,port:brokerPort});s.cleanup.push(()=>closeServer(gw));await waitServer(gw);
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
 const s=setup(t),workerPort=await openPort();
 await startWorker(s,workerPort);const brokerPort=await openPort();
 const pol=save(s,{...policy(s,'http://127.0.0.1:'+workerPort+'/'),enabled:false});
 const gw=broker.startBroker({dir:s.g,policyFile:pol,port:brokerPort});s.cleanup.push(()=>closeServer(gw));await waitServer(gw);
 await assert.rejects(()=>broker.callBroker({dir:s.p,url:'http://127.0.0.1:'+brokerPort+'/',expectedGateway:s.G.fingerprint,
  expectedWorkerPublicKey:fs.readFileSync(path.join(s.w,'identity-public.pem')),job:job()}),/403|disabled|refused/i);
});
test('a disabled broker never advertises itself as ready for routing',async t=>{
 const s=setup(t),port=await openPort();
 const pol=save(s,{...policy(s,'http://127.0.0.1:34567/'),enabled:false});
 const gw=broker.startBroker({dir:s.g,policyFile:pol,port});s.cleanup.push(()=>closeServer(gw));await waitServer(gw);
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
 const gw=broker.startBroker({dir:s.g,policyFile:pol,port});s.cleanup.push(()=>closeServer(gw));await waitServer(gw);
 const response=await fetch('http://127.0.0.1:'+port+'/v1/broker-health');
 assert.equal(response.status,200);const body=await response.json();
 assert.equal(body.status,'held');assert.equal(body.routingEnabled,false);
});

test('broker refuses a worker listener in its own runtime',async t=>{
 const s=setup(t),workerPort=await openPort();
 const worker=fed.startServer(s.w,workerPort);s.cleanup.push(()=>closeServer(worker));await waitServer(worker);
 const brokerPort=await openPort(),policyFile=save(s,policy(s,'http://127.0.0.1:'+workerPort+'/'));
 assert.throws(()=>broker.startBroker({dir:s.g,policyFile,port:brokerPort}),/same runtime/);
 assert.equal(fs.readdirSync(path.join(s.w,'jobs')).length,0);
});

test('forwarding boundary re-reads owner policy, upstream scope and revocation',t=>{
 const s=setup(t),p=policy(s,'http://127.0.0.1:34567/'),file=save(s,p);
 const input={dir:s.g,policyFile:file,expectedPolicy:p,peerFingerprint:s.P.fingerprint,capability:'compute.dot.v1'};
 assert.equal(broker.authorizeForwarding(input).enabled,true);
 save(s,{...p,enabled:false});assert.throws(()=>broker.authorizeForwarding(input),/changed|disabled/);
 save(s,p);
 const localFile=path.join(s.g,'policy.json'),local=JSON.parse(fs.readFileSync(localFile));
 fs.writeFileSync(localFile,JSON.stringify({...local,allowedCapabilities:['compute.sha256.v1']}));
 assert.throws(()=>broker.authorizeForwarding(input),/capability/);
 fs.writeFileSync(localFile,JSON.stringify(local));
 fed.revokePeer(s.g,s.P.fingerprint);assert.throws(()=>broker.authorizeForwarding(input),/peer|HOLD/);
});
