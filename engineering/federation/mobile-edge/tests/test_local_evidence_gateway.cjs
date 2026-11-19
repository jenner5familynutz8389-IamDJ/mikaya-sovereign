'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http'),crypto=require('node:crypto');
const fed=require('../../live/federation-node.cjs'),ledger=require('../../live/sovereign-event-ledger.cjs');
const tollbooth=require('../../live/security-tollbooth.cjs');
const collector=require('../../../../integrations/security-tollbooth/verified-events/ledger_event_collector.cjs');
const gateway=require('../local-evidence-gateway.cjs');
function fixture(t,{owner='MIKAYA',admission={}}={}){
 tollbooth.configure({globalCapacity:64,perIpCapacity:64,globalRefillPerSecond:100,perIpRefillPerSecond:100,...admission});
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-mobile-evidence-'));
 const dir=path.join(root,'node'),events=path.join(root,'events'),state=path.join(root,'projection');
 const identity=fed.initNode(dir,owner,'owned-mobile-fixture');
 ledger.initializeLedger({nodeDir:dir,ledgerDir:events});
 ledger.appendDigest({nodeDir:dir,ledgerDir:events,kind:'DEVICE_HEALTH_OBSERVED',payloadSha256:fed.sha('synthetic observation, not hardware')});
 const c={schema:'mikaya.verified-ledger-config.v1',ledger_dir:events,public_key_path:path.join(dir,'identity-public.pem'),
  expected_fingerprint:identity.fingerprint,state_dir:state,max_age_ms:60000};
 collector.collect(c,{initialize:true});
 const servers=[];t.after(async()=>{
  for(const s of servers)if(s.listening)await new Promise(resolve=>s.close(resolve));
  fs.rmSync(root,{recursive:true,force:true});
 });
 return {root,dir,events,state,c,identity,servers};
}
async function start(s,options={}){
 const server=gateway.startLocalGateway({dir:s.dir,expectedFingerprint:s.identity.fingerprint,collectorConfig:s.c,port:0,allowWork:()=>true,...options});
 s.servers.push(server);await new Promise((resolve,reject)=>{server.once('listening',resolve);server.once('error',reject);});return server;
}
function request(server,route,headers={},method='GET',body){return new Promise((resolve,reject)=>{
 const req=http.request({hostname:'127.0.0.1',port:server.address().port,path:route,method,headers},res=>{
  const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>resolve({status:res.statusCode,body:JSON.parse(Buffer.concat(chunks).toString('utf8'))}));res.on('error',reject);
 });req.on('error',reject);req.end(body);
});}
async function auth(s,server,changes={}){
 const challenge=await request(server,'/healthz');assert.equal(challenge.status,200);
 return gateway.signRead({dir:s.dir,expectedFingerprint:s.identity.fingerprint,bootNonce:challenge.body.bootNonce,...changes});
}
function sourceBytes(s){return Object.fromEntries([...fs.readdirSync(s.events).map(n=>'events/'+n),...['identity-private.pem','identity-public.pem','node.json','policy.json','peers.json'].map(n=>'node/'+n)].map(n=>[n,fs.readFileSync(path.join(s.root,n)).toString('base64')]));}

test('owner-local signed read reuses existing verifier and preserves each device identity and ledger',async t=>{
 for(const owner of ['MIKAYA','MOTOROLA']){
  const s=fixture(t,{owner}),before=sourceBytes(s),server=await start(s);
  const body=await gateway.readLocalGateway({dir:s.dir,expectedFingerprint:s.identity.fingerprint,port:server.address().port});
  assert.equal(body.status,'VERIFIED_LOCAL_EVIDENCE');assert.equal(body.ownerFingerprint,s.identity.fingerprint);
  assert.equal(body.recognizedEventCount,1);assert.equal(body.newEvents,0);
  assert.equal(body.measurementClass,'SIGNED_LOCAL_OBSERVATION_DIGESTS');assert.equal(body.hardwareAttested,false);
  assert.equal(body.actAdmission,'HOLD');assert.equal(body.computeAuthorized,false);assert.equal(body.fileTransferAuthorized,false);
  assert.equal(body.paymentAuthorized,false);assert.equal(body.deviceControlAuthorized,false);
  assert.equal(JSON.stringify(body).includes(s.root),false);assert.deepEqual(sourceBytes(s),before);
  await new Promise(resolve=>server.close(resolve));
 }
});

test('gateway refuses unsigned reads, browser origins, foreign hosts and unsupported routes',async t=>{
 const s=fixture(t),server=await start(s);
 assert.equal((await request(server,gateway.ROUTE)).status,401);
 assert.equal((await request(server,gateway.ROUTE,{'X-Mikaya-Local-Test':'1'})).status,401);
 assert.equal((await request(server,'/healthz',{Origin:'https://example.invalid'})).status,403);
 assert.equal((await request(server,'/healthz',{Host:'example.invalid'})).status,403);
 for(const route of ['/mcp','/v1/task','/api/v1/telemetry?node=pixel10','/v1/mobile/evidence?path=/private'])
  assert.equal((await request(server,route)).status,404);
 assert.equal((await request(server,gateway.ROUTE,{},'POST')).status,404);
});

test('current owner signature binds route, instance, freshness, nonce and evidence reply',async t=>{
 const s=fixture(t),server=await start(s),signed=await auth(s,server);
 const response=await request(server,gateway.ROUTE,{Authorization:gateway.readHeader(signed)});assert.equal(response.status,200);
 const pub=fed.loadNode(s.dir).publicKey;
 assert.equal(gateway.verifyReply({reply:response.body,request:signed,publicKey:pub,expectedFingerprint:s.identity.fingerprint}).recognizedEventCount,1);
 const altered={...response.body,body:{...response.body.body,hardwareAttested:true}};
 assert.throws(()=>gateway.verifyReply({reply:altered,request:signed,publicKey:pub,expectedFingerprint:s.identity.fingerprint}),/mismatch/);
 // Valid signatures never turn stale observations or admission flags into proof.
 const resign=body=>{
  const {signature,...a}=response.body.auth;a.bodySha256=fed.sha(fed.canonical(body));
  return {body,auth:{...a,signature:crypto.sign(null,Buffer.from('MIKAYA-MOBILE-EDGE-LOCAL-READ/1\nRES\n'+fed.canonical(a)),fed.loadNode(s.dir).privateKey).toString('base64')}};
 };
 for(const body of [{...response.body.body,sourceLatestAtMs:Date.now()-60001},{...response.body.body,hardwareAttested:true},
   {...response.body.body,paymentAuthorized:true},{...response.body.body,extra:'unreviewed'}])
  assert.throws(()=>gateway.verifyReply({reply:resign(body),request:signed,publicKey:pub,expectedFingerprint:s.identity.fingerprint}),/semantics|freshness/);
 assert.equal((await request(server,gateway.ROUTE,{Authorization:gateway.readHeader(signed)})).status,401);
 const changed={...signed,nonce:crypto.randomBytes(16).toString('hex')};
 assert.equal((await request(server,gateway.ROUTE,{Authorization:gateway.readHeader(changed)})).status,401);
 const stale=await auth(s,server,{issuedAtMs:Date.now()-60001});
 assert.equal((await request(server,gateway.ROUTE,{Authorization:gateway.readHeader(stale)})).status,401);
 const future=await auth(s,server,{issuedAtMs:Date.now()+65000});
 assert.equal((await request(server,gateway.ROUTE,{Authorization:gateway.readHeader(future)})).status,401);
 await new Promise(resolve=>server.close(resolve));
 const restarted=await start(s);
 assert.equal((await request(restarted,gateway.ROUTE,{Authorization:gateway.readHeader(signed)})).status,401);
});

test('even an independently pinned Motorola peer cannot read another device owner-local evidence',async t=>{
 const s=fixture(t),other=path.join(s.root,'other'),identity=fed.initNode(other,'MOTOROLA','other-owned-phone');
 fed.pinPeer(s.dir,path.join(other,'identity-public.pem'),'MOTOROLA',identity.nodeId,identity.fingerprint);
 const server=await start(s),challenge=await request(server,'/healthz');
 const signed=gateway.signRead({dir:other,expectedFingerprint:identity.fingerprint,bootNonce:challenge.body.bootNonce});
 assert.equal((await request(server,gateway.ROUTE,{Authorization:gateway.readHeader(signed)})).status,401);
});

test('owner kill switch applies after startup and native thermal HOLD blocks evidence collection',async t=>{
 const s=fixture(t),before=sourceBytes(s),server=await start(s,{allowWork:()=>false}),signed=await auth(s,server);
 assert.equal((await request(server,gateway.ROUTE,{Authorization:gateway.readHeader(signed)})).status,503);
 assert.deepEqual(sourceBytes(s),before);
 const p=path.join(s.dir,'policy.json'),policy=JSON.parse(fs.readFileSync(p));policy.enabled=false;fs.writeFileSync(p,JSON.stringify(policy));
 assert.equal((await request(server,'/healthz')).body.error,'owner_policy_hold');
});

test('missing native thermal status remains HOLD with production defaults',async t=>{
 const s=fixture(t),server=gateway.startLocalGateway({dir:s.dir,expectedFingerprint:s.identity.fingerprint,collectorConfig:s.c,port:0});
 s.servers.push(server);await new Promise(resolve=>server.once('listening',resolve));
 const signed=await auth(s,server),reply=await request(server,gateway.ROUTE,{Authorization:gateway.readHeader(signed)});
 assert.equal(reply.status,503);assert.equal(reply.body.error,'thermal_policy_hold');
});

test('tampered, stale, rolled-back or absent evidence fails without recreating source or checkpoint',async t=>{
 const s=fixture(t),server=await start(s),rowPath=path.join(s.events,'000001.json'),raw=fs.readFileSync(rowPath);
 const row=JSON.parse(raw);row.payloadSha256='f'.repeat(64);fs.writeFileSync(rowPath,fed.canonical(row)+'\n');
 let signed=await auth(s,server);
 assert.equal((await request(server,gateway.ROUTE,{Authorization:gateway.readHeader(signed)})).status,503);
 fs.writeFileSync(rowPath,raw);
 const realNow=Date.now.bind(Date);t.mock.method(Date,'now',()=>realNow()+65000);
 signed=await auth(s,server);
 assert.equal((await request(server,gateway.ROUTE,{Authorization:gateway.readHeader(signed)})).status,503);t.mock.restoreAll();
 fs.unlinkSync(rowPath);signed=await auth(s,server);
 assert.equal((await request(server,gateway.ROUTE,{Authorization:gateway.readHeader(signed)})).status,503);
 assert.equal(fs.existsSync(rowPath),false);
 fs.writeFileSync(rowPath,raw,{mode:0o600});fs.unlinkSync(path.join(s.state,'projection.jsonl'));signed=await auth(s,server);
 assert.equal((await request(server,gateway.ROUTE,{Authorization:gateway.readHeader(signed)})).status,503);
 assert.equal(fs.existsSync(path.join(s.state,'projection.jsonl')),false);
});

test('explicit loopback and existing state are mandatory, including listener rebinds',async t=>{
 const s=fixture(t),options={dir:s.dir,expectedFingerprint:s.identity.fingerprint,collectorConfig:s.c,port:0};
 assert.throws(()=>gateway.startLocalGateway({...options,host:'0.0.0.0'}),/loopback/);
 assert.throws(()=>gateway.startLocalGateway({...options,expectedFingerprint:'0'.repeat(64)}),/identity/);
 assert.throws(()=>gateway.startLocalGateway({...options,collectorConfig:{...s.c,max_age_ms:86400000}}),/fresh/);
 const server=await start(s);
 assert.throws(()=>server.listen({port:0,host:'0.0.0.0'}),/loopback/);
 await new Promise(resolve=>server.close(resolve));
 assert.throws(()=>server.listen(0,'127.0.0.1'),/single/);
});

test('gateway keeps 8192-byte admission and shares busy and slow-body limits across listeners',async t=>{
 const s=fixture(t,{admission:{bodyTimeoutMs:100,requestTimeoutMs:1000}}),one=await start(s),two=await start(s);
 assert.equal((await request(one,'/healthz',{'Content-Length':'8193'},'POST','x')).status,413);
 const accepted=new Promise(resolve=>one.once('request',resolve));
 const slow=new Promise((resolve,reject)=>{
  const req=http.request({hostname:'127.0.0.1',port:one.address().port,path:'/anything',method:'POST',headers:{'Content-Length':'8'}},res=>{
   res.resume();res.on('end',()=>resolve(res.statusCode));
  });req.on('error',reject);req.write('x');
 });
 await accepted;
 assert.equal((await request(two,'/healthz')).status,429);
 assert.equal(await slow,408);
 assert.equal((await request(two,'/healthz')).status,200);
});

test('local client has an absolute deadline even when an endpoint keeps dribbling bytes',async t=>{
 const s=fixture(t),server=http.createServer((req,res)=>{
  res.writeHead(200,{'Content-Type':'application/json'});res.write('{');
  const timer=setInterval(()=>res.write(' '),100);res.on('close',()=>clearInterval(timer));
 });
 s.servers.push(server);server.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
 const began=performance.now();
 await assert.rejects(()=>gateway.readLocalGateway({dir:s.dir,expectedFingerprint:s.identity.fingerprint,port:server.address().port}),/abort|timeout/i);
 assert.ok(performance.now()-began<5000,'inactivity must not extend the absolute deadline');
});

test('explicit owned runtime cohosts the existing node and evidence port with one lease',async t=>{
 const s=fixture(t),net=require('node:net');
 const nodePort=await new Promise(resolve=>{const reserve=net.createServer();reserve.listen(0,'127.0.0.1',()=>{const p=reserve.address().port;reserve.close(()=>resolve(p));});});
 const remote=path.join(s.root,'motorola'),peer=fed.initNode(remote,'MOTOROLA','separate-motorola');
 fed.pinPeer(s.dir,path.join(remote,'identity-public.pem'),'MOTOROLA',peer.nodeId,peer.fingerprint);
 fed.pinPeer(remote,path.join(s.dir,'identity-public.pem'),'MIKAYA',s.identity.nodeId,s.identity.fingerprint);
 const runtime=await gateway.startOwnedRuntime({dir:s.dir,expectedFingerprint:s.identity.fingerprint,collectorConfig:s.c,nodePort,port:0,allowWork:()=>true});
 t.after(()=>runtime.close());
 const lease=fs.readFileSync(path.join(s.dir,tollbooth.LOCK_NAME,'owner.json'));
 const result=await fed.clientCall({dir:remote,url:'http://127.0.0.1:'+nodePort,expectedPeer:s.identity.fingerprint,route:'/v1/task',
  body:{schema:'mikaya.federation.job.v1',id:crypto.randomBytes(16).toString('hex'),capability:'compute.dot.v1',payload:{a:[2],b:[4]}}});
 assert.equal(result.body.result,8);
 assert.equal((await gateway.readLocalGateway({dir:s.dir,expectedFingerprint:s.identity.fingerprint,port:runtime.gateway.address().port})).actAdmission,'HOLD');
 assert.deepEqual(fs.readFileSync(path.join(s.dir,tollbooth.LOCK_NAME,'owner.json')),lease);
 await runtime.close();assert.equal(fs.existsSync(path.join(s.dir,tollbooth.LOCK_NAME)),false);
});

test('runtime startup never clears an existing writer lease or creates a replacement owner',async t=>{
 const s=fixture(t),lock=path.join(s.dir,tollbooth.LOCK_NAME),before=sourceBytes(s);
 fs.mkdirSync(lock,{mode:0o700});fs.writeFileSync(path.join(lock,'owner.json'),'existing owner lease\n',{mode:0o600});
 await assert.rejects(()=>gateway.startOwnedRuntime({dir:s.dir,expectedFingerprint:s.identity.fingerprint,collectorConfig:s.c,nodePort:43829,port:0,allowWork:()=>true}),/writer lease exists/);
 assert.equal(fs.readFileSync(path.join(lock,'owner.json'),'utf8'),'existing owner lease\n');assert.deepEqual(sourceBytes(s),before);
});
