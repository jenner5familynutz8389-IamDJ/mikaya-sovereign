'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http');
const {spawnSync}=require('node:child_process');
const fed=require('../../live/federation-node.cjs'),tollbooth=require('../../live/security-tollbooth.cjs');
const collector=require('../../../../integrations/security-tollbooth/verified-events/ledger_event_collector.cjs');
const gateway=require('../local-evidence-gateway.cjs'),workflow=require('../observe-and-read.cjs');
const {createNativeMtgPolicy}=require('../native-mtg.cjs');
const moto=require('../motorola-observation-producer.cjs');
const f110=require('../../../../integrations/security-tollbooth/verified-events/device_observation_producer.cjs');
const CLI=path.resolve(__dirname,'../observe-and-read.cjs');
const PREFIX='/data/data/com.termux/files/usr';
const json=(file,value)=>fs.writeFileSync(file,fed.canonical(value)+'\n',{mode:0o600});
tollbooth.configure({globalCapacity:64,perIpCapacity:64,globalRefillPerSecond:100,perIpRefillPerSecond:100});

function fixture(t,{owner='MOTOROLA',stale=false}={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-observe-read-'));fs.chmodSync(root,0o700);
 const node=path.join(root,'existing-node'),meta=fed.initNode(node,owner,'synthetic-observation-owner');
 const p=owner==='MIKAYA'?f110:moto,prefix=owner==='MIKAYA'?'mikaya.device-observation':'mikaya.motorola-observation';
 const o={schema:prefix+'-config.v1',node_dir:node,ledger_dir:path.join(root,'signed-observations'),
  receipt_dir:path.join(root,'observation-receipts'),expected_fingerprint:meta.fingerprint};
 const c={schema:'mikaya.verified-ledger-config.v1',ledger_dir:o.ledger_dir,public_key_path:path.join(node,'identity-public.pem'),
  expected_fingerprint:meta.fingerprint,state_dir:path.join(root,'existing-projection'),max_age_ms:60000};
 const when=Date.now()-(stale?70000:2000),{ledger}=collector.loadVerifier();
 ledger.initializeLedger({nodeDir:node,ledgerDir:o.ledger_dir,nowMs:when});fs.mkdirSync(o.receipt_dir,{mode:0o700});
 // Explicitly synthetic historical fixture, signed with a fresh test-only owner key.
 const historicalReceipt={schema:prefix+'.v1',observedAtMs:when,...Object.fromEntries(p.PROBES.map(v=>[v.field,v.expected]))};
 const digest=fed.sha(fed.canonical(historicalReceipt));json(path.join(o.receipt_dir,digest+'.json'),historicalReceipt);
 ledger.appendDigest({nodeDir:node,ledgerDir:o.ledger_dir,kind:'DEVICE_HEALTH_OBSERVED',payloadSha256:digest,nowMs:when});
 collector.collect(c,{initialize:true,nowMs:when});
 fs.writeFileSync(path.join(node,'journal.jsonl'),'unchanged old compute journal fixture\n',{mode:0o600});
 fs.writeFileSync(path.join(root,'old-spine.jsonl'),'unchanged separate event spine fixture\n',{mode:0o600});
 const command=path.join(root,'synthetic-mtg'),policyFile=path.join(root,'synthetic-policy.py'),marker=path.join(root,'samples');
 const status={android_thermal_severity:0,decision_for_optional_jobs:'ALLOW',nice_increase:15,poll_interval_seconds:10,
  resume_requires:'two consecutive samples with severity 0 or 1',factory_throttling_modified:false,adb_required:false};
 const commandRaw=Buffer.from('#!/bin/sh\nprintf "sample\\n" >> "'+marker+'"\nprintf \'%s\\n\' \''+JSON.stringify(status)+'\'\n');
 const policyRaw=Buffer.from('# Synthetic native policy: no device calls.\n');
 fs.writeFileSync(command,commandRaw,{mode:0o700});fs.writeFileSync(policyFile,policyRaw,{mode:0o600});
 const profile={command,commandSha256:fed.sha(commandRaw),policyFile,policySha256:fed.sha(policyRaw)};
 const g={schema:'mikaya.mobile-edge.local-gateway.v1',nodeDir:node,expectedFingerprint:meta.fingerprint,
  collectorConfigFile:path.join(root,'collector.json'),port:4188,nativeMtg:profile};
 const input={gatewayConfigFile:path.join(root,'gateway.json'),observationConfigFile:path.join(root,'observation.json')};
 json(g.collectorConfigFile,c);json(input.gatewayConfigFile,g);json(input.observationConfigFile,o);
 const servers=[];t.after(async()=>{
  for(const s of servers)if(s.listening)await new Promise(resolve=>s.close(resolve));
  fs.rmSync(root,{recursive:true,force:true});
 });
 const runner=(cmd,args)=>({status:0,signal:null,stdout:Buffer.from(p.PROBES.find(v=>v.property===args[0]).expected+'\n'),stderr:Buffer.alloc(0)});
 return {root,node,meta,p,o,c,g,input,servers,marker,when,ledger,runner};
}
async function start(x,{allowWork=()=>true,collectorConfig=x.c}={}){
 const server=gateway.startLocalGateway({dir:x.node,expectedFingerprint:x.meta.fingerprint,collectorConfig,port:0,allowWork});
 x.servers.push(server);await new Promise((resolve,reject)=>{server.once('listening',resolve);server.once('error',reject);});
 x.g.port=server.address().port;json(x.input.gatewayConfigFile,x.g);return server;
}
function immutableOwner(x){
 return Object.fromEntries(['identity-private.pem','identity-public.pem','node.json','peers.json','policy.json','journal.jsonl']
  .map(n=>[n,fed.sha(fs.readFileSync(path.join(x.node,n)))]).concat([['old-spine',fed.sha(fs.readFileSync(path.join(x.root,'old-spine.jsonl')))]]));
}
function source(x){return {
 ledger:Object.fromEntries(fs.readdirSync(x.o.ledger_dir).map(n=>[n,fed.sha(fs.readFileSync(path.join(x.o.ledger_dir,n)))])),
 receipts:Object.fromEntries(fs.readdirSync(x.o.receipt_dir).map(n=>[n,fed.sha(fs.readFileSync(path.join(x.o.receipt_dir,n)))])),
 projection:fed.sha(fs.readFileSync(path.join(x.c.state_dir,'projection.jsonl')))
};}
function harness(x,overrides={}){
 let now=0,samples=0,reads=0;const calls=[],events=[];
 const deps={policy:profile=>{assert.deepEqual(profile,x.g.nativeMtg);return ()=>{events.push('sample');return ++samples===2;};},
  now:()=>now,sleep:async ms=>{events.push('wait');now+=ms;},
  read:async options=>{events.push('read');reads++;return gateway.readLocalGateway(options);},
  run:(command,args,options)=>{
   events.push('produce');calls.push({command,args,options});
   const config=JSON.parse(fs.readFileSync(args[2])),selected=require(args[0]);
   const receipt=selected.produce(config,{runner:x.runner});
   return {status:0,signal:null,stdout:Buffer.from(JSON.stringify(receipt)+'\n'),stderr:Buffer.alloc(0)};
  },...overrides};
 return {run:workflow.forTesting(deps),deps,calls,events,samples:()=>samples,reads:()=>reads,advance:ms=>{now+=ms;}};
}
function denied(result,phase){
 assert.equal(result.status,'HOLD');if(phase)assert.equal(result.phase,phase);
 assert.equal(result.verifiedGatewayBody,null);assert.equal(result.actAdmission,'HOLD');
 for(const key of ['hardwareAttested','computeAuthorized','fileTransferAuthorized','paymentAuthorized','deviceControlAuthorized'])assert.equal(result[key],false);
}

test('fixed F110 and Motorola normal-mode producers feed actual authenticated loopback reads without changing owner state',async t=>{
 for(const owner of ['MIKAYA','MOTOROLA']){
  const x=fixture(t,{owner}),before=immutableOwner(x);let gatewaySamples=0;
  await start(x,{allowWork:()=>++gatewaySamples>1});const h=harness(x),out=await h.run(x.input);
  assert.equal(out.status,'VERIFIED_LOCAL_OBSERVATION');assert.equal(out.phase,'complete');assert.equal(out.observationWriteAttempted,true);
  assert.equal(h.samples(),2);assert.equal(h.reads(),2);assert.equal(h.calls.length,1);
  assert.deepEqual(h.events,['sample','read','wait','sample','produce','read']);
  const child=h.calls[0];assert.equal(child.command,process.execPath);
  assert.equal(child.args[0],owner==='MIKAYA'?path.resolve(__dirname,'../../../../integrations/security-tollbooth/verified-events/device_observation_producer.cjs'):path.resolve(__dirname,'../motorola-observation-producer.cjs'));
  assert.deepEqual(child.args.slice(1),['--config',x.input.observationConfigFile]);
  assert.equal(child.options.shell,false);assert.equal(child.options.timeout,8000);assert.equal(child.options.maxBuffer,8192);assert.equal(child.options.killSignal,'SIGKILL');
  assert.deepEqual(child.options.env,{HOME:os.homedir(),PREFIX,PATH:PREFIX+'/bin',LANG:'C.UTF-8'});
  assert.equal(out.producerReceipt.initialized,false);assert.equal(out.producerReceipt.index,2);assert.equal(out.producerReceipt.already_recorded,false);
  const body=out.verifiedGatewayBody;assert.equal(body.status,'VERIFIED_LOCAL_EVIDENCE');assert.equal(body.ownerFingerprint,x.meta.fingerprint);
  assert.equal(body.recognizedEventCount,2);assert.equal(body.sourceLatestAtMs,out.producerReceipt.observed_at_ms);
  assert.equal(body.projectionSha256,fed.sha(fs.readFileSync(path.join(x.c.state_dir,'projection.jsonl'))));
  assert.equal(Object.isFrozen(out),true);assert.equal(Object.isFrozen(out.producerReceipt),true);assert.equal(Object.isFrozen(body),true);
  for(const value of [out,body]){assert.equal(value.actAdmission,'HOLD');for(const key of ['hardwareAttested','computeAuthorized','fileTransferAuthorized','paymentAuthorized','deviceControlAuthorized'])assert.equal(value[key],false);}
  assert.throws(()=>{out.paymentAuthorized=true;},TypeError);assert.deepEqual(immutableOwner(x),before);
  assert.doesNotMatch(JSON.stringify(out),/PRIVATE KEY|PUBLIC KEY|identity-private|node_dir|receipt_dir|LD_PRELOAD/);
 }
});

test('a real stale-source 503 is warmed, followed by one fresh signed observation and verified evidence',async t=>{
 const x=fixture(t,{stale:true});await start(x);
 await assert.rejects(()=>gateway.readLocalGateway({dir:x.node,expectedFingerprint:x.meta.fingerprint,port:x.g.port}),/local_gateway_hold_503/);
 const h=harness(x),out=await h.run(x.input);assert.equal(out.status,'VERIFIED_LOCAL_OBSERVATION');assert.equal(h.calls.length,1);
 assert.ok(out.producerReceipt.observed_at_ms>x.when+60000);assert.equal(out.verifiedGatewayBody.maxAgeMs,60000);
 assert.equal(x.c.max_age_ms,60000);assert.equal(JSON.parse(fs.readFileSync(x.g.collectorConfigFile)).max_age_ms,60000);
});

test('the helper and listener each obtain two real native samples across the same warm-up interval',async t=>{
 const x=fixture(t);await start(x,{allowWork:createNativeMtgPolicy(x.g.nativeMtg)});const h=harness(x);
 const run=workflow.forTesting({run:h.deps.run});const out=await run(x.input);
 assert.equal(out.status,'VERIFIED_LOCAL_OBSERVATION');assert.equal(h.calls.length,1);
 assert.equal(fs.readFileSync(x.marker,'utf8'),'sample\nsample\nsample\nsample\n');
});

test('closed configs, owner/profile mismatch and collector redirection refuse before native work or writes',async t=>{
 const changes=[
  x=>{x.g.remoteHost='example.invalid';json(x.input.gatewayConfigFile,x.g);},
  x=>{x.g.nativeMtg.clock=0;json(x.input.gatewayConfigFile,x.g);},
  x=>{x.o.runner='/unreviewed';json(x.input.observationConfigFile,x.o);},
  x=>{x.o.schema='mikaya.device-observation-config.v1';json(x.input.observationConfigFile,x.o);},
  x=>{x.o.schema=[x.o.schema];json(x.input.observationConfigFile,x.o);},
  x=>{x.o.expected_fingerprint='0'.repeat(64);json(x.input.observationConfigFile,x.o);},
  x=>{x.c.ledger_dir=path.join(x.root,'different-events');json(x.g.collectorConfigFile,x.c);},
  x=>{x.c.max_age_ms=300000;json(x.g.collectorConfigFile,x.c);},
  x=>{x.o.receipt_dir=x.node;json(x.input.observationConfigFile,x.o);},
  x=>{const file=path.join(x.node,'node.json'),meta=JSON.parse(fs.readFileSync(file));meta.platform.androidApi=35;json(file,meta);},
  x=>{const file=path.join(x.node,'policy.json'),p=JSON.parse(fs.readFileSync(file));p.enabled=false;json(file,p);}
 ];
 for(const change of changes){const x=fixture(t),before=source(x);change(x);const h=harness(x),out=await h.run(x.input);
  denied(out,'configuration');assert.equal(out.observationWriteAttempted,false);assert.equal(h.samples(),0);assert.equal(h.calls.length,0);
  // A path mismatch changes only configuration, never the actual source directories.
  const stored=JSON.parse(fs.readFileSync(x.input.observationConfigFile));
  assert.equal(fs.readdirSync(path.join(x.root,'signed-observations')).length,Object.keys(before.ledger).length);
  assert.equal(fs.readdirSync(path.join(x.root,'observation-receipts')).length,Object.keys(before.receipts).length);
  assert.equal(stored.schema!==undefined,true);
 }
});

for(const kind of ['symlink','hardlink','mode','relative','parent-traversal','oversize','invalid-utf8'])test('config reads refuse '+kind,async t=>{
  const x=fixture(t),before=source(x),h=harness(x);let input={...x.input};
  if(kind==='symlink'){const target=path.join(x.root,'linked-config');fs.symlinkSync(x.input.gatewayConfigFile,target);input.gatewayConfigFile=target;}
  if(kind==='hardlink'){
   const link=path.join(x.root,'other-link');
   try{fs.linkSync(x.input.gatewayConfigFile,link);}
   catch(e){
    if((process.platform==='android'||process.execPath.startsWith('/data/data/com.termux/files/usr/bin/')) && ['EACCES','EPERM','ENOTSUP','EOPNOTSUPP'].includes(e.code)){
     assert.equal(fs.existsSync(link),false);
     assert.equal(fs.statSync(x.input.gatewayConfigFile).nlink,1);
     assert.deepEqual(source(x),before);
     assert.equal(h.calls.length,0);assert.equal(h.samples(),0);
     t.skip('Android refused hard-link fixture; application rejection not exercised');return;
    }
    throw e;
   }
   assert.equal(fs.statSync(x.input.gatewayConfigFile).nlink,2);
  }
  if(kind==='mode')fs.chmodSync(x.input.gatewayConfigFile,0o644);
  if(kind==='relative')input.gatewayConfigFile=path.relative(process.cwd(),x.input.gatewayConfigFile);
  if(kind==='parent-traversal')input.gatewayConfigFile=path.join(x.root,'missing')+'/../gateway.json';
  if(kind==='oversize')fs.writeFileSync(x.input.gatewayConfigFile,Buffer.alloc(8193,32));
  if(kind==='invalid-utf8')fs.writeFileSync(x.input.gatewayConfigFile,Buffer.from([0xff]));
  const out=await h.run(input);denied(out,'configuration');assert.equal(h.calls.length,0);assert.equal(h.samples(),0);assert.deepEqual(source(x),before);
});

test('missing checkpoint, receipt or source and mismatched initialization cannot be repaired by this helper',async t=>{
 for(const kind of ['checkpoint','receipt','source','header-pin','receipt-tamper','checkpoint-head']){
  const x=fixture(t),file=path.join(x.c.state_dir,'projection.jsonl');
  if(kind==='checkpoint')fs.unlinkSync(file);
  if(kind==='receipt')fs.unlinkSync(path.join(x.o.receipt_dir,fs.readdirSync(x.o.receipt_dir)[0]));
  if(kind==='source')fs.unlinkSync(path.join(x.o.ledger_dir,'000001.json'));
  if(kind==='receipt-tamper'){const r=path.join(x.o.receipt_dir,fs.readdirSync(x.o.receipt_dir)[0]);fs.writeFileSync(r,'{}\n');}
  if(kind==='header-pin'||kind==='checkpoint-head'){
   const lines=fs.readFileSync(file,'utf8').trimEnd().split('\n'),header=JSON.parse(lines[0]);
   if(kind==='header-pin')header.signerFingerprint='0'.repeat(64);else header.headHash='0'.repeat(64);
   lines[0]=fed.canonical(header);fs.writeFileSync(file,lines.join('\n')+'\n');
  }
  const h=harness(x),out=await h.run(x.input);denied(out,'initialized_state');assert.equal(h.samples(),0);assert.equal(h.calls.length,0);
  if(kind==='checkpoint')assert.equal(fs.existsSync(file),false);
  if(kind==='receipt')assert.equal(fs.readdirSync(x.o.receipt_dir).length,0);
  if(kind==='source')assert.equal(fs.existsSync(path.join(x.o.ledger_dir,'000001.json')),false);
 }
});

test('existing producer, append and collector locks remain untouched and prevent any attempt',async t=>{
 for(const [dir,key] of [['receipt_dir','.producer.lock'],['ledger_dir','.append.lock'],['state_dir','.collector.lock']]){
  const x=fixture(t),where=path.join(x.o[dir]||x.c[dir],key);fs.mkdirSync(where,{mode:0o700});
  const ino=fs.lstatSync(where).ino,h=harness(x),out=await h.run(x.input);denied(out,'initialized_state');
  assert.equal(out.observationWriteAttempted,false);assert.equal(h.samples(),0);assert.equal(h.calls.length,0);assert.equal(fs.lstatSync(where).ino,ino);
 }
});

test('unsafe, late or missing second native samples hold without calling a producer',async t=>{
 for(const mode of ['unsafe-second','unsafe-first','late','rollback']){
  const x=fixture(t),before=source(x);await start(x);let calls=0;
  const h=harness(x,{policy:()=>()=>{calls++;return false;}});
  if(mode==='unsafe-first')h.deps.policy=()=>()=>++calls===1;
  if(mode==='late')h.deps.sleep=async()=>h.advance(20001);
  if(mode==='rollback')h.deps.sleep=async()=>h.advance(-1);
  const out=await workflow.forTesting(h.deps)(x.input);denied(out,mode==='unsafe-first'?'native_warmup':'native_admission');
  assert.equal(h.calls.length,0);assert.equal(out.observationWriteAttempted,false);assert.deepEqual(source(x),before);
 }
});

test('warm-up accepts only the specific 503 HOLD, not authentication, capacity, timeout or malformed errors',async t=>{
 for(const error of ['local_gateway_hold_401','local_gateway_hold_429','local_gateway_timeout','invalid_local_challenge']){
  const x=fixture(t),before=source(x),h=harness(x,{read:async()=>{throw Error(error);}}),out=await h.run(x.input);
  denied(out,'warm_gateway');assert.equal(h.samples(),1);assert.equal(h.calls.length,0);assert.deepEqual(source(x),before);
 }
});

test('config changes and owner kill switch during cooldown are rechecked before a source attempt',async t=>{
 for(const change of ['config','policy','missing-checkpoint']){
  const x=fixture(t);await start(x);const h=harness(x);
  h.deps.sleep=async ms=>{
   h.advance(ms);
   if(change==='config'){x.o.expected_fingerprint='0'.repeat(64);json(x.input.observationConfigFile,x.o);}
   if(change==='policy'){const file=path.join(x.node,'policy.json'),policy=JSON.parse(fs.readFileSync(file));policy.enabled=false;json(file,policy);}
   if(change==='missing-checkpoint')fs.unlinkSync(path.join(x.c.state_dir,'projection.jsonl'));
  };
  const out=await workflow.forTesting(h.deps)(x.input);denied(out,'state_recheck');assert.equal(h.calls.length,0);assert.equal(out.observationWriteAttempted,false);
  assert.equal(fs.readdirSync(x.o.ledger_dir).length,2);
 }
});

test('native source drift and an unverified Play Termux loader pin cannot reach the fixed producer',async t=>{
 for(const mode of ['source-drift','unverified-termux-loader']){
  const x=fixture(t);await start(x);const before=source(x),h=harness(x);
  if(mode==='source-drift')h.deps.sleep=async ms=>{h.advance(ms);fs.appendFileSync(x.g.nativeMtg.policyFile,'# changed pinned source\n');};
  else{x.g.nativeMtg.termuxExecSha256='0'.repeat(64);json(x.input.gatewayConfigFile,x.g);}
  const out=await workflow.forTesting(h.deps)(x.input);denied(out,'native_admission');
  assert.equal(out.observationWriteAttempted,false);assert.equal(h.calls.length,0);assert.deepEqual(source(x),before);
 }
});

test('a final signed-read HOLD preserves the successful producer receipt and immutable new observation',async t=>{
 const x=fixture(t);await start(x);let reads=0;
 const h=harness(x,{read:async options=>{if(++reads===2)throw Error('local_gateway_hold_503');return gateway.readLocalGateway(options);}});
 const out=await h.run(x.input);denied(out,'verify_gateway');assert.equal(out.observationWriteAttempted,true);
 assert.equal(h.calls.length,1);assert.equal(out.producerReceipt.index,2);assert.equal(fs.readdirSync(x.o.ledger_dir).length,3);
 assert.equal(fs.readdirSync(x.o.receipt_dir).length,2);assert.equal(out.producerReceipt.initialized,false);
 assert.equal(JSON.parse(fs.readFileSync(path.join(x.c.state_dir,'projection.jsonl'),'utf8').split('\n')[0]).headIndex,1);
 const resumed=await gateway.readLocalGateway({dir:x.node,expectedFingerprint:x.meta.fingerprint,port:x.g.port});
 assert.equal(resumed.recognizedEventCount,2);assert.equal(resumed.sourceLatestAtMs,out.producerReceipt.observed_at_ms);
});

test('a child timeout after append neither retries nor removes source evidence or a foreign lock',async t=>{
 const x=fixture(t);await start(x);const h=harness(x),original=h.deps.run;
 h.deps.run=(command,args,options)=>{
  original(command,args,options);fs.mkdirSync(path.join(x.o.receipt_dir,'.producer.lock'),{mode:0o700});
  return {status:null,signal:'SIGKILL',error:Error('synthetic timeout after append'),stdout:Buffer.alloc(0),stderr:Buffer.alloc(0)};
 };
 const out=await workflow.forTesting(h.deps)(x.input);denied(out,'produce');assert.equal(out.observationWriteAttempted,true);
 assert.equal(out.producerReceipt,null);assert.equal(h.calls.length,1);assert.equal(fs.readdirSync(x.o.ledger_dir).length,3);
 assert.equal(fs.statSync(path.join(x.o.receipt_dir,'.producer.lock')).isDirectory(),true);
});

test('an authentic same-owner gateway on a different signed source cannot satisfy the produced-observation binding',async t=>{
 const x=fixture(t),other=path.join(x.root,'different-valid-ledger'),state=path.join(x.root,'different-valid-projection');
 x.ledger.initializeLedger({nodeDir:x.node,ledgerDir:other});
 x.ledger.appendDigest({nodeDir:x.node,ledgerDir:other,kind:'OWNER_EVIDENCE_REVIEWED',payloadSha256:fed.sha('separate synthetic evidence')});
 const c={...x.c,ledger_dir:other,state_dir:state};collector.collect(c,{initialize:true});await start(x,{collectorConfig:c});
 const h=harness(x),out=await h.run(x.input);denied(out,'bind_evidence');assert.equal(h.calls.length,1);
 assert.equal(out.producerReceipt.index,2);assert.equal(fs.readdirSync(x.o.ledger_dir).length,3);
 assert.equal(JSON.parse(fs.readFileSync(path.join(x.c.state_dir,'projection.jsonl'),'utf8').split('\n')[0]).headIndex,1);
});

test('actual gateway verification rejects a signed response whose evidence body was altered in transport',async t=>{
 const x=fixture(t),real=await start(x),originalPort=real.address().port;
 const proxy=http.createServer((req,res)=>{
  const incoming=http.request({hostname:'127.0.0.1',port:originalPort,path:req.url,method:req.method,
   headers:{...req.headers,host:'127.0.0.1:'+originalPort}},response=>{
   const chunks=[];response.on('data',chunk=>chunks.push(chunk));response.on('end',()=>{
    const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if(value.body)value.body.paymentAuthorized=true;
    const raw=Buffer.from(JSON.stringify(value));res.writeHead(response.statusCode,{'Content-Type':'application/json','Content-Length':raw.length});res.end(raw);
   });
  });incoming.on('error',()=>{res.writeHead(503);res.end('{}');});req.pipe(incoming);
 });
 x.servers.push(proxy);proxy.listen(0,'127.0.0.1');await new Promise(resolve=>proxy.once('listening',resolve));
 x.g.port=proxy.address().port;json(x.input.gatewayConfigFile,x.g);
 const before=source(x),h=harness(x),out=await h.run(x.input);denied(out,'warm_gateway');assert.equal(h.calls.length,0);assert.deepEqual(source(x),before);
});

test('CLI accepts only both explicit config paths, cannot initialize, and refuses NODE_OPTIONS',t=>{
 const x=fixture(t),env={...process.env};delete env.NODE_OPTIONS;
 fs.unlinkSync(path.join(x.c.state_dir,'projection.jsonl'));
 const correct=['--gateway-config',x.input.gatewayConfigFile,'--observation-config',x.input.observationConfigFile];
 const invoke=(args,extra={})=>spawnSync(process.execPath,[CLI,...args],{timeout:3000,encoding:'utf8',env:{...env,...extra}});
 let child=invoke(correct);assert.equal(child.status,2);denied(JSON.parse(child.stdout),'initialized_state');assert.equal(child.stderr,'');
 assert.equal(fs.existsSync(path.join(x.c.state_dir,'projection.jsonl')),false);
 for(const args of [[...correct,'--initialize-new'],['--config',x.input.gatewayConfigFile],
  ['--observation-config',x.input.observationConfigFile,'--gateway-config',x.input.gatewayConfigFile],
  [...correct,'--runner','anything'],[...correct,'--clock','0']]){
  child=invoke(args);assert.equal(child.status,2);denied(JSON.parse(child.stdout),'usage');
 }
 child=invoke(correct,{NODE_OPTIONS:'--no-warnings'});assert.equal(child.status,2);denied(JSON.parse(child.stdout),'configuration');
 assert.equal(fs.readdirSync(x.o.ledger_dir).length,2);assert.equal(fs.readdirSync(x.o.receipt_dir).length,1);
 assert.throws(()=>workflow.forTesting({host:'remote.invalid'}));assert.throws(()=>workflow.forTesting({initialize:true}));
});
