#!/usr/bin/env node
'use strict';
/** One bounded owner-local observation and authenticated read. Never initialize or recover state. */
const fs=require('node:fs'),path=require('node:path');
const {spawnSync}=require('node:child_process'),{TextDecoder}=require('node:util');
const fed=require('../live/federation-node.cjs');
const gateway=require('./local-evidence-gateway.cjs');
const {createNativeMtgPolicy,nativeExecutionEnvironment}=require('./native-mtg.cjs');
const SHA=/^[a-f0-9]{64}$/;
const LIMITS=Object.freeze({configBytes:8192,keyBytes:4096,rowBytes:2200,receiptBytes:512,
 projectionBytes:8*1024*1024,records:4096,childBytes:8192,childTimeoutMs:8000,
 sampleMinimumMs:10000,warmCooldownMs:10800,sampleMaximumMs:20000,maxAgeMs:60000});
const PROFILES=Object.freeze({
 'mikaya.device-observation-config.v1':Object.freeze({owner:'MIKAYA',api:35,
  script:path.resolve(__dirname,'../../../integrations/security-tollbooth/verified-events/device_observation_producer.cjs'),
  receiptSchema:'mikaya.device-observation.v1',productionSchema:'mikaya.device-observation-production.v1',
  model:'F110 Pro',platform:'mt6835',androidRelease:'15'}),
 'mikaya.motorola-observation-config.v1':Object.freeze({owner:'MOTOROLA',api:34,
  script:path.join(__dirname,'motorola-observation-producer.cjs'),
  receiptSchema:'mikaya.motorola-observation.v1',productionSchema:'mikaya.motorola-observation-production.v1',
  model:'moto g power 5G - 2023',platform:'mt6855',androidRelease:'14'})
});
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join('|')===[...keys].sort().join('|');
const hash=x=>typeof x==='string'&&SHA.test(x);
const fail=()=>{throw Error('owner_local_observation_hold');};
const text=raw=>new TextDecoder('utf-8',{fatal:true}).decode(raw);
const identity=s=>[s.dev,s.ino,s.size,s.mtimeNs,s.ctimeNs,s.nlink,s.uid,s.mode].map(String).join(':');
function absolute(file){if(typeof file!=='string'||!path.isAbsolute(file)||path.resolve(file)!==file)fail();}
function privateDir(dir){
 absolute(dir);if(fs.realpathSync(dir)!==dir||typeof process.getuid!=='function')fail();
 const st=fs.lstatSync(dir);
 if(!st.isDirectory()||st.isSymbolicLink()||(st.mode&0o077)||st.uid!==process.getuid())fail();
}
function privateRead(file,max){
 absolute(file);if(fs.realpathSync(file)!==file||typeof process.getuid!=='function')fail();
 const before=fs.lstatSync(file,{bigint:true});
 if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1n||before.size<1n||before.size>BigInt(max)||
    (Number(before.mode)&0o077)||before.uid!==BigInt(process.getuid()))fail();
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 try{
  if(identity(before)!==identity(fs.fstatSync(fd,{bigint:true})))fail();
  const bytes=Buffer.alloc(max+1);let count=0,n;
  while(count<bytes.length&&(n=fs.readSync(fd,bytes,count,bytes.length-count,null)))count+=n;
  if(BigInt(count)!==before.size||count>max||identity(before)!==identity(fs.fstatSync(fd,{bigint:true}))||
     identity(before)!==identity(fs.lstatSync(file,{bigint:true}))||fs.realpathSync(file)!==file)fail();
  return bytes.subarray(0,count);
 }finally{fs.closeSync(fd);}
}
function jsonFile(file,max){const raw=privateRead(file,max);return {file,raw,value:JSON.parse(text(raw))};}
function currentOwner(c){
 privateDir(c.g.nodeDir);
 // Keep all node reads bounded/private before reusing the existing key/policy loader.
 for(const file of ['node.json','policy.json','peers.json','identity-public.pem','identity-private.pem'])
  privateRead(path.join(c.g.nodeDir,file),file.endsWith('.pem')?LIMITS.keyBytes:LIMITS.configBytes);
 const n=fed.loadNode(c.g.nodeDir),p=c.profile;
 if(n.meta.fingerprint!==c.g.expectedFingerprint||fed.fp(n.publicKey)!==c.g.expectedFingerprint||
    n.meta.owner!==p.owner||n.meta.platform?.os!=='android'||n.meta.platform?.androidApi!==p.api||
    n.meta.platform?.arch!=='aarch64')fail();
 return n;
}
function configuration(input){
 if(!exact(input,['gatewayConfigFile','observationConfigFile']))fail();
 const gFile=jsonFile(input.gatewayConfigFile,LIMITS.configBytes),g=gFile.value;
 const optional=['nodePort','nativeMtg'].filter(key=>plain(g)&&Object.hasOwn(g,key));
 if(!exact(g,['schema','nodeDir','expectedFingerprint','collectorConfigFile','port',...optional])||
    g.schema!=='mikaya.mobile-edge.local-gateway.v1'||!hash(g.expectedFingerprint)||
    !Number.isInteger(g.port)||g.port<1024||g.port>65535||
    (Object.hasOwn(g,'nodePort')&&(!Number.isInteger(g.nodePort)||g.nodePort<1024||g.nodePort>65535||g.nodePort===g.port)))fail();
 if(Object.hasOwn(g,'nativeMtg')){
  const p=g.nativeMtg;
  const extra=plain(p)&&Object.hasOwn(p,'termuxExecSha256')?['termuxExecSha256']:[];
  if(!exact(p,['command','commandSha256','policyFile','policySha256',...extra])||!hash(p.commandSha256)||!hash(p.policySha256)||
     (extra.length&&!hash(p.termuxExecSha256)))fail();
  absolute(p.command);absolute(p.policyFile);
 }
 const oFile=jsonFile(input.observationConfigFile,LIMITS.configBytes),o=oFile.value;
 if(!exact(o,['schema','node_dir','ledger_dir','receipt_dir','expected_fingerprint'])||
    typeof o.schema!=='string'||!Object.hasOwn(PROFILES,o.schema)||o.node_dir!==g.nodeDir||o.expected_fingerprint!==g.expectedFingerprint)fail();
 const cFile=jsonFile(g.collectorConfigFile,LIMITS.configBytes),collector=cFile.value;
 if(!exact(collector,['schema','ledger_dir','public_key_path','expected_fingerprint','state_dir','max_age_ms'])||
    collector.schema!=='mikaya.verified-ledger-config.v1'||collector.ledger_dir!==o.ledger_dir||
    collector.expected_fingerprint!==g.expectedFingerprint||collector.max_age_ms!==LIMITS.maxAgeMs)fail();
 const dirs=[g.nodeDir,o.ledger_dir,o.receipt_dir,collector.state_dir];dirs.forEach(absolute);
 for(let i=0;i<dirs.length;i++)for(let j=i+1;j<dirs.length;j++)
  if(dirs[i]===dirs[j]||dirs[i].startsWith(dirs[j]+'/')||dirs[j].startsWith(dirs[i]+'/'))fail();
 const c={g,o,collector,profile:PROFILES[o.schema],files:[gFile,oFile,cFile],observationConfigFile:input.observationConfigFile};
 currentOwner(c);
 if(fed.fp(privateRead(collector.public_key_path,LIMITS.keyBytes))!==g.expectedFingerprint)fail();
 return c;
}
function unchangedConfig(c){for(const f of c.files)if(!privateRead(f.file,LIMITS.configBytes).equals(f.raw))fail();currentOwner(c);}
function noEntry(file){try{fs.lstatSync(file);}catch(e){if(e.code==='ENOENT')return;throw e;}fail();}
function ledgerRow(c,index){
 const raw=privateRead(path.join(c.o.ledger_dir,String(index).padStart(6,'0')+'.json'),LIMITS.rowBytes),row=JSON.parse(text(raw));
 if(!exact(row,['schema','index','prevHash','nodeFingerprint','kind','payloadSha256','issuedAtMs','nonce','entryHash','signature'])||
    row.schema!=='mikaya.sovereign.event.v1'||row.index!==index||row.nodeFingerprint!==c.g.expectedFingerprint||
    !hash(row.entryHash)||!hash(row.payloadSha256)||!Number.isSafeInteger(row.issuedAtMs)||row.issuedAtMs<0||
    text(raw)!==fed.canonical(row)+'\n')fail();
 return row;
}
function matchingReceipt(c,row){
 const raw=privateRead(path.join(c.o.receipt_dir,row.payloadSha256+'.json'),LIMITS.receiptBytes),r=JSON.parse(text(raw)),p=c.profile;
 if(!exact(r,['schema','observedAtMs','model','platform','androidRelease'])||r.schema!==p.receiptSchema||
    r.observedAtMs!==row.issuedAtMs||r.model!==p.model||r.platform!==p.platform||r.androidRelease!==p.androidRelease||
    text(raw)!==fed.canonical(r)+'\n'||fed.sha(fed.canonical(r))!==row.payloadSha256)fail();
}
function projection(c){
 const raw=privateRead(path.join(c.collector.state_dir,'projection.jsonl'),LIMITS.projectionBytes),lines=text(raw).split('\n');
 if(lines.pop()!=='')fail();
 const header=JSON.parse(lines.shift());
 if(!exact(header,['type','schema','signerFingerprint','genesisHash','headIndex','headHash','eventCount','latestObservationAtMs','projectionSha256'])||
    header.type!=='MIKAYA_VERIFIED_LEDGER_CHECKPOINT'||header.schema!=='mikaya.verified-ledger-projection.v1'||
    header.signerFingerprint!==c.g.expectedFingerprint||!hash(header.genesisHash)||!hash(header.headHash)||!hash(header.projectionSha256)||
    !Number.isSafeInteger(header.headIndex)||header.headIndex<1||header.headIndex>=LIMITS.records||
    header.eventCount!==header.headIndex||lines.length!==header.eventCount||!Number.isSafeInteger(header.latestObservationAtMs)||
    header.latestObservationAtMs<0||text(raw)!==fed.canonical(header)+'\n'+lines.join('\n')+'\n'||
    fed.sha(lines.join('\n')+'\n')!==header.projectionSha256)fail();
 const events=lines.map((line,i)=>{
  const event=JSON.parse(line),d=event?.data;
  if(!exact(event,['type','ts','data'])||event.type!=='INTERNAL_WATCHER'||
     !exact(d,['source','kind','index','entry_sha256','payload_sha256'])||d.source!=='verified_sovereign_ledger_v1'||
     d.index!==i+1||!['DEVICE_HEALTH_OBSERVED','TOYBOX_CHAIN_OBSERVED','FEDERATION_COMPUTE_OBSERVED','OWNER_CORRECTION_DRAFTED','OWNER_EVIDENCE_REVIEWED'].includes(d.kind)||
     !hash(d.entry_sha256)||!hash(d.payload_sha256)||
     typeof event.ts!=='string'||!Number.isSafeInteger(Date.parse(event.ts))||line!==fed.canonical(event))fail();
  return event;
 });
 const first=ledgerRow(c,0),head=ledgerRow(c,header.headIndex),last=events.at(-1);
 if(first.kind!=='GENESIS'||first.entryHash!==header.genesisHash||head.entryHash!==header.headHash||
    head.issuedAtMs!==header.latestObservationAtMs||last.data.entry_sha256!==head.entryHash||
    last.data.payload_sha256!==head.payloadSha256||last.data.kind!==head.kind||last.ts!==new Date(head.issuedAtMs).toISOString())fail();
 return {raw,header,events};
}
function initializedState(c,prior){
 for(const dir of [c.o.ledger_dir,c.o.receipt_dir,c.collector.state_dir])privateDir(dir);
 noEntry(path.join(c.o.ledger_dir,'.append.lock'));noEntry(path.join(c.o.receipt_dir,'.producer.lock'));
 noEntry(path.join(c.collector.state_dir,'.collector.lock'));
 const state=projection(c),observed=state.events.findLast(e=>e.data.kind==='DEVICE_HEALTH_OBSERVED');
 if(!observed)fail();
 const row=ledgerRow(c,observed.data.index);
 if(row.kind!=='DEVICE_HEALTH_OBSERVED'||row.entryHash!==observed.data.entry_sha256||
    row.payloadSha256!==observed.data.payload_sha256||observed.ts!==new Date(row.issuedAtMs).toISOString())fail();
 matchingReceipt(c,row);
 if(prior&&(state.header.genesisHash!==prior.header.genesisHash||state.header.headIndex<prior.header.headIndex||
    ledgerRow(c,prior.header.headIndex).entryHash!==prior.header.headHash))fail();
 return state;
}
function producerResult(out,c){
 if(!out||out.error||out.signal||out.status!==0)fail();
 const stdout=Buffer.isBuffer(out.stdout)?out.stdout:typeof out.stdout==='string'?Buffer.from(out.stdout):null;
 const stderr=Buffer.isBuffer(out.stderr)?out.stderr:typeof out.stderr==='string'?Buffer.from(out.stderr):null;
 if(!stdout||stdout.length<1||stdout.length>LIMITS.childBytes||!stderr||stderr.length)fail();
 const r=JSON.parse(text(stdout)),now=Date.now();
 if(!exact(r,['schema','status','initialized','already_recorded','index','entry_sha256','payload_sha256','observed_at_ms','hardware_attested','payment_authorized'])||
    r.schema!==c.profile.productionSchema||r.status!=='DEVICE_OBSERVATION_SIGNED'||r.initialized!==false||
    typeof r.already_recorded!=='boolean'||!Number.isSafeInteger(r.index)||r.index<1||r.index>=LIMITS.records||
    !hash(r.entry_sha256)||!hash(r.payload_sha256)||!Number.isSafeInteger(r.observed_at_ms)||r.observed_at_ms<0||
    now-r.observed_at_ms>LIMITS.maxAgeMs||r.observed_at_ms>now+30000||r.hardware_attested!==false||r.payment_authorized!==false)fail();
 return Object.freeze(r);
}
function bindProducedEvidence(c,receipt,body,prior){
 const state=initializedState(c,prior),row=ledgerRow(c,receipt.index),event=state.events[receipt.index-1];
 if(body.schema!=='mikaya.mobile-edge.evidence.v1'||body.status!=='VERIFIED_LOCAL_EVIDENCE'||
    body.source!=='existing_signed_sovereign_ledger'||body.maxAgeMs!==LIMITS.maxAgeMs||
    body.measurementClass!=='SIGNED_LOCAL_OBSERVATION_DIGESTS'||body.hardwareAttested!==false||body.actAdmission!=='HOLD'||
    body.computeAuthorized!==false||body.fileTransferAuthorized!==false||body.paymentAuthorized!==false||body.deviceControlAuthorized!==false||
    body.ownerFingerprint!==c.g.expectedFingerprint||body.projectionSha256!==fed.sha(state.raw)||
    body.recognizedEventCount!==state.header.eventCount||body.sourceLatestAtMs!==state.header.latestObservationAtMs||
    row.kind!=='DEVICE_HEALTH_OBSERVED'||row.entryHash!==receipt.entry_sha256||row.payloadSha256!==receipt.payload_sha256||
    row.issuedAtMs!==receipt.observed_at_ms||!event||event.data.entry_sha256!==row.entryHash||
    event.data.payload_sha256!==row.payloadSha256||event.data.kind!==row.kind||event.ts!==new Date(row.issuedAtMs).toISOString())fail();
 matchingReceipt(c,row);
}
function result(status,phase,attempted,producerReceipt,verifiedGatewayBody){
 return Object.freeze({schema:'mikaya.mobile-edge.observe-and-read.v1',status,phase,observationWriteAttempted:attempted,
  producerReceipt,verifiedGatewayBody:verifiedGatewayBody?Object.freeze(verifiedGatewayBody):null,
  hardwareAttested:false,actAdmission:'HOLD',computeAuthorized:false,fileTransferAuthorized:false,
  paymentAuthorized:false,deviceControlAuthorized:false});
}
const native=Object.freeze({policy:createNativeMtgPolicy,read:gateway.readLocalGateway,run:spawnSync,
 now:()=>performance.now(),sleep:ms=>new Promise(resolve=>setTimeout(resolve,ms))});
function workflow(deps){return async input=>{
 let phase='configuration',attempted=false,receipt=null;
 try{
  // Node already processes loader variables at startup; launchers must clear them too.
  if(Object.hasOwn(process.env,'NODE_OPTIONS'))fail();
  const c=configuration(input);phase='initialized_state';const prior=initializedState(c);
  phase='native_warmup';const allow=deps.policy(c.g.nativeMtg),started=deps.now();
  if(typeof allow!=='function'||!Number.isFinite(started)||started<0||allow()!==false)fail();
  const firstFinished=deps.now();if(!Number.isFinite(firstFinished)||firstFinished<started)fail();
  const readOptions=Object.freeze({dir:c.g.nodeDir,expectedFingerprint:c.g.expectedFingerprint,port:c.g.port});
  phase='warm_gateway';
  try{await deps.read(readOptions);}catch(e){if(e?.message!=='local_gateway_hold_503')throw e;}
  phase='cooldown';const afterWarm=deps.now();if(!Number.isFinite(afterWarm)||afterWarm<firstFinished)fail();
  // The listener takes its first sample during the warm read, after our own.
  // Start this wait when that read completes so both cooldowns have elapsed.
  await deps.sleep(LIMITS.warmCooldownMs);
  phase='state_recheck';unchangedConfig(c);initializedState(c,prior);
  phase='native_admission';const secondAt=deps.now();
  if(!Number.isFinite(secondAt)||secondAt-firstFinished<LIMITS.sampleMinimumMs||
     secondAt-started>LIMITS.sampleMaximumMs||allow()!==true)fail();
  // No service control, initialization flag, shell, remote host or inherited loader environment.
  unchangedConfig(c);const env=nativeExecutionEnvironment(c.g.nativeMtg);phase='produce';attempted=true;
  receipt=producerResult(deps.run(process.execPath,[c.profile.script,'--config',c.observationConfigFile],{
   shell:false,timeout:LIMITS.childTimeoutMs,maxBuffer:LIMITS.childBytes,killSignal:'SIGKILL',stdio:['ignore','pipe','pipe'],
   env
  }),c);
  phase='verify_gateway';unchangedConfig(c);const body=await deps.read(readOptions);
  phase='bind_evidence';unchangedConfig(c);bindProducedEvidence(c,receipt,body,prior);
  return result('VERIFIED_LOCAL_OBSERVATION','complete',true,receipt,body);
 }catch{return result('HOLD',phase,attempted,receipt,null);}
};}
const observeAndRead=workflow(native);
// Test-only closures cannot be selected through CLI arguments or any configuration file.
function forTesting(overrides){
 if(!plain(overrides)||Object.keys(overrides).some(k=>!Object.hasOwn(native,k)||typeof overrides[k]!=='function'))fail();
 return workflow(Object.freeze({...native,...overrides}));
}
async function main(args){
 if(args.length!==4||args[0]!=='--gateway-config'||args[2]!=='--observation-config'){
  console.log(JSON.stringify(result('HOLD','usage',false,null,null)));process.exitCode=2;return;
 }
 const out=await observeAndRead({gatewayConfigFile:args[1],observationConfigFile:args[3]});
 console.log(JSON.stringify(out));if(out.status==='HOLD')process.exitCode=2;
}
if(require.main===module)main(process.argv.slice(2)).catch(()=>{console.log(JSON.stringify(result('HOLD','unexpected',false,null,null)));process.exitCode=2;});
module.exports={observeAndRead,forTesting,LIMITS};
