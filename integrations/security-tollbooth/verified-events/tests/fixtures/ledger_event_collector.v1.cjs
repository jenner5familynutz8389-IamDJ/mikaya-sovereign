#!/usr/bin/env node
'use strict';
/** One-shot public-key-only projection. No signing, networking, service or wallet API. */
const fs=require('node:fs'), path=require('node:path'), crypto=require('node:crypto');
const {TextDecoder}=require('node:util'), Module=require('node:module');
const PINS=Object.freeze({
 'sovereign-event-ledger.cjs':'56c894c87d6d7d4bb57d90e520b80f968a72a683469defc0b5e7d36c49f13c65',
 'federation-node.cjs':'33ea94880c74c7392535ff443b467a7df79117f2bf42993956a5add4ee7f1827'
});
const LIMITS=Object.freeze({records:4096,rowBytes:2200,sourceBytes:8*1024*1024,projectionBytes:8*1024*1024,configBytes:8192,keyBytes:4096,futureSkewMs:30000});
const SHA=/^[a-f0-9]{64}$/, FILE=/^[0-9]{6}\.json$/;
const KIND=new Set(['DEVICE_HEALTH_OBSERVED','TOYBOX_CHAIN_OBSERVED','FEDERATION_COMPUTE_OBSERVED','OWNER_CORRECTION_DRAFTED','OWNER_EVIDENCE_REVIEWED']);
const O=fs.constants, uid=process.getuid?.();
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const fail=x=>{throw Error(x);};
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join('|')===[...keys].sort().join('|');
const identity=s=>[s.dev,s.ino,s.size,s.mtimeNs,s.ctimeNs,s.nlink].map(String).join(':');
function readRegular(file,max,{privateFile=false,owned=true}={}){
 const pre=fs.lstatSync(file,{bigint:true});
 if(!pre.isFile()||pre.isSymbolicLink()||pre.nlink!==1n||pre.size>BigInt(max)||
    (privateFile&&(Number(pre.mode)&0o077))||(owned&&uid!==undefined&&pre.uid!==BigInt(uid)))fail('unsafe_input_file');
 const fd=fs.openSync(file,O.O_RDONLY|O.O_NOFOLLOW|O.O_NONBLOCK);
 try{
  const before=fs.fstatSync(fd,{bigint:true});
  if(identity(pre)!==identity(before))fail('input_changed');
  const buf=Buffer.alloc(max+1);let count=0;
  while(count<=max){const n=fs.readSync(fd,buf,count,buf.length-count,null);if(!n)break;count+=n;}
  if(count>max||identity(before)!==identity(fs.fstatSync(fd,{bigint:true})))fail('input_changed_or_oversized');
  return buf.subarray(0,count);
 }finally{fs.closeSync(fd);}
}
function text(raw){return new TextDecoder('utf-8',{fatal:true}).decode(raw);}
function privateDir(dir){
 if(typeof dir!=='string'||!path.isAbsolute(dir)||path.resolve(dir)!==dir||fs.realpathSync(dir)!==dir)fail('canonical_absolute_directory_required');
 const s=fs.lstatSync(dir);
 if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o077)||(uid!==undefined&&s.uid!==uid))fail('unsafe_private_directory');
 return s;
}
function loadVerifier(){
 const cache=new Map();
 function load(name){
  if(cache.has(name))return cache.get(name).exports;
  if(!Object.hasOwn(PINS,name))fail('unreviewed_verifier_dependency');
  const file=path.join(__dirname,'vendor',name),raw=readRegular(file,131072,{owned:false});
  if(sha(raw)!==PINS[name])fail('verifier_source_pin_failed');
  const mod=new Module(file);cache.set(name,mod);mod.filename=file;
  mod.require=specifier=>{
   if(specifier.startsWith('node:')&&['node:fs','node:path','node:crypto','node:http','node:https','node:url'].includes(specifier))return require(specifier);
   if(specifier==='./federation-node.cjs')return load(specifier.slice(2));
   fail('unreviewed_verifier_dependency');
  };
  mod._compile(text(raw),file);return mod.exports;
 }
 return {ledger:load('sovereign-event-ledger.cjs'),fed:load('federation-node.cjs')};
}
function configCheck(c){
 if(!exact(c,['schema','ledger_dir','public_key_path','expected_fingerprint','state_dir','max_age_ms'])||
    c.schema!=='mikaya.verified-ledger-config.v1'||!SHA.test(c.expected_fingerprint)||
    !Number.isSafeInteger(c.max_age_ms)||c.max_age_ms<60000||c.max_age_ms>86400000)fail('invalid_config');
 for(const k of ['ledger_dir','public_key_path','state_dir'])if(typeof c[k]!=='string'||!path.isAbsolute(c[k])||path.resolve(c[k])!==c[k])fail('absolute_config_path_required');
 if(c.state_dir===c.ledger_dir||c.state_dir.startsWith(c.ledger_dir+'/')||c.ledger_dir.startsWith(c.state_dir+'/'))fail('state_and_source_must_be_separate');
}
function syncedWrite(file,raw){
 const fd=fs.openSync(file,O.O_WRONLY|O.O_CREAT|O.O_EXCL|O.O_NOFOLLOW,0o600);
 try{fs.writeFileSync(fd,raw);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
}
function syncDir(dir){const fd=fs.openSync(dir,O.O_RDONLY|O.O_DIRECTORY|O.O_NOFOLLOW);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function previousProjection(file,canonical){
 const raw=readRegular(file,LIMITS.projectionBytes,{privateFile:true}),lines=text(raw).split('\n');
 if(lines.pop()!=='')fail('checkpoint_newline_required');
 const header=JSON.parse(lines.shift());
 const keys=['type','schema','signerFingerprint','genesisHash','headIndex','headHash','eventCount','latestObservationAtMs','projectionSha256'];
 if(!exact(header,keys)||header.type!=='MIKAYA_VERIFIED_LEDGER_CHECKPOINT'||header.schema!=='mikaya.verified-ledger-projection.v1'||
    !SHA.test(header.signerFingerprint)||!SHA.test(header.genesisHash)||!SHA.test(header.headHash)||!SHA.test(header.projectionSha256)||
    !Number.isSafeInteger(header.headIndex)||header.headIndex<1||header.headIndex>=LIMITS.records||
    header.eventCount!==header.headIndex||lines.length!==header.eventCount||!Number.isSafeInteger(header.latestObservationAtMs))fail('invalid_checkpoint');
 if(canonical(header)+'\n'+lines.join('\n')+'\n'!==text(raw)||sha(lines.join('\n')+'\n')!==header.projectionSha256)fail('checkpoint_integrity_failed');
 return {header,raw};
}
function collectInto(c,{initialize=false,nowMs=Date.now(),preparedState=false}={}){
 configCheck(c);
 if(!Number.isSafeInteger(nowMs)||nowMs<0)fail('invalid_clock');
 privateDir(c.ledger_dir);
 if(initialize&&!preparedState){privateDir(path.dirname(c.state_dir));fs.mkdirSync(c.state_dir,{mode:0o700});}
 privateDir(c.state_dir);
 const lock=path.join(c.state_dir,'.collector.lock');fs.mkdirSync(lock,{mode:0o700});
 const lockIdentity=fs.lstatSync(lock);let snapshot;
 try{
  const {ledger,fed}=loadVerifier(),checkpoint=path.join(c.state_dir,'projection.jsonl');
  const prior=initialize?null:previousProjection(checkpoint,fed.canonical);
  if(initialize&&fs.existsSync(checkpoint))fail('initialization_refuses_existing_checkpoint');
  const pem=readRegular(c.public_key_path,LIMITS.keyBytes);
  if(!/^-----BEGIN PUBLIC KEY-----\n[\s\S]*\n-----END PUBLIC KEY-----\n?$/.test(text(pem)))fail('public_spki_pem_required');
  const publicKey=crypto.createPublicKey(pem);
  if(publicKey.asymmetricKeyType!=='ed25519'||fed.fp(publicKey)!==c.expected_fingerprint)fail('public_identity_pin_failed');
  const before=fs.statSync(c.ledger_dir,{bigint:true}),names=fs.readdirSync(c.ledger_dir).sort();
  if(names.length<2||names.length>LIMITS.records||names.some((n,i)=>!FILE.test(n)||n!==String(i).padStart(6,'0')+'.json'))fail('ledger_missing_busy_or_out_of_bounds');
  snapshot=fs.mkdtempSync(path.join(c.state_dir,'.verify-'));fs.chmodSync(snapshot,0o700);
  const rows=[];let total=0;
  for(const name of names){
   const raw=readRegular(path.join(c.ledger_dir,name),LIMITS.rowBytes,{privateFile:true});
   total+=raw.length;if(total>LIMITS.sourceBytes)fail('ledger_byte_limit');
   rows.push(JSON.parse(text(raw)));syncedWrite(path.join(snapshot,name),raw);
  }
  if(identity(before)!==identity(fs.statSync(c.ledger_dir,{bigint:true}))||names.join('|')!==fs.readdirSync(c.ledger_dir).sort().join('|'))fail('ledger_changed_during_snapshot');
  const verified=ledger.verifyLedger({ledgerDir:snapshot,publicPem:pem});
  if(verified.ownerFingerprint!==c.expected_fingerprint||verified.entries!==rows.length)fail('verified_source_mismatch');
  const first=rows[0],last=rows.at(-1);
  if(last.issuedAtMs>nowMs+LIMITS.futureSkewMs||nowMs-last.issuedAtMs>c.max_age_ms)fail('ledger_observation_stale_or_future');
  if(prior){const p=prior.header;
   if(p.signerFingerprint!==c.expected_fingerprint||p.genesisHash!==first.entryHash||
      rows.length<=p.headIndex||rows[p.headIndex].entryHash!==p.headHash)fail('ledger_rollback_or_replacement');
  }
  const events=rows.slice(1).map(row=>{
   if(!KIND.has(row.kind))fail('unmapped_signed_event_kind');
   return {type:'INTERNAL_WATCHER',ts:new Date(row.issuedAtMs).toISOString(),data:{source:'verified_sovereign_ledger_v1',kind:row.kind,index:row.index,entry_sha256:row.entryHash,payload_sha256:row.payloadSha256}};
  });
  const body=events.map(fed.canonical).join('\n')+'\n';
  const header={type:'MIKAYA_VERIFIED_LEDGER_CHECKPOINT',schema:'mikaya.verified-ledger-projection.v1',signerFingerprint:c.expected_fingerprint,genesisHash:first.entryHash,headIndex:last.index,headHash:last.entryHash,eventCount:events.length,latestObservationAtMs:last.issuedAtMs,projectionSha256:sha(body)};
  const raw=Buffer.from(fed.canonical(header)+'\n'+body);
  if(raw.length>LIMITS.projectionBytes)fail('projection_byte_limit');
  const unchanged=prior&&prior.raw.equals(raw);
  if(!unchanged){const temporary=path.join(c.state_dir,'.projection-'+crypto.randomBytes(12).toString('hex')+'.tmp');
   try{syncedWrite(temporary,raw);fs.renameSync(temporary,checkpoint);syncDir(c.state_dir);}finally{if(fs.existsSync(temporary))fs.unlinkSync(temporary);}
  }
  return {schema:'mikaya.verified-ledger-collection.v1',status:'VERIFIED_LOCAL_PROJECTION',projection_path:checkpoint,projection_sha256:sha(raw),recognized_event_count:events.length,new_events:prior?last.index-prior.header.headIndex:events.length,source_latest_at_ms:last.issuedAtMs,unchanged:!!unchanged,payment_authorized:false,hardware_attested:false};
 }finally{
  if(snapshot)fs.rmSync(snapshot,{recursive:true,force:true});
  const current=fs.lstatSync(lock);
  if(current.dev===lockIdentity.dev&&current.ino===lockIdentity.ino)fs.rmdirSync(lock);
 }
}
function collect(c,{initialize=false,nowMs=Date.now()}={}){
 configCheck(c);
 if(!initialize)return collectInto(c,{nowMs});
 const parent=path.dirname(c.state_dir);privateDir(parent);
 if(fs.existsSync(c.state_dir))fail('EEXIST: initialization_refuses_existing_state');
 const initLock=path.join(parent,'.'+path.basename(c.state_dir)+'.initialize.lock');
 fs.mkdirSync(initLock,{mode:0o700});const lease=fs.lstatSync(initLock);let staging;
 try{
  staging=fs.mkdtempSync(path.join(parent,'.initialize-events-'));fs.chmodSync(staging,0o700);
  const result=collectInto({...c,state_dir:staging},{initialize:true,nowMs,preparedState:true});
  if(fs.existsSync(c.state_dir))fail('EEXIST: initialization_refuses_existing_state');
  fs.renameSync(staging,c.state_dir);syncDir(parent);
  return {...result,projection_path:path.join(c.state_dir,'projection.jsonl')};
 }finally{
  if(staging&&fs.existsSync(staging))fs.rmSync(staging,{recursive:true,force:true});
  const current=fs.lstatSync(initLock);if(current.dev===lease.dev&&current.ino===lease.ino)fs.rmdirSync(initLock);
 }
}
function main(args){
 if(args.length<2||args.length>3||args[0]!=='--config'||(args[2]&&args[2]!=='--initialize-new'))fail('usage: --config PRIVATE_JSON [--initialize-new]');
 const c=JSON.parse(text(readRegular(args[1],LIMITS.configBytes,{privateFile:true})));
 console.log(JSON.stringify(collect(c,{initialize:args[2]==='--initialize-new'})));
}
if(require.main===module){try{main(process.argv.slice(2));}catch{console.error(JSON.stringify({status:'HOLD',reason:'signed_ledger_collection_failed'}));process.exitCode=2;}}
module.exports={collect,LIMITS,PINS,loadVerifier};
