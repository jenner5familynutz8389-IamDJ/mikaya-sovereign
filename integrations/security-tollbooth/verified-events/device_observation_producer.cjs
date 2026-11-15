#!/usr/bin/env node
'use strict';
/** One-shot fixed native observation. Only the pinned native API signs ledger rows. */
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {spawnSync}=require('node:child_process'),{TextDecoder}=require('node:util');
const {loadVerifier}=require('./ledger_event_collector.cjs');
const LIMITS=Object.freeze({records:4096,rowBytes:2200,ledgerBytes:8*1024*1024,receipts:4096,receiptBytes:512,configBytes:8192,probeBytes:256,probeTimeoutMs:1000,observationAgeMs:5000,futureSkewMs:30000});
const PROBES=Object.freeze([
 Object.freeze({property:'ro.product.model',field:'model',expected:'F110 Pro'}),
 Object.freeze({property:'ro.board.platform',field:'platform',expected:'mt6835'}),
 Object.freeze({property:'ro.build.version.release',field:'androidRelease',expected:'15'})
]);
const O=fs.constants,SHA=/^[a-f0-9]{64}$/,RECEIPT=/^([a-f0-9]{64})\.json$/,uid=process.getuid?.();
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const fail=x=>{throw Error(x);};
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join('|')===[...keys].sort().join('|');
const identity=s=>[s.dev,s.ino,s.size,s.mtimeNs,s.ctimeNs,s.nlink].map(String).join(':');
const text=b=>new TextDecoder('utf-8',{fatal:true}).decode(b);
function absolute(p){if(typeof p!=='string'||!path.isAbsolute(p)||path.resolve(p)!==p)fail('canonical_absolute_path_required');}
function privateDir(p){
 absolute(p);if(fs.realpathSync(p)!==p)fail('canonical_private_directory_required');
 const s=fs.lstatSync(p);
 if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o077)||(uid!==undefined&&s.uid!==uid))fail('unsafe_private_directory');
 return s;
}
function readRegular(file,max){
 const pre=fs.lstatSync(file,{bigint:true});
 if(!pre.isFile()||pre.isSymbolicLink()||pre.nlink!==1n||pre.size>BigInt(max)||(Number(pre.mode)&0o077)||(uid!==undefined&&pre.uid!==BigInt(uid)))fail('unsafe_input_file');
 const fd=fs.openSync(file,O.O_RDONLY|O.O_NOFOLLOW|O.O_NONBLOCK);
 try{
  const before=fs.fstatSync(fd,{bigint:true});if(identity(pre)!==identity(before))fail('input_changed');
  const bytes=Buffer.alloc(max+1);let n=0;
  while(n<bytes.length){const read=fs.readSync(fd,bytes,n,bytes.length-n,null);if(!read)break;n+=read;}
  if(n>max||identity(before)!==identity(fs.fstatSync(fd,{bigint:true})))fail('input_changed_or_oversized');
  return bytes.subarray(0,n);
 }finally{fs.closeSync(fd);}
}
function syncDir(dir){const fd=fs.openSync(dir,O.O_RDONLY|O.O_DIRECTORY|O.O_NOFOLLOW);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function writeNew(file,bytes,durable=true){
 const fd=fs.openSync(file,O.O_WRONLY|O.O_CREAT|O.O_EXCL|O.O_NOFOLLOW,0o600);
 try{fs.writeFileSync(fd,bytes);if(durable)fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
}
function durableReceipt(file,bytes,dir){
 if(!readRegular(file,LIMITS.receiptBytes).equals(bytes))fail('receipt_conflict');
 const before=fs.lstatSync(file,{bigint:true}),fd=fs.openSync(file,O.O_RDONLY|O.O_NOFOLLOW|O.O_NONBLOCK);
 try{if(identity(before)!==identity(fs.fstatSync(fd,{bigint:true})))fail('receipt_changed');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
 syncDir(dir);
}
function configCheck(c){
 if(!exact(c,['schema','node_dir','ledger_dir','receipt_dir','expected_fingerprint'])||c.schema!=='mikaya.device-observation-config.v1'||typeof c.expected_fingerprint!=='string'||!SHA.test(c.expected_fingerprint))fail('invalid_config');
 const dirs=[c.node_dir,c.ledger_dir,c.receipt_dir];dirs.forEach(absolute);
 for(let i=0;i<dirs.length;i++)for(let j=i+1;j<dirs.length;j++)if(dirs[i]===dirs[j]||dirs[i].startsWith(dirs[j]+'/')||dirs[j].startsWith(dirs[i]+'/'))fail('private_directories_must_be_separate');
}
function currentClock(nowMs){
 const age=Date.now()-nowMs;
 if(!Number.isSafeInteger(nowMs)||nowMs<0||age>LIMITS.observationAgeMs||age < -LIMITS.futureSkewMs)fail('observation_clock_stale_or_future');
}
function receiptCheck(row){
 if(!exact(row,['schema','observedAtMs','model','platform','androidRelease'])||row.schema!=='mikaya.device-observation.v1'||!Number.isSafeInteger(row.observedAtMs)||row.observedAtMs<0||PROBES.some(p=>row[p.field]!==p.expected))fail('invalid_receipt');
}
function receiptInventory(dir,canonical){
 const names=fs.readdirSync(dir).filter(n=>n!=='.producer.lock');
 if(names.length>LIMITS.receipts)fail('receipt_capacity');
 const hashes=new Set();
 for(const name of names){
  const match=RECEIPT.exec(name);if(!match)fail('unexpected_receipt_file');
  const raw=readRegular(path.join(dir,name),LIMITS.receiptBytes);let row;
  try{row=JSON.parse(text(raw));}catch{fail('invalid_receipt');}
  receiptCheck(row);const serialized=canonical(row);
  if(!raw.equals(Buffer.from(serialized+'\n'))||sha(serialized)!==match[1])fail('receipt_digest_mismatch');
  hashes.add(match[1]);
 }
 return hashes;
}
function checkedLedger(dir,publicPem,ledger,lock){
 privateDir(dir);const names=fs.readdirSync(dir).sort();
 if(names.length<1||names.length>LIMITS.records||names.some((name,i)=>name!==String(i).padStart(6,'0')+'.json'))fail('ledger_missing_busy_or_out_of_bounds');
 const snapshot=path.join(lock,'snapshot');fs.mkdirSync(snapshot,{mode:0o700});
 const rows=[];let bytes=0;
 try{
  for(const name of names){const raw=readRegular(path.join(dir,name),LIMITS.rowBytes);bytes+=raw.length;if(bytes>LIMITS.ledgerBytes)fail('ledger_byte_limit');writeNew(path.join(snapshot,name),raw,false);rows.push(JSON.parse(text(raw)));}
  const verified=ledger.verifyLedger({ledgerDir:snapshot,publicPem});
  return {rows,verified};
 }finally{
  // This directory is exclusively created inside our own lease, never source state.
  for(const name of fs.readdirSync(snapshot))fs.unlinkSync(path.join(snapshot,name));fs.rmdirSync(snapshot);
 }
}
function probe(nowMs,runner){
 const receipt={schema:'mikaya.device-observation.v1',observedAtMs:nowMs};
 for(const p of PROBES){
  let out;try{out=runner('/system/bin/getprop',[p.property],{timeout:LIMITS.probeTimeoutMs,maxBuffer:LIMITS.probeBytes,shell:false,stdio:['ignore','pipe','pipe'],env:{PATH:'/system/bin'}});}catch{fail('probe_failed');}
  if(!out||out.error||out.status!==0||out.signal)fail('probe_failed');
  const raw=Buffer.isBuffer(out.stdout)?out.stdout:typeof out.stdout==='string'?Buffer.from(out.stdout):null;
  const err=Buffer.isBuffer(out.stderr)?out.stderr:typeof out.stderr==='string'?Buffer.from(out.stderr):null;
  if(!raw||raw.length<1||raw.length>LIMITS.probeBytes||!err||err.length)fail('probe_output_invalid');
  let value;try{value=text(raw);}catch{fail('probe_utf8_invalid');}
  if(value!==p.expected&&value!==p.expected+'\n'&&value!==p.expected+'\r\n')fail('device_observation_mismatch');
  receipt[p.field]=p.expected;
 }
 currentClock(nowMs);return receipt;
}
function produce(c,{initialize=false,nowMs=Date.now(),runner=spawnSync}={}){
 configCheck(c);if(typeof initialize!=='boolean'||typeof runner!=='function')fail('invalid_producer_options');currentClock(nowMs);
 privateDir(c.node_dir);privateDir(path.dirname(c.ledger_dir));
 if(initialize&&fs.existsSync(c.ledger_dir))fail('initialization_refuses_existing_ledger');
 if(!initialize&&!fs.existsSync(c.ledger_dir))fail('initialization_required');
 if(!fs.existsSync(c.receipt_dir)){
  if(!initialize)fail('receipt_initialization_required');
  privateDir(path.dirname(c.receipt_dir));fs.mkdirSync(c.receipt_dir,{mode:0o700});syncDir(path.dirname(c.receipt_dir));
 }
 privateDir(c.receipt_dir);
 const lock=path.join(c.receipt_dir,'.producer.lock');try{fs.mkdirSync(lock,{mode:0o700});}catch{fail('producer_busy');}
 const lease=fs.lstatSync(lock);
 try{
  const {ledger,fed}=loadVerifier(),node=fed.loadNode(c.node_dir);
  if(node.meta.fingerprint!==c.expected_fingerprint||fed.fp(node.publicKey)!==c.expected_fingerprint)fail('native_identity_pin_failed');
  if(node.meta.owner!=='MIKAYA'||node.meta.platform?.os!=='android'||node.meta.platform?.androidApi!==35||node.meta.platform?.arch!=='aarch64')fail('native_device_metadata_failed');
  const receipts=receiptInventory(c.receipt_dir,fed.canonical);
  let checked=initialize?null:checkedLedger(c.ledger_dir,node.publicKey,ledger,lock);
  if(checked&&nowMs<checked.verified.latestAtMs)fail('observation_clock_rollback');
  const receipt=probe(nowMs,runner),serialized=fed.canonical(receipt),digest=sha(serialized);
  if(Buffer.byteLength(serialized+'\n')>LIMITS.receiptBytes)fail('receipt_byte_limit');
  if(!receipts.has(digest)&&receipts.size>=LIMITS.receipts)fail('receipt_capacity');
  if(initialize){ledger.initializeLedger({nodeDir:c.node_dir,ledgerDir:c.ledger_dir,nowMs});syncDir(c.ledger_dir);syncDir(path.dirname(c.ledger_dir));checked=checkedLedger(c.ledger_dir,node.publicKey,ledger,lock);}
  const existing=checked.rows.filter(r=>r.kind==='DEVICE_HEALTH_OBSERVED'&&r.payloadSha256===digest);
  if(existing.length>1||existing.some(r=>r.issuedAtMs!==nowMs))fail('receipt_ledger_ambiguity');
  if(!existing.length&&checked.verified.entries>=LIMITS.records)fail('ledger_capacity');
  // Orphan receipts remain immutable and bounded; retry can safely reuse them.
  const receiptPath=path.join(c.receipt_dir,digest+'.json');
  if(!receipts.has(digest)){
   try{writeNew(receiptPath,Buffer.from(serialized+'\n'));syncDir(c.receipt_dir);}catch(e){if(e.code!=='EEXIST')throw e;if(!readRegular(receiptPath,LIMITS.receiptBytes).equals(Buffer.from(serialized+'\n')))fail('receipt_conflict');}
  }
  // Re-establish durability for an orphan left before a previous directory sync.
  durableReceipt(receiptPath,Buffer.from(serialized+'\n'),c.receipt_dir);
  currentClock(nowMs);
  const signed=existing[0]||ledger.appendDigest({nodeDir:c.node_dir,ledgerDir:c.ledger_dir,kind:'DEVICE_HEALTH_OBSERVED',payloadSha256:digest,nowMs});
  syncDir(c.ledger_dir);
  return {schema:'mikaya.device-observation-production.v1',status:'DEVICE_OBSERVATION_SIGNED',initialized:initialize,already_recorded:existing.length===1,index:signed.index,entry_sha256:signed.entryHash,payload_sha256:digest,observed_at_ms:nowMs,hardware_attested:false,payment_authorized:false};
 }finally{
  const current=fs.lstatSync(lock);if(current.dev===lease.dev&&current.ino===lease.ino)fs.rmdirSync(lock);
 }
}
function main(args){
 if(args.length<2||args.length>3||args[0]!=='--config'||(args[2]&&args[2]!=='--initialize-new'))fail('usage: --config PRIVATE_JSON [--initialize-new]');
 absolute(args[1]);if(fs.realpathSync(args[1])!==args[1])fail('unsafe_config_path');
 const config=JSON.parse(text(readRegular(args[1],LIMITS.configBytes)));
 console.log(JSON.stringify(produce(config,{initialize:args[2]==='--initialize-new'})));
}
if(require.main===module){try{main(process.argv.slice(2));}catch{console.error(JSON.stringify({status:'HOLD',reason:'device_observation_production_failed'}));process.exitCode=2;}}
module.exports={produce,LIMITS,PROBES};
