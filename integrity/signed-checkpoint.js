#!/usr/bin/env node
'use strict';
/* Sovereign Duty: independently signed, chained release/boot checkpoints. */
const fs=require('fs'),path=require('path'),crypto=require('crypto'),cp=require('child_process');
const root=path.join(process.env.HOME,'sovereign_exec');
const ledger=path.join(root,'ledger','signed-checkpoints.jsonl');
const pri=path.join(root,'ahava','identity','node-ed25519-private.pem');
const pubfile=path.join(root,'ahava','identity','node-ed25519-public.pem');
const canon=x=>JSON.stringify(x,(_,v)=>v&&!Array.isArray(v)&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
const genesis='0'.repeat(64);
function prop(name){try{return cp.execFileSync('getprop',[name],{encoding:'utf8',timeout:3000}).trim();}catch{return ''}}
function correction(){const x=cp.execFileSync('node',[path.join(root,'integrity','correction-ledger.js'),'verify'],{encoding:'utf8',timeout:7000});return JSON.parse(x)}
function trusted(pub){
 const id=digest(Buffer.from(pub));if(fs.readFileSync(pubfile,'utf8')===pub)return true;
 const candidate=path.join(root,'ahava','trusted',id+'.pem');
 return fs.existsSync(candidate)&&fs.readFileSync(candidate,'utf8')===pub;
}
function verify(){
 let seq=0,prev=genesis;
 if(!fs.existsSync(ledger))return {ok:true,records:0,tip:prev};
 const lines=fs.readFileSync(ledger,'utf8').split('\n');
 for(let i=0;i<lines.length;i++){
  if(lines[i]===''){if(i!==lines.length-1)throw Error('blank record '+(i+1));continue}
  const rec=JSON.parse(lines[i]);const {signature,recordHash,...body}=rec;
  if(body.schema!=='sovereign.signed-checkpoint.v1'||body.seq!==seq+1||body.previousHash!==prev)throw Error('broken checkpoint chain line '+(i+1));
  if(!trusted(body.publicKey))throw Error('untrusted checkpoint signer');
  if(body.signer!==digest(Buffer.from(body.publicKey)))throw Error('signer digest mismatch');
  if(!crypto.verify(null,Buffer.from(canon(body)),body.publicKey,Buffer.from(signature,'base64')))throw Error('checkpoint signature failed');
  if(digest(Buffer.from(canon({...body,signature})))!==recordHash)throw Error('checkpoint hash mismatch');
  seq++;prev=recordHash;
 }
 return {ok:true,records:seq,tip:prev};
}
function sourceDigests(){
 const names=['.gitignore','start_sovereign_secure.sh','ahava/core.js','ahava/peer-server.js','ahava/sync.js',
  'integrity/correction-ledger.js','integrity/signed-checkpoint.js','boot/mesh_bridge_secure.js','motorola_mesh_client_secure.js'];
 const hashes={};for(const rel of names){const p=path.join(root,rel);if(fs.existsSync(p)&&fs.statSync(p).isFile())hashes[rel]=digest(fs.readFileSync(p))}
 return hashes;
}
function checkpoint(){
 const v=verify(),corr=correction(),pub=fs.readFileSync(pubfile,'utf8'),priv=fs.readFileSync(pri,'utf8');
 const source=sourceDigests();
 const mesh=path.join(root,'ledger','mesh-events.jsonl');
 const body={schema:'sovereign.signed-checkpoint.v1',seq:v.records+1,at:new Date().toISOString(),node:process.env.AHAVA_NODE||prop('ro.product.model'),
  signer:digest(Buffer.from(pub)),publicKey:pub,previousHash:v.tip,
  platform:{model:prop('ro.product.model'),build:prop('ro.build.fingerprint'),vendorBuild:prop('ro.vendor.build.fingerprint'),
   apexUpdatable:prop('ro.apex.updatable'),verifiedBoot:prop('ro.boot.verifiedbootstate')},
  corrections:{records:corr.records,tip:corr.tip},software:{sourceHashes:source,sha256:digest(Buffer.from(canon(source)))},
  telemetry:{ledgerSha256:fs.existsSync(mesh)?digest(fs.readFileSync(mesh)):null},
  releaseStatus:'userspace-mesh-tested; system-firmware-image-not-signed-or-flashed'};
 const signature=crypto.sign(null,Buffer.from(canon(body)),priv).toString('base64');
 const recordHash=digest(Buffer.from(canon({...body,signature})));
 const rec={...body,signature,recordHash};
 fs.mkdirSync(path.dirname(ledger),{recursive:true,mode:0o700});
 const fd=fs.openSync(ledger,fs.constants.O_APPEND|fs.constants.O_CREAT|fs.constants.O_WRONLY,0o600);
 try{fs.writeSync(fd,JSON.stringify(rec)+'\n');fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
 const result=verify();
 return {ok:result.ok,seq:rec.seq,hash:recordHash,sourceDigest:body.software.sha256,node:body.node};
}
try{const op=process.argv[2]||'verify';console.log(JSON.stringify(op==='verify'?verify():op==='create'?checkpoint():(()=>{throw Error('expected create or verify')})()))}
catch(e){console.error('SOVEREIGN_CHECKPOINT_FAIL',e.message);process.exitCode=1}
