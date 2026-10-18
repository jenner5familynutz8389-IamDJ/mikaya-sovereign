#!/usr/bin/env node
'use strict';
/* AHAVA append-only discrepancy ledger. No old event file is ever rewritten. */
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const base=path.join(process.env.HOME,'sovereign_exec');
const file=path.join(base,'ledger','integrity-corrections.jsonl');
const genesis='0'.repeat(64);
function sorted(x){if(Array.isArray(x))return x.map(sorted);if(x&&typeof x==='object')return Object.fromEntries(Object.keys(x).sort().map(k=>[k,sorted(x[k])]));return x;}
function digest(obj){return crypto.createHash('sha256').update('AHAVA-CORRECTIONS-V1\0').update(JSON.stringify(sorted(obj))).digest('hex');}
function verify(){
 let seq=0,prev=genesis;
 if(!fs.existsSync(file))return {ok:true,records:0,tip:prev};
 const lines=fs.readFileSync(file,'utf8').split('\n');
 for(let i=0;i<lines.length;i++){
  if(lines[i]===''){if(i!==lines.length-1)throw Error('blank line '+(i+1));continue;}
  let rec;try{rec=JSON.parse(lines[i]);}catch{throw Error('invalid JSON at line '+(i+1));}
  const {hash,...body}=rec;
  if(rec.schema!=='ahava.correction.v1'||rec.seq!==seq+1||rec.previousHash!==prev)throw Error('broken link at line '+(i+1));
  if(digest(body)!==hash)throw Error('changed record at line '+(i+1));
  seq++;prev=hash;
 }
 return {ok:true,records:seq,tip:prev};
}
function append(obj){
 if(!obj||!['observation','discrepancy','correction','resolution','checkpoint'].includes(obj.kind))throw Error('invalid correction kind');
 if(typeof obj.subject!=='string'||!obj.subject)throw Error('subject required');
 if(!obj.evidence||typeof obj.evidence!=='object')throw Error('evidence required');
 if(typeof obj.fallback!=='string'||!obj.fallback)throw Error('fallback required');
 fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});
 const lock=file+'.lock';
 fs.mkdirSync(lock,{mode:0o700});
 try{
  const v=verify();
  const body={schema:'ahava.correction.v1',seq:v.records+1,time:new Date().toISOString(),node:process.env.AHAVA_NODE||'local',
    kind:obj.kind,subject:obj.subject,evidence:obj.evidence,fallback:obj.fallback,
    policy:obj.policy||{},previousHash:v.tip};
  const rec={...body,hash:digest(body)};
  const fd=fs.openSync(file,fs.constants.O_APPEND|fs.constants.O_CREAT|fs.constants.O_WRONLY,0o600);
  try{fs.writeSync(fd,JSON.stringify(rec)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  return {seq:rec.seq,hash:rec.hash};
 }finally{fs.rmdirSync(lock);}
}
function decide(target){
 let decision=target.startsWith('legacy-')?'deny':'allow';
 let reason=decision==='deny'?'default-legacy-deny':'not-blocked';
 const state=verify();
 if(fs.existsSync(file))for(const line of fs.readFileSync(file,'utf8').split('\n')){
  if(!line)continue;const obj=JSON.parse(line);
  if(obj.policy&&obj.policy.target===target&&['allow','deny'].includes(obj.policy.action)){
   decision=obj.policy.action;reason=obj.subject;
  }
 }
 return {decision,reason,target,ledgerTip:state.tip};
}
try{
 const cmd=process.argv[2];
 let out;
 if(cmd==='verify')out=verify();
 else if(cmd==='append')out=append(JSON.parse(process.argv[3]||'null'));
 else if(cmd==='check'){out=decide(process.argv[3]||'');if(out.decision==='deny')process.exitCode=2;}
 else throw Error('usage: verify | append JSON | check TARGET');
 console.log(JSON.stringify(out));
}catch(e){console.error('AHAVA_CORRECTION_FAILURE',e.message);process.exitCode=1;}
