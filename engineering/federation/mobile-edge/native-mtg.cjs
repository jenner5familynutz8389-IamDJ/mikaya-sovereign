'use strict';
// Explicitly pin an existing native MTG wrapper and policy without changing them.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {createMtgPolicy}=require('../live/mtg-policy.cjs');
const MAX_SOURCE_BYTES=262144,SHA=/^[a-f0-9]{64}$/;
const FIELDS=['command','commandSha256','policyFile','policySha256'];
const fail=message=>{throw Error(message);};
const identity=s=>[s.dev,s.ino,s.size,s.mtimeNs,s.ctimeNs,s.nlink,s.uid,s.mode].map(String).join(':');

function profileCopy(profile){
 if(profile===null||typeof profile!=='object'||Array.isArray(profile)||Object.getPrototypeOf(profile)!==Object.prototype||
    Object.keys(profile).sort().join('|')!==[...FIELDS].sort().join('|'))fail('invalid_native_mtg_profile');
 const copy={...profile};
 for(const key of ['command','policyFile'])
  if(typeof copy[key]!=='string'||!path.isAbsolute(copy[key])||path.resolve(copy[key])!==copy[key])fail('invalid_native_mtg_profile');
 if(typeof copy.commandSha256!=='string'||typeof copy.policySha256!=='string'||
    !SHA.test(copy.commandSha256)||!SHA.test(copy.policySha256))fail('invalid_native_mtg_profile');
 return Object.freeze(copy);
}

function pinnedSource(file,expected,{executable=false}={}){
 if(typeof process.getuid!=='function'||fs.realpathSync(file)!==file)fail('native_mtg_source_hold');
 const pre=fs.lstatSync(file,{bigint:true});
 if(!pre.isFile()||pre.isSymbolicLink()||pre.nlink!==1n||pre.uid!==BigInt(process.getuid())||
    pre.size<1n||pre.size>BigInt(MAX_SOURCE_BYTES)||(Number(pre.mode)&0o077)||!(Number(pre.mode)&0o400)||
    (executable&&!(Number(pre.mode)&0o100)))fail('native_mtg_source_hold');
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 try{
  const before=fs.fstatSync(fd,{bigint:true});
  if(identity(pre)!==identity(before))fail('native_mtg_source_hold');
  const raw=Buffer.alloc(MAX_SOURCE_BYTES+1);let size=0,count;
  while(size<raw.length&&(count=fs.readSync(fd,raw,size,raw.length-size,null)))size+=count;
  if(size>MAX_SOURCE_BYTES||BigInt(size)!==before.size||
     identity(before)!==identity(fs.fstatSync(fd,{bigint:true}))||
     identity(before)!==identity(fs.lstatSync(file,{bigint:true}))||fs.realpathSync(file)!==file||
     crypto.createHash('sha256').update(raw.subarray(0,size)).digest('hex')!==expected)fail('native_mtg_source_hold');
 }finally{fs.closeSync(fd);}
}

function createNativeMtgPolicy(profile){
 // Existing configurations retain the original native-path and cooldown contract.
 if(profile===undefined)return createMtgPolicy();
 const pinned=profileCopy(profile);
 const check=()=>{
  pinnedSource(pinned.command,pinned.commandSha256,{executable:true});
  pinnedSource(pinned.policyFile,pinned.policySha256);
 };
 // Explicit profiles must be valid before a listener can acquire an owner lease.
 try{check();}catch{fail('native_mtg_source_hold');}
 const fresh=()=>createMtgPolicy({command:pinned.command,policyFile:pinned.policyFile});
 let native=fresh();
 return ()=>{
  try{check();return native();}
  catch{
   // Restoring pinned bytes cannot revive permission cached before a source failure.
   native=fresh();return false;
  }
 };
}

module.exports={createNativeMtgPolicy};
