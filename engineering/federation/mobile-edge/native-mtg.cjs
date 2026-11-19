'use strict';
// Explicitly pin an existing native MTG wrapper and policy without changing them.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),os=require('node:os');
const childProcess=require('node:child_process');
const {createMtgPolicy}=require('../live/mtg-policy.cjs');
const MAX_SOURCE_BYTES=262144,SHA=/^[a-f0-9]{64}$/;
const FIELDS=['command','commandSha256','policyFile','policySha256'];
const PREFIX='/data/data/com.termux/files/usr',TERMUX_EXEC=PREFIX+'/lib/libtermux-exec.so';
const fail=message=>{throw Error(message);};
const identity=s=>[s.dev,s.ino,s.size,s.mtimeNs,s.ctimeNs,s.nlink,s.uid,s.mode].map(String).join(':');

function profileCopy(profile){
 const fields=[...FIELDS];
 if(profile&&Object.hasOwn(profile,'termuxExecSha256'))fields.push('termuxExecSha256');
 if(profile===null||typeof profile!=='object'||Array.isArray(profile)||Object.getPrototypeOf(profile)!==Object.prototype||
    Object.keys(profile).sort().join('|')!==fields.sort().join('|'))fail('invalid_native_mtg_profile');
 const copy={...profile};
 for(const key of ['command','policyFile'])
  if(typeof copy[key]!=='string'||!path.isAbsolute(copy[key])||path.resolve(copy[key])!==copy[key])fail('invalid_native_mtg_profile');
 if(typeof copy.commandSha256!=='string'||typeof copy.policySha256!=='string'||
    !SHA.test(copy.commandSha256)||!SHA.test(copy.policySha256))fail('invalid_native_mtg_profile');
 if(Object.hasOwn(copy,'termuxExecSha256')&&
    (typeof copy.termuxExecSha256!=='string'||!SHA.test(copy.termuxExecSha256)))fail('invalid_native_mtg_profile');
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

function checkProfile(pinned){
 pinnedSource(pinned.command,pinned.commandSha256,{executable:true});
 pinnedSource(pinned.policyFile,pinned.policySha256);
 if(pinned.termuxExecSha256!==undefined)pinnedSource(TERMUX_EXEC,pinned.termuxExecSha256);
}
function environment(pinned){
 return {HOME:os.homedir(),PREFIX,PATH:PREFIX+'/bin',LANG:'C.UTF-8',
  ...(pinned?.termuxExecSha256!==undefined?{LD_PRELOAD:TERMUX_EXEC}:{})};
}
function nativeExecutionEnvironment(profile){
 if(profile===undefined)return environment();
 const pinned=profileCopy(profile);checkProfile(pinned);return environment(pinned);
}

function createNativeMtgPolicy(profile){
 // Existing configurations retain the original native-path and cooldown contract.
 if(profile===undefined)return createMtgPolicy();
 const pinned=profileCopy(profile);
 const check=()=>{
  checkProfile(pinned);
  // The official Play Termux loader must already be active in the parent.
  // Checking here cannot attest code that ran before Node startup; the owned
  // launcher verifies this exact library before exec and supplies only this path.
  if(pinned.termuxExecSha256!==undefined&&process.env.LD_PRELOAD!==TERMUX_EXEC)fail('native_termux_exec_parent_required');
 };
 // Explicit profiles must be valid before a listener can acquire an owner lease.
 try{check();}catch{fail('native_mtg_source_hold');}
 const fresh=()=>createMtgPolicy({command:pinned.command,policyFile:pinned.policyFile,
  ...(pinned.termuxExecSha256!==undefined?{execute:(command,args,options)=>{
   check();return childProcess.spawnSync(command,args,{...options,env:environment(pinned)});
  }}:{})});
 let native=fresh();
 return ()=>{
  try{check();return native();}
  catch{
   // Restoring pinned bytes cannot revive permission cached before a source failure.
   native=fresh();return false;
  }
 };
}

module.exports={createNativeMtgPolicy,nativeExecutionEnvironment};
