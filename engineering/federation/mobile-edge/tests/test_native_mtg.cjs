'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const childProcess=require('node:child_process');
const {createNativeMtgPolicy,nativeExecutionEnvironment}=require('../native-mtg.cjs');
const sha=raw=>crypto.createHash('sha256').update(raw).digest('hex');
const quote=s=>"'"+s.replace(/'/g,"'\\''")+"'";
const safeStatus={name:'Synthetic native MTG fixture',android_thermal_severity:0,decision_for_optional_jobs:'ALLOW',
 nice_increase:15,poll_interval_seconds:10,resume_requires:'two consecutive samples with severity 0 or 1',
 factory_throttling_modified:false,adb_required:false};

function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-native-mtg-'));
 const command=path.join(root,'native-wrapper'),policyFile=path.join(root,'native-policy.py');
 const observation=path.join(root,'observation.json'),executions=path.join(root,'executions');
 const commandBytes=Buffer.from('#!/bin/sh\nprintf "sample\\n" >> '+quote(executions)+'\nexec /bin/cat '+quote(observation)+'\n');
 const policyBytes=Buffer.from('# Synthetic owner-reviewed policy source; no Android calls.\n');
 fs.writeFileSync(command,commandBytes,{mode:0o700});fs.writeFileSync(policyFile,policyBytes,{mode:0o600});
 fs.writeFileSync(observation,JSON.stringify(safeStatus)+'\n',{mode:0o600});
 const profile={command,commandSha256:sha(commandBytes),policyFile,policySha256:sha(policyBytes)};
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 return {root,command,policyFile,commandBytes,policyBytes,observation,executions,profile,
  samples:()=>fs.existsSync(executions)?fs.readFileSync(executions,'utf8').trim().split('\n').length:0};
}

const TERMUX_PREFIX='/data/data/com.termux/files/usr';
const TERMUX_EXEC=TERMUX_PREFIX+'/lib/libtermux-exec.so';
function environmentValue(t,name,value){
 const existed=Object.hasOwn(process.env,name),previous=process.env[name];
 t.after(()=>{if(existed)process.env[name]=previous;else delete process.env[name];});
 if(value===undefined)delete process.env[name];else process.env[name]=value;
}
function termuxFixture(t){
 const f=fixture(t),library=path.join(f.root,'installed-termux-exec.so');
 const libraryBytes=Buffer.from('Synthetic installed Termux loader fixture; never executed.\n');
 fs.writeFileSync(library,libraryBytes,{mode:0o600});
 const realpathSync=fs.realpathSync,lstatSync=fs.lstatSync,openSync=fs.openSync;
 // Redirect only the fixed production path. All descriptor, permission, size,
 // stable-read and digest checks still inspect a real private fixture file.
 t.mock.method(fs,'realpathSync',function(file,...args){
  if(file!==TERMUX_EXEC)return realpathSync.call(fs,file,...args);
  const resolved=realpathSync.call(fs,library,...args);
  return resolved===library?TERMUX_EXEC:resolved;
 });
 t.mock.method(fs,'lstatSync',function(file,...args){return lstatSync.call(fs,file===TERMUX_EXEC?library:file,...args);});
 t.mock.method(fs,'openSync',function(file,...args){return openSync.call(fs,file===TERMUX_EXEC?library:file,...args);});
 const calls=[];
 t.mock.method(childProcess,'spawnSync',(command,args,options)=>{
  calls.push({command,args,options});
  return {status:0,signal:null,stdout:JSON.stringify(safeStatus)+'\n',stderr:''};
 });
 environmentValue(t,'LD_PRELOAD',TERMUX_EXEC);
 return {...f,library,libraryBytes,calls,profile:{...f.profile,termuxExecSha256:sha(libraryBytes)}};
}

test('explicit native profile has a closed schema and no execution or clock overrides',t=>{
 const f=fixture(t),{policySha256,...missing}=f.profile;
 for(const profile of [null,[],{},missing,{...f.profile,allowWork:true},{...f.profile,execute:()=>true},
  {...f.profile,now:()=>0},{...f.profile,command:'relative-wrapper'},{...f.profile,policyFile:f.root+'/./native-policy.py'},
  {...f.profile,policySha256:'A'.repeat(64)},{...f.profile,commandSha256:0}])
  assert.throws(()=>createNativeMtgPolicy(profile),/invalid_native_mtg_profile/);
 assert.equal(f.samples(),0);
});

test('pinned native wrapper runs real bounded status calls and requires two fresh samples',t=>{
 const f=fixture(t);let now=0;t.mock.method(performance,'now',()=>now);
 const allow=createNativeMtgPolicy(f.profile);assert.equal(f.samples(),0,'construction must not execute native status');
 // A caller cannot redirect the captured profile after validation.
 f.profile.command='/unreviewed-wrapper';f.profile.policySha256='0'.repeat(64);
 assert.equal(allow(),false);assert.equal(f.samples(),1);
 now=9999;assert.equal(allow(),false);assert.equal(f.samples(),1);
 now=10000;assert.equal(allow(),true);assert.equal(f.samples(),2);
});

test('any source pin failure immediately cancels cached ALLOW and restoration restarts cooldown',t=>{
 let now=0;t.mock.method(performance,'now',()=>now);
 for(const key of ['command','policyFile']){
  const f=fixture(t);now=0;const allow=createNativeMtgPolicy(f.profile);
  assert.equal(allow(),false);now=10000;assert.equal(allow(),true);assert.equal(f.samples(),2);
  const original=fs.readFileSync(f[key]);fs.appendFileSync(f[key],'# changed\n');
  now=10001;assert.equal(allow(),false);assert.equal(f.samples(),2,'mismatched sources must not execute');
  fs.writeFileSync(f[key],original);
  now=10002;assert.equal(allow(),false);assert.equal(f.samples(),3);
  now=20002;assert.equal(allow(),true);assert.equal(f.samples(),4);
 }
});

for(const kind of ['missing','symlink','hardlink','oversized','empty','group-readable','not-executable','unowned'])test('native source refuses '+kind,t=>{
  const f=fixture(t);
  if(kind==='missing')fs.unlinkSync(f.policyFile);
  if(kind==='symlink'){
   const target=f.policyFile+'.target';fs.renameSync(f.policyFile,target);fs.symlinkSync(target,f.policyFile);
  }
  if(kind==='hardlink'){
   const link=f.policyFile+'.link',original=fs.readFileSync(f.policyFile);
   try{fs.linkSync(f.policyFile,link);}catch(e){
    if((process.platform==='android'||process.execPath.startsWith('/data/data/com.termux/files/usr/bin/')) && ['EACCES','EPERM','ENOTSUP','EOPNOTSUPP'].includes(e.code)){
     assert.equal(fs.existsSync(link),false);assert.equal(fs.statSync(f.policyFile).nlink,1);
     assert.deepEqual(fs.readFileSync(f.policyFile),original);assert.equal(f.samples(),0);
     t.skip('Android refused hard-link fixture; application rejection not exercised');return;
    }throw e;
   }assert.equal(fs.statSync(f.policyFile).nlink,2);
  }
  if(kind==='oversized')fs.writeFileSync(f.policyFile,Buffer.alloc(262145,32));
  if(kind==='empty')fs.truncateSync(f.policyFile,0);
  if(kind==='group-readable')fs.chmodSync(f.policyFile,0o640);
  if(kind==='not-executable')fs.chmodSync(f.command,0o600);
  if(kind==='unowned'){const uid=process.getuid();t.mock.method(process,'getuid',()=>uid+1);}
  assert.throws(()=>createNativeMtgPolicy(f.profile),/native_mtg_source_hold/,kind);
  if(kind==='unowned')t.mock.restoreAll();
  assert.equal(f.samples(),0,kind);
});

test('a native source that changes during bounded reading cannot preserve permission',t=>{
 const f=fixture(t);let now=0;t.mock.method(performance,'now',()=>now);
 const allow=createNativeMtgPolicy(f.profile);assert.equal(allow(),false);
 now=10000;let changed=false;const originalRead=fs.readSync;
 const readMock=t.mock.method(fs,'readSync',function(...args){
  const result=originalRead.apply(fs,args);
  if(!changed){changed=true;fs.appendFileSync(f.command,'# changed during capture\n');}
  return result;
 });
 assert.equal(allow(),false);assert.equal(f.samples(),1);readMock.mock.restore();
 fs.writeFileSync(f.command,f.commandBytes);
 now=10001;assert.equal(allow(),false);assert.equal(f.samples(),2);
 now=20001;assert.equal(allow(),true);assert.equal(f.samples(),3);
});

test('native unsafe status, missed sampling windows and clock rollback retain legacy HOLD behavior',t=>{
 const f=fixture(t);let now=0;t.mock.method(performance,'now',()=>now);
 const allow=createNativeMtgPolicy(f.profile);
 assert.equal(allow(),false);now=10000;assert.equal(allow(),true);
 fs.writeFileSync(f.observation,JSON.stringify({...safeStatus,android_thermal_severity:2})+'\n');
 now=20000;assert.equal(allow(),false);
 fs.writeFileSync(f.observation,JSON.stringify(safeStatus)+'\n');
 now=30000;assert.equal(allow(),false);now=40000;assert.equal(allow(),true);
 now=60001;assert.equal(allow(),false);now=70001;assert.equal(allow(),true);
 now=70000;assert.equal(allow(),false);
 now=80000;assert.equal(allow(),false);now=90000;assert.equal(allow(),true);
 fs.writeFileSync(f.observation,'not a native status\n');now=100000;assert.equal(allow(),false);
});

test('omitting the native profile preserves unavailable-default HOLD rather than allowing work',()=>{
 const allow=createNativeMtgPolicy();assert.equal(typeof allow,'function');assert.equal(allow(),false);
});

test('pinned Termux loader retains exact bounded status options and a closed child environment',t=>{
 const f=termuxFixture(t);let now=0;t.mock.method(performance,'now',()=>now);
 environmentValue(t,'MIKAYA_TEST_PARENT_SECRET','must-not-reach-child');
 environmentValue(t,'NODE_OPTIONS','--require=/unreviewed-parent-module');
 environmentValue(t,'LD_LIBRARY_PATH','/unreviewed-parent-library-path');
 const base={HOME:os.homedir(),PREFIX:TERMUX_PREFIX,PATH:TERMUX_PREFIX+'/bin',LANG:'C.UTF-8'};
 const expectedEnv={...base,LD_PRELOAD:TERMUX_EXEC};
 assert.deepEqual(nativeExecutionEnvironment(f.profile),expectedEnv);
 assert.deepEqual(nativeExecutionEnvironment(),base,'unconfigured callers must not inherit preload');
 const {termuxExecSha256,...legacy}=f.profile;
 assert.deepEqual(nativeExecutionEnvironment(legacy),base);
 const allow=createNativeMtgPolicy(f.profile);assert.equal(f.calls.length,0,'construction must not execute');
 assert.equal(allow(),false);now=10000;assert.equal(allow(),true);assert.equal(f.calls.length,2);
 for(const call of f.calls){
  assert.equal(call.command,f.command);assert.deepEqual(call.args,['status']);
  assert.deepEqual(call.options,{encoding:'utf8',shell:false,timeout:1000,maxBuffer:4096,killSignal:'SIGKILL',
   stdio:['ignore','pipe','pipe'],env:expectedEnv});
  for(const name of ['MIKAYA_TEST_PARENT_SECRET','NODE_OPTIONS','LD_LIBRARY_PATH'])
   assert.equal(Object.hasOwn(call.options.env,name),false,name);
 }
 assert.equal(f.samples(),0,'the synthetic loader is never passed to a real child process');
});

test('Termux profile rejects missing, wrong or additional parent preload libraries before execution',t=>{
 const f=termuxFixture(t);
 for(const value of [undefined,'','/unreviewed/libtermux-exec.so',TERMUX_EXEC+' /another.so',
  TERMUX_EXEC+':/another.so',TERMUX_EXEC+' '+TERMUX_EXEC]){
  if(value===undefined)delete process.env.LD_PRELOAD;else process.env.LD_PRELOAD=value;
  assert.throws(()=>createNativeMtgPolicy(f.profile),/native_mtg_source_hold/,String(value));
  assert.equal(f.calls.length,0);
 }
 process.env.LD_PRELOAD=TERMUX_EXEC;
 assert.equal(typeof createNativeMtgPolicy(f.profile),'function');
 assert.equal(f.calls.length,0);
});

test('Termux library hash or private-mode changes immediately cancel ALLOW and restart cooldown',t=>{
 const f=termuxFixture(t);let now=0;t.mock.method(performance,'now',()=>now);
 const allow=createNativeMtgPolicy(f.profile);
 assert.equal(allow(),false);now=10000;assert.equal(allow(),true);
 for(const kind of ['hash','permissions']){
  const before=f.calls.length;
  if(kind==='hash')fs.appendFileSync(f.library,'changed loader bytes\n');
  else fs.chmodSync(f.library,0o640);
  now++;assert.equal(allow(),false,kind);assert.equal(f.calls.length,before,'unsafe loader must not spawn');
  assert.throws(()=>nativeExecutionEnvironment(f.profile),/native_mtg_source_hold/,kind);
  if(kind==='hash')fs.writeFileSync(f.library,f.libraryBytes);else fs.chmodSync(f.library,0o600);
  now++;assert.equal(allow(),false,'restoration needs a new first sample');assert.equal(f.calls.length,before+1);
  now+=10000;assert.equal(allow(),true);assert.equal(f.calls.length,before+2);
 }
});

test('changing the parent loader after ALLOW cannot retain cached native permission',t=>{
 const f=termuxFixture(t);let now=0;t.mock.method(performance,'now',()=>now);
 const allow=createNativeMtgPolicy(f.profile);
 assert.equal(allow(),false);now=10000;assert.equal(allow(),true);assert.equal(f.calls.length,2);
 process.env.LD_PRELOAD=TERMUX_EXEC+':/another.so';
 now++;assert.equal(allow(),false);assert.equal(f.calls.length,2);
 process.env.LD_PRELOAD=TERMUX_EXEC;
 now++;assert.equal(allow(),false);assert.equal(f.calls.length,3);
 now+=10000;assert.equal(allow(),true);assert.equal(f.calls.length,4);
});

test('Termux profiles permit only the optional digest, never an environment, library path or execution override',t=>{
 const f=fixture(t);
 for(const termuxExecSha256 of [undefined,null,false,0,'','a'.repeat(63),'A'.repeat(64),'g'.repeat(64)]){
  const profile={...f.profile,termuxExecSha256};
  assert.throws(()=>createNativeMtgPolicy(profile),/invalid_native_mtg_profile/);
  assert.throws(()=>nativeExecutionEnvironment(profile),/invalid_native_mtg_profile/);
 }
 for(const extra of [{env:{LD_PRELOAD:TERMUX_EXEC}},{LD_PRELOAD:TERMUX_EXEC},{termuxExecPath:TERMUX_EXEC},
  {libraryPath:TERMUX_EXEC},{execute:()=>safeStatus},{now:()=>0},{commandArgs:['status']}]){
  const profile={...f.profile,termuxExecSha256:'a'.repeat(64),...extra};
  assert.throws(()=>createNativeMtgPolicy(profile),/invalid_native_mtg_profile/);
  assert.throws(()=>nativeExecutionEnvironment(profile),/invalid_native_mtg_profile/);
 }
 assert.equal(f.samples(),0);
});
