'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {createNativeMtgPolicy}=require('../native-mtg.cjs');
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

test('missing, linked, oversized, nonprivate or unowned native sources fail before execution',t=>{
 for(const kind of ['missing','symlink','hardlink','oversized','empty','group-readable','not-executable','unowned']){
  const f=fixture(t);
  if(kind==='missing')fs.unlinkSync(f.policyFile);
  if(kind==='symlink'){
   const target=f.policyFile+'.target';fs.renameSync(f.policyFile,target);fs.symlinkSync(target,f.policyFile);
  }
  if(kind==='hardlink')fs.linkSync(f.policyFile,f.policyFile+'.link');
  if(kind==='oversized')fs.writeFileSync(f.policyFile,Buffer.alloc(262145,32));
  if(kind==='empty')fs.truncateSync(f.policyFile,0);
  if(kind==='group-readable')fs.chmodSync(f.policyFile,0o640);
  if(kind==='not-executable')fs.chmodSync(f.command,0o600);
  if(kind==='unowned'){const uid=process.getuid();t.mock.method(process,'getuid',()=>uid+1);}
  assert.throws(()=>createNativeMtgPolicy(f.profile),/native_mtg_source_hold/,kind);
  if(kind==='unowned')t.mock.restoreAll();
  assert.equal(f.samples(),0,kind);
 }
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
