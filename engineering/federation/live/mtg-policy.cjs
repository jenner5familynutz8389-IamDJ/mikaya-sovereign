'use strict';
// Adapt the existing native MTG status command; no timer, queue or new service.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawnSync}=require('node:child_process');
const CHECK_MS=10000,MAX_SAMPLE_GAP_MS=20000,READ_TIMEOUT_MS=1000,MAX_OUTPUT=4096;
const PREFIX='/data/data/com.termux/files/usr';

function safeFile(file,{executable=false}={}){
 const st=fs.lstatSync(file);
 return path.isAbsolute(file)&&st.isFile()&&!st.isSymbolicLink()&&st.nlink===1&&st.size<=262144&&
  !(st.mode&0o022)&&(!process.getuid||st.uid===process.getuid())&&(!executable||!!(st.mode&0o100));
}
function safeObservation(result){
 if(!result||result.error||result.signal||result.status!==0||typeof result.stdout!=='string'||
    Buffer.byteLength(result.stdout)>MAX_OUTPUT||typeof result.stderr!=='string'||result.stderr.length)return false;
 const value=JSON.parse(result.stdout);
 return value&&typeof value==='object'&&!Array.isArray(value)&&
  Number.isInteger(value.android_thermal_severity)&&[0,1].includes(value.android_thermal_severity)&&
  value.decision_for_optional_jobs==='ALLOW'&&value.nice_increase===15&&value.poll_interval_seconds===10&&
  value.resume_requires==='two consecutive samples with severity 0 or 1'&&
  value.factory_throttling_modified===false&&value.adb_required===false;
}
function createMtgPolicy({command=path.join(PREFIX,'bin/mikaya-nice'),
 policyFile=path.join(os.homedir(),'.local/share/mikaya/mtg_policy.py'),
 now=()=>performance.now(),execute=spawnSync}={}){
 let checkedAt=null,lastNow=null,safeSamples=0,allowed=false;
 function hold(){safeSamples=0;allowed=false;return false;}
 return function allowWork(){
  let current;
  try{current=now();}catch{checkedAt=null;lastNow=null;return hold();}
  if(!Number.isFinite(current)||current<0||(lastNow!==null&&current<lastNow)){
   checkedAt=null;lastNow=null;return hold();
  }
  lastNow=current;
  if(checkedAt!==null&&current-checkedAt<CHECK_MS)return allowed;
  // A missed sampling window cannot contribute an old safe reading to cooldown.
  if(checkedAt!==null&&current-checkedAt>MAX_SAMPLE_GAP_MS)safeSamples=0;
  // Expired permission is never used while the bounded fresh read runs.
  checkedAt=current;allowed=false;
  try{
   if(!safeFile(command,{executable:true})||!safeFile(policyFile))return hold();
   const result=execute(command,['status'],{encoding:'utf8',shell:false,timeout:READ_TIMEOUT_MS,
    maxBuffer:MAX_OUTPUT,killSignal:'SIGKILL',stdio:['ignore','pipe','pipe'],
    env:{PATH:path.join(PREFIX,'bin'),HOME:os.homedir(),PREFIX,LANG:'C.UTF-8'}});
   if(!safeObservation(result))return hold();
   safeSamples=Math.min(2,safeSamples+1);allowed=safeSamples===2;
   return allowed;
  }catch{return hold();}
 };
}
module.exports={createMtgPolicy};
