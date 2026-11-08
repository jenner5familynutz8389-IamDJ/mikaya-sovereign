#!/usr/bin/env node
'use strict';
/**
 * Actual TCP integration of two independently signing node processes, on ONE HOST.
 * LAB-PEER is a synthetic owner; NOT ACT-Omega's real signing authority.
 * Saves independently re-verifiable public Ed25519 evidence. Never uses wallets,
 * firmware, ADB, root, network peer discovery, or external endpoints.
 */
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const http=require('node:http');
const net=require('node:net');
const crypto=require('node:crypto');
const {spawn,execFileSync}=require('node:child_process');
const fed=require('./federation-node.cjs');
const entry=path.join(__dirname,'federation-node.cjs');
// Android 14 Termux may launch Node via a wrapper that sets the NDK runtime library path.
// Direct child processes use process.execPath and therefore must inherit that linker path.
const limitedEnv={PATH:process.env.PATH||'',HOME:process.env.HOME||'',TMPDIR:os.tmpdir(),PREFIX:process.env.PREFIX||'',LD_LIBRARY_PATH:process.env.LD_LIBRARY_PATH||''};
function cmd(args){
 const out=execFileSync(process.execPath,[entry,...args],{encoding:'utf8',timeout:10000,env:limitedEnv,stdio:['ignore','pipe','pipe'],maxBuffer:16384});
 return JSON.parse(out.trim());
}
async function port(){return new Promise((resolve,reject)=>{const s=net.createServer();s.once('error',reject);s.listen(0,'127.0.0.1',()=>{const port=s.address().port;s.close(()=>resolve(port));});});}
async function server(dir,number){return new Promise((resolve,reject)=>{
 const p=spawn(process.execPath,[entry,'serve',dir,String(number)],{env:limitedEnv,stdio:['ignore','pipe','pipe']});
 let out='',err='',ready=false;
 const timer=setTimeout(()=>{p.kill('SIGTERM');reject(Error('node startup timeout '+err.slice(0,150)));},5000);
 p.stdout.on('data',data=>{out+=data.toString();if(!ready&&out.includes('FEDERATION_READY')){ready=true;clearTimeout(timer);resolve(p);}});
 p.stderr.on('data',data=>err+=data.toString().slice(0,1000));
 p.once('exit',code=>{if(!ready){clearTimeout(timer);reject(Error('node startup failed '+code+' '+err.slice(0,150)));}});
 });}
async function close(p){if(!p)return;return new Promise(resolve=>{if(p.exitCode!==null||p.signalCode!==null)return resolve();p.once('exit',resolve);p.kill('SIGTERM');setTimeout(()=>{if(p.exitCode===null)p.kill('SIGKILL');resolve();},1500).unref();});}
function writeEvidence(file,report){
 const directory=path.dirname(path.resolve(file));fs.mkdirSync(directory,{recursive:true,mode:0o700});
 const payload=fed.canonical(report)+'\n';
 fs.writeFileSync(file,payload,{encoding:'utf8',flag:'wx',mode:0o600});
 return fed.sha(Buffer.from(payload));
}
async function demo(outFile){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-symbiosis-live-'));
 fs.chmodSync(root,0o700);
 let sa,sb;
 try{
  const a=path.join(root,'MIKAYA'),b=path.join(root,'LAB-PEER');
  const ma=cmd(['init',a,'MIKAYA','f110-demo']);
  const mb=cmd(['init',b,'LAB-PEER','partner-demo']);
  cmd(['pin',a,path.join(b,'identity-public.pem'),'LAB-PEER','partner-demo',mb.fingerprint]);
  cmd(['pin',b,path.join(a,'identity-public.pem'),'MIKAYA','f110-demo',ma.fingerprint]);
  const pa=await port(),pb=await port();
  sa=await server(a,pa);sb=await server(b,pb);
  const urlA='http://127.0.0.1:'+pa,urlB='http://127.0.0.1:'+pb;
  const helloB=cmd(['hello',a,urlB,mb.fingerprint]);
  const helloA=cmd(['hello',b,urlA,ma.fingerprint]);
  if(!helloB.verified||!helloA.verified||helloA.body.owner!=='MIKAYA'||helloB.body.owner!=='LAB-PEER')throw Error('mutual hello verification failed');
  const jobB=cmd(['compute',a,urlB,mb.fingerprint,'compute.dot.v1',JSON.stringify({a:[2,3,4],b:[5,6,7]})]);
  const jobA=cmd(['compute',b,urlA,ma.fingerprint,'compute.dot.v1',JSON.stringify({a:[10,-5],b:[3,4]})]);
  if(jobB.body.result!==56||jobA.body.result!==10||!jobA.verified||!jobB.verified)throw Error('bidirectional arithmetic mismatch');
  const bad={schema:'mikaya.federation.job.v1',id:crypto.randomBytes(16).toString('hex'),capability:'firmware.flash',payload:{a:[1],b:[1]}};
  const signed=fed.signRequest({dir:a,to:mb.fingerprint,method:'POST',route:'/v1/task',body:bad});
  const denied=await fed.rawPost(urlB+'/v1/task',{auth:signed,body:bad});
  if(denied.status!==422)throw Error('unsafe capability not rejected by remote');
  const proof=fed.buildEvidence({a,b,exchanges:[jobB,jobA],mode:'LOCAL_TWO_PROCESSES_ONE_DEVICE'});
  const check=fed.verifyEvidence(proof);
  if(!check.valid||!fed.verifyLocalJournal(a)||!fed.verifyLocalJournal(b))throw Error('evidence or journals failed verification');
  const evidenceDigest=writeEvidence(outFile,proof);
  const result={schema:'mikaya.federation.live-demo-result.v1',status:'LOCAL_TWO_PROCESS_AUTHENTICATED',onThisHost:process.platform,
   physicalIndependentHosts:false,externalActOmegaAuthenticated:false,realWalletPayments:false,firmwareChanged:false,
   ownerA:'MIKAYA',ownerB:'LAB-PEER',mutualHelloVerified:true,jobReceiptsVerified:2,
   workerAResult:jobA.body.result,workerBResult:jobB.body.result,unsafeFirmwareRequestDenied:denied.status===422,
   localLedgersValid:true,verifiedPublicProof:check.valid,combinedSha256:check.combinedSha256,
   evidencePath:path.resolve(outFile),evidenceSha256:evidenceDigest,
   notes:'REAL local TCP processes on one device. LAB-PEER is synthetic; ACT-Omega signing identity not verified.'};
  return result;
 }finally{
  await Promise.allSettled([close(sa),close(sb)]);
  fs.rmSync(root,{recursive:true,force:true});
 }
}
if(require.main===module){
 const out=process.argv[2];
 if(!out||process.argv.length!==3){console.error('usage: node demo_two_nodes.cjs /PRIVATE/PATH/public-evidence.json');process.exit(2);}
 demo(out).then(data=>console.log(fed.canonical(data))).catch(error=>{console.error('MIKAYA_DEMO_HOLD: '+error.message);process.exitCode=2;});
}
module.exports={demo};
