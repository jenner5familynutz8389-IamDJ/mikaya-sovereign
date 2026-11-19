'use strict';
const fs=require('node:fs'),http=require('node:http'),path=require('node:path');
const root='/data/data/com.termux/files/home/.local/share/mikaya/mobile-evidence-78a363fd516634cd';
const gateway=require(path.join(root,'engineering/federation/mobile-edge/local-evidence-gateway.cjs'));
const fed=require(path.join(root,'engineering/federation/live/federation-node.cjs'));
const get=(port,route,authorization)=>new Promise((resolve,reject)=>{
 const request=http.get({hostname:'127.0.0.1',port,path:route,signal:AbortSignal.timeout(3000),
  headers:authorization?{Authorization:authorization}:{}},r=>{
  const parts=[];let n=0;r.on('error',reject);
  r.on('data',b=>{n+=b.length;if(n>8192)request.destroy(Error('reply_limit'));else parts.push(b);});
  r.on('end',()=>{try{resolve({status:r.statusCode,body:JSON.parse(Buffer.concat(parts).toString('utf8'))});}catch(e){reject(e);}});
 });request.on('error',reject);
});
(async()=>{
 if(process.argv.length!==3||!path.isAbsolute(process.argv[2]))throw Error('private_config_required');
 const c=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
 if(c.schema!=='mikaya.mobile-edge.local-gateway.v1'||c.port!==4188)throw Error('gateway_config');
 const owner=fed.loadNode(c.nodeDir);
 if(owner.meta.fingerprint!==c.expectedFingerprint)throw Error('owner_pin');
 const challenge=await get(c.port,'/healthz');
 if(challenge.status!==200||challenge.body.schema!=='mikaya.mobile-edge.challenge.v1'||
    challenge.body.actAdmission!=='HOLD'||challenge.body.ownerReadSignatureRequired!==true)throw Error('challenge_hold');
 const request=gateway.signRead({dir:c.nodeDir,expectedFingerprint:c.expectedFingerprint,bootNonce:challenge.body.bootNonce});
 const response=await get(c.port,gateway.ROUTE,gateway.readHeader(request));
 if(response.status!==200){console.log(JSON.stringify({status:'HOLD',httpStatus:response.status,error:response.body.error}));return;}
 const verified=gateway.verifyReply({reply:response.body,request,publicKey:owner.publicKey,expectedFingerprint:c.expectedFingerprint});
 console.log(JSON.stringify({schema:'mikaya.mobile-edge.native-read-proof.v1',status:verified.status,
  sourceCommit:'78a363fd516634cd12331810dbde6a938b157e1b',verifiedAtMs:Date.now(),signatureVerified:true,
  ownerFingerprint:c.expectedFingerprint,publicKey:owner.publicKey.toString('utf8'),request,reply:response.body}));
})().catch(()=>{console.error('NATIVE_EVIDENCE_READ_HOLD');process.exitCode=2;});
