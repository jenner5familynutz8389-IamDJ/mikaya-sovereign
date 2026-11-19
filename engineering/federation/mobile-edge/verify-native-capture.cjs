#!/usr/bin/env node
'use strict';
// Read-only verification of saved public-key proofs, at their captured times.
// This does not contact a phone or establish current freshness or hardware trust.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const gatewayFile=path.join(__dirname,'local-evidence-gateway.cjs');
const federationFile=path.join(__dirname,'../live/federation-node.cjs');
const SOURCE_COMMIT='78a363fd516634cd12331810dbde6a938b157e1b';
const owners=new Map([
 ['f1ddd223e3e47a99d895ce9d99504f3a532e8202959627402f50220bb4e6ed15','F110'],
 ['d3d67bbe4c8403f7af2b0c4d6e99d182b6db491dd2f236e70c4589a1c4b7f722','Motorola']
]);
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
function requireThat(value,reason){if(!value)throw Error(reason);}
function boundedRead(file,maximum){
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 try{
  const st=fs.fstatSync(fd);requireThat(st.isFile()&&st.size<=maximum,'bounded_regular_file_required');
  const data=Buffer.alloc(maximum+1);let used=0,n;
  do{n=fs.readSync(fd,data,used,data.length-used,null);used+=n;}while(n&&used<data.length);
  requireThat(used===st.size&&used<=maximum,'file_changed_or_oversized');return data.subarray(0,used);
 }finally{fs.closeSync(fd);}
}
function main(files){
 requireThat(files.length>0,'capture_paths_required');
 requireThat(hash(boundedRead(gatewayFile,131072))==='ccba77b8e5089a29ecc4960bc3e2704720a373d42ca1696fd4a483d15123ca3c','reviewed_gateway_source_required');
 requireThat(hash(boundedRead(federationFile,131072))==='bdf5ea0c64ed1fea7333a62a822d9f76756bb0fca53b13a747087cbdced29b08','reviewed_federation_source_required');
 const gateway=require(gatewayFile),fed=require(federationFile);
 const results=files.map(file=>{
  const bytes=boundedRead(file,8192),p=JSON.parse(bytes.toString('utf8'));
  requireThat(p&&Object.keys(p).sort().join('|')===
   ['schema','status','sourceCommit','verifiedAtMs','signatureVerified','ownerFingerprint','publicKey','request','reply'].sort().join('|')&&
   p.schema==='mikaya.mobile-edge.native-read-proof.v1'&&p.sourceCommit===SOURCE_COMMIT&&
   p.status==='VERIFIED_LOCAL_EVIDENCE'&&p.signatureVerified===true&&owners.has(p.ownerFingerprint)&&
   typeof p.publicKey==='string'&&Number.isSafeInteger(p.verifiedAtMs)&&p.verifiedAtMs>=0,'capture_contract');
  const key=crypto.createPublicKey(p.publicKey),request=p.request;
  requireThat(key.asymmetricKeyType==='ed25519'&&key.export({type:'spki',format:'pem'})===p.publicKey&&
   fed.fp(p.publicKey)===p.ownerFingerprint,'public_owner_pin');
  requireThat(request&&Object.keys(request).sort().join('|')===
   ['schema','ownerFingerprint','method','route','bootNonce','nonce','issuedAtMs','signature'].sort().join('|')&&
   request.schema==='mikaya.mobile-edge.read-request.v1'&&request.ownerFingerprint===p.ownerFingerprint&&
   request.method==='GET'&&request.route===gateway.ROUTE&&/^[a-f0-9]{64}$/.test(request.bootNonce)&&
   /^[a-f0-9]{32}$/.test(request.nonce)&&Number.isSafeInteger(request.issuedAtMs)&&
   Math.abs(p.verifiedAtMs-request.issuedAtMs)<=60000&&
   typeof request.signature==='string'&&/^[A-Za-z0-9+/]{86}==$/.test(request.signature),'signed_request_contract');
  const {signature,...unsigned}=request,sig=Buffer.from(signature,'base64');
  requireThat(sig.length===64&&sig.toString('base64')===signature&&crypto.verify(null,
   Buffer.from('MIKAYA-MOBILE-EDGE-LOCAL-READ/1\nREQ\n'+fed.canonical(unsigned)),key,sig),'request_signature_invalid');
  const body=gateway.verifyReply({reply:p.reply,request,publicKey:p.publicKey,
   expectedFingerprint:p.ownerFingerprint,nowMs:p.verifiedAtMs});
  return {file:path.basename(file),captureSha256:hash(bytes),device:owners.get(p.ownerFingerprint),
   sourceCommit:SOURCE_COMMIT,requestSignatureVerified:true,responseSignatureVerified:true,
   capturedVerificationTime:new Date(p.verifiedAtMs).toISOString(),sourceAgeAtCaptureMs:p.verifiedAtMs-body.sourceLatestAtMs,
   recognizedEventCount:body.recognizedEventCount,projectionSha256:body.projectionSha256,
   freshnessScope:'CAPTURED_VERIFICATION_TIME_ONLY',hardwareAttested:body.hardwareAttested,
   actAdmission:body.actAdmission,computeAuthorized:body.computeAuthorized,fileTransferAuthorized:body.fileTransferAuthorized,
   paymentAuthorized:body.paymentAuthorized,deviceControlAuthorized:body.deviceControlAuthorized};
 });
 console.log(JSON.stringify({status:'SAVED_NATIVE_SIGNATURES_VERIFIED',results},null,2));
}
try{main(process.argv.slice(2));}catch(e){console.error(JSON.stringify({status:'HOLD',reason:e.message}));process.exitCode=2;}
