#!/usr/bin/env node
'use strict';
/**
 * Independent federation proof gate. Signed software inventory is *not* device
 * attestation. Hardware admission requires a separately pinned manufacturer CA,
 * a device-generated-key certificate chain, and fresh challenge binding.
 * No auto-enrollment, service execution or wallet authorization.
 */
const fs=require('node:fs');
const crypto=require('node:crypto');
const fed=require('./federation-node.cjs');
const HEX64=/^[0-9a-f]{64}$/;
const DOMAIN='MIKAYA-SOVEREIGN-FEDERATION-ATTEST/1\n';
// Vendor root DER fingerprints acquired from documented first-party sources
// on 2026-11-08. Update only after independent published-root review.
const OFFICIAL_VENDOR_ROOTS=Object.freeze({
 ANDROID_KEYMINT:Object.freeze([
  'cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc',
  '6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0']),
 YUBIKEY_PIV:Object.freeze([
  '62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8',
  '63ece914e54dd87915f34033c85af4c0696ba1512f8add66ced738331207b546'])
});
const exact=(o,fields)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&Object.getPrototypeOf(o)===Object.prototype&&Object.keys(o).sort().join('|')===[...fields].sort().join('|');
const check=(condition,msg)=>{if(!condition)throw Error(msg);};
function validObservations(observations){
 return exact(observations,['androidApi','verifiedBoot','kernel','os','architecture'])&&
   Number.isSafeInteger(observations.androidApi)&&observations.androidApi>0&&observations.androidApi<100&&
   ['green','yellow','orange','red','unknown'].includes(observations.verifiedBoot)&&
   typeof observations.kernel==='string'&&observations.kernel.length<160&&
   observations.os==='android'&&observations.architecture==='aarch64';
}
function softReport({dir,nonce,observations,codeSha256,issuedAtMs=Date.now()}){
 const n=fed.loadNode(dir);
 check(HEX64.test(nonce)&&HEX64.test(codeSha256),'invalid challenge or artifact hash');
 check(validObservations(observations),'invalid minimal non-secret observation');
 check(Number.isSafeInteger(issuedAtMs),'invalid observation time');
 const report={schema:'mikaya.federation.software-observation.v1',nodeFingerprint:n.meta.fingerprint,nonce,issuedAtMs,codeSha256,observations};
 return {...report,signature:crypto.sign(null,Buffer.from(DOMAIN+'SOFTWARE\n'+fed.canonical(report)),n.privateKey).toString('base64')};
}
function verifySoftware({report,pinnedPublicKey,nonce,nowMs=Date.now()}){
 check(exact(report,['schema','nodeFingerprint','nonce','issuedAtMs','codeSha256','observations','signature'])&&report.schema==='mikaya.federation.software-observation.v1','software report invalid');
 check(HEX64.test(nonce)&&report.nonce===nonce&&HEX64.test(report.codeSha256)&&Number.isSafeInteger(report.issuedAtMs)&&Math.abs(nowMs-report.issuedAtMs)<=120000,'expired or mismatched software challenge');
 check(validObservations(report.observations),'unexpected or sensitive device observations refused');
 check(fed.fp(pinnedPublicKey)===report.nodeFingerprint,'software signing identity not pinned');
 const {signature,...message}=report;
 check(typeof signature==='string'&&signature.length<160,'invalid software signature');
 const bytes=Buffer.from(signature,'base64');
 check(bytes.length===64&&bytes.toString('base64')===signature&&crypto.verify(null,Buffer.from(DOMAIN+'SOFTWARE\n'+fed.canonical(message)),pinnedPublicKey,bytes),'software signature verification failed');
 // No relation to Google hardware root established by this evidence.
 return {softwareSignatureVerified:true,hardwareAttested:false,securityAdmitted:false,claimType:'SIGNED_DEVICE_OBSERVATION_ONLY',blockers:['hardware_key_certificate_chain_missing','verified_boot_root_of_trust_not_certified']};
}
function expectedChallenge(fingerprint,nonce){
 check(HEX64.test(fingerprint)&&HEX64.test(nonce),'invalid hardware challenge');
 return crypto.createHash('sha256').update(DOMAIN+'CHALLENGE\n'+fingerprint+'\n'+nonce).digest();
}
// Tiny bounded DER reader for the Android KeyDescription extension. Fails
// closed on BER indefinite lengths, truncation, excessive tags and nesting.
function der(buffer,offset=0,limit=buffer.length){
 check(Buffer.isBuffer(buffer)&&offset>=0&&offset<limit&&limit<=buffer.length,'invalid DER bounds');
 let i=offset,b=buffer[i++],tag=b&31;
 if(tag===31){tag=0;let digits=0,z;do{check(i<limit&&++digits<5,'oversize DER tag');z=buffer[i++];tag=tag*128+(z&127);}while(z&128);check(tag>=31,'noncanonical DER tag');}
 check(i<limit,'missing DER length');const l=buffer[i++];let length=l;
 if(l===0x80)throw Error('indefinite BER length refused');
 if(l>=0x81){const octets=l&127;check(octets>=1&&octets<=3&&i+octets<=limit&&buffer[i]!==0,'noncanonical DER length');length=0;for(let j=0;j<octets;j++)length=length*256+buffer[i++];check(length>=128,'noncanonical short DER length');}
 check(i+length<=limit&&length<=100000,'invalid DER length');
 return {tag,cls:b>>6,constructed:!!(b&32),offset,valueStart:i,end:i+length,bytes:buffer.subarray(i,i+length)};
}
function children(buffer,n){check(n&&n.constructed,'expected constructed DER');let i=n.valueStart,list=[];while(i<n.end){const x=der(buffer,i,n.end);list.push(x);check(list.length<=1024,'unbounded DER children');i=x.end;}return list;}
function decodeInt(node){check(node.bytes.length>=1&&node.bytes.length<=4&&node.bytes[0]<0x80,'invalid DER integer');let n=0;for(const b of node.bytes)n=n*256+b;return n;}
function decodeExtension(certDer){
 check(Buffer.isBuffer(certDer)&&certDer.length<=100000,'invalid certificate DER');
 const root=der(certDer);check(root.offset===0&&root.end===certDer.length&&root.tag===16&&root.cls===0,'invalid certificate encoding');
 const seq=children(certDer,root);check(seq.length===3&&seq[0].tag===16,'invalid X.509 TBSCertificate');const tbs=seq[0],items=children(certDer,tbs);
 const wrapper=items.find(n=>n.cls===2&&n.tag===3);
 check(wrapper,'Android key attestation extension absent');
 const outer=children(certDer,wrapper);check(outer.length===1&&outer[0].tag===16,'bad cert extensions');
 const list=children(certDer,outer[0]);
 const keyOid=Buffer.from('2b06010401d679020111','hex'); // 1.3.6.1.4.1.11129.2.1.17
 let found=[];
 for(const ext of list){const p=children(certDer,ext);if(p[0]?.tag===6&&p[0].bytes.equals(keyOid))found.push(p.at(-1));}
 check(found.length===1&&found[0].tag===4,'ambiguous Android attestation extension');
 return found[0].bytes;
}
function androidKeyDescription(certDer,requiredChallenge){
 const blob=decodeExtension(certDer),root=der(blob);
 check(root.end===blob.length&&root.tag===16,'bad Android key description DER');
 const arr=children(blob,root);check(arr.length>=8&&arr[1].tag===10&&arr[3].tag===10&&arr[4].tag===4,'missing Android key description fields');
 const attestationSecurity=decodeInt(arr[1]),keySecurity=decodeInt(arr[3]);
 check(arr[4].bytes.equals(requiredChallenge),'Android hardware attestation challenge mismatch');
 check(attestationSecurity>=1&&attestationSecurity<=2&&keySecurity>=1&&keySecurity<=2,'Android key is not hardware backed');
 const secureList=arr[7];check(secureList.tag===16&&secureList.cls===0,'missing tee authorization list');
 const rootOfTrust=children(blob,secureList).filter(x=>x.cls===2&&x.tag===704);
 check(rootOfTrust.length===1,'hardware root of trust missing');
 const auth=children(blob,rootOfTrust[0]);const entry=auth[0];check(auth.length===1&&entry.tag===16,'invalid Android root of trust');
 const ro=children(blob,entry);
 check(ro.length>=3&&ro[1].tag===1&&ro[1].bytes.length===1&&ro[1].bytes[0]===0xff&&ro[2].tag===10&&decodeInt(ro[2])===0,'Android boot not locked and verified');
 return {securityLevel:attestationSecurity===2?'STRONGBOX':'TEE',keySecurityLevel:keySecurity,deviceLocked:true,verifiedBootState:'VERIFIED',keyDescriptionValid:true};
}
function verifyChain(chain,approvedRoots){
 check(Array.isArray(chain)&&chain.length>=2&&chain.length<=5&&chain.every(x=>typeof x==='string'&&x.includes('-----BEGIN CERTIFICATE-----')&&x.length<10000),'attestation certificate chain missing');
 check(Array.isArray(approvedRoots)&&approvedRoots.length>=1&&approvedRoots.length<=8&&approvedRoots.every(x=>exact(x,['sha256','name'])&&HEX64.test(x.sha256)&&typeof x.name==='string'&&x.name.length<100),'no approved independent hardware CA');
 const certs=chain.map(p=>new crypto.X509Certificate(p));const now=Date.now();
 for(let i=0;i<certs.length;i++){
  const c=certs[i];check(Date.parse(c.validFrom)<=now&&now<=Date.parse(c.validTo),'expired or not yet valid attestation certificate');
  if(i>0)check(c.ca===true,'attestation issuing CA missing basic constraints');
  if(i>0)check(certs[i-1].checkIssued(c)&&certs[i-1].verify(c.publicKey),'broken attestation issuer chain');
 }
 const root=certs.at(-1),rootHash=fed.sha(root.raw);
 check(approvedRoots.some(x=>x.sha256===rootHash),'attestation root CA not independently approved');
 check(root.checkIssued(root)&&root.verify(root.publicKey),'invalid hardware root certificate');
 return certs;
}
function verifyHardware({evidence,approvedRoots,expectedFingerprint,nonce}){
 check(exact(evidence,['schema','kind','federationFingerprint','nonce','certificatesPem','challengeSignatureBase64'])&&evidence.schema==='mikaya.federation.hardware-attestation.v1'&&['ANDROID_KEYMINT','YUBIKEY_PIV'].includes(evidence.kind),'unknown hardware attestation proof type');
 check(evidence.federationFingerprint===expectedFingerprint&&evidence.nonce===nonce,'hardware proof not bound to expected node and nonce');
 const challenge=expectedChallenge(expectedFingerprint,nonce);
 const certs=verifyChain(evidence.certificatesPem,approvedRoots);
 const trustedRoot=fed.sha(certs.at(-1).raw);
 check(OFFICIAL_VENDOR_ROOTS[evidence.kind].includes(trustedRoot),
  'attestation root is not the published Google or Yubico manufacturer CA');
 const sig=Buffer.from(evidence.challengeSignatureBase64,'base64');
 check(sig.length>=64&&sig.length<=512&&sig.toString('base64')===evidence.challengeSignatureBase64&&crypto.verify('sha256',challenge,certs[0].publicKey,sig),'hardware-generated private key failed challenge');
 let hardware;
 if(evidence.kind==='ANDROID_KEYMINT')hardware=androidKeyDescription(certs[0].raw,challenge);
 else hardware={securityLevel:'YUBIKEY_PIV_GENERATED_KEY',deviceLocked:null,verifiedBootState:null,attestationCertificateValid:true};
 // Certificate revocation and remote independent app authorization must be
 // checked using authoritative, fresh evidence before hardware admission.
 // An X.509 signature alone does not prove a nonrevoked credential or device
 // ownership, and neither keymint nor PIV proves wallet settlement.
 return {verifiedCryptographicChain:true,manufacturerRootPinned:true,hardwareAttested:false,
  challengeBoundToFederationIdentity:true,...hardware,
  hardwareClaimSource:evidence.kind,hardwareAdmission:'HOLD_REVOCATION_AND_OWNER_AUTHORIZATION',
  revocationVerified:false,ownerApproved:false,collaborationAdmitted:false,walletAuthorized:false};
}
module.exports={softReport,verifySoftware,expectedChallenge,verifyChain,androidKeyDescription,verifyHardware,der,children,OFFICIAL_VENDOR_ROOTS};