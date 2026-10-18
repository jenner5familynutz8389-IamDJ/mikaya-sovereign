'use strict';
/* Offline verifier of FOSSiBOT-issued source attestation; requires only public information. */
const fs=require('fs'),crypto=require('crypto'),path=require('path');
const folder=process.argv[2]||__dirname;
const raw=fs.readFileSync(path.join(folder,'RELEASE-SOURCE-MANIFEST.json'));
const att=JSON.parse(fs.readFileSync(path.join(folder,'RELEASE-SOURCE-MANIFEST.sig.json'),'utf8'));
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
if(att.schema!=='sovereign.ed25519.manifest-attestation.v1'||att.algorithm!=='Ed25519'||
 sha(raw)!==att.sha256||sha(Buffer.from(att.publicKeyPem,'utf8'))!==att.signerFingerprint||
 !crypto.verify(null,raw,att.publicKeyPem,Buffer.from(att.signatureBase64,'base64'))){
 console.error('SOURCE_ATTESTATION_INVALID');process.exitCode=1;
}else console.log(JSON.stringify({verified:true,manifestSha256:att.sha256,signerFingerprint:att.signerFingerprint}));
