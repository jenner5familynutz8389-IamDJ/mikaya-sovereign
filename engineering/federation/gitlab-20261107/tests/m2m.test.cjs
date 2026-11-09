'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const m = require('../m2m-gate.cjs');
const NOW = 1794070000000;
const telemetry = Buffer.from(JSON.stringify({schema:'mikaya.f110.jitter-evidence-chain.v1',measurements:[{rtt_ms:15.5,observed_utc:'2026-11-07T00:00:00Z'}],local_identity_verified:true}));
const sha = crypto.createHash('sha256').update(telemetry).digest('hex');
const offer = () => ({schema:'m2m.compute-offer.v1',jobId:'job-demo-1',buyer:'MIKAYA',seller:'ACT-OMEGA',capability:'telemetry.aggregate.v1',payloadSha256:sha,invoicePaymentHash:'a'.repeat(64),amountSats:21,expiresAtMs:NOW+60000});
const grant = async(o=offer(), opts={})=>m.issueCredential({offer:o,rootKey:Buffer.alloc(32,71),ownerApproval: async()=>true,settlementVerifier:async()=>({settled:true,paymentHash:o.invoicePaymentHash,amountSats:o.amountSats}),nowMs:NOW,...opts});
const request=()=>({buyer:'MIKAYA',seller:'ACT-OMEGA',jobId:'job-demo-1',capability:'telemetry.aggregate.v1',payloadSha256:sha,invoicePaymentHash:'a'.repeat(64),amountSats:21});
const store=()=>{const dir=fs.mkdtempSync(path.join(os.tmpdir(),'m2m-test-'));return {dir,cleanup:()=>fs.rmSync(dir,{recursive:true,force:true})}};
test('allowlisted schema preserves exact telemetry byte digest without changing fields',()=>{
 assert.equal(m.telemetryDigest(telemetry),sha);
 assert.equal(m.validateTelemetry(telemetry).schema,'mikaya.f110.jitter-evidence-chain.v1');
 assert.deepEqual(JSON.parse(telemetry.toString()).measurements[0],{rtt_ms:15.5,observed_utc:'2026-11-07T00:00:00Z'});
});
test('node hello uses pinned Ed25519 key and checks specific owner role',()=>{
 const k=crypto.generateKeyPairSync('ed25519');
 const hello=m.makeHello({owner:'MIKAYA',nodeId:'moto-brain',role:'DUO_BRAIN_FIRMWARE_OEM',privateKey:k.privateKey,nowMs:NOW,nonce:'f'.repeat(32)});
 assert.equal(m.verifyHello({hello,pinnedPublicKey:k.publicKey,expectedOwner:'MIKAYA',nowMs:NOW}),true);
 assert.throws(()=>m.verifyHello({hello,pinnedPublicKey:crypto.generateKeyPairSync('ed25519').publicKey,expectedOwner:'MIKAYA',nowMs:NOW}));
 assert.throws(()=>m.verifyHello({hello,pinnedPublicKey:k.publicKey,expectedOwner:'ACT-OMEGA',nowMs:NOW}));
 assert.throws(()=>m.verifyHello({hello,pinnedPublicKey:k.publicKey,expectedOwner:'MIKAYA',nowMs:NOW+120000}));
});
test('node hello fails on incorrect role or wire mutation',()=>{
 const k=crypto.generateKeyPairSync('ed25519');
 assert.throws(()=>m.makeHello({owner:'MIKAYA',nodeId:'x',role:'HARDWARE_SOFTWARE_COMPUTE',privateKey:k.privateKey,nowMs:NOW}));
 const h=m.makeHello({owner:'ACT-OMEGA',nodeId:'compute-1',role:'HARDWARE_SOFTWARE_COMPUTE',privateKey:k.privateKey,nowMs:NOW});
 assert.throws(()=>m.verifyHello({hello:{...h,nodeId:'compute-2'},pinnedPublicKey:k.publicKey,expectedOwner:'ACT-OMEGA',nowMs:NOW}));
});
test('no credential without independently checked settlement',async()=>{
 await assert.rejects(grant(offer(),{settlementVerifier:async()=>({settled:false})}));
 await assert.rejects(grant(offer(),{settlementVerifier:async()=>({settled:true,paymentHash:'b'.repeat(64),amountSats:21})}));
 await assert.rejects(grant(offer(),{settlementVerifier:async()=>({settled:true,paymentHash:'a'.repeat(64),amountSats:20})}));
});
test('owner approval gate cannot be bypassed by payment',async()=>{
 await assert.rejects(grant(offer(),{ownerApproval:async()=>false}));
 await assert.rejects(grant(offer(),{ownerApproval:undefined}));
});
test('macaroon authorizes one bounded job and has enforced caveats',async()=>{
 const {dir,cleanup}=store();try{
 const cred=await grant();
 assert.equal(cred.schema,'m2m.first-party-macaroon.v1');
 assert.equal(cred.caveats.capability,'telemetry.aggregate.v1');
 const result=m.authorizeCredential({macaroon:cred,rootKey:Buffer.alloc(32,71),request:request(),nowMs:NOW,replayDir:dir});
 assert.equal(result.authorized,true);
 assert.equal(result.execute,false);
 }finally{cleanup()}
});
test('persistent replay refusal even on new invocation',async()=>{
 const {dir,cleanup}=store();try{
 const cred=await grant();
 m.authorizeCredential({macaroon:cred,rootKey:Buffer.alloc(32,71),request:request(),nowMs:NOW,replayDir:dir});
 assert.throws(()=>m.authorizeCredential({macaroon:cred,rootKey:Buffer.alloc(32,71),request:request(),nowMs:NOW,replayDir:dir}),/replay/i);
 }finally{cleanup()}
});
test('wrong actor, amount, digest, job or capability fails closed',async()=>{
 const cred=await grant();
 for(const patch of [{buyer:'ACT-OMEGA'},{amountSats:22},{payloadSha256:'b'.repeat(64)},{jobId:'different'},{capability:'firmware.flash'}]){
 const d=store();try{assert.throws(()=>m.authorizeCredential({macaroon:cred,rootKey:Buffer.alloc(32,71),request:{...request(),...patch},nowMs:NOW,replayDir:d.dir}));}finally{d.cleanup()}}
});
test('MAC alteration and wrong root key are rejected',async()=>{
 const cred=await grant();const d=store();try{
 assert.throws(()=>m.authorizeCredential({macaroon:{...cred,caveats:{...cred.caveats,amountSats:5}},rootKey:Buffer.alloc(32,71),request:request(),nowMs:NOW,replayDir:d.dir}));
 assert.throws(()=>m.authorizeCredential({macaroon:cred,rootKey:Buffer.alloc(32,4),request:request(),nowMs:NOW,replayDir:d.dir}));
 }finally{d.cleanup()}
});
test('expired macaroon and dangerous action are rejected',async()=>{
 const cred=await grant();const d=store();try{
 assert.throws(()=>m.authorizeCredential({macaroon:cred,rootKey:Buffer.alloc(32,71),request:request(),nowMs:NOW+61000,replayDir:d.dir}));
 assert.throws(()=>m.validateOffer({...offer(),capability:'firmware.flash'},NOW));
 assert.throws(()=>m.validateOffer({...offer(),capability:'adb.shell'},NOW));
 }finally{d.cleanup()}
});
test('receipt is independently signed by the provider key and binds to job',()=>{
 const k=crypto.generateKeyPairSync('ed25519');
 const rec=m.makeReceipt({provider:'ACT-OMEGA',jobId:'job-demo-1',payloadSha256:sha,resultSha256:'c'.repeat(64),privateKey:k.privateKey,nowMs:NOW});
 assert.equal(m.verifyReceipt({receipt:rec,pinnedPublicKey:k.publicKey,expectedProvider:'ACT-OMEGA'}),true);
 assert.throws(()=>m.verifyReceipt({receipt:{...rec,resultSha256:'d'.repeat(64)},pinnedPublicKey:k.publicKey,expectedProvider:'ACT-OMEGA'}));
});
test('no API in this package transfers money or performs firmware modifications',()=>{
 assert.equal(typeof m.payInvoice,'undefined');
 assert.equal(typeof m.flashFirmware,'undefined');
 assert.equal(typeof m.connectRemoteShell,'undefined');
});
