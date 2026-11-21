'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const A=require('./rotating-audit.cjs');
const root=()=>crypto.generateKeyPairSync('ed25519');
const H='a'.repeat(64),B='b'.repeat(64),C='c'.repeat(64);
const claim=(n=0)=>({schema:'mikaya.audit.caveat-receipt.v1',kind:'SIGNED_COMPUTE_RECEIPT',
 jobSha256:(n%2?B:H),receiptSha256:C,ownerGrantSha256:H,macaroonSha256:B,
 policySha256:C,capability:'compute.sha256.v1',paymentAuthorized:false,actAdmitted:false});
test('two successive signed records use different fresh CSPRNG keys and full predecessor hashes',()=>{
 const k=root(),one=A.append({entries:[],rootPrivateKey:k.privateKey,event:claim(0),issuedAtMs:1000});
 const two=A.append({entries:[one],rootPrivateKey:k.privateKey,event:claim(1),issuedAtMs:1001});
 assert.equal(one.sequence,1);assert.equal(two.sequence,2);
 assert.equal(two.previousHash,one.entryHash);
 assert.notEqual(one.signerFingerprint,two.signerFingerprint);
 const v=A.verify({entries:[one,two],rootPublicKey:k.publicKey,expectedHeadHash:two.entryHash});
 assert.equal(v.valid,true);assert.equal(v.rotatedKeys,2);assert.equal(v.witnessMatched,true);
});
test('missing independent witness remains explicitly unverified',()=>{
 const k=root(),x=A.append({entries:[],rootPrivateKey:k.privateKey,event:claim(),issuedAtMs:1000});
 assert.equal(A.verify({entries:[x],rootPublicKey:k.publicKey}).witnessMatched,false);
 assert.throws(()=>A.verify({entries:[x],rootPublicKey:k.publicKey,requireWitness:true}),/AUDIT_WITNESS_REQUIRED/);
});
test('altered event, predecessor, policy or delegation signature is refused',()=>{
 const k=root(),one=A.append({entries:[],rootPrivateKey:k.privateKey,event:claim(),issuedAtMs:1000});
 const two=A.append({entries:[one],rootPrivateKey:k.privateKey,event:claim(1),issuedAtMs:1001});
 for(const change of [x=>x[1].previousHash=H,x=>x[1].event.policySha256=H,x=>x[1].delegation.signature='AA==']){
  const data=structuredClone([one,two]);change(data);
  assert.throws(()=>A.verify({entries:data,rootPublicKey:k.publicKey}),/AUDIT_/);
 }
});
test('wrong root and missing events are refused',()=>{
 const k=root(),one=A.append({entries:[],rootPrivateKey:k.privateKey,event:claim(),issuedAtMs:1000});
 const two=A.append({entries:[one],rootPrivateKey:k.privateKey,event:claim(1),issuedAtMs:1001});
 assert.throws(()=>A.verify({entries:[one,two],rootPublicKey:root().publicKey}),/AUDIT_/);
 assert.throws(()=>A.verify({entries:[two],rootPublicKey:k.publicKey}),/AUDIT_/);
});
test('payment, ACT admission and arbitrary code capability claims are refused',()=>{
 const k=root();
 for(const field of [{paymentAuthorized:true},{actAdmitted:true},{capability:'shell.exec.v1'}])
  assert.throws(()=>A.append({entries:[],rootPrivateKey:k.privateKey,event:{...claim(),...field},issuedAtMs:1000}),/AUDIT_/);
});
test('unsigned and reused authorization cannot be treated as live permission',()=>{
 const k=root(),one=A.append({entries:[],rootPrivateKey:k.privateKey,event:claim(),issuedAtMs:1000});
 const result=A.verify({entries:[one],rootPublicKey:k.publicKey,expectedHeadHash:one.entryHash});
 assert.equal(result.executionAuthorized,false);assert.equal(result.financialSettlementVerified,false);
});
test('cannot append a duplicate job receipt even with a fresh rotating signer',()=>{
 const rootKey=root(),one=A.append({entries:[],rootPrivateKey:rootKey.privateKey,event:claim(0),issuedAtMs:1000});
 assert.throws(()=>A.append({entries:[one],rootPrivateKey:rootKey.privateKey,event:claim(0),issuedAtMs:1001}),/AUDIT_REPLAY_DETECTED/);
});
test('trusted chain audit rejects duplicated job on externally supplied sequential entries',()=>{
 const rootKey=root(),one=A.append({entries:[],rootPrivateKey:rootKey.privateKey,event:claim(0),issuedAtMs:1000});
 const two=A.append({entries:[one],rootPrivateKey:rootKey.privateKey,event:claim(1),issuedAtMs:1001});
 const changed=structuredClone([one,two]);changed[1].event.jobSha256=one.event.jobSha256;
 assert.throws(()=>A.verify({entries:changed,rootPublicKey:rootKey.publicKey}),/AUDIT_REPLAY_DETECTED|AUDIT_/);
});
