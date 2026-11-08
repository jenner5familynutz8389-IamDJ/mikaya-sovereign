'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const fed=require('../federation-node.cjs');
const grant=require('../owner-authorization.cjs');
const broker=require('../federation-broker.cjs');
const attest=require('../attestation-gate.cjs');
const context='MIKAYA-INDEPENDENT-SECURITY-REVIEW/1\n';
function fixture(){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'act-authorization-test-'));fs.chmodSync(root,0o700);
 const m=path.join(root,'f110'),a=path.join(root,'act'),w=path.join(root,'motorola');
 fed.initNode(m,'MIKAYA','sovereign-f110');fed.initNode(a,'ACT-OMEGA','act-alpha');fed.initNode(w,'MOTOROLA','moto-worker');
 const M=fed.loadNode(m),A=fed.loadNode(a),W=fed.loadNode(w);
 fed.pinPeer(m,path.join(a,'identity-public.pem'),'ACT-OMEGA',A.meta.nodeId,A.meta.fingerprint);
 fed.pinPeer(m,path.join(w,'identity-public.pem'),'MOTOROLA',W.meta.nodeId,W.meta.fingerprint);
 const signer=crypto.generateKeyPairSync('ed25519');const pub=signer.publicKey.export({format:'pem',type:'spki'});
 const sfp=fed.fp(pub);fs.mkdirSync(path.join(m,'reviewers'),{mode:0o700});fs.writeFileSync(path.join(m,'reviewers',sfp+'.pem'),pub,{mode:0o600});
 const now=Date.now();const reportBody={schema:'mikaya.federation.independent-security-attestation.v1',gatewayFingerprint:M.meta.fingerprint,peerFingerprint:A.meta.fingerprint,verifierFingerprint:sfp,hardwareKind:'YUBIKEY_PIV',hardwareEvidenceSha256:'a'.repeat(64),challengeSha256:'b'.repeat(64),manufacturerRootSha256:attest.OFFICIAL_VENDOR_ROOTS.YUBIKEY_PIV[0],manufacturerChainVerified:true,revocationVerified:true,verdict:'PASS',issuedAtMs:now,expiresAtMs:now+180000};
 const signed=(body)=>({...body,signature:crypto.sign(null,Buffer.from(context+fed.canonical(body)),signer.privateKey).toString('base64')});
 const report=signed(reportBody);
 function ownerGrant(){return grant.issueGrant({dir:m,report,reviewerPublicKey:pub,peerFingerprint:A.meta.fingerprint,allowedCapabilities:['compute.dot.v1'],ownerApproval:'I_APPROVE_ACT_OMEGA_LIMITED_COMPUTE',nowMs:now,lifetimeMs:60000});}
 function policy(approval=ownerGrant()){return {schema:'mikaya.federation.broker-policy.v2',enabled:true,testOnly:false,allowedUpstream:{[A.meta.fingerprint]:['compute.dot.v1']},downstream:{fingerprint:W.meta.fingerprint,url:'https://192.0.2.10:43829/'},maxRequestsInFlight:1,authorization:{grant:approval,securityReport:report,verifierFingerprint:sfp}};}
 return {root,m,a,w,M,A,W,signer,pub,sfp,report,reportBody,signed,now,ownerGrant,policy};
}
test('RED/production independent report cannot be replaced with boolean, unsigned statement or owner key',()=>{
 const x=fixture();assert.throws(()=>grant.verifySecurityReport({report:{...x.report,signature:'invalid'},reviewerPublicKey:x.pub,gatewayFingerprint:x.M.meta.fingerprint,peerFingerprint:x.A.meta.fingerprint,nowMs:x.now}));
 assert.throws(()=>grant.verifySecurityReport({report:{...x.report,manufacturerRootSha256:'0'.repeat(64)},reviewerPublicKey:x.pub,gatewayFingerprint:x.M.meta.fingerprint,peerFingerprint:x.A.meta.fingerprint,nowMs:x.now}));
 assert.throws(()=>grant.verifySecurityReport({report:{...x.report,revocationVerified:false},reviewerPublicKey:x.pub,gatewayFingerprint:x.M.meta.fingerprint,peerFingerprint:x.A.meta.fingerprint,nowMs:x.now}));
});
test('independent reviewed hardware report can be verified only with pinned independent verifier key',()=>{
 const x=fixture();const valid=grant.verifySecurityReport({report:x.report,reviewerPublicKey:x.pub,gatewayFingerprint:x.M.meta.fingerprint,peerFingerprint:x.A.meta.fingerprint,nowMs:x.now});assert.equal(valid.verified,true);assert.equal(valid.hardwareReviewIndependent,true);
 assert.throws(()=>grant.verifySecurityReport({report:x.report,reviewerPublicKey:x.M.publicKey,gatewayFingerprint:x.M.meta.fingerprint,peerFingerprint:x.A.meta.fingerprint,nowMs:x.now}));
 assert.throws(()=>grant.verifySecurityReport({report:x.report,reviewerPublicKey:x.A.publicKey,gatewayFingerprint:x.M.meta.fingerprint,peerFingerprint:x.A.meta.fingerprint,nowMs:x.now}));
});
test('owner cannot issue compute grant without exact explicit approval, reviewed hardware evidence and pinned ACT',()=>{
 const x=fixture();assert.throws(()=>grant.issueGrant({dir:x.m,report:x.report,reviewerPublicKey:x.pub,peerFingerprint:x.A.meta.fingerprint,allowedCapabilities:['compute.dot.v1'],ownerApproval:'yes',nowMs:x.now}));
 assert.throws(()=>grant.issueGrant({dir:x.m,report:{...x.report,verdict:'HOLD'},reviewerPublicKey:x.pub,peerFingerprint:x.A.meta.fingerprint,allowedCapabilities:['compute.dot.v1'],ownerApproval:'I_APPROVE_ACT_OMEGA_LIMITED_COMPUTE',nowMs:x.now}));
 assert.throws(()=>grant.issueGrant({dir:x.m,report:x.report,reviewerPublicKey:x.pub,peerFingerprint:x.A.meta.fingerprint,allowedCapabilities:['shell.exec'],ownerApproval:'I_APPROVE_ACT_OMEGA_LIMITED_COMPUTE',nowMs:x.now}));
});
test('ACT owner grant binds exact peer, verifier, digest, scope, expiry and nonpayment status',()=>{
 const x=fixture(),g=x.ownerGrant();const result=grant.verifyGrant({dir:x.m,grant:g,report:x.report,reviewerPublicKey:x.pub,nowMs:x.now});assert.deepEqual(result.capabilities,['compute.dot.v1']);assert.equal(result.verified,true);assert.equal(result.paymentAuthorized,false);
 for(const modified of [{...g,peerFingerprint:'c'.repeat(64)},{...g,capabilities:['compute.sha256.v1']},{...g,expiryMs:x.now-1},{...g,securityReportSha256:'f'.repeat(64)}])assert.throws(()=>grant.verifyGrant({dir:x.m,grant:modified,report:x.report,reviewerPublicKey:x.pub,nowMs:x.now}));
 assert.throws(()=>grant.verifyGrant({dir:x.m,grant:g,report:x.report,reviewerPublicKey:x.pub,nowMs:x.now+70000}));
});
test('revoking a previously pinned ACT identity immediately invalidates signed grant',()=>{
 const x=fixture(),g=x.ownerGrant();fed.revokePeer(x.m,x.A.meta.fingerprint);assert.throws(()=>grant.verifyGrant({dir:x.m,grant:g,report:x.report,reviewerPublicKey:x.pub,nowMs:x.now}));
});
test('broker v2 only accepts ACT when separately signed owner AND independent reviewer evidence agree',()=>{
 const x=fixture(),p=x.policy();const v=broker.validatePolicy(p,fed.loadNode(x.m),{dir:x.m,nowMs:x.now});assert.equal(v.enabled,true);assert.equal(v.testOnly,false);
 assert.throws(()=>broker.validatePolicy({...p,authorization:undefined},fed.loadNode(x.m),{dir:x.m,nowMs:x.now}));
 assert.throws(()=>broker.validatePolicy({...p,allowedUpstream:{[x.A.meta.fingerprint]:['compute.sha256.v1']}},fed.loadNode(x.m),{dir:x.m,nowMs:x.now}));
 assert.throws(()=>broker.validatePolicy({...p,authorization:{...p.authorization,verifierFingerprint:'0'.repeat(64)}},fed.loadNode(x.m),{dir:x.m,nowMs:x.now}));
});
test('broker v2 HOLD requires no ACT certificate or reviewer root merely for a disabled status',()=>{
 const x=fixture(),p=x.policy();p.enabled=false;p.allowedUpstream={};p.authorization=null;
 const valid=broker.validatePolicy(p,fed.loadNode(x.m),{dir:x.m,nowMs:x.now});assert.equal(valid.enabled,false);
});