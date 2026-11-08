#!/usr/bin/env node
'use strict';
/**
 * Sovereign owner approval layer for a separately attested ACT-Omega peer.
 * The broker MUST validate both the owner-signed grant and an independent,
 * pinned security review before allowing a restricted, unpaid compute route.
 * A signed review is NOT itself a raw hardware attestation certificate. The
 * independent verifier must validate hardware challenge/chain/revocation.
 * No private key, wallet credential, ADB, root or firmware access is conveyed.
 */
const crypto=require('node:crypto');
const fed=require('./federation-node.cjs');
const att=require('./attestation-gate.cjs');
const HASH=/^[a-f0-9]{64}$/;
const NONCE=/^[a-f0-9]{32}$/;
const DOMAIN='MIKAYA-INDEPENDENT-SECURITY-REVIEW/1\n';
const GRANT_DOMAIN='MIKAYA-ACT-OWNER-AUTHORIZATION/1\n';
const CAPS=new Set(['compute.dot.v1','compute.sha256.v1']);
const REVIEW_KEYS=['schema','gatewayFingerprint','peerFingerprint','verifierFingerprint','hardwareKind','hardwareEvidenceSha256','challengeSha256','manufacturerRootSha256','manufacturerChainVerified','revocationVerified','verdict','issuedAtMs','expiresAtMs','signature'];
const GRANT_KEYS=['schema','ownerFingerprint','peerFingerprint','verifierFingerprint','securityReportSha256','capabilities','nonce','issuedAtMs','expiryMs','paymentAuthorized','shellAuthorized','firmwareAuthorized','signature'];
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
const exact=(o,fields)=>plain(o)&&Object.keys(o).sort().join('|')===[...fields].sort().join('|');
function ensure(ok,msg){if(!ok)throw Error(msg);}
function sigOk(sig,data,key){
 if(typeof sig!=='string'||sig.length!==88||!/^[A-Za-z0-9+/]+={0,2}$/.test(sig))return false;
 const buf=Buffer.from(sig,'base64');return buf.length===64&&buf.toString('base64')===sig&&crypto.verify(null,Buffer.from(data),key,buf);
}
function validCaps(x){return Array.isArray(x)&&x.length>0&&x.length<=2&&x.every(s=>CAPS.has(s))&&new Set(x).size===x.length;}
function verifySecurityReport({report,reviewerPublicKey,gatewayFingerprint,peerFingerprint,nowMs=Date.now()}){
 ensure(exact(report,REVIEW_KEYS)&&report.schema==='mikaya.federation.independent-security-attestation.v1','independent security report schema invalid');
 ensure(HASH.test(gatewayFingerprint)&&HASH.test(peerFingerprint)&&gatewayFingerprint!==peerFingerprint,'invalid identity boundary');
 ensure(HASH.test(report.verifierFingerprint)&&fed.fp(reviewerPublicKey)===report.verifierFingerprint&&report.verifierFingerprint!==gatewayFingerprint&&report.verifierFingerprint!==peerFingerprint,'independent verifier must be pinned and separate');
 ensure(report.gatewayFingerprint===gatewayFingerprint&&report.peerFingerprint===peerFingerprint,'security report target mismatch');
 ensure(['ANDROID_KEYMINT','YUBIKEY_PIV'].includes(report.hardwareKind),'unrecognized hardware proof type');
 ensure(HASH.test(report.hardwareEvidenceSha256)&&HASH.test(report.challengeSha256)&&HASH.test(report.manufacturerRootSha256),'missing evidence and challenge digests');
 ensure(att.OFFICIAL_VENDOR_ROOTS[report.hardwareKind].includes(report.manufacturerRootSha256),'manufacturer root is not independently published');
 ensure(report.manufacturerChainVerified===true&&report.revocationVerified===true&&report.verdict==='PASS','manufacturer chain and revocation review HOLD');
 ensure(Number.isSafeInteger(report.issuedAtMs)&&Number.isSafeInteger(report.expiresAtMs)&&Number.isSafeInteger(nowMs)&&report.issuedAtMs<=nowMs+5000&&nowMs<report.expiresAtMs&&report.expiresAtMs>report.issuedAtMs&&report.expiresAtMs-report.issuedAtMs<=300000,'security report stale or expired');
 const {signature,...unsigned}=report;
 ensure(sigOk(signature,DOMAIN+fed.canonical(unsigned),reviewerPublicKey),'independent security reviewer signature invalid');
 return {verified:true,hardwareReviewIndependent:true,issuerRootPinned:true,revocationClaimIndependentlySigned:true,actualHardwareEvidenceIncluded:false,peerFingerprint};
}
function issueGrant({dir,report,reviewerPublicKey,peerFingerprint,allowedCapabilities,ownerApproval,nowMs=Date.now(),lifetimeMs=60000}){
 ensure(ownerApproval==='I_APPROVE_ACT_OMEGA_LIMITED_COMPUTE','explicit owner approval required');
 const n=fed.loadNode(dir);
 ensure(n.meta.owner==='MIKAYA'&&HASH.test(peerFingerprint)&&n.peers[peerFingerprint]?.enabled===true&&n.peers[peerFingerprint]?.owner==='ACT-OMEGA','only pinned ACT peer may be owner-approved');
 ensure(validCaps(allowedCapabilities)&&Number.isSafeInteger(lifetimeMs)&&lifetimeMs>=1000&&lifetimeMs<=120000,'owner capability scope invalid');
 verifySecurityReport({report,reviewerPublicKey,gatewayFingerprint:n.meta.fingerprint,peerFingerprint,nowMs});
 const expiryMs=Math.min(nowMs+lifetimeMs,report.expiresAtMs);
 ensure(expiryMs>nowMs+999,'insufficient verified review lifetime');
 const body={schema:'mikaya.federation.owner-authorization.v1',ownerFingerprint:n.meta.fingerprint,peerFingerprint,verifierFingerprint:report.verifierFingerprint,securityReportSha256:fed.sha(fed.canonical(report)),capabilities:[...allowedCapabilities].sort(),nonce:crypto.randomBytes(16).toString('hex'),issuedAtMs:nowMs,expiryMs,paymentAuthorized:false,shellAuthorized:false,firmwareAuthorized:false};
 return {...body,signature:crypto.sign(null,Buffer.from(GRANT_DOMAIN+fed.canonical(body)),n.privateKey).toString('base64')};
}
function verifyGrant({dir,grant,report,reviewerPublicKey,nowMs=Date.now()}){
 const n=fed.loadNode(dir);
 ensure(n.meta.owner==='MIKAYA'&&exact(grant,GRANT_KEYS)&&grant.schema==='mikaya.federation.owner-authorization.v1','owner grant schema invalid');
 ensure(HASH.test(grant.peerFingerprint)&&n.peers[grant.peerFingerprint]?.enabled===true&&n.peers[grant.peerFingerprint]?.owner==='ACT-OMEGA','ACT peer not authorized or revoked');
 ensure(grant.ownerFingerprint===n.meta.fingerprint&&grant.verifierFingerprint===fed.fp(reviewerPublicKey)&&grant.securityReportSha256===fed.sha(fed.canonical(report)),'owner grant identity or report mismatch');
 ensure(validCaps(grant.capabilities)&&NONCE.test(grant.nonce)&&grant.paymentAuthorized===false&&grant.shellAuthorized===false&&grant.firmwareAuthorized===false,'owner scope escalation denied');
 ensure(Number.isSafeInteger(nowMs)&&Number.isSafeInteger(grant.issuedAtMs)&&Number.isSafeInteger(grant.expiryMs)&&grant.issuedAtMs<=nowMs+5000&&nowMs<grant.expiryMs&&grant.expiryMs-grant.issuedAtMs<=120000&&grant.expiryMs>grant.issuedAtMs,'owner permission expired');
 ensure(grant.expiryMs<=report.expiresAtMs,'grant exceeds security review');
 verifySecurityReport({report,reviewerPublicKey,gatewayFingerprint:n.meta.fingerprint,peerFingerprint:grant.peerFingerprint,nowMs});
 const {signature,...unsigned}=grant;
 ensure(sigOk(signature,GRANT_DOMAIN+fed.canonical(unsigned),n.publicKey),'owner grant signature invalid');
 return {verified:true,peerFingerprint:grant.peerFingerprint,capabilities:grant.capabilities,expiresAtMs:grant.expiryMs,paymentAuthorized:false,shellAuthorized:false,firmwareAuthorized:false,independentSecuritySignatureVerified:true};
}
module.exports={verifySecurityReport,issueGrant,verifyGrant,REVIEW_KEYS,GRANT_KEYS};