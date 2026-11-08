#!/usr/bin/env node
'use strict';
/** MIKAYA federated service-accounting substrate.
 * Signed quotes are NOT Lightning invoices, funding proofs or authorization.
 * Economic trust begins with independently verified work; paid operations
 * require a separately implemented seller-local invoice/settlement verifier.
 */
const crypto=require('node:crypto');
const fed=require('./federation-node.cjs');
const SHA=/^[a-f0-9]{64}$/;
const CAPABILITIES=new Set(['compute.dot.v1','compute.sha256.v1']);
const FIELDS=['schema','sellerFingerprint','buyerFingerprint','capability','units','unitPriceMsat','totalMsat','asset','issuedAtMs','expiresAtMs','nonce','paymentStatus','authorizesExecution','signature'];
const PREFIX='MIKAYA-FEDERATION-ECONOMY/1\nQUOTE\n';
function fail(msg){throw Error(msg);}
function plain(x){return x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;}
function shape(x,fields){return plain(x)&&Object.keys(x).sort().join('|')===fields.slice().sort().join('|');}
function activityFromProof(proof){
 const result=fed.verifyEvidence(proof);
 if(!result.valid||result.participants!==2||result.jobs!==2)fail('unverified symbiotic work');
 return {schema:'mikaya.federation.verified-work.v1',publicProofSha256:fed.sha(fed.canonical(proof)),
   combinedSha256:result.combinedSha256,participants:result.participants,verifiedWorkCount:result.jobs,
   paymentVerified:false,securityAttested:false,ownerPermissionsGranted:false,
   trustClass:'SIGNED_COMPLETION_ONLY_NO_FUNDS'};
}
function makeQuote({dir,buyerFingerprint,capability,units,unitPriceMsat,nowMs=Date.now(),lifetimeMs=300000}){
 const n=fed.loadNode(dir);
 if(!SHA.test(buyerFingerprint)||!n.peers[buyerFingerprint]||n.peers[buyerFingerprint].enabled!==true)fail('buyer must be an explicitly pinned peer');
 if(!CAPABILITIES.has(capability)||!n.policy.allowedCapabilities.includes(capability)||
   !n.peers[buyerFingerprint].capabilities.includes(capability))fail('capability not permitted');
 if(!Number.isSafeInteger(units)||units<1||units>100||!Number.isSafeInteger(unitPriceMsat)||
   unitPriceMsat<1||unitPriceMsat>1000000||!Number.isSafeInteger(nowMs)||
   !Number.isSafeInteger(lifetimeMs)||lifetimeMs<1000||lifetimeMs>900000)fail('quote units or limit invalid');
 const body={schema:'mikaya.federation.service-quote.v1',sellerFingerprint:n.meta.fingerprint,buyerFingerprint,
   capability,units,unitPriceMsat,totalMsat:units*unitPriceMsat,asset:'BTC-LN-msat',
   issuedAtMs:nowMs,expiresAtMs:nowMs+lifetimeMs,nonce:crypto.randomBytes(16).toString('hex'),
   paymentStatus:'UNPAID',authorizesExecution:false};
 const signature=crypto.sign(null,Buffer.from(PREFIX+fed.canonical(body)),n.privateKey).toString('base64');
 return {...body,signature};
}
function verifyQuote({quote,pinnedSellerPublic,expectedBuyer,nowMs=Date.now()}){
 if(!shape(quote,FIELDS)||quote.schema!=='mikaya.federation.service-quote.v1'||!SHA.test(expectedBuyer)||
  quote.buyerFingerprint!==expectedBuyer||!SHA.test(quote.sellerFingerprint)||
  !pinnedSellerPublic||fed.fp(pinnedSellerPublic)!==quote.sellerFingerprint)fail('quote seller or buyer identity mismatch');
 if(!CAPABILITIES.has(quote.capability)||quote.asset!=='BTC-LN-msat'||quote.paymentStatus!=='UNPAID'||
    quote.authorizesExecution!==false)fail('quote capability or authorization invalid');
 if(!Number.isSafeInteger(quote.units)||quote.units<1||quote.units>100||
  !Number.isSafeInteger(quote.unitPriceMsat)||quote.unitPriceMsat<1||quote.unitPriceMsat>1000000||
  quote.totalMsat!==quote.units*quote.unitPriceMsat)fail('quote amount invalid');
 if(!Number.isSafeInteger(nowMs)||!Number.isSafeInteger(quote.issuedAtMs)||
  !Number.isSafeInteger(quote.expiresAtMs)||quote.issuedAtMs>nowMs+5000||nowMs>=quote.expiresAtMs||
  quote.expiresAtMs-quote.issuedAtMs>900000||quote.expiresAtMs-quote.issuedAtMs<1000)fail('quote expired');
 if(typeof quote.nonce!=='string'||!/^[a-f0-9]{32}$/.test(quote.nonce)||typeof quote.signature!=='string'||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(quote.signature)||quote.signature.length!==88)fail('quote signature invalid');
 const {signature,...body}=quote;const raw=Buffer.from(signature,'base64');
 if(raw.length!==64||raw.toString('base64')!==signature||
   !crypto.verify(null,Buffer.from(PREFIX+fed.canonical(body)),pinnedSellerPublic,raw))fail('quote signature invalid');
 return {verified:true,paymentVerified:false,authorizesExecution:false,quoteSha256:fed.sha(fed.canonical(quote))};
}
function authorizePaidWork(_input){return false;}
module.exports={activityFromProof,makeQuote,verifyQuote,authorizePaidWork};