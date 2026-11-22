'use strict';
/**
 * MIKAYA work receipt -> economic reconciliation boundary (source-only).
 * Exact signed job and quote + a consumed Macaroon V2 TEST caveat create an
 * unpaid billable claim. The claim never mints funds or authorizes ACT.
 *
 * Settlement *claims* are reconciled only via separately configured seller
 * and owner callbacks. No wallet/network/ledger invocation occurs here.
 * The private ledger must independently reverify settlement and reject
 * reused funding IDs before registering any actual service revenue.
 */
const crypto=require('node:crypto');
const fed=require('./federation-node.cjs');
const econ=require('./mesh-economy.cjs');
const mac=require('../interop/capability-macaroons.cjs');
const HASH=/^[a-f0-9]{64}$/,AMOUNT=/^(0|[1-9][0-9]{0,17})$/;
const DOMAIN='MIKAYA-WORK-REVENUE-PROFILE/1\n';
const CLAIM_DOMAIN='MIKAYA-WORK-REVENUE-CLAIM/1\n';
const issued=new WeakSet();
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
function reject(code){const e=Error('WORK_REVENUE_'+code);e.code='WORK_REVENUE_'+code;throw e;}
function plain(v){return v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.getPrototypeOf(v)===Object.prototype;}
function exact(v,fields){return plain(v)&&Object.keys(v).sort().join('|')===[...fields].sort().join('|');}
function amount(v,positive=false){
 if(typeof v!=='string'||!AMOUNT.test(v))reject('AMOUNT_INVALID');
 const b=BigInt(v);if(positive&&b===0n)reject('AMOUNT_INVALID');return b;
}
function profileDigest(quote){
 if(!plain(quote)||quote.schema!=='mikaya.federation.service-quote.v1')reject('QUOTE_SCHEMA_INVALID');
 return sha(DOMAIN+fed.canonical({
  schema:'mikaya.work-revenue.profile.v1',
  quoteSha256:fed.sha(fed.canonical(quote)),
  sellerFingerprint:quote.sellerFingerprint,
  buyerFingerprint:quote.buyerFingerprint,capability:quote.capability,
  units:quote.units
 }));
}
function prepareWorkClaim({proof,quote,pinnedSellerPublic,expectedBuyer,capability,nowMs=Date.now()}={}){
 // Cryptographically check source evidence and the quote BEFORE consuming
 // any macaroon budget or creating an economic candidate.
 const evidence=fed.verifyEvidence(proof);
 if(!evidence.valid||evidence.jobs!==2||evidence.participants!==2)reject('WORK_PROOF_INVALID');
 const verified=econ.verifyQuote({quote,pinnedSellerPublic,expectedBuyer,nowMs});
 if(!verified.verified)reject('QUOTE_NOT_VERIFIED');
 if(!plain(capability)||!Object.keys(capability).sort().every(k=>['rootKey','stateDir','token'].includes(k))||
   Object.keys(capability).length!==3)reject('CAVEAT_CONFIGURATION_INVALID');
 const eligible=proof.exchanges.filter(e=>e.responseAuth.from===quote.sellerFingerprint&&
  e.requestAuth.from===quote.buyerFingerprint&&e.requestAuth.to===quote.sellerFingerprint&&
  e.body.workerFingerprint===quote.sellerFingerprint&&e.requestBody.capability===quote.capability);
 if(eligible.length!==quote.units||quote.units!==1)reject('SIGNED_WORK_SELLER_SCOPE_MISMATCH');
 const record=eligible[0];
 const context={
  holderKeySha256:record.requestAuth.from,
  audience:record.requestAuth.to,
  profileSha256:profileDigest(quote),
  operation:record.requestBody.capability,
  bodySha256:record.requestAuth.bodySha256,
  requestNonce:record.requestAuth.nonce,
  requestBytes:Buffer.byteLength(fed.canonical(record.requestBody))
 };
 const grant=mac.verifyCapability({token:capability.token,rootKey:capability.rootKey,
  stateDir:capability.stateDir,context,nowMs});
 if(grant.verified!==true||grant.testOnly!==true||grant.liveAdmission!==false||
  grant.paymentAuthorized!==false||grant.hardwareAttested!==false)reject('CAVEAT_AUTHORITY_ESCALATION');
 const body={
  schema:'mikaya.work-revenue.claim.v1',
  workProofSha256:fed.sha(fed.canonical(proof)),
  workReceiptSha256:fed.sha(fed.canonical(record.body)),
  billableJobId:record.requestBody.id,
  quoteSha256:verified.quoteSha256,
  macaroonTokenSha256:sha(Buffer.from(capability.token,'base64url')),
  sellerFingerprint:quote.sellerFingerprint,
  buyerFingerprint:quote.buyerFingerprint,
  capability:quote.capability,
  amountDueMsat:String(quote.totalMsat),
  asset:'BTC-LN-msat',
  workReceiptVerified:true,macaroonsVerified:true,macaroonsTestOnly:true,
  productionCapabilityAuthorized:false,hardwareAttested:false,actOperatorApproved:false,
  liveActAdmission:false,paymentVerified:false,revenueRecognized:false,
  localPrincipalLedgerUpdated:false,ahavaDistributed:false
 };
 const result=Object.freeze({...body,claimSha256:sha(CLAIM_DOMAIN+fed.canonical(body))});
 issued.add(result);
 return result;
}
async function reconcileSettlement({claim,verifySellerSettlement,verifyOwnerApproval}={}){
 if(!plain(claim)||!issued.has(claim))reject('CLAIM_NOT_SOURCE_VERIFIED');
 if(typeof verifySellerSettlement!=='function'||typeof verifyOwnerApproval!=='function')
  reject('VERIFIER_REQUIRED');
 const scope=Object.freeze({schema:'mikaya.work-revenue.reconciliation-request.v1',
  claimSha256:claim.claimSha256,quoteSha256:claim.quoteSha256,
  workProofSha256:claim.workProofSha256,sellerFingerprint:claim.sellerFingerprint,
  buyerFingerprint:claim.buyerFingerprint,amountDueMsat:claim.amountDueMsat});
 const settlement=await verifySellerSettlement(scope);
 const names=['schema','settled','invoicePaymentHash','settlementId','amountMsat','netRevenueMsat',
  'feeMsat','asset','quoteSha256','workProofSha256','claimSha256','evidenceSha256'];
 if(!exact(settlement,names)||settlement.schema!=='mikaya.seller-local-settlement-evidence.v1'||
  settlement.settled!==true||!HASH.test(settlement.invoicePaymentHash)||
  !HASH.test(settlement.settlementId)||!HASH.test(settlement.evidenceSha256)||
  settlement.asset!=='BTC-LN-msat'||settlement.quoteSha256!==claim.quoteSha256||
  settlement.workProofSha256!==claim.workProofSha256||
  settlement.claimSha256!==claim.claimSha256||
  settlement.amountMsat!==claim.amountDueMsat)reject('SETTLEMENT_EVIDENCE_INVALID');
 const gross=amount(settlement.amountMsat,true),net=amount(settlement.netRevenueMsat,true),
  fee=amount(settlement.feeMsat);
 if(net+fee!==gross)reject('SETTLEMENT_AMOUNT_MISMATCH');
 const approval=await verifyOwnerApproval(Object.freeze({
  schema:'mikaya.work-revenue.approval-request.v1',
  claimSha256:claim.claimSha256,settlementId:settlement.settlementId,
  settlementEvidenceSha256:settlement.evidenceSha256
 }));
 if(!exact(approval,['schema','approved','claimSha256','settlementId','approvalEvidenceSha256'])||
  approval.schema!=='mikaya.work-revenue.owner-review.v1'||approval.approved!==true||
  approval.claimSha256!==claim.claimSha256||approval.settlementId!==settlement.settlementId||
  !HASH.test(approval.approvalEvidenceSha256))reject('OWNER_REVIEW_MISSING');
 if(gross%1000n!==0n||net%1000n!==0n||fee%1000n!==0n)
  reject('SAT_CONVERSION_UNSUPPORTED');
 const grossSat=gross/1000n,netSat=net/1000n;
 const poolSat=netSat*500n/10000n;
 return Object.freeze({
  schema:'mikaya.work-revenue.handoff.v1',
  claimSha256:claim.claimSha256,quoteSha256:claim.quoteSha256,
  workProofSha256:claim.workProofSha256,settlementId:settlement.settlementId,
  settlementEvidenceSha256:settlement.evidenceSha256,
  ownerReviewEvidenceSha256:approval.approvalEvidenceSha256,
  asset:'BTC-sat',grossSat:grossSat.toString(),netRevenueSat:netSat.toString(),
  sharedUserPoolSat:poolSat.toString(),outsidePoolSat:(netSat-poolSat).toString(),
  amountBasis:'NEW_SETTLED_REVENUE_ONLY',poolBasisPoints:500,
  sellerVerifierReportedSettled:true,
  externalPaymentIndependentlyVerified:false,
  privateLedgerFundingPosted:false,ahavaDistributed:false,
  actOperatorApproved:false,testOnlyMacaroon:true,
  nextGate:'PRIVATE_LEDGER_MUST_REVERIFY_LOCAL_SETTLEMENT_AND_OWNER_AUTHORIZATION'
 });
}
module.exports={profileDigest,prepareWorkClaim,reconcileSettlement};
