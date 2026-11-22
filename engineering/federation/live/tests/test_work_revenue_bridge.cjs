'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const fed=require('../federation-node.cjs'),econ=require('../mesh-economy.cjs');
const mac=require('../../interop/capability-macaroons.cjs');
const bridge=require('../work-revenue-bridge.cjs');
const NOW=1900000000000;
const H=x=>crypto.createHash('sha256').update(String(x)).digest('hex');
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-revenue-bridge-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const a=path.join(root,'MIKAYA'),b=path.join(root,'LAB-PEER');
 const A=fed.initNode(a,'MIKAYA','work-source'),B=fed.initNode(b,'LAB-PEER','lab-seller');
 fed.pinPeer(a,path.join(b,'identity-public.pem'),'LAB-PEER','lab-seller',B.fingerprint);
 fed.pinPeer(b,path.join(a,'identity-public.pem'),'MIKAYA','work-source',A.fingerprint);
 const exchange=(from,to,toFp,id)=>{
  const job={schema:'mikaya.federation.job.v1',id,capability:'compute.dot.v1',payload:{a:[2,3],b:[4,5]}};
  const requestAuth=fed.signRequest({dir:from,to:toFp,method:'POST',route:'/v1/task',body:job,nonce:crypto.randomBytes(16).toString('hex'),issuedAtMs:NOW});
  const worker=fed.loadNode(to);
  const body={schema:'mikaya.federation.result.v1',jobId:job.id,capability:job.capability,
   workerFingerprint:worker.meta.fingerprint,requestSha256:fed.sha(fed.canonical(job)),result:fed.computeJob(job)};
  const unsigned={schema:'mikaya.federation.response.v1',from:worker.meta.fingerprint,
   to:requestAuth.from,inReplyTo:requestAuth.nonce,bodySha256:fed.sha(fed.canonical(body)),
   issuedAtMs:NOW+1};
  const auth={...unsigned,signature:crypto.sign(null,Buffer.from('MIKAYA-INDEPENDENT-FEDERATION/1\nRES\n'+fed.canonical(unsigned)),worker.privateKey).toString('base64')};
  return {route:'/v1/task',requestAuth,requestBody:job,auth,body,verified:true};
 };
 const one=exchange(a,b,B.fingerprint,crypto.randomBytes(16).toString('hex'));
 const two=exchange(b,a,A.fingerprint,crypto.randomBytes(16).toString('hex'));
 const proof=fed.buildEvidence({a,b,exchanges:[one,two],mode:'LOCAL_TWO_PROCESSES_ONE_DEVICE'});
 const quote=econ.makeQuote({dir:b,buyerFingerprint:A.fingerprint,capability:'compute.dot.v1',units:1,unitPriceMsat:100000,nowMs:NOW,lifetimeMs:60000});
 const pinnedSellerPublic=fs.readFileSync(path.join(b,'identity-public.pem'),'utf8');
 const macaroonRootKey=crypto.randomBytes(32),stateDir=path.join(root,'macaroon-state');
 mac.initializeReplayState(stateDir);
 const capability={
  rootKey:macaroonRootKey,stateDir,
  token:mac.mintTestCapability({rootKey:macaroonRootKey,holderKeySha256:one.requestAuth.from,
   audience:one.requestAuth.to,profileSha256:bridge.profileDigest(quote),operation:one.requestBody.capability,
   bodySha256:one.requestAuth.bodySha256,issuedAtMs:NOW,expiresAtMs:NOW+30000,
   maxUses:1,maxBytes:8192})
 };
 return {proof,quote,capability,pinnedSellerPublic,A,B,a,b,one,two,
  prepare:(overrides={})=>bridge.prepareWorkClaim({proof,quote,capability,pinnedSellerPublic,expectedBuyer:A.fingerprint,nowMs:NOW+1000,...overrides})};
}
test('signed job + seller quote + bound Macaroon V2 generates a work receipt claim, never revenue',t=>{
 const f=fixture(t),out=f.prepare();
 assert.equal(out.schema,'mikaya.work-revenue.claim.v1');
 assert.equal(out.workReceiptVerified,true);assert.equal(out.macaroonsVerified,true);
 assert.equal(out.macaroonsTestOnly,true);assert.equal(out.liveActAdmission,false);
 assert.equal(out.paymentVerified,false);assert.equal(out.revenueRecognized,false);
 assert.equal(out.ahavaDistributed,false);
 assert.equal(out.amountDueMsat,'100000');
 assert.equal(out.billableJobId,f.one.requestBody.id);
 assert.match(out.claimSha256,/^[0-9a-f]{64}$/);
 assert.equal(JSON.stringify(out).includes(f.capability.token),false);
});
test('signed work and price cannot be tampered into billable revenue',t=>{
 const f=fixture(t),proof=structuredClone(f.proof);
 proof.exchanges[0].body.result=789;
 assert.throws(()=>f.prepare({proof}),/receipt|evidence|signature|digest|result|mismatch/i);
 assert.throws(()=>f.prepare({quote:{...f.quote,totalMsat:1}}),/quote|signature|amount/i);
});
// Seller identity and capability are bound to the signed proof during claim preparation.
test('a seller cannot price and claim two jobs when its signature covers only one performed job',t=>{
 const f=fixture(t);
 const overstated=econ.makeQuote({dir:f.b,buyerFingerprint:f.A.fingerprint,capability:'compute.dot.v1',
  units:2,unitPriceMsat:100000,nowMs:NOW,lifetimeMs:60000});
 assert.throws(()=>f.prepare({quote:overstated}),/SELLER_SCOPE_MISMATCH/);
});
test('both directions of the signed federation independently produce scoped, unpaid work receipts',t=>{
 const f=fixture(t),first=f.prepare();
 const otherQuote=econ.makeQuote({dir:f.a,buyerFingerprint:f.B.fingerprint,capability:'compute.dot.v1',
  units:1,unitPriceMsat:80000,nowMs:NOW,lifetimeMs:60000});
 const otherRoot=crypto.randomBytes(32);
 const otherState=path.join(path.dirname(f.capability.stateDir),'other-capability-state');
 mac.initializeReplayState(otherState);
 const otherToken=mac.mintTestCapability({rootKey:otherRoot,
  holderKeySha256:f.two.requestAuth.from,audience:f.two.requestAuth.to,
  profileSha256:bridge.profileDigest(otherQuote),operation:f.two.requestBody.capability,
  bodySha256:f.two.requestAuth.bodySha256,issuedAtMs:NOW,expiresAtMs:NOW+30000,
  maxUses:1,maxBytes:8192});
 const other=bridge.prepareWorkClaim({proof:f.proof,quote:otherQuote,
  pinnedSellerPublic:fs.readFileSync(path.join(f.a,'identity-public.pem'),'utf8'),
  expectedBuyer:f.B.fingerprint,
  capability:{rootKey:otherRoot,stateDir:otherState,token:otherToken},nowMs:NOW+1000});
 assert.equal(other.workProofSha256,first.workProofSha256);
 assert.notEqual(other.billableJobId,first.billableJobId);
 assert.notEqual(other.sellerFingerprint,first.sellerFingerprint);
 assert.notEqual(other.claimSha256,first.claimSha256);
 assert.equal(other.macaroonsTestOnly,true);
 assert.equal(other.ahavaDistributed,false);
});
test('unauthorized macaroon, wrong request binding and replay are rejected',t=>{
 const f=fixture(t),bad=mac.addFirstPartyCaveat(f.capability.token,'owner_approved = yes');
 assert.throws(()=>f.prepare({capability:{...f.capability,token:bad}}),/caveat|unknown/i);
 const out=f.prepare();assert.equal(out.macaroonsVerified,true);
 assert.throws(()=>f.prepare(),/replay|budget/i);
});
test('a signed work claim without trusted settlement and owner approval does not create funding',async t=>{
 const f=fixture(t),claim=f.prepare();
 await assert.rejects(bridge.reconcileSettlement({claim}),/VERIFIER_REQUIRED/);
 await assert.rejects(bridge.reconcileSettlement({claim,verifySellerSettlement:async()=>({settled:true})}),/VERIFIER_REQUIRED/);
});
test('seller-reported settled service is bound to quote, work and owner approval, but does not post money',async t=>{
 const f=fixture(t),claim=f.prepare();
 const settlement=goodSettlement(claim);
 const result=await bridge.reconcileSettlement({claim,verifySellerSettlement:async()=>settlement,
  verifyOwnerApproval:async()=>goodApproval(claim,settlement)});
 assert.equal(result.schema,'mikaya.work-revenue.handoff.v1');
 assert.equal(result.grossSat,'100');assert.equal(result.netRevenueSat,'100');
 assert.equal(result.sharedUserPoolSat,'5');assert.equal(result.outsidePoolSat,'95');
 assert.equal(result.privateLedgerFundingPosted,false);assert.equal(result.externalPaymentIndependentlyVerified,false);
 assert.equal(result.ahavaDistributed,false);assert.equal(result.actOperatorApproved,false);
 assert.equal(result.testOnlyMacaroon,true);
 assert.equal(result.settlementEvidenceSha256,settlement.evidenceSha256);
});
function goodSettlement(claim,overrides={}){
 return {schema:'mikaya.seller-local-settlement-evidence.v1',settled:true,invoicePaymentHash:H('invoice'),
  settlementId:H('seller-locally-verified-unique'),amountMsat:claim.amountDueMsat,netRevenueMsat:claim.amountDueMsat,
  feeMsat:'0',asset:'BTC-LN-msat',quoteSha256:claim.quoteSha256,
  workProofSha256:claim.workProofSha256,claimSha256:claim.claimSha256,evidenceSha256:H('trusted-local-lnd-evidence'),...overrides};
}
function goodApproval(claim,settlement,overrides={}){
 return {schema:'mikaya.work-revenue.owner-review.v1',approved:true,claimSha256:claim.claimSha256,
  settlementId:settlement.settlementId,approvalEvidenceSha256:H('owner-control'),...overrides};
}
test('faked settlement, mismatched invoice amounts, evidence, or owner rejection cannot generate a handoff',async t=>{
 const f=fixture(t),claim=f.prepare();
 for(const changes of [
  {settled:false},{amountMsat:'999'},{netRevenueMsat:'999'},{feeMsat:'10'},
  {quoteSha256:H('wrong-quote')},{workProofSha256:H('wrong-work')},{claimSha256:H('wrong-claim')},
  {settlementId:'bad'}
 ]){
  const settlement=goodSettlement(claim,changes);
  await assert.rejects(bridge.reconcileSettlement({claim,verifySellerSettlement:async()=>settlement,
   verifyOwnerApproval:async()=>goodApproval(claim,settlement)}),/SETTLEMENT_/);
 }
 const settlement=goodSettlement(claim);
 await assert.rejects(bridge.reconcileSettlement({claim,verifySellerSettlement:async()=>settlement,
  verifyOwnerApproval:async()=>goodApproval(claim,settlement,{approved:false})}),/OWNER_/);
});
test('msat amounts require exact sat conversion before private BTC-sat ledger handoff',async t=>{
 const f=fixture(t),claim=f.prepare();
 const settlement=goodSettlement(claim,{netRevenueMsat:'99999',feeMsat:'1'});
 await assert.rejects(bridge.reconcileSettlement({claim,verifySellerSettlement:async()=>settlement,
  verifyOwnerApproval:async()=>goodApproval(claim,settlement)}),/SAT_CONVERSION_/);
});
test('missing ACT enrollment and cryptographic owner approval never become self-certified',t=>{
 const f=fixture(t),claim=f.prepare();
 assert.equal(claim.hardwareAttested,false);
 assert.equal(claim.actOperatorApproved,false);
 assert.equal(claim.localPrincipalLedgerUpdated,false);
});
