'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const chain=require('./rotating-audit.cjs'),witness=require('./witness-checkpoints.cjs');
const gen=()=>crypto.generateKeyPairSync('ed25519');
const h=n=>crypto.createHash('sha256').update(String(n)).digest('hex');
const event=n=>({
 schema:'mikaya.audit.caveat-receipt.v1',kind:'SIGNED_COMPUTE_RECEIPT',
 jobSha256:h(n),receiptSha256:h('receipt'+n),ownerGrantSha256:h('grant'+n),
 macaroonSha256:h('macaroon'+n),policySha256:h('policy'),capability:'compute.sha256.v1',
 paymentAuthorized:false,actAdmitted:false});
function createChain(){const owner=gen();let rows=[];for(let i=0;i<3;i++)rows.push(chain.append({entries:rows,rootPrivateKey:owner.privateKey,event:event(i),issuedAtMs:1000+i}));return {owner,rows};}
test('independent witness signs the actual owner-verified ledger head, never a self-claimed hash',()=>{
 const {owner,rows}=createChain(),independent=gen();
 const receipt=witness.observe({entries:rows,rootPublicKey:owner.publicKey,witnessPrivateKey:independent.privateKey,issuedAtMs:2000});
 assert.equal(receipt.sequence,3);assert.equal(receipt.headHash,rows[2].entryHash);
 const outcome=witness.verifyStream({entries:rows,rootPublicKey:owner.publicKey,witnessPublicKey:independent.publicKey,receipts:[receipt]});
 assert.equal(outcome.signaturesVerified,1);assert.equal(outcome.executionAuthorized,false);
 assert.equal(outcome.externalCustodyVerified,false);
});
test('witness receipts link prior full checkpoint digest, preserve monotonic sequence, and reject replay',()=>{
 const {owner,rows}=createChain(),independent=gen();
 const first=witness.observe({entries:rows.slice(0,1),rootPublicKey:owner.publicKey,witnessPrivateKey:independent.privateKey,issuedAtMs:2000});
 const second=witness.observe({entries:rows,rootPublicKey:owner.publicKey,witnessPrivateKey:independent.privateKey,previousReceipt:first,issuedAtMs:2001});
 assert.equal(second.previousCheckpointDigest,first.receiptDigest);
 assert.equal(second.sequence,3);
 assert.equal(witness.verifyStream({entries:rows,rootPublicKey:owner.publicKey,witnessPublicKey:independent.publicKey,receipts:[first,second],expectedLatestDigest:second.receiptDigest}).signaturesVerified,2);
 assert.throws(()=>witness.verifyStream({entries:rows,rootPublicKey:owner.publicKey,witnessPublicKey:independent.publicKey,receipts:[first,first]}),/WITNESS_/);
 assert.throws(()=>witness.observe({entries:rows.slice(0,1),rootPublicKey:owner.publicKey,witnessPrivateKey:independent.privateKey,previousReceipt:first,issuedAtMs:2001}),/WITNESS_/);
});
test('altered signed hash, chained receipt or signer pin must fail',()=>{
 const {owner,rows}=createChain(),independent=gen();
 const signed=witness.observe({entries:rows,rootPublicKey:owner.publicKey,witnessPrivateKey:independent.privateKey,issuedAtMs:2000});
 for(const mutate of [r=>r.headHash='0'.repeat(64),r=>r.signature='AA==',r=>r.receiptDigest='0'.repeat(64)]){
  const copy=structuredClone(signed);mutate(copy);
  assert.throws(()=>witness.verifyStream({entries:rows,rootPublicKey:owner.publicKey,witnessPublicKey:independent.publicKey,receipts:[copy]}),/WITNESS_/);
 }
 assert.throws(()=>witness.verifyStream({entries:rows,rootPublicKey:owner.publicKey,witnessPublicKey:gen().publicKey,receipts:[signed]}),/WITNESS_/);
});
test('older valid witness record is rejected when caller pins a newer checkpoint',()=>{
 const {owner,rows}=createChain(),independent=gen();
 const first=witness.observe({entries:rows.slice(0,1),rootPublicKey:owner.publicKey,witnessPrivateKey:independent.privateKey,issuedAtMs:2000});
 const second=witness.observe({entries:rows,rootPublicKey:owner.publicKey,witnessPrivateKey:independent.privateKey,previousReceipt:first,issuedAtMs:2001});
 assert.throws(()=>witness.verifyStream({entries:rows.slice(0,1),rootPublicKey:owner.publicKey,witnessPublicKey:independent.publicKey,receipts:[first],expectedLatestDigest:second.receiptDigest}),/WITNESS_/);
});
test('independent two-witness quorum accepts distinct keys and matching owner head',()=>{
 const {owner,rows}=createChain(),w1=gen(),w2=gen();
 const r1=witness.observe({entries:rows,rootPublicKey:owner.publicKey,witnessPrivateKey:w1.privateKey,issuedAtMs:2000});
 const r2=witness.observe({entries:rows,rootPublicKey:owner.publicKey,witnessPrivateKey:w2.privateKey,issuedAtMs:2001});
 const x=witness.verifyQuorum({entries:rows,rootPublicKey:owner.publicKey,
  witnesses:[{publicKey:w1.publicKey,receipt:r1},{publicKey:w2.publicKey,receipt:r2}],minimumWitnesses:2});
 assert.equal(x.signaturesVerified,2);assert.equal(x.cryptographicQuorumMet,true);
 assert.equal(x.independentHardwareConfirmed,false);
 assert.throws(()=>witness.verifyQuorum({entries:rows,rootPublicKey:owner.publicKey,
  witnesses:[{publicKey:w1.publicKey,receipt:r1},{publicKey:w1.publicKey,receipt:r1}],minimumWitnesses:2}),/WITNESS_/);
});
test('missing witnesses or claims of external custody do not constitute admission or certification',()=>{
 const {owner,rows}=createChain(),independent=gen();
 assert.throws(()=>witness.verifyStream({entries:rows,rootPublicKey:owner.publicKey,witnessPublicKey:independent.publicKey,receipts:[]}),/WITNESS_/);
 const receipt=witness.observe({entries:rows,rootPublicKey:owner.publicKey,witnessPrivateKey:independent.privateKey,issuedAtMs:2000});
 assert.equal(Object.hasOwn(receipt,'privateKey'),false);
 assert.equal(Object.hasOwn(receipt,'paymentAuthorized'),false);
 const v=witness.verifyStream({entries:rows,rootPublicKey:owner.publicKey,witnessPublicKey:independent.publicKey,receipts:[receipt]});
 assert.equal(v.actAdmitted,false);assert.equal(v.financialSettlementVerified,false);assert.equal(v.governmentCertified,false);
});
test('a valid historic checkpoint cannot be represented as witnessing a later unsupervised chain head',()=>{
 const {owner,rows}=createChain(),w=gen();
 const old=witness.observe({entries:rows.slice(0,1),rootPublicKey:owner.publicKey,witnessPrivateKey:w.privateKey,issuedAtMs:2000});
 assert.throws(()=>witness.verifyStream({entries:rows,rootPublicKey:owner.publicKey,witnessPublicKey:w.publicKey,receipts:[old]}),/WITNESS_STALE_HEAD/);
});
test('owner root cannot act as its own supposedly independent witness',()=>{
 const {owner,rows}=createChain();
 assert.throws(()=>witness.observe({entries:rows,rootPublicKey:owner.publicKey,witnessPrivateKey:owner.privateKey,issuedAtMs:2000}),/WITNESS_IDENTITY_NOT_INDEPENDENT/);
});
test('an invalid forged first checkpoint cannot seed a new witness lineage',()=>{
 const {owner,rows}=createChain(),w=gen();
 const initial=witness.observe({entries:rows.slice(0,1),rootPublicKey:owner.publicKey,witnessPrivateKey:w.privateKey,issuedAtMs:2000});
 assert.throws(()=>witness.observe({entries:rows,rootPublicKey:owner.publicKey,witnessPrivateKey:w.privateKey,previousReceipt:{...initial,headHash:'f'.repeat(64)},issuedAtMs:2001}),/WITNESS_/);
});
