'use strict';
/**
 * Independent signature for an already verified MIKAYA rotating audit chain.
 * No sockets, keys persisted, ACT enrollment or payment effects.
 *
 * An independent witness identity signs a bounded, exact chain checkpoint.
 * Witness identity verification is cryptographic, NOT proof of hardware
 * independence or off-device immutable retention.
 */
const crypto=require('node:crypto');
const audit=require('./rotating-audit.cjs');
const HASH=/^[a-f0-9]{64}$/,NONCE=/^[a-f0-9]{32}$/,ZERO='0'.repeat(64);
const CHECKPOINT='MIKAYA-INDEPENDENT-AUDIT-WITNESS/1\n';
const DIGEST='MIKAYA-INDEPENDENT-WITNESS-DIGEST/1\n';
const FIELDS=['schema','rootFingerprint','witnessFingerprint','sequence','headHash','previousCheckpointDigest','issuedAtMs','nonce','scope','signature','receiptDigest'];
function hold(s){const e=Error('WITNESS_'+s);e.code='WITNESS_'+s;throw e;}
function plain(x){return x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;}
function canonical(x){
 if(x===null||typeof x==='string'||typeof x==='boolean')return JSON.stringify(x);
 if(typeof x==='number'&&Number.isSafeInteger(x))return JSON.stringify(x);
 if(Array.isArray(x))return '['+x.map(canonical).join(',')+']';
 if(plain(x))return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';
 hold('INVALID_SHAPE');
}
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function asKey(x,required){
 let k;try{k=x?.type===required?x:required==='public'?crypto.createPublicKey(x):crypto.createPrivateKey(x);}catch{hold('KEY_INVALID');}
 if(k.type!==required||k.asymmetricKeyType!=='ed25519')hold('KEY_INVALID');
 return k;
}
const fingerprint=x=>sha(asKey(x,'public').export({type:'spki',format:'der'}));
function decodeSignature(x){
 if(typeof x!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(x))hold('SIGNATURE_INVALID');
 const buf=Buffer.from(x,'base64');
 if(buf.length!==64||buf.toString('base64')!==x)hold('SIGNATURE_INVALID');
 return buf;
}
function sign(privateKey,body){
 return crypto.sign(null,Buffer.from(CHECKPOINT+canonical(body)),asKey(privateKey,'private')).toString('base64');
}
function checkOne({receipt,entries,rootPublicKey,witnessPublicKey}){
 if(!plain(receipt)||Object.keys(receipt).sort().join('|')!==FIELDS.slice().sort().join('|'))hold('CHECKPOINT_SHAPE');
 if(receipt.schema!=='mikaya.audit.witness-checkpoint.v1'||receipt.scope!=='OBSERVE_CHAIN_ONLY'||
  !Number.isSafeInteger(receipt.sequence)||receipt.sequence<1||receipt.sequence>entries.length||
  !Number.isSafeInteger(receipt.issuedAtMs)||receipt.issuedAtMs<entries[receipt.sequence-1].issuedAtMs||
  !HASH.test(receipt.previousCheckpointDigest)||!HASH.test(receipt.headHash)||
  !NONCE.test(receipt.nonce)||receipt.rootFingerprint!==fingerprint(rootPublicKey)||
  receipt.witnessFingerprint!==fingerprint(witnessPublicKey)||
  receipt.rootFingerprint===receipt.witnessFingerprint||
  receipt.headHash!==entries[receipt.sequence-1].entryHash)hold('CHECKPOINT_BOUNDARY');
 const {signature,receiptDigest,...body}=receipt;
 const computed=sha(DIGEST+canonical({...body,signature}));
 if(!HASH.test(receiptDigest)||computed!==receiptDigest)hold('DIGEST_MISMATCH');
 if(!crypto.verify(null,Buffer.from(CHECKPOINT+canonical(body)),
    asKey(witnessPublicKey,'public'),decodeSignature(signature)))hold('SIGNATURE_MISMATCH');
 return true;
}
function checkLedger(entries,rootPublicKey){
 const verification=audit.verify({entries,rootPublicKey});
 if(!verification.valid||!entries.length)hold('LEDGER_INVALID');
 return verification;
}
function observe({entries,rootPublicKey,witnessPrivateKey,previousReceipt=null,issuedAtMs}={}){
 checkLedger(entries,rootPublicKey);
 const wPrivate=asKey(witnessPrivateKey,'private'),wPublic=crypto.createPublicKey(wPrivate);
 const owner=asKey(rootPublicKey,'public');
 if(fingerprint(owner)===fingerprint(wPublic))hold('IDENTITY_NOT_INDEPENDENT');
 if(!Number.isSafeInteger(issuedAtMs)||issuedAtMs<entries[entries.length-1].issuedAtMs)hold('CLOCK_INVALID');
 if(previousReceipt!==null){
  checkOne({receipt:previousReceipt,entries,rootPublicKey:owner,witnessPublicKey:wPublic});
  if(previousReceipt.sequence>=entries.length||previousReceipt.issuedAtMs>issuedAtMs)hold('NONMONOTONIC_CHECKPOINT');
 }
 const body={
  schema:'mikaya.audit.witness-checkpoint.v1',rootFingerprint:fingerprint(owner),
  witnessFingerprint:fingerprint(wPublic),sequence:entries.length,
  headHash:entries[entries.length-1].entryHash,
  previousCheckpointDigest:previousReceipt?.receiptDigest??ZERO,
  issuedAtMs,nonce:crypto.randomBytes(16).toString('hex'),scope:'OBSERVE_CHAIN_ONLY'
 };
 const signature=sign(wPrivate,body);
 return {...body,signature,receiptDigest:sha(DIGEST+canonical({...body,signature}))};
}
function verifyStream({entries,rootPublicKey,witnessPublicKey,receipts,expectedLatestDigest=null}={}){
 checkLedger(entries,rootPublicKey);
 if(!Array.isArray(receipts)||receipts.length<1||receipts.length>10000)hold('EMPTY_OR_OVERSIZE');
 let previousDigest=ZERO,priorSequence=0,priorTime=-1;
 const seenNonces=new Set();
 for(const r of receipts){
  checkOne({receipt:r,entries,rootPublicKey,witnessPublicKey});
  if(r.previousCheckpointDigest!==previousDigest||r.sequence<=priorSequence||
   r.issuedAtMs<priorTime||seenNonces.has(r.nonce))hold('CHECKPOINT_REPLAY_OR_FORK');
  previousDigest=r.receiptDigest;priorSequence=r.sequence;priorTime=r.issuedAtMs;seenNonces.add(r.nonce);
 }
 if(priorSequence!==entries.length)hold('STALE_HEAD');
 if(expectedLatestDigest!==null&&(!HASH.test(expectedLatestDigest)||expectedLatestDigest!==previousDigest))
  hold('PINNED_HEAD_ROLLBACK');
 return {schema:'mikaya.audit.witness-verification.v1',valid:true,
  signaturesVerified:receipts.length,ledgerEntries:entries.length,
  witnessFingerprint:fingerprint(witnessPublicKey),latestSequence:priorSequence,
  latestDigest:previousDigest,cryptographicallyDistinctFromOwner:true,
  externalCustodyVerified:false,independentHardwareConfirmed:false,
  executionAuthorized:false,actAdmitted:false,financialSettlementVerified:false,governmentCertified:false};
}
function verifyQuorum({entries,rootPublicKey,witnesses,minimumWitnesses=2}={}){
 checkLedger(entries,rootPublicKey);
 if(!Number.isInteger(minimumWitnesses)||minimumWitnesses<2||minimumWitnesses>8||
  !Array.isArray(witnesses)||witnesses.length<minimumWitnesses||witnesses.length>8)
  hold('QUORUM_CONFIGURATION');
 const distinct=new Set();
 for(const item of witnesses){
  if(!plain(item))hold('QUORUM_INVALID');
  const pub=asKey(item.publicKey,'public'),f=fingerprint(pub);
  if(distinct.has(f))hold('DUPLICATE_WITNESS');
  const result=verifyStream({entries,rootPublicKey,witnessPublicKey:pub,receipts:item.receipts||[item.receipt]});
  if(result.latestSequence!==entries.length)hold('QUORUM_STALE');
  distinct.add(f);
 }
 return {schema:'mikaya.audit.witness-quorum.v1',valid:true,
  signaturesVerified:distinct.size,cryptographicQuorumMet:distinct.size>=minimumWitnesses,
  headHash:entries.at(-1).entryHash,independentHardwareConfirmed:false,
  externalCustodyVerified:false,executionAuthorized:false,
  actAdmitted:false,financialSettlementVerified:false,governmentCertified:false};
}
module.exports={observe,verifyStream,verifyQuorum};
