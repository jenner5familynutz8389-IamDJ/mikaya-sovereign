'use strict';
/**
 * Optional MIKAYA caveat-receipt evidence adapter. The original federation
 * request/response and ACT identity protocols remain unchanged. Pure code:
 * no listener, wallet, key-file writes, payment, or production admission.
 * Each entry has a fresh OS-CSPRNG Ed25519 one-use key, authorized by a
 * separate owner root; each binds the full preceding SHA-256 and signer.
 */
const crypto=require('node:crypto');
const HASH=/^[a-f0-9]{64}$/,NONCE=/^[a-f0-9]{32}$/,ZERO='0'.repeat(64);
const ROOT_DOMAIN='MIKAYA-ROTATING-ROOT-DELEGATION/1\n';
const ENTRY_DOMAIN='MIKAYA-ROTATING-AUDIT-ENTRY/1\n';
const HASH_DOMAIN='MIKAYA-ROTATING-AUDIT-HASH/1\n';
const CLAIM_FIELDS=['schema','kind','jobSha256','receiptSha256','ownerGrantSha256','macaroonSha256','policySha256','capability','paymentAuthorized','actAdmitted'];
const ENTRY_FIELDS=['schema','sequence','previousHash','previousSignerFingerprint','signerPublicKey','signerFingerprint','delegation','event','issuedAtMs','eventSignature','entryHash'];
const DELEGATION_FIELDS=['schema','sequence','rootFingerprint','previousHash','previousSignerFingerprint','signerFingerprint','nonce','scope','issuedAtMs','signature'];
const CAPS=new Set(['compute.sha256.v1','compute.dot.v1','telemetry.aggregate.v1']);
function fail(reason){const err=Error('AUDIT_'+reason);err.code='AUDIT_'+reason;throw err;}
function exact(v,names){return v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join('|')===names.slice().sort().join('|');}
function canonical(value){
 if(value===null||typeof value==='string'||typeof value==='boolean')return JSON.stringify(value);
 if(typeof value==='number'&&Number.isSafeInteger(value))return JSON.stringify(value);
 if(Array.isArray(value)){
  if(value.length>512)return fail('INPUT_TOO_LARGE');
  return '['+value.map(canonical).join(',')+']';
 }
 if(value&&Object.getPrototypeOf(value)===Object.prototype){
  const keys=Object.keys(value).sort();
  if(keys.length>32||keys.some(k=>['__proto__','constructor','prototype'].includes(k)))fail('INPUT_INVALID');
  return '{'+keys.map(k=>{
   const d=Object.getOwnPropertyDescriptor(value,k);
   if(!d||!Object.hasOwn(d,'value'))fail('INPUT_INVALID');
   return JSON.stringify(k)+':'+canonical(d.value);
  }).join(',')+'}';
 }
 fail('INPUT_INVALID');
}
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function key(k,required){
 let x;try{x=k?.type===required?k:required==='public'?crypto.createPublicKey(k):crypto.createPrivateKey(k);}catch{fail('KEY_INVALID');}
 if(x.asymmetricKeyType!=='ed25519'||x.type!==required)fail('KEY_INVALID');
 return x;
}
function fp(pub){return sha(key(pub,'public').export({format:'der',type:'spki'}));}
function b64sig(raw){
 if(typeof raw!=='string'||!/^[a-zA-Z0-9+/]{86}==$/.test(raw))fail('SIGNATURE_ENCODING');
 const buf=Buffer.from(raw,'base64');
 if(buf.length!==64||buf.toString('base64')!==raw)fail('SIGNATURE_ENCODING');
 return buf;
}
function sign(privateKey,domain,body){return crypto.sign(null,Buffer.from(domain+canonical(body)),key(privateKey,'private')).toString('base64');}
function check(pub,domain,body,signature){
 try{if(!crypto.verify(null,Buffer.from(domain+canonical(body)),key(pub,'public'),b64sig(signature)))fail('SIGNATURE_INVALID');}
 catch(e){if(e.code?.startsWith('AUDIT_'))throw e;fail('SIGNATURE_INVALID');}
}
function validateEvent(e){
 if(!exact(e,CLAIM_FIELDS)||e.schema!=='mikaya.audit.caveat-receipt.v1'||
 e.kind!=='SIGNED_COMPUTE_RECEIPT'||!CAPS.has(e.capability)||
 e.paymentAuthorized!==false||e.actAdmitted!==false||
 ![e.jobSha256,e.receiptSha256,e.ownerGrantSha256,e.macaroonSha256,e.policySha256].every(x=>typeof x==='string'&&HASH.test(x)))
 fail('CAVEAT_CLAIM_REFUSED');
 if(Buffer.byteLength(canonical(e))>4096)fail('INPUT_TOO_LARGE');
}
function verify({entries,rootPublicKey,expectedHeadHash=null,requireWitness=false}={}){
 if(!Array.isArray(entries)||entries.length>10000)fail('SEQUENCE_INVALID');
 const root=key(rootPublicKey,'public'),rootFingerprint=fp(root);
 let priorHash=ZERO,priorSigner=rootFingerprint,priorTime=-1;
 const seenKeys=new Set(),seenJobs=new Set();
 for(let i=0;i<entries.length;i++){
  const row=entries[i];
  if(!exact(row,ENTRY_FIELDS)||row.schema!=='mikaya.audit.rotating-entry.v1'||
   row.sequence!==i+1||row.previousHash!==priorHash||row.previousSignerFingerprint!==priorSigner||
   !Number.isSafeInteger(row.issuedAtMs)||row.issuedAtMs<priorTime)fail('CHAIN_BROKEN');
  validateEvent(row.event);
  if(seenJobs.has(row.event.jobSha256))fail('REPLAY_DETECTED');
  seenJobs.add(row.event.jobSha256);
  let publicKey;
  try{
   const raw=Buffer.from(row.signerPublicKey,'base64');
   if(raw.toString('base64')!==row.signerPublicKey||raw.length>512)fail('KEY_INVALID');
   publicKey=crypto.createPublicKey({key:raw,format:'der',type:'spki'});
  }catch(e){if(e.code?.startsWith('AUDIT_'))throw e;fail('KEY_INVALID');}
  const signer=fp(publicKey);
  if(signer!==row.signerFingerprint||seenKeys.has(signer)||signer===rootFingerprint)fail('KEY_REUSED_OR_SUBSTITUTED');
  const d=row.delegation;
  if(!exact(d,DELEGATION_FIELDS)||d.schema!=='mikaya.audit.one-use-delegation.v1'||
   d.sequence!==row.sequence||d.rootFingerprint!==rootFingerprint||
   d.previousHash!==priorHash||d.previousSignerFingerprint!==priorSigner||
   d.signerFingerprint!==signer||d.issuedAtMs!==row.issuedAtMs||
   d.scope!=='SIGN_EXACTLY_ONE_ENTRY'||!NONCE.test(d.nonce))fail('DELEGATION_INVALID');
  const {signature:rootSig,...delegationBody}=d;
  check(root,ROOT_DOMAIN,delegationBody,rootSig);
  const {eventSignature,entryHash,...entryBody}=row;
  check(publicKey,ENTRY_DOMAIN,entryBody,eventSignature);
  const computed=sha(HASH_DOMAIN+canonical({...entryBody,eventSignature}));
  if(!HASH.test(entryHash)||computed!==entryHash)fail('HASH_MISMATCH');
  seenKeys.add(signer);priorHash=entryHash;priorSigner=signer;priorTime=row.issuedAtMs;
 }
 if(requireWitness&&!expectedHeadHash)fail('WITNESS_REQUIRED');
 if(expectedHeadHash!==null&&(!HASH.test(expectedHeadHash)||expectedHeadHash!==priorHash))fail('WITNESS_MISMATCH');
 return {schema:'mikaya.audit.rotating-verification.v1',valid:true,events:entries.length,headHash:priorHash,
  rotatedKeys:seenKeys.size,witnessMatched:expectedHeadHash!==null,
  externalWitnessIndependentlyVerified:false,executionAuthorized:false,
  financialSettlementVerified:false,actAdmitted:false,hardwareAttested:false};
}
function append({entries=[],rootPrivateKey,event,issuedAtMs}={}){
 validateEvent(event);
 if(!Number.isSafeInteger(issuedAtMs)||issuedAtMs<0)fail('CLOCK_INVALID');
 const root=key(rootPrivateKey,'private'),rootPub=crypto.createPublicKey(root);
 if(entries.length)verify({entries,rootPublicKey:rootPub});
 if(entries.some(row=>row.event.jobSha256===event.jobSha256))fail('REPLAY_DETECTED');
 const prior=entries.at(-1),sequence=entries.length+1;
 if(sequence>10000||(prior&&issuedAtMs<prior.issuedAtMs))fail('SEQUENCE_INVALID');
 const previousHash=prior?prior.entryHash:ZERO;
 const previousSignerFingerprint=prior?prior.signerFingerprint:fp(rootPub);
 const fresh=crypto.generateKeyPairSync('ed25519'),signerFingerprint=fp(fresh.publicKey);
 const unsignedDelegation={schema:'mikaya.audit.one-use-delegation.v1',sequence,
  rootFingerprint:fp(rootPub),previousHash,previousSignerFingerprint,signerFingerprint,
  nonce:crypto.randomBytes(16).toString('hex'),scope:'SIGN_EXACTLY_ONE_ENTRY',issuedAtMs};
 const delegation={...unsignedDelegation,signature:sign(root,ROOT_DOMAIN,unsignedDelegation)};
 const unsigned={schema:'mikaya.audit.rotating-entry.v1',sequence,previousHash,previousSignerFingerprint,
  signerPublicKey:fresh.publicKey.export({type:'spki',format:'der'}).toString('base64'),
  signerFingerprint,delegation,event,issuedAtMs};
 const eventSignature=sign(fresh.privateKey,ENTRY_DOMAIN,unsigned);
 const entry={...unsigned,eventSignature,entryHash:sha(HASH_DOMAIN+canonical({...unsigned,eventSignature}))};
 // The transient per-entry secret is not exported, serialized or returned.
 return entry;
}
module.exports={append,verify,ZERO};
