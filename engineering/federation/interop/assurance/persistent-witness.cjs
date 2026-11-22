'use strict';
/**
 * MIKAYA persistent witness state, independent of ACT / L402 / payment / call tracing.
 * Explicit opt-in only; nothing starts on import. The owner/witness keys are
 * supplied by the caller, never stored in this module or checkpoint file.
 *
 * One signed checkpoint line is retained per observation. Each replacement
 * is durably synced to an exclusive, private local directory. This provides
 * restart continuity on the storage host, NOT physical/off-device independence.
 */
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const audit=require('./rotating-audit.cjs');
const witness=require('./witness-checkpoints.cjs');
const HASH=/^[a-f0-9]{64}$/;
const MAX_BYTES=12*1024*1024;
const MAX_CHECKPOINTS=10000;
const STATE='checkpoint-state.json';
const LOCK=STATE+'.lock';

function fail(kind){const err=Error('VAULT_'+kind);err.code='VAULT_'+kind;throw err;}
function exact(x,fields){
 return x!==null && typeof x==='object' && !Array.isArray(x) &&
   Object.getPrototypeOf(x)===Object.prototype &&
   Object.keys(x).sort().join('|')===fields.slice().sort().join('|');
}
function keyPublic(x){
 let k;
 try{k=x?.type==='public'?x:crypto.createPublicKey(x);}
 catch{fail('KEY_INVALID');}
 if(k.type!=='public'||k.asymmetricKeyType!=='ed25519')fail('KEY_INVALID');
 return k;
}
function fingerprint(k){return crypto.createHash('sha256').update(keyPublic(k).export({type:'spki',format:'der'})).digest('hex');}
function protect(pathname,kind){
 let s;
 try{s=fs.lstatSync(pathname);}catch(e){if(e.code==='ENOENT')return null;fail(kind+'_UNREADABLE');}
 if(s.isSymbolicLink()||s.nlink!==1||(s.mode&0o077)!==0||
   (typeof process.getuid==='function'&&s.uid!==process.getuid()))
  fail(kind+'_INSECURE');
 return s;
}
function validDir(dir,create){
 if(typeof dir!=='string'||!path.isAbsolute(dir)||dir==='/'||path.normalize(dir)!==dir)
  fail('PATH_INVALID');
 let st;
 try{st=fs.lstatSync(dir);}catch(e){
  if(e.code!=='ENOENT')fail('DIRECTORY_UNREADABLE');
  if(!create)fail('UNINITIALIZED');
  try{fs.mkdirSync(dir,{recursive:false,mode:0o700});}
  catch{fail('DIRECTORY_CREATE_FAILED');}
  st=fs.lstatSync(dir);
 }
 if(!st.isDirectory()||st.isSymbolicLink()||
    (st.mode&0o077)!==0||
    (typeof process.getuid==='function'&&st.uid!==process.getuid()))
  fail('DIRECTORY_INSECURE');
 return dir;
}
function syncDir(dir){
 let fd;
 try{fd=fs.openSync(dir,fs.constants.O_RDONLY);fs.fsyncSync(fd);}
 catch{fail('DURABILITY_UNAVAILABLE');}
 finally{if(fd!==undefined)fs.closeSync(fd);}
}
function readState(dir){
 const file=path.join(dir,STATE);
 const stat=protect(file,'STATE');
 if(!stat)return null;
 if(!stat.isFile()||stat.size<20||stat.size>MAX_BYTES)fail('STATE_INSECURE');
 let fd,raw;
 try{
  fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));
  const actual=fs.fstatSync(fd);
  if(!actual.isFile()||actual.ino!==stat.ino||actual.dev!==stat.dev||
     actual.size!==stat.size||actual.nlink!==1||(actual.mode&0o077)!==0)
    fail('STATE_RACE');
  raw=fs.readFileSync(fd);
 }catch(e){if(e.code?.startsWith('VAULT_'))throw e;fail('STATE_UNREADABLE');}
 finally{if(fd!==undefined)fs.closeSync(fd);}
 let state;
 try{state=JSON.parse(raw.toString('utf8'));}
 catch{fail('STATE_CORRUPT');}
 if(!exact(state,['schema','ownerFingerprint','witnessFingerprint',
      'highWaterSequence','latestReceiptDigest','receipts'])||
    state.schema!=='mikaya.witness.persistent-state.v1'||
    !HASH.test(state.ownerFingerprint)||!HASH.test(state.witnessFingerprint)||
    !HASH.test(state.latestReceiptDigest)||
    !Number.isSafeInteger(state.highWaterSequence)||state.highWaterSequence<1||
    !Array.isArray(state.receipts)||state.receipts.length<1||state.receipts.length>MAX_CHECKPOINTS||
    !exact(state.receipts.at(-1),[
      'schema','rootFingerprint','witnessFingerprint','sequence','headHash',
      'previousCheckpointDigest','issuedAtMs','nonce','scope','signature','receiptDigest'])||
    state.receipts.at(-1).receiptDigest!==state.latestReceiptDigest||
    state.receipts.at(-1).sequence!==state.highWaterSequence)
  fail('STATE_CORRUPT');
 return state;
}
function verifyState(state,{entries,rootPublicKey,witnessPublicKey}){
 if(!Array.isArray(entries)||!entries.length)fail('LEDGER_REQUIRED');
 const owner=keyPublic(rootPublicKey),observer=keyPublic(witnessPublicKey);
 if(state.ownerFingerprint!==fingerprint(owner)||state.witnessFingerprint!==fingerprint(observer))
  fail('SIGNER_MISMATCH');
 if(entries.length<state.highWaterSequence)fail('ROLLBACK');
 try{
  audit.verify({entries,rootPublicKey:owner});
  witness.verifyStream({
   entries:entries.slice(0,state.highWaterSequence),rootPublicKey:owner,
   witnessPublicKey:observer,receipts:state.receipts,
   expectedLatestDigest:state.latestReceiptDigest
  });
 }catch{fail('INTEGRITY_INVALID');}
 return state;
}
function checkExternal(state,{expectedMinimumSequence=0,expectedLatestDigest=null}={}){
 if(!Number.isSafeInteger(expectedMinimumSequence)||expectedMinimumSequence<0)
  fail('EXTERNAL_PIN_INVALID');
 if(state.highWaterSequence<expectedMinimumSequence)fail('ROLLBACK');
 if(expectedLatestDigest!==null&&
   (!HASH.test(expectedLatestDigest)||expectedLatestDigest!==state.latestReceiptDigest))
  fail('EXTERNAL_PIN_MISMATCH');
}
function withExclusive(dir,fn){
 const lock=path.join(dir,LOCK);
 let fd;
 try{
  fd=fs.openSync(lock,fs.constants.O_CREAT|fs.constants.O_EXCL|
    fs.constants.O_WRONLY|(fs.constants.O_NOFOLLOW||0),0o600);
  fs.writeSync(fd,String(process.pid)+'\n');
  fs.fsyncSync(fd);
 }catch{fail('LOCKED');}
 finally{if(fd!==undefined)fs.closeSync(fd);}
 try{return fn();}
 finally{
  // A crashed process intentionally leaves its lock; never auto-steal it.
  fs.unlinkSync(lock);
  syncDir(dir);
 }
}
function commit(dir,data){
 const payload=Buffer.from(JSON.stringify(data)+'\n','utf8');
 if(payload.length>MAX_BYTES)fail('STATE_OVERSIZE');
 const tmp=path.join(dir,'.checkpoint-'+crypto.randomBytes(12).toString('hex')+'.tmp');
 let fd;
 try{
  fd=fs.openSync(tmp,fs.constants.O_CREAT|fs.constants.O_EXCL|
     fs.constants.O_WRONLY|(fs.constants.O_NOFOLLOW||0),0o600);
  fs.writeFileSync(fd,payload);
  fs.fsyncSync(fd);
  fs.closeSync(fd);fd=undefined;
  fs.renameSync(tmp,path.join(dir,STATE));
  syncDir(dir);
 }catch(e){
  if(fd!==undefined)fs.closeSync(fd);
  try{fs.unlinkSync(tmp);}catch{}
  if(e.code?.startsWith('VAULT_'))throw e;
  fail('COMMIT_FAILED');
 }
}
function record({dir,entries,rootPublicKey,witnessPrivateKey,issuedAtMs,
  bootstrap=false,expectedPriorDigest=null}={}){
 validDir(dir,bootstrap);
 return withExclusive(dir,()=>{
  const state=readState(dir);
  let previousReceipt=null,receipts=[];
  const observerPublic=(()=>{try{return crypto.createPublicKey(witnessPrivateKey);}catch{fail('KEY_INVALID');}})();
  if(!state){
   if(!bootstrap)fail('UNINITIALIZED');
   if(expectedPriorDigest!==null)fail('EXTERNAL_PIN_MISMATCH');
  }else{
   if(bootstrap)fail('BOOTSTRAP_ALREADY_DONE');
   verifyState(state,{entries,rootPublicKey,witnessPublicKey:observerPublic});
   if(expectedPriorDigest!==null&&
     (!HASH.test(expectedPriorDigest)||state.latestReceiptDigest!==expectedPriorDigest))
    fail('EXTERNAL_PIN_MISMATCH');
   if(entries.length<state.highWaterSequence)fail('ROLLBACK');
   if(entries.length===state.highWaterSequence)fail('REPLAY');
   previousReceipt=state.receipts.at(-1);
   receipts=state.receipts.slice();
  }
  if(receipts.length>=MAX_CHECKPOINTS)fail('STATE_OVERSIZE');
  let signed;
  try{signed=witness.observe({entries,rootPublicKey,witnessPrivateKey,previousReceipt,issuedAtMs});}
  catch{fail('OBSERVATION_REFUSED');}
  receipts.push(signed);
  commit(dir,{schema:'mikaya.witness.persistent-state.v1',
    ownerFingerprint:signed.rootFingerprint,witnessFingerprint:signed.witnessFingerprint,
    highWaterSequence:signed.sequence,latestReceiptDigest:signed.receiptDigest,receipts});
  return signed;
 });
}
function inspect({dir,entries,rootPublicKey,witnessPublicKey,expectedMinimumSequence=0,
  expectedLatestDigest=null}={}){
 validDir(dir,false);
 const state=readState(dir);
 if(!state)fail('UNINITIALIZED');
 verifyState(state,{entries,rootPublicKey,witnessPublicKey});
 checkExternal(state,{expectedMinimumSequence,expectedLatestDigest});
 if(entries.length!==state.highWaterSequence)fail('STALE_HEAD');
 return {schema:'mikaya.witness.persistent-verification.v1',
  verified:true,ledgerEntries:entries.length,highWaterSequence:state.highWaterSequence,
  latestReceiptDigest:state.latestReceiptDigest,witnessCheckpoints:state.receipts.length,
  externalPinMatched:expectedLatestDigest!==null,
  externalCustodyVerified:false,independentHardwareConfirmed:false,
  executionAuthorized:false,financialSettlementVerified:false,actAdmitted:false,
  governmentCertified:false};
}
module.exports={record,inspect};
