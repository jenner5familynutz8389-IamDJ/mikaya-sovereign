'use strict';
/**
 * Strict MIKAYA source-release verification, read-only, no network or device operations.
 * Distinguishes owner-signed historical subsets from complete Git-tracked releases.
 * A signature alone never asserts hardware, regulatory, wallet or ACT admission.
 */
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),cp=require('node:child_process');
const HEX=/^[a-f0-9]{64}$/,MAX_FILES=10000,MAX_FILE_BYTES=16*1024*1024;
const DEFAULT_SIGNER='9270d9fe0490a497e223f39318209939a8739b6b5a39e5eeef3577477a6057a3';
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
function fail(code){const e=Error(code);e.code=code;throw e;}
function plain(x){return x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;}
function validPath(rel){
 return typeof rel==='string'&&rel.length>0&&rel.length<250&&!rel.startsWith('/')&&
 !rel.includes('\\')&&!rel.includes('\0')&&!rel.includes(':')&&
 !rel.split('/').some(part=>part===''||part==='.'||part==='..')&&
 !rel.split('/').includes('.git');
}
function boundedFile(root,rel){
 if(!validPath(rel))fail('UNSAFE_MANIFEST_PATH');
 let p=root;
 for(const part of rel.split('/')){
  p=path.join(p,part);
  let info;try{info=fs.lstatSync(p);}catch{fail('SOURCE_MISSING');}
  if(info.isSymbolicLink())fail('SYMLINK_IN_RELEASE');
 }
 const info=fs.statSync(p);
 if(!info.isFile()||info.size>MAX_FILE_BYTES)fail('SOURCE_FILE_INVALID');
 const fd=fs.openSync(p,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));
 try{const st=fs.fstatSync(fd);if(!st.isFile()||st.size!==info.size)fail('SOURCE_FILE_INVALID');return fs.readFileSync(fd);}
 finally{fs.closeSync(fd);}
}
function tracked(root,exclude){
 let out;
 try{out=cp.execFileSync('git',['-C',root,'ls-files','--cached','-z'],{encoding:'utf8',timeout:5000,maxBuffer:2097152});}
 catch{fail('TRACKED_INVENTORY_UNAVAILABLE');}
 const names=out.split('\0').filter(Boolean).filter(p=>!exclude.has(p)).sort();
 if(names.length>MAX_FILES||names.some(x=>!validPath(x)))fail('TRACKED_INVENTORY_INVALID');
 return names;
}
function verifyRelease({root,expectedSignerFingerprint=DEFAULT_SIGNER,requireComplete=false,
 manifestName='RELEASE-SOURCE-MANIFEST.json',attestationName='RELEASE-SOURCE-MANIFEST.sig.json'}={}){
 if(typeof root!=='string'||!path.isAbsolute(root)||!HEX.test(expectedSignerFingerprint)||
 !validPath(manifestName)||!validPath(attestationName)||manifestName===attestationName)fail('RELEASE_CONFIGURATION_INVALID');
 const raw=boundedFile(root,manifestName),attBytes=boundedFile(root,attestationName);
 let m,a;try{m=JSON.parse(raw.toString('utf8'));a=JSON.parse(attBytes.toString('utf8'));}catch{fail('INVALID_RELEASE_JSON');}
 if(!plain(a)||a.schema!=='sovereign.ed25519.manifest-attestation.v1'||a.algorithm!=='Ed25519'||
 a.signedFilename!==manifestName||!HEX.test(a.sha256)||a.sha256!==hash(raw)||
 !HEX.test(a.signerFingerprint)||a.signerFingerprint!==expectedSignerFingerprint||
 typeof a.publicKeyPem!=='string'||a.publicKeyPem.length>4096||
 hash(Buffer.from(a.publicKeyPem,'utf8'))!==expectedSignerFingerprint||
 typeof a.signatureBase64!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(a.signatureBase64))
  fail(a?.signerFingerprint!==expectedSignerFingerprint?'SIGNER_NOT_PINNED':'INVALID_RELEASE_ATTESTATION');
 let key;
 try{key=crypto.createPublicKey(a.publicKeyPem);}catch{fail('INVALID_SIGNER_KEY');}
 if(key.asymmetricKeyType!=='ed25519')fail('INVALID_SIGNER_KEY');
 const sig=Buffer.from(a.signatureBase64,'base64');
 if(sig.length!==64||sig.toString('base64')!==a.signatureBase64||
 !crypto.verify(null,raw,key,sig))fail('RELEASE_SIGNATURE_INVALID');
 if(!plain(m)||m.schema!=='sovereign.source-list.v1'||!plain(m.hashes))fail('INVALID_RELEASE_MANIFEST');
 const files=Object.entries(m.hashes);
 if(files.length===0||files.length>MAX_FILES)fail('RELEASE_FILE_COUNT_INVALID');
 for(const [rel,digest] of files){
  if(!validPath(rel))fail('UNSAFE_MANIFEST_PATH');
  if(!HEX.test(digest))fail('INVALID_MANIFEST_HASH');
  if(hash(boundedFile(root,rel))!==digest)fail('SOURCE_HASH_MISMATCH');
 }
 const signedNames=files.map(([rel])=>rel).sort();
 const actual=tracked(root,new Set([manifestName,attestationName]));
 const complete=signedNames.length===actual.length&&signedNames.every((f,i)=>f===actual[i]);
 if(requireComplete&&!complete)fail('INCOMPLETE_RELEASE_INVENTORY');
 return {schema:'mikaya.strict-release-closure.v1',verified:true,
  manifestSignatureVerified:true,filesVerified:files.length,trackedFiles:actual.length,
  complete,releaseStatus:complete?'COMPLETE_SIGNED_SOURCE':'HISTORICAL_SCOPED_SOURCE',
  manifestSha256:hash(raw),signerFingerprint:expectedSignerFingerprint,
  governmentCertified:false,productionAuthorized:false,hardwareAttested:false,actAdmitted:false};
}
if(require.main===module){
 try{
 const args=process.argv.slice(2),root=path.resolve(args.find(x=>!x.startsWith('--'))||'.');
 const data=verifyRelease({root,requireComplete:args.includes('--require-complete')});
 console.log(JSON.stringify(data));if(!data.complete)process.exitCode=2;
 }catch(e){console.error('MIKAYA_RELEASE_HOLD: '+e.code||e.message);process.exitCode=2;}
}
module.exports={verifyRelease};
