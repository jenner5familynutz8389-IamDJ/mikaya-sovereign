'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto'),cp=require('node:child_process');
const {verifyRelease}=require('../tools/verify-release-closure.cjs');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function fixture(t,{extra=false}={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-release-test-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const p=crypto.generateKeyPairSync('ed25519');
 const pk=p.publicKey.export({format:'pem',type:'spki'});
 fs.writeFileSync(path.join(root,'good.cjs'),"module.exports=1;\n");
 fs.writeFileSync(path.join(root,'README.md'),"# Controlled test\n");
 const hashes={'good.cjs':sha(fs.readFileSync(path.join(root,'good.cjs'))),'README.md':sha(fs.readFileSync(path.join(root,'README.md')))};
 if(extra){fs.writeFileSync(path.join(root,'unlisted.cjs'),"module.exports=2;\n");}
 const manifest={schema:'sovereign.source-list.v1',status:'test-signed-source-only',hashes};
 const raw=Buffer.from(JSON.stringify(manifest)+'\n');
 const fp=sha(Buffer.from(pk));
 const sig=crypto.sign(null,raw,p.privateKey).toString('base64');
 fs.writeFileSync(path.join(root,'RELEASE-SOURCE-MANIFEST.json'),raw);
 fs.writeFileSync(path.join(root,'RELEASE-SOURCE-MANIFEST.sig.json'),JSON.stringify({
  schema:'sovereign.ed25519.manifest-attestation.v1',algorithm:'Ed25519',
  signedFilename:'RELEASE-SOURCE-MANIFEST.json',sha256:sha(raw),
  signerFingerprint:fp,publicKeyPem:pk,signatureBase64:sig
 }));
 cp.execFileSync('git',['init','-q',root]);
 cp.execFileSync('git',['-C',root,'add','-A']);
 return {root,fp,pk,manifest};
}
function run(f,more={}){return verifyRelease({root:f.root,expectedSignerFingerprint:f.fp,...more});}
test('signed, pinned, byte-exact complete tracked release passes',t=>{
 const f=fixture(t);
 const result=run(f,{requireComplete:true});
 assert.equal(result.verified,true);assert.equal(result.complete,true);assert.equal(result.filesVerified,2);
 assert.equal(result.governmentCertified,false);assert.equal(result.productionAuthorized,false);
});
test('tampered source fails even when manifest signature remains valid',t=>{
 const f=fixture(t);fs.appendFileSync(path.join(f.root,'good.cjs'),'// tampered\n');
 assert.throws(()=>run(f),/SOURCE_HASH_MISMATCH/);
});
test('untrusted signer fingerprint is rejected',t=>{
 const f=fixture(t);assert.throws(()=>verifyRelease({root:f.root,expectedSignerFingerprint:'0'.repeat(64)}),/SIGNER_NOT_PINNED/);
});
test('incomplete signed inventory never constitutes a complete release',t=>{
 const f=fixture(t,{extra:true});assert.throws(()=>run(f,{requireComplete:true}),/INCOMPLETE_RELEASE_INVENTORY/);
 const r=run(f,{requireComplete:false});assert.equal(r.verified,true);assert.equal(r.complete,false);
});
test('traversal paths are rejected before file access',t=>{
 const f=fixture(t);const bad={...f.manifest,hashes:{'../escape.txt':'a'.repeat(64)}};
 const raw=Buffer.from(JSON.stringify(bad)+'\n');
 const kp=crypto.generateKeyPairSync('ed25519'),pk=kp.publicKey.export({format:'pem',type:'spki'});
 const fp=sha(Buffer.from(pk));
 fs.writeFileSync(path.join(f.root,'RELEASE-SOURCE-MANIFEST.json'),raw);
 fs.writeFileSync(path.join(f.root,'RELEASE-SOURCE-MANIFEST.sig.json'),JSON.stringify({
  schema:'sovereign.ed25519.manifest-attestation.v1',algorithm:'Ed25519',
  signedFilename:'RELEASE-SOURCE-MANIFEST.json',sha256:sha(raw),signerFingerprint:fp,publicKeyPem:pk,
  signatureBase64:crypto.sign(null,raw,kp.privateKey).toString('base64')}));
 assert.throws(()=>verifyRelease({root:f.root,expectedSignerFingerprint:fp}),/UNSAFE_MANIFEST_PATH/);
});
test('symlinked release input is rejected even when content matches',t=>{
 const f=fixture(t);const file=path.join(f.root,'good.cjs');const original=fs.readFileSync(file);
 fs.renameSync(file,path.join(f.root,'outside.data'));fs.symlinkSync('outside.data',file);
 assert.throws(()=>run(f),/SYMLINK_IN_RELEASE/);
});
