'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const verifier=process.env.VERIFIER || path.join(__dirname,'verify-release.js');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function fixture(options={}){
  const folder=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-release-'));
  const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
  const pem=publicKey.export({type:'spki',format:'pem'});
  const rel=options.rel??'ahava/example.txt';
  fs.mkdirSync(path.join(folder,'ahava'),{recursive:true});
  fs.writeFileSync(path.join(folder,'ahava/example.txt'),'verified data');
  const raw=Buffer.from(JSON.stringify({schema:'sovereign.source-list.v1',hashes:{[rel]:options.hash??sha('verified data')}}));
  fs.writeFileSync(path.join(folder,'RELEASE-SOURCE-MANIFEST.json'),raw);
  const signature=crypto.sign(null,raw,privateKey);
  fs.writeFileSync(path.join(folder,'RELEASE-SOURCE-MANIFEST.sig.json'),JSON.stringify({schema:'sovereign.ed25519.manifest-attestation.v1',algorithm:'Ed25519',sha256:sha(raw),signerFingerprint:sha(pem),publicKeyPem:pem,signatureBase64:signature.toString('base64')}));
  const run=()=>spawnSync(process.execPath,[verifier,folder],{encoding:'utf8'});
  const cleanup=()=>fs.rmSync(folder,{recursive:true,force:true});
  return {folder,run,cleanup};
}
function scenario(name,mutation,accepted){test(name,()=>{const t=fixture();try{mutation(t);const r=t.run();assert.equal(r.status,accepted?0:1,'stdout='+r.stdout+' stderr='+r.stderr);if(accepted)assert.match(r.stdout,/"verified":true/);else assert.match(r.stderr,/SOURCE_ATTESTATION_INVALID/);}finally{t.cleanup()}})}
scenario('valid signed manifest and matching source bytes passes',()=>{},true);
scenario('tampered source file is rejected',t=>fs.writeFileSync(path.join(t.folder,'ahava/example.txt'),'tampered data'),false);
scenario('missing signed source file is rejected',t=>fs.unlinkSync(path.join(t.folder,'ahava/example.txt')),false);
scenario('symlink replacing signed file is rejected',t=>{fs.writeFileSync(path.join(t.folder,'outside'),'verified data');fs.unlinkSync(path.join(t.folder,'ahava/example.txt'));fs.symlinkSync('../outside',path.join(t.folder,'ahava/example.txt'))},false);
scenario('signed-source parent directory symlink is rejected',t=>{fs.renameSync(path.join(t.folder,'ahava'),path.join(t.folder,'elsewhere'));fs.symlinkSync('elsewhere',path.join(t.folder,'ahava'))},false);
scenario('invalid manifest signature is rejected',t=>{const p=path.join(t.folder,'RELEASE-SOURCE-MANIFEST.json');const obj=JSON.parse(fs.readFileSync(p));obj.hashes['ahava/example.txt']='0'.repeat(64);fs.writeFileSync(p,JSON.stringify(obj))},false);
test('path traversal inside signed manifest is rejected',()=>{const t=fixture({rel:'../file.txt'});try{const r=t.run();assert.equal(r.status,1,'stdout='+r.stdout+' stderr='+r.stderr);}finally{t.cleanup()}});
test('bogus digest format is rejected',()=>{const t=fixture({hash:'xx'});try{const r=t.run();assert.equal(r.status,1,'stdout='+r.stdout+' stderr='+r.stderr);}finally{t.cleanup()}});
