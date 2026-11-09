'use strict';
/* Verify owner-signed public source manifest AND every listed file's SHA-256.
 * This does not verify OEM firmware, Android boot images, or live device state.
 */
const fs=require('node:fs'),crypto=require('node:crypto'),path=require('node:path');
const root=path.resolve(process.argv[2]||__dirname);
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const validHash=x=>typeof x==='string'&&/^[a-f0-9]{64}$/i.test(x);
function verify(){
  const raw=fs.readFileSync(path.join(root,'RELEASE-SOURCE-MANIFEST.json'));
  const att=JSON.parse(fs.readFileSync(path.join(root,'RELEASE-SOURCE-MANIFEST.sig.json'),'utf8'));
  if(att.schema!=='sovereign.ed25519.manifest-attestation.v1'||att.algorithm!=='Ed25519'||
    !validHash(att.sha256)||sha(raw)!==att.sha256||
    typeof att.publicKeyPem!=='string'||!validHash(att.signerFingerprint)||
    sha(Buffer.from(att.publicKeyPem,'utf8'))!==att.signerFingerprint||
    typeof att.signatureBase64!=='string'||
    !crypto.verify(null,raw,att.publicKeyPem,Buffer.from(att.signatureBase64,'base64')))
    throw Error('invalid source attestation');
  const manifest=JSON.parse(raw.toString('utf8'));
  if(manifest.schema!=='sovereign.source-list.v1'||!manifest.hashes||
    typeof manifest.hashes!=='object'||Array.isArray(manifest.hashes))
    throw Error('invalid manifest format');
  const entries=Object.entries(manifest.hashes);
  if(entries.length===0||entries.length>1000)throw Error('invalid file count');
  for(const [rel,expected] of entries){
    if(typeof rel!=='string'||rel.length===0||rel.includes('\\')||rel.includes('\0')||
       rel.startsWith('/')||rel.split('/').some(x=>x===''||x==='.'||x==='..')||
       rel.includes(':')||!validHash(expected))throw Error('unsafe manifest entry');
    const resolved=path.resolve(root,rel);
    if(!resolved.startsWith(root+path.sep))throw Error('source file outside root');
    // Reject symlink traversal at every component, not only the final file.
    let cur=root;
    for(const part of rel.split('/')){
      cur=path.join(cur,part);
      if(fs.lstatSync(cur).isSymbolicLink())throw Error('symlink in signed source path');
    }
    if(!fs.statSync(resolved).isFile()||sha(fs.readFileSync(resolved))!==expected.toLowerCase())
      throw Error('source hash mismatch');
  }
  console.log(JSON.stringify({verified:true,filesVerified:entries.length,
    manifestSha256:att.sha256,signerFingerprint:att.signerFingerprint,
    attestationScope:'owner_source_only_not_OEM_AVB'}));
}
try{verify()}catch(err){console.error('SOURCE_ATTESTATION_INVALID');process.exitCode=1}
