'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {execFileSync}=require('node:child_process');
const fed=require('../federation-node.cjs');
const gate=require('../attestation-gate.cjs');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
function setup(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-attest-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));const a=path.join(root,'f110'),b=path.join(root,'moto');fed.initNode(a,'MIKAYA','f110-lab');fed.initNode(b,'MOTOROLA','moto-lab');return {root,a,b};}
const obs=()=>({os:'android',androidApi:35,verifiedBoot:'green',kernel:'5.15.197-android13',architecture:'aarch64'});
test('software inventory has Ed25519 source integrity but cannot claim hardware attestation',t=>{
 const s=setup(t),nonce=crypto.randomBytes(32).toString('hex');
 const signed=gate.softReport({dir:s.a,nonce,observations:obs(),codeSha256:sha('source')});
 const r=gate.verifySoftware({report:signed,pinnedPublicKey:fs.readFileSync(path.join(s.a,'identity-public.pem')),nonce});
 assert.equal(r.softwareSignatureVerified,true);assert.equal(r.hardwareAttested,false);assert.equal(r.securityAdmitted,false);
 assert.match(r.blockers.join(','),/hardware_key_certificate_chain/);
});
test('falsified observations, wrong node, wrong nonce, and expired signed inventory fail',t=>{
 const s=setup(t),nonce=crypto.randomBytes(32).toString('hex');
 const signed=gate.softReport({dir:s.a,nonce,observations:obs(),codeSha256:sha('source')});
 const pub=fs.readFileSync(path.join(s.a,'identity-public.pem'));
 assert.throws(()=>gate.verifySoftware({report:signed,pinnedPublicKey:pub,nonce:sha('notnonce')}),/challenge/);
 assert.throws(()=>gate.verifySoftware({report:{...signed,observations:{...obs(),verifiedBoot:'yellow'}},pinnedPublicKey:pub,nonce}),/signature/);
 assert.throws(()=>gate.verifySoftware({report:signed,pinnedPublicKey:fs.readFileSync(path.join(s.b,'identity-public.pem')),nonce}),/not pinned/);
 assert.throws(()=>gate.verifySoftware({report:signed,pinnedPublicKey:pub,nonce,nowMs:signed.issuedAtMs+500000}),/expired/);
});
test('software identity report rejects invasive private fields and unreviewed firmware claims',t=>{
 const s=setup(t);assert.throws(()=>gate.softReport({dir:s.a,nonce:'a'.repeat(64),codeSha256:sha('x'),observations:{...obs(),imei:'hidden'}}),/observation/);
 assert.throws(()=>gate.softReport({dir:s.a,nonce:'a'.repeat(64),codeSha256:sha('x'),observations:{...obs(),securityPatch:'signed-but-not-a-patch'}}),/observation/);
});
test('invalid ASN.1 extension length and nonexistent Android KeyMint attestation fail closed',()=>{
 assert.throws(()=>gate.der(Buffer.from('3080','hex')),/indefinite/);
 assert.throws(()=>gate.androidKeyDescription(Buffer.from('3000','hex'),Buffer.alloc(32)),/attestation|DER|certificate/i);
});
test('only published Google and Yubico root DER fingerprints are trusted vendor anchors',()=>{
 assert.equal(gate.OFFICIAL_VENDOR_ROOTS.ANDROID_KEYMINT.length,2);
 assert.equal(gate.OFFICIAL_VENDOR_ROOTS.YUBIKEY_PIV.length,2);
 assert.equal(gate.OFFICIAL_VENDOR_ROOTS.ANDROID_KEYMINT.some(x=>!(/^[a-f0-9]{64}$/.test(x))),false);
 assert.equal(gate.OFFICIAL_VENDOR_ROOTS.YUBIKEY_PIV.some(x=>!(/^[a-f0-9]{64}$/.test(x))),false);
});
test('missing, self-signed-only and unpinned certificate chain cannot assert hardware',t=>{
 const s=setup(t),nonce=crypto.randomBytes(32).toString('hex'),n=fed.loadNode(s.a);
 const proto={schema:'mikaya.federation.hardware-attestation.v1',kind:'ANDROID_KEYMINT',federationFingerprint:n.meta.fingerprint,nonce,certificatesPem:[],challengeSignatureBase64:'AA=='};
 assert.throws(()=>gate.verifyHardware({evidence:proto,approvedRoots:[],expectedFingerprint:n.meta.fingerprint,nonce}),/certificate|chain/);
 assert.throws(()=>gate.verifyHardware({evidence:{...proto,certificatesPem:['-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----']},approvedRoots:[{name:'invented',sha256:'0'.repeat(64)}],expectedFingerprint:n.meta.fingerprint,nonce}),/certificate|chain/);
});
test('even attacker-pinned test CA cannot impersonate official vendor attestation',t=>{
 const s=setup(t),n=fed.loadNode(s.a),nonce=crypto.randomBytes(32).toString('hex');
 const caKey=path.join(s.root,'ca.key'),caCert=path.join(s.root,'ca.crt'),leafKey=path.join(s.root,'leaf.key'),leafCsr=path.join(s.root,'leaf.csr'),leafCert=path.join(s.root,'leaf.crt');
 const openssl=(...args)=>execFileSync('openssl',args,{stdio:['ignore','ignore','ignore'],timeout:5000});
 openssl('req','-x509','-newkey','rsa:2048','-keyout',caKey,'-out',caCert,'-days','1','-nodes','-subj','/CN=Lab-Test-CA','-addext','basicConstraints=critical,CA:TRUE');
 openssl('req','-newkey','rsa:2048','-keyout',leafKey,'-out',leafCsr,'-nodes','-subj','/CN=Lab-Test-Leaf');
 openssl('x509','-req','-in',leafCsr,'-CA',caCert,'-CAkey',caKey,'-CAcreateserial','-out',leafCert,'-days','1');
 const root=new crypto.X509Certificate(fs.readFileSync(caCert));
 const chain=[fs.readFileSync(leafCert,'utf8'),fs.readFileSync(caCert,'utf8')];
 const allowed=[{name:'test-root',sha256:sha(root.raw)}];
 assert.equal(gate.verifyChain(chain,allowed).length,2);
 const challenge=gate.expectedChallenge(n.meta.fingerprint,nonce);
 const signature=crypto.sign('sha256',challenge,fs.readFileSync(leafKey)).toString('base64');
 const evidence={schema:'mikaya.federation.hardware-attestation.v1',kind:'YUBIKEY_PIV',federationFingerprint:n.meta.fingerprint,nonce,certificatesPem:chain,challengeSignatureBase64:signature};
 assert.throws(()=>gate.verifyHardware({evidence,approvedRoots:allowed,expectedFingerprint:n.meta.fingerprint,nonce}),/published Google or Yubico/);
 assert.throws(()=>gate.verifyHardware({evidence:{...evidence,nonce:'f'.repeat(64)},approvedRoots:allowed,expectedFingerprint:n.meta.fingerprint,nonce}),/not bound/);
});
test('a fully signed but privacy-violating software inventory is refused by the verifier',t=>{
 const s=setup(t),nonce=crypto.randomBytes(32).toString('hex');
 const signed=gate.softReport({dir:s.a,nonce,observations:obs(),codeSha256:sha('source')});
 const bad={...signed,observations:{...obs(),rawSubscriberId:'MUST_NOT_CROSS_OWNER_BOUNDARY'}};
 const {signature,...message}=bad;
 bad.signature=crypto.sign(null,Buffer.from('MIKAYA-SOVEREIGN-FEDERATION-ATTEST/1\nSOFTWARE\n'+fed.canonical(message)),fs.readFileSync(path.join(s.a,'identity-private.pem'))).toString('base64');
 assert.throws(()=>gate.verifySoftware({report:bad,pinnedPublicKey:fs.readFileSync(path.join(s.a,'identity-public.pem')),nonce}),/sensitive|observation/i);
});