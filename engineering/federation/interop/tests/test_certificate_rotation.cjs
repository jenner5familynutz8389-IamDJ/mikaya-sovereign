'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),cp=require('node:child_process');
const direct=require('../direct-transport.cjs'),fed=require('../../live/federation-node.cjs'),rotation=require('../certificate-rotation.cjs');
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-rotate-'));fs.chmodSync(root,0o700);
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const a=path.join(root,'a'),b=path.join(root,'b'),A=direct.initialize(a),B=direct.initialize(b);
 const policy={schema:'mikaya.interop.distribution-policy.v1',policyId:'rotation-test',unit:require('../ledger-receipts.cjs').UNIT,rates:['compute.dot.v1','compute.sha256.v1'].map(capability=>({capability,creditUnits:1000})),beneficiaries:[A,B].map(x=>({fingerprint:x.fingerprint,basisPoints:5000}))};
 direct.pinPeer(a,B,policy);direct.pinPeer(b,A,policy);
 const ar=rotation.renew(a,8),br=rotation.renew(b,8);
 return {root,a,b,A,B,ar,br,dir:path.join(a,'direct-transport')};
}
function disable(f){
 const p=path.join(f.dir,'owner-policy.json'),j=JSON.parse(fs.readFileSync(p));j.enabled=false;fs.writeFileSync(p,JSON.stringify(j)+'\n');fs.writeFileSync(path.join(f.dir,'kill-switch'),'{}\n',{mode:0o600});
}
test('renewal retains application and TLS identity; active public state unchanged',t=>{
 const f=fixture(t);assert.equal(f.ar.fingerprint,f.A.fingerprint);assert.notEqual(f.ar.tlsCertificateSha256,f.A.tlsCertificateSha256);assert.deepEqual(JSON.parse(fs.readFileSync(path.join(f.dir,'public-peer.json'))),f.A);assert.equal(direct.validatePeer(f.ar).fingerprint,f.A.fingerprint);
});
test('rotation refuses active policy, accepts only exact approved plan after stop, preserves ledger and kill marker',t=>{
 const f=fixture(t);assert.throws(()=>rotation.plan(f.a,f.ar,f.br),/offline/);
 disable(f);const p=rotation.plan(f.a,f.ar,f.br),ledger=fs.readFileSync(path.join(f.dir,'distribution-policy.json'));
 assert.throws(()=>rotation.apply(f.a,f.ar,f.br,'0'.repeat(64)),/digest/);
 rotation.apply(f.a,f.ar,f.br,p.digest);
 const own=direct.loadOwn(f.a),auth=direct.loadAuthority(own,false);
 assert.equal(own.peer.tlsCertificateSha256,f.ar.tlsCertificateSha256);assert.equal(auth.peer.tlsCertificateSha256,f.br.tlsCertificateSha256);assert.equal(auth.policy.enabled,false);assert.ok(fs.existsSync(path.join(f.dir,'kill-switch')));assert.deepEqual(fs.readFileSync(path.join(f.dir,'distribution-policy.json')),ledger);
 rotation.rollback(f.a,p.digest);assert.equal(direct.loadOwn(f.a).peer.tlsCertificateSha256,f.A.tlsCertificateSha256);assert.equal(direct.loadAuthority(direct.loadOwn(f.a),false).peer.tlsCertificateSha256,f.B.tlsCertificateSha256);
});
test('refuses wrong application identity, reused cert, tampering and active process metadata',t=>{
 const f=fixture(t);disable(f);
 assert.throws(()=>rotation.plan(f.a,f.br,f.ar),/continuity/);
 assert.throws(()=>rotation.plan(f.a,f.A,f.br),/advance/);
 assert.throws(()=>rotation.plan(f.a,{...f.ar,signature:f.A.signature},f.br),/signature/);
 fs.writeFileSync(path.join(f.dir,'server.lock'),'{}\n',{mode:0o600});assert.throws(()=>rotation.plan(f.a,f.ar,f.br),/offline/);
});
