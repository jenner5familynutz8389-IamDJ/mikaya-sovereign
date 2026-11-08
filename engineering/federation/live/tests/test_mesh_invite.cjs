'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const crypto=require('node:crypto');
const fed=require('../federation-node.cjs');
const mesh=require('../mesh-invite.cjs');
function setup(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-join-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const a=path.join(root,'mi'),b=path.join(root,'act');
 const A=fed.initNode(a,'MIKAYA','f110-owner'),B=fed.initNode(b,'ACT-OMEGA','act-owner');
 return {a,b,A,B};
}
const now=Date.parse('2026-11-08T16:00:00Z');
test('owner-signed invitation verifies with out-of-band pinned inviter identity',t=>{
 const s=setup(t);const invite=mesh.makeInvite({dir:s.a,invitedOwner:'ACT-OMEGA',nowMs:now});
 assert.equal(mesh.verifyInvite({invite,expectedFingerprint:s.A.fingerprint,nowMs:now+1000}).verified,true);
 assert.equal(invite.authorization,'NONE_UNTIL_OWNER_PIN');
 assert.equal(invite.routeStatus,'OVERLAY_ROUTE_PENDING');
 assert.equal(invite.invitedOwner,'ACT-OMEGA');
 assert.equal(JSON.stringify(invite).includes('PRIVATE KEY'),false);
 assert.equal(JSON.stringify(invite).includes('192.168.'),false);
});
test('wrong pinned inviter, wrong owner, and bad signature all rejected',t=>{
 const s=setup(t);const i=mesh.makeInvite({dir:s.a,invitedOwner:'ACT-OMEGA',nowMs:now});
 assert.throws(()=>mesh.verifyInvite({invite:i,expectedFingerprint:s.B.fingerprint,nowMs:now}),/pinned|identity/i);
 assert.throws(()=>mesh.verifyInvite({invite:{...i,invitedOwner:'MIKAYA'},expectedFingerprint:s.A.fingerprint,nowMs:now}),/signature|owner/i);
 assert.throws(()=>mesh.verifyInvite({invite:{...i,signature:'garbage'},expectedFingerprint:s.A.fingerprint,nowMs:now}),/signature/i);
});
test('expired invitation and overlong lifetime rejected',t=>{
 const s=setup(t);const i=mesh.makeInvite({dir:s.a,invitedOwner:'ACT-OMEGA',nowMs:now,lifetimeMs:60000});
 assert.throws(()=>mesh.verifyInvite({invite:i,expectedFingerprint:s.A.fingerprint,nowMs:now+70000}),/expired/i);
 assert.throws(()=>mesh.makeInvite({dir:s.a,invitedOwner:'ACT-OMEGA',nowMs:now,lifetimeMs:31*60*1000}),/lifetime/i);
});
test('ACT reply signed by its own key binds exact MI invitation and capabilities',t=>{
 const s=setup(t);const i=mesh.makeInvite({dir:s.a,invitedOwner:'ACT-OMEGA',nowMs:now});
 const response=mesh.makeReply({dir:s.b,invite:i,expectedInviterFingerprint:s.A.fingerprint,nowMs:now+1200});
 const v=mesh.verifyReply({invite:i,reply:response,expectedInviterFingerprint:s.A.fingerprint,expectedResponderFingerprint:s.B.fingerprint,nowMs:now+2400});
 assert.equal(v.verified,true);assert.equal(v.enrolled,false);assert.equal(v.walletEnabled,false);
 assert.equal(response.requestedCapabilities.length,2);
});
test('an unapproved third-party claiming ACT does not become an enrolled node',t=>{
 const s=setup(t);const fake=path.join(path.dirname(s.a),'fake');const F=fed.initNode(fake,'ACT-OMEGA','rogue');
 const i=mesh.makeInvite({dir:s.a,invitedOwner:'ACT-OMEGA',nowMs:now});
 const response=mesh.makeReply({dir:fake,invite:i,expectedInviterFingerprint:s.A.fingerprint,nowMs:now+100});
 assert.throws(()=>mesh.verifyReply({invite:i,reply:response,expectedInviterFingerprint:s.A.fingerprint,expectedResponderFingerprint:s.B.fingerprint,nowMs:now+200}),/pinned|responder/i);
 assert.notEqual(F.fingerprint,s.B.fingerprint);
});
test('replayed reply cannot be accepted under a different invitation',t=>{
 const s=setup(t);const a=mesh.makeInvite({dir:s.a,invitedOwner:'ACT-OMEGA',nowMs:now});
 const b=mesh.makeInvite({dir:s.a,invitedOwner:'ACT-OMEGA',nowMs:now});
 const reply=mesh.makeReply({dir:s.b,invite:a,expectedInviterFingerprint:s.A.fingerprint,nowMs:now+100});
 assert.throws(()=>mesh.verifyReply({invite:b,reply,expectedInviterFingerprint:s.A.fingerprint,expectedResponderFingerprint:s.B.fingerprint,nowMs:now+150}),/invite|digest/i);
});
test('self-enrollment, malformed owner and unsupported capability rejected',t=>{
 const s=setup(t);
 assert.throws(()=>mesh.makeInvite({dir:s.a,invitedOwner:'MIKAYA',nowMs:now}),/separate|owner/i);
 assert.throws(()=>mesh.makeInvite({dir:s.a,invitedOwner:'ADMIN',nowMs:now}),/owner/i);
 const i=mesh.makeInvite({dir:s.a,invitedOwner:'ACT-OMEGA',nowMs:now});
 const reply=mesh.makeReply({dir:s.b,invite:i,expectedInviterFingerprint:s.A.fingerprint,nowMs:now+100});
 assert.throws(()=>mesh.verifyReply({invite:i,reply:{...reply,requestedCapabilities:['shell.exec']},expectedInviterFingerprint:s.A.fingerprint,expectedResponderFingerprint:s.B.fingerprint,nowMs:now+150}),/capability|signature/i);
});
test('invitation and reply contain public-only data; no wallet or firmware authority',t=>{
 const s=setup(t);const i=mesh.makeInvite({dir:s.a,invitedOwner:'ACT-OMEGA',nowMs:now});
 const r=mesh.makeReply({dir:s.b,invite:i,expectedInviterFingerprint:s.A.fingerprint,nowMs:now+10});
 // Inspect semantic fields, never arbitrary substrings of random signatures,
 // fingerprints or public PEM encodings (which can naturally contain 'adb').
 const forbiddenKeys=new Set(['privateKey','walletSeed','macaroon','adb','firmware','rootShell','lndAdminMacaroon']);
 for(const doc of [i,r]){
  for(const field of Object.keys(doc))assert.equal(forbiddenKeys.has(field),false);
  const capabilities=[...(doc.capabilities||[]),...(doc.requestedCapabilities||[])];
  for(const cap of capabilities)assert.ok(['compute.dot.v1','compute.sha256.v1'].includes(cap));
 }
 assert.equal(i.authorization,'NONE_UNTIL_OWNER_PIN');
 assert.equal(i.routeStatus,'OVERLAY_ROUTE_PENDING');
 assert.equal(mesh.verifyReply({invite:i,reply:r,expectedInviterFingerprint:s.A.fingerprint,expectedResponderFingerprint:s.B.fingerprint,nowMs:now+20}).enrolled,false);
});