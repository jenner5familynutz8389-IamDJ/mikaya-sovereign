#!/usr/bin/env node
'use strict';
/** Signed, PUBLIC-ONLY cross-owner peer invitation and reciprocal proof-of-key.
 * It does not publish network routes, enroll a peer, authorize jobs, provision a
 * wallet or imply hardware attestation.  Mutual pinning is an independent step.
 */
const crypto=require('node:crypto');
const fs=require('node:fs');
const fed=require('./federation-node.cjs');
const SHA=/^[a-f0-9]{64}$/;
const NONCE=/^[a-f0-9]{32}$/;
const ALLOWED=new Set(['MIKAYA','MOTOROLA','LAB-PEER','ACT-OMEGA']);
const CAPS=new Set(['compute.dot.v1','compute.sha256.v1']);
const INVITE_FIELDS=['schema','inviterOwner','inviterNodeId','inviterFingerprint','inviterPublicKey','invitedOwner','capabilities','nonce','issuedAtMs','expiresAtMs','routeStatus','authorization','signature'];
const REPLY_FIELDS=['schema','inviteSha256','inviterFingerprint','responderOwner','responderNodeId','responderFingerprint','responderPublicKey','requestedCapabilities','nonce','issuedAtMs','signature'];
const INV_PREFIX='MIKAYA-FEDERATION-JOIN/1\nINVITE\n';
const REP_PREFIX='MIKAYA-FEDERATION-JOIN/1\nREPLY\n';
function fail(msg){throw Error(msg);}
function plain(o){return o!==null&&typeof o==='object'&&!Array.isArray(o)&&Object.getPrototypeOf(o)===Object.prototype;}
function shape(o,fields){return plain(o)&&Object.keys(o).sort().join('|')===fields.slice().sort().join('|');}
function validCaps(caps){return Array.isArray(caps)&&caps.length>0&&caps.length<=CAPS.size&&caps.every(x=>CAPS.has(x))&&new Set(caps).size===caps.length;}
function signed(body,privateKey,prefix){return crypto.sign(null,Buffer.from(prefix+fed.canonical(body)),privateKey).toString('base64');}
function checkedSignature(signature,body,publicKey,prefix){
 if(typeof signature!=='string'||!/^[A-Za-z0-9+/]+={0,2}$/.test(signature)||signature.length!==88)fail('join signature invalid');
 const bytes=Buffer.from(signature,'base64');
 if(bytes.length!==64||bytes.toString('base64')!==signature||!crypto.verify(null,Buffer.from(prefix+fed.canonical(body)),publicKey,bytes))fail('join signature invalid');
}
function bodyWithoutSig(doc){const {signature,...body}=doc;return body;}
function makeInvite({dir,invitedOwner,nowMs=Date.now(),lifetimeMs=5*60*1000}){
 const n=fed.loadNode(dir);
 if(!ALLOWED.has(invitedOwner)||n.meta.owner===invitedOwner)fail('invite must target separate valid owner');
 if(!Number.isSafeInteger(nowMs)||!Number.isSafeInteger(lifetimeMs)||lifetimeMs<1000||lifetimeMs>30*60*1000)fail('invite lifetime invalid');
 const capabilities=n.policy.allowedCapabilities.filter(c=>CAPS.has(c));
 if(!validCaps(capabilities))fail('invite capability policy invalid');
 const body={schema:'mikaya.federation.join-invite.v1',inviterOwner:n.meta.owner,inviterNodeId:n.meta.nodeId,
  inviterFingerprint:n.meta.fingerprint,inviterPublicKey:n.publicKey.toString('utf8'),invitedOwner,
  capabilities,nonce:crypto.randomBytes(16).toString('hex'),issuedAtMs:nowMs,expiresAtMs:nowMs+lifetimeMs,
  routeStatus:'OVERLAY_ROUTE_PENDING',authorization:'NONE_UNTIL_OWNER_PIN'};
 return {...body,signature:signed(body,n.privateKey,INV_PREFIX)};
}
function verifyInvite({invite,expectedFingerprint,nowMs=Date.now()}){
 if(!shape(invite,INVITE_FIELDS)||invite.schema!=='mikaya.federation.join-invite.v1'||!SHA.test(expectedFingerprint)||invite.inviterFingerprint!==expectedFingerprint)
  fail('pinned inviter identity mismatch');
 if(!ALLOWED.has(invite.inviterOwner)||!ALLOWED.has(invite.invitedOwner)||invite.inviterOwner===invite.invitedOwner||
   !/^[A-Za-z0-9_-]{2,64}$/.test(invite.inviterNodeId)||!NONCE.test(invite.nonce)||!validCaps(invite.capabilities))fail('join owner or capability invalid');
 if(invite.routeStatus!=='OVERLAY_ROUTE_PENDING'||invite.authorization!=='NONE_UNTIL_OWNER_PIN')fail('join authority escalation refused');
 if(typeof invite.inviterPublicKey!=='string'||invite.inviterPublicKey.length>2048||fed.fp(invite.inviterPublicKey)!==expectedFingerprint)fail('join public-key identity mismatch');
 if(!Number.isSafeInteger(nowMs)||!Number.isSafeInteger(invite.issuedAtMs)||!Number.isSafeInteger(invite.expiresAtMs)||
  invite.issuedAtMs>nowMs+5000||nowMs>=invite.expiresAtMs||invite.expiresAtMs-invite.issuedAtMs<1000||
  invite.expiresAtMs-invite.issuedAtMs>30*60*1000)fail('join invitation expired or invalid lifetime');
 checkedSignature(invite.signature,bodyWithoutSig(invite),invite.inviterPublicKey,INV_PREFIX);
 return {verified:true,inviterFingerprint:expectedFingerprint,invitedOwner:invite.invitedOwner,enrolled:false};
}
function makeReply({dir,invite,expectedInviterFingerprint,nowMs=Date.now()}){
 verifyInvite({invite,expectedFingerprint:expectedInviterFingerprint,nowMs});
 const n=fed.loadNode(dir);
 if(n.meta.owner!==invite.invitedOwner||n.meta.fingerprint===invite.inviterFingerprint)fail('responder owner not invited');
 const caps=invite.capabilities.filter(c=>n.policy.allowedCapabilities.includes(c));
 if(!validCaps(caps))fail('responder has no allowed capabilities');
 const body={schema:'mikaya.federation.join-reply.v1',inviteSha256:fed.sha(fed.canonical(invite)),
  inviterFingerprint:invite.inviterFingerprint,responderOwner:n.meta.owner,responderNodeId:n.meta.nodeId,
  responderFingerprint:n.meta.fingerprint,responderPublicKey:n.publicKey.toString('utf8'),
  requestedCapabilities:caps,nonce:crypto.randomBytes(16).toString('hex'),issuedAtMs:nowMs};
 return {...body,signature:signed(body,n.privateKey,REP_PREFIX)};
}
function verifyReply({invite,reply,expectedInviterFingerprint,expectedResponderFingerprint,nowMs=Date.now()}){
 verifyInvite({invite,expectedFingerprint:expectedInviterFingerprint,nowMs});
 if(!shape(reply,REPLY_FIELDS)||reply.schema!=='mikaya.federation.join-reply.v1'||!SHA.test(expectedResponderFingerprint)||reply.responderFingerprint!==expectedResponderFingerprint)
  fail('pinned responder identity mismatch');
 if(reply.inviteSha256!==fed.sha(fed.canonical(invite))||reply.inviterFingerprint!==invite.inviterFingerprint)fail('join reply invitation digest mismatch');
 if(reply.responderOwner!==invite.invitedOwner||!/^[A-Za-z0-9_-]{2,64}$/.test(reply.responderNodeId)||!NONCE.test(reply.nonce)||!validCaps(reply.requestedCapabilities)||
 !reply.requestedCapabilities.every(x=>invite.capabilities.includes(x)))fail('reply owner or capability mismatch');
 if(typeof reply.responderPublicKey!=='string'||reply.responderPublicKey.length>2048||fed.fp(reply.responderPublicKey)!==expectedResponderFingerprint)fail('reply public identity mismatch');
 if(!Number.isSafeInteger(reply.issuedAtMs)||Math.abs(nowMs-reply.issuedAtMs)>60000||reply.issuedAtMs<invite.issuedAtMs-5000)fail('join reply expired');
 checkedSignature(reply.signature,bodyWithoutSig(reply),reply.responderPublicKey,REP_PREFIX);
 return {verified:true,inviterFingerprint:invite.inviterFingerprint,responderFingerprint:reply.responderFingerprint,
   requestedCapabilities:reply.requestedCapabilities,enrolled:false,walletEnabled:false,ownerPinRequired:true};
}
function main(argv=process.argv.slice(2)){
 const [command,...a]=argv;
 if(command==='invite')console.log(fed.canonical(makeInvite({dir:a[0],invitedOwner:a[1]})));
 else if(command==='verify-invite')console.log(fed.canonical(verifyInvite({invite:JSON.parse(fs.readFileSync(a[0],'utf8')),expectedFingerprint:a[1]})));
 else if(command==='reply')console.log(fed.canonical(makeReply({dir:a[0],invite:JSON.parse(fs.readFileSync(a[1],'utf8')),expectedInviterFingerprint:a[2]})));
 else if(command==='verify-reply')console.log(fed.canonical(verifyReply({invite:JSON.parse(fs.readFileSync(a[0],'utf8')),
   reply:JSON.parse(fs.readFileSync(a[1],'utf8')),expectedInviterFingerprint:a[2],expectedResponderFingerprint:a[3]})));
 else fail('usage: invite DIR PEER_OWNER | verify-invite INVITE_JSON PINNED_FP | reply DIR INVITE_JSON PINNED_INVITER_FP | verify-reply INVITE_JSON REPLY_JSON PINNED_INVITER_FP PINNED_RESPONDER_FP');
}
if(require.main===module)try{main()}catch(e){console.error('MIKAYA_JOIN_REFUSED: '+e.message);process.exitCode=2;}
module.exports={makeInvite,verifyInvite,makeReply,verifyReply};