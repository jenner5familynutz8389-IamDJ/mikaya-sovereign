'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const fed=require('../federation-node.cjs'),economy=require('../mesh-economy.cjs');
const now=Date.parse('2026-11-08T17:00:00Z');
function setup(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'mika-econ-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const a=path.join(root,'a'),b=path.join(root,'b');const A=fed.initNode(a,'MIKAYA','f110-test'),B=fed.initNode(b,'ACT-OMEGA','act-test');
 fed.pinPeer(a,path.join(b,'identity-public.pem'),'ACT-OMEGA','act-test',B.fingerprint);
 fed.pinPeer(b,path.join(a,'identity-public.pem'),'MIKAYA','f110-test',A.fingerprint);
 return {root,a,b,A,B};}
async function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mika-synthetic-economy-proof-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const evidence=path.join(root,'public-synthetic-evidence.json');
 const result=await require('../demo_two_nodes.cjs').demo(evidence);
 assert.equal(result.verifiedPublicProof,true);
 assert.equal(result.physicalIndependentHosts,false);
 return JSON.parse(fs.readFileSync(evidence,'utf8'));
}
test('verified signed joint work becomes non-financial trust evidence only',async t=>{
 const out=economy.activityFromProof(await fixture(t));
 assert.equal(out.verifiedWorkCount,2);assert.equal(out.paymentVerified,false);
 assert.equal(out.securityAttested,false);assert.equal(out.ownerPermissionsGranted,false);
 assert.match(out.publicProofSha256,/^[a-f0-9]{64}$/);
});
test('altered proof cannot mint trust evidence',async t=>{
 const bad=await fixture(t);bad.exchanges[0].body.result=987654321;
 assert.throws(()=>economy.activityFromProof(bad),/signature|digest|result|mismatch/i);
});
test('seller signs quote with its own private key and recipient verifies public key',t=>{
 const s=setup(t),quote=economy.makeQuote({dir:s.b,buyerFingerprint:s.A.fingerprint,capability:'compute.dot.v1',units:12,unitPriceMsat:2500,nowMs:now});
 assert.equal(economy.verifyQuote({quote,pinnedSellerPublic:fs.readFileSync(path.join(s.b,'identity-public.pem')),expectedBuyer:s.A.fingerprint,nowMs:now+1000}).verified,true);
 assert.equal(quote.paymentStatus,'UNPAID');
 assert.equal(quote.authorizesExecution,false);
});
test('unknown buyer, forbidden capability and excessive quote rejected',t=>{
 const s=setup(t);
 assert.throws(()=>economy.makeQuote({dir:s.b,buyerFingerprint:'f'.repeat(64),capability:'compute.dot.v1',units:2,unitPriceMsat:1,nowMs:now}),/buyer|pinned/i);
 assert.throws(()=>economy.makeQuote({dir:s.b,buyerFingerprint:s.A.fingerprint,capability:'shell.exec',units:2,unitPriceMsat:1,nowMs:now}),/capability/i);
 assert.throws(()=>economy.makeQuote({dir:s.b,buyerFingerprint:s.A.fingerprint,capability:'compute.dot.v1',units:1000000000,unitPriceMsat:1,nowMs:now}),/units|limit/i);
});
test('tampering quote, wrong seller key, expiry never authorizes a paid job',t=>{
 const s=setup(t),quote=economy.makeQuote({dir:s.b,buyerFingerprint:s.A.fingerprint,capability:'compute.sha256.v1',units:2,unitPriceMsat:1000,nowMs:now,lifetimeMs:60000});
 const publicB=fs.readFileSync(path.join(s.b,'identity-public.pem'));
 assert.throws(()=>economy.verifyQuote({quote:{...quote,unitPriceMsat:1},pinnedSellerPublic:publicB,expectedBuyer:s.A.fingerprint,nowMs:now+1000}),/signature|quote/i);
 assert.throws(()=>economy.verifyQuote({quote,pinnedSellerPublic:fs.readFileSync(path.join(s.a,'identity-public.pem')),expectedBuyer:s.A.fingerprint,nowMs:now+1000}),/seller|identity/i);
 assert.throws(()=>economy.verifyQuote({quote,pinnedSellerPublic:publicB,expectedBuyer:s.A.fingerprint,nowMs:now+70000}),/expired/i);
});
test('quote remains inert without independently implemented seller settlement backend',t=>{
 const s=setup(t),quote=economy.makeQuote({dir:s.b,buyerFingerprint:s.A.fingerprint,capability:'compute.dot.v1',units:1,unitPriceMsat:1000,nowMs:now});
 assert.equal(economy.authorizePaidWork({quote}),false);
 assert.ok(!JSON.stringify(quote).includes('macaroon'));
 assert.ok(!JSON.stringify(quote).includes('PRIVATE KEY'));
});
