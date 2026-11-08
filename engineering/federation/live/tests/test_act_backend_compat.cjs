'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const b=require('../act-backend-compat.cjs');
const fed=require('../federation-node.cjs');
const DOMAIN='MIKAYA-INDEPENDENT-FEDERATION/1\n';
function pair(){const k=crypto.generateKeyPairSync('ed25519');return {privateKey:k.privateKey,publicKey:k.publicKey,fingerprint:fed.fp(k.publicKey)};}
function signed(k,kind,unsigned){return {...unsigned,signature:crypto.sign(null,Buffer.from(DOMAIN+kind+'\n'+fed.canonical(unsigned)),k.privateKey).toString('base64')};}
function fixture(){
 const owner=pair(),act=pair(),now=1730000000000;
 const job={schema:'mikaya.federation.job.v1',id:'1234567890abcdef1234567890abcdef',capability:'compute.dot.v1',payload:{a:[1,2,3],b:[4,5,6]}};
 const reqUnsigned={schema:'mikaya.federation.request.v1',from:owner.fingerprint,to:act.fingerprint,method:'POST',route:'/v1/task',bodySha256:fed.sha(fed.canonical(job)),nonce:'0123456789abcdef0123456789abcdef',issuedAtMs:now};
 const body={schema:'mikaya.federation.result.v1',jobId:job.id,capability:job.capability,workerFingerprint:act.fingerprint,requestSha256:fed.sha(fed.canonical(job)),result:32};
 const resUnsigned={schema:'mikaya.federation.response.v1',from:act.fingerprint,to:owner.fingerprint,inReplyTo:reqUnsigned.nonce,bodySha256:fed.sha(fed.canonical(body)),issuedAtMs:now+40};
 return {owner,act,now,request:{auth:signed(owner,'REQ',reqUnsigned),body:job},response:{auth:signed(act,'RES',resUnsigned),body}};
}
function resign(key,kind,envelope){const {signature,...unsigned}=envelope;return signed(key,kind,unsigned);}
function verify(f){return b.verifyDeterministicReceipt({request:f.request,response:f.response,ownerPublicKey:f.owner.publicKey,actPublicKey:f.act.publicKey,expectedActFingerprint:f.act.fingerprint,nowMs:f.now+90});}
test('public ACT endpoint may be discovered but confers zero authorization',()=>{const out=b.inspectCatalog({endpoint:'https://mcp.act-omega-net.dev/mcp',document:{jsonrpc:'2.0',id:1,result:{serverInfo:{name:'ACT-Omega-Sovereign-Manifold-MCP',version:'68.0.0'}}}});assert.equal(out.backendAuthorized,false);assert.equal(out.trust,'DISCOVERY_ONLY');});
test('public catalog endpoint cannot be swapped for an arbitrary host',()=>assert.throws(()=>b.inspectCatalog({endpoint:'https://evil.example/mcp',document:{jsonrpc:'2.0',result:{serverInfo:{name:'a',version:'1'}}}}),/endpoint|origin/i));
test('two separately signed receipts verify deterministic useful work',()=>{const out=verify(fixture());assert.equal(out.verified,true);assert.equal(out.result,32);assert.equal(out.hardwareAttested,false);assert.equal(out.paymentSettled,false);assert.equal(out.executionAuthorized,false);});
test('static TOOL_CALLED_OK MCP catalog responses are not worker receipts',()=>{const f=fixture();f.response={jsonrpc:'2.0',id:1,result:{content:[{type:'text',text:'{"status":"TOOL_CALLED_OK"}'}]}};assert.throws(()=>verify(f),/signed|receipt|response|envelope/i)});
test('forged worker result even with worker signature is rejected',()=>{const f=fixture();f.response.body.result=999;f.response.auth=resign(f.act,'RES',{...f.response.auth,bodySha256:fed.sha(fed.canonical(f.response.body))});assert.throws(()=>verify(f),/result|computation/i)});
test('wrong worker signer and worker fingerprint are rejected',()=>{const f=fixture(),other=pair();f.response.auth=resign(other,'RES',f.response.auth);assert.throws(()=>verify(f),/signature|identity|fingerprint/i)});
test('nonce substitution is rejected even if worker-signed',()=>{const f=fixture();f.response.auth=resign(f.act,'RES',{...f.response.auth,inReplyTo:'f'.repeat(32)});assert.throws(()=>verify(f),/nonce|reply/i)});
test('expired request and receipt are refused',()=>{const f=fixture();assert.throws(()=>b.verifyDeterministicReceipt({request:f.request,response:f.response,ownerPublicKey:f.owner.publicKey,actPublicKey:f.act.publicKey,expectedActFingerprint:f.act.fingerprint,nowMs:f.now+61000}),/expired|stale|time/i)});
test('owner request body tampering is rejected',()=>{const f=fixture();f.request.body.payload.a[0]=42;assert.throws(()=>verify(f),/request|digest|body|signature/i)});
test('a pinned public key mismatch is rejected',()=>{const f=fixture();assert.throws(()=>b.verifyDeterministicReceipt({request:f.request,response:f.response,ownerPublicKey:f.owner.publicKey,actPublicKey:pair().publicKey,expectedActFingerprint:f.act.fingerprint,nowMs:f.now+90}),/fingerprint|identity/i)});
