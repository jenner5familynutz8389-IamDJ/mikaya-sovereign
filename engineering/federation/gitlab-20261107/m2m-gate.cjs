'use strict';
/**
 * MIKAYA × ACT-Omega federation review: inert, no-wallet/no-network core.
 * First-party HMAC chained caveat token; NOT a BOLT11/L402 standard macaroon
 * serializer. A real LND settlement verifier is deliberately external.
 * Neither owner shares private signing keys, wallet credentials or OEM authority.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const HASH = /^[a-f0-9]{64}$/;
const NONCE = /^[a-f0-9]{32}$/;
const CAPABILITIES = new Set(['telemetry.aggregate.v1','compute.hash.v1']);
const ROLES = Object.freeze({'MIKAYA':'DUO_BRAIN_FIRMWARE_OEM','ACT-OMEGA':'HARDWARE_SOFTWARE_COMPUTE'});
const sha = input => crypto.createHash('sha256').update(input).digest('hex');
function isObject(x){return x!==null && typeof x==='object' && !Array.isArray(x);}
function canonical(v){
 if(Array.isArray(v))return '['+v.map(canonical).join(',')+']';
 if(isObject(v))return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
 if(v===null || typeof v==='string' || typeof v==='boolean' || (typeof v==='number'&&Number.isFinite(v)))return JSON.stringify(v);
 throw Error('invalid canonical value');
}
function telemetryDigest(buf){if(!Buffer.isBuffer(buf)||!buf.length||buf.length>1048576)throw Error('telemetry bytes invalid');return sha(buf);}
function validateTelemetry(buf){
 telemetryDigest(buf);let v;try{v=JSON.parse(buf.toString('utf8'));}catch{throw Error('telemetry JSON malformed');}
 if(!isObject(v)||v.schema!=='mikaya.f110.jitter-evidence-chain.v1'||!Array.isArray(v.measurements))throw Error('unexpected telemetry schema');
 return v; // exact bytes remain at owner; callers may only send the SHA-256 digest
}
function helloBody({owner,nodeId,role,nowMs,nonce}){
 if(!Object.hasOwn(ROLES,owner)||ROLES[owner]!==role)throw Error('node role not authorized for owner');
 if(typeof nodeId!=='string'||!/^[a-zA-Z0-9_-]{2,64}$/.test(nodeId)||!Number.isSafeInteger(nowMs)||!NONCE.test(nonce))throw Error('invalid node hello');
 return {schema:'mikaya.m2m.node-hello.v1',owner,nodeId,role,nonce,issuedAtMs:nowMs,expiresAtMs:nowMs+60000};
}
function makeHello({owner,nodeId,role,privateKey,nowMs=Date.now(),nonce=crypto.randomBytes(16).toString('hex')}){
 if(!privateKey)throw Error('private signing key absent');
 const body=helloBody({owner,nodeId,role,nowMs,nonce});
 const signature=crypto.sign(null,Buffer.from('MIKAYA-M2M-HELLO/1\n'+canonical(body)),privateKey).toString('base64');
 return {...body,signature};
}
function verifyHello({hello,pinnedPublicKey,expectedOwner,nowMs=Date.now()}){
 if(!isObject(hello)||!pinnedPublicKey||!Number.isSafeInteger(nowMs))throw Error('peer identity absent');
 const {signature,...b}=hello;
 if(!Number.isSafeInteger(b.issuedAtMs)||Math.abs(nowMs-b.issuedAtMs)>60000||b.expiresAtMs!==b.issuedAtMs+60000)throw Error('node hello expired');
 const expected=helloBody({owner:b.owner,nodeId:b.nodeId,role:b.role,nowMs:b.issuedAtMs,nonce:b.nonce});
 if(b.owner!==expectedOwner||canonical(expected)!==canonical(b))throw Error('node hello identity mismatch');
 if(typeof signature!=='string'||!/^[a-zA-Z0-9+/]+={0,2}$/.test(signature)||signature.length>180)throw Error('node hello signature absent');
 if(!crypto.verify(null,Buffer.from('MIKAYA-M2M-HELLO/1\n'+canonical(b)),pinnedPublicKey,Buffer.from(signature,'base64')))throw Error('node hello signature invalid');
 return true;
}
function validateOffer(o,nowMs=Date.now()){
 if(!isObject(o)||o.schema!=='m2m.compute-offer.v1'||o.buyer===o.seller||!Object.hasOwn(ROLES,o.buyer)||!Object.hasOwn(ROLES,o.seller)||
 typeof o.jobId!=='string'||!/^[a-zA-Z0-9_-]{3,96}$/.test(o.jobId)||!CAPABILITIES.has(o.capability)||!HASH.test(o.payloadSha256)||!HASH.test(o.invoicePaymentHash)||
 !Number.isSafeInteger(o.amountSats)||o.amountSats<1||o.amountSats>100000||!Number.isSafeInteger(o.expiresAtMs)||!Number.isSafeInteger(nowMs)||
 o.expiresAtMs<=nowMs||o.expiresAtMs>nowMs+3600000)throw Error('offer rejected by bounded capability and invoice policy');
 return o;
}
function root(rootKey){if(!Buffer.isBuffer(rootKey)||rootKey.length!==32)throw Error('macaroon root key invalid');return rootKey;}
function macaroonTag(key,identifier,caveats){
 let sig=crypto.createHmac('sha256',root(key)).update('MIKAYA-M2M-TOKEN/1\n'+identifier).digest();
 for(const [k,v] of Object.entries(caveats))sig=crypto.createHmac('sha256',sig).update(k+'='+String(v)).digest();
 return sig.toString('hex');
}
async function issueCredential({offer,rootKey,ownerApproval,settlementVerifier,nowMs=Date.now()}){
 validateOffer(offer,nowMs);root(rootKey);
 if(typeof ownerApproval!=='function'||typeof settlementVerifier!=='function')throw Error('independent approval and settlement verification required');
 if(await ownerApproval({...offer})!==true)throw Error('owner permission denied');
 // settlementVerifier is a seller-local dependency injected by operator configuration;
 // do not implement it as a buyer-controlled JSON field or trust mempool proof as invoice settlement.
 const proof=await settlementVerifier({paymentHash:offer.invoicePaymentHash,jobId:offer.jobId,amountSats:offer.amountSats});
 if(!isObject(proof)||proof.settled!==true||proof.paymentHash!==offer.invoicePaymentHash||!Number.isSafeInteger(proof.amountSats)||proof.amountSats<offer.amountSats)
   throw Error('independent Lightning settlement unverified');
 const identifier=crypto.randomBytes(16).toString('hex');
 const caveats={buyer:offer.buyer,seller:offer.seller,jobId:offer.jobId,capability:offer.capability,payloadSha256:offer.payloadSha256,invoicePaymentHash:offer.invoicePaymentHash,amountSats:offer.amountSats,expiresAtMs:offer.expiresAtMs,uses:1};
 return {schema:'m2m.first-party-macaroon.v1',identifier,caveats,signature:macaroonTag(rootKey,identifier,caveats)};
}
function authorizeCredential({macaroon,rootKey,request,nowMs=Date.now(),replayDir}){
 root(rootKey);
 if(!isObject(macaroon)||macaroon.schema!=='m2m.first-party-macaroon.v1'||!NONCE.test(macaroon.identifier)||!isObject(macaroon.caveats)||
 typeof macaroon.signature!=='string'||!HASH.test(macaroon.signature))throw Error('invalid service macaroon');
 const expectedKeys=['buyer','seller','jobId','capability','payloadSha256','invoicePaymentHash','amountSats','expiresAtMs','uses'];
 if(canonical(Object.keys(macaroon.caveats).sort())!==canonical([...expectedKeys].sort()))throw Error('unrecognized macaroon caveat');
 const got=Buffer.from(macaroon.signature,'hex'),expected=Buffer.from(macaroonTag(rootKey,macaroon.identifier,macaroon.caveats),'hex');
 if(!crypto.timingSafeEqual(got,expected))throw Error('macaroon signature invalid');
 const c=macaroon.caveats;
 if(!Number.isSafeInteger(c.expiresAtMs)||nowMs>=c.expiresAtMs||c.uses!==1||!CAPABILITIES.has(c.capability)||!HASH.test(c.payloadSha256)||!HASH.test(c.invoicePaymentHash))throw Error('macaroon expired or forbidden');
 if(!isObject(request)||!expectedKeys.filter(k=>k!=='expiresAtMs'&&k!=='uses').every(k=>request[k]===c[k]))throw Error('macaroon request constraints mismatched');
 if(!Number.isSafeInteger(c.amountSats)||c.amountSats<1)throw Error('invalid amount');
 if(typeof replayDir!=='string'||!replayDir||!fs.existsSync(replayDir)||!fs.statSync(replayDir).isDirectory()||fs.lstatSync(replayDir).isSymbolicLink())throw Error('durable replay store absent');
 const receiptPath=path.join(replayDir,sha('M2M-USED/1:'+macaroon.identifier)+'.used');
 let handle;
 try{handle=fs.openSync(receiptPath,'wx',0o600);fs.writeSync(handle,sha(canonical(c))+'\n');fs.fsyncSync(handle);}
 catch(e){if(e?.code==='EEXIST')throw Error('macaroon replay refused');throw e;}
 finally{if(handle!==undefined)fs.closeSync(handle);}
 return {authorized:true,execute:false,jobId:c.jobId,capability:c.capability,payloadSha256:c.payloadSha256};
}
function makeReceipt({provider,jobId,payloadSha256,resultSha256,privateKey,nowMs=Date.now()}){
 if(!privateKey||!Object.hasOwn(ROLES,provider)||!/^[a-zA-Z0-9_-]{3,96}$/.test(jobId)||!HASH.test(payloadSha256)||!HASH.test(resultSha256)||!Number.isSafeInteger(nowMs))throw Error('invalid signed receipt');
 const b={schema:'mikaya.m2m.result-receipt.v1',provider,jobId,payloadSha256,resultSha256,createdAtMs:nowMs,status:'RESULT_DIGEST_ONLY'};
 return {...b,signature:crypto.sign(null,Buffer.from('MIKAYA-M2M-RECEIPT/1\n'+canonical(b)),privateKey).toString('base64')};
}
function verifyReceipt({receipt,pinnedPublicKey,expectedProvider}){
 if(!isObject(receipt)||!pinnedPublicKey||receipt.provider!==expectedProvider||!Object.hasOwn(ROLES,receipt.provider))throw Error('receipt peer mismatch');
 const {signature,...b}=receipt;
 if(b.schema!=='mikaya.m2m.result-receipt.v1'||b.status!=='RESULT_DIGEST_ONLY'||!HASH.test(b.resultSha256)||!HASH.test(b.payloadSha256)||!/^[a-zA-Z0-9_-]{3,96}$/.test(b.jobId)||!Number.isSafeInteger(b.createdAtMs)||typeof signature!=='string')throw Error('receipt invalid');
 if(!crypto.verify(null,Buffer.from('MIKAYA-M2M-RECEIPT/1\n'+canonical(b)),pinnedPublicKey,Buffer.from(signature,'base64')))throw Error('signed receipt verification failed');
 return true;
}
module.exports={telemetryDigest,validateTelemetry,makeHello,verifyHello,validateOffer,issueCredential,authorizeCredential,makeReceipt,verifyReceipt};
