#!/usr/bin/env node
'use strict';
/**
 * ACT-Omega backend compatibility v1 — verification only, no network I/O.
 *
 * Public MCP tool catalogs and unverified "TOOL_CALLED_OK" values are never
 * accepted as proof of executed jobs. ACT must independently sign real work
 * with its out-of-band verified Ed25519 key and return the MIKAYA federation
 * request/response envelope; ACT's actual implementation is not yet verified.
 *
 * This module confers zero hardware attestation, payment or execution rights.
 */
const crypto=require('node:crypto');
const fed=require('./federation-node.cjs');
const SHA=/^[a-f0-9]{64}$/;
const NONCE=/^[a-f0-9]{32}$/;
const DOMAIN='MIKAYA-INDEPENDENT-FEDERATION/1\n';
const PUBLIC_MCP_ENDPOINT='https://mcp.act-omega-net.dev/mcp';
function fail(msg){throw Error(msg);}
function plain(x){return x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;}
function exact(o,keys){return plain(o)&&Object.keys(o).sort().join('|')===[...keys].sort().join('|');}
function validSignature(pub,kind,envelope) {
 if(!plain(envelope)||typeof envelope.signature!=='string'||envelope.signature.length>128||!/^[A-Za-z0-9+/]+={0,2}$/.test(envelope.signature))return false;
 const sig=Buffer.from(envelope.signature,'base64');
 if(sig.length!==64||sig.toString('base64')!==envelope.signature)return false;
 const {signature,...unsigned}=envelope;
 return crypto.verify(null,Buffer.from(DOMAIN+kind+'\n'+fed.canonical(unsigned)),pub,sig);
}
function inspectCatalog({endpoint,document}) {
 if(endpoint!==PUBLIC_MCP_ENDPOINT)fail('untrusted MCP endpoint origin');
 if(!plain(document)||document.jsonrpc!=='2.0'||!plain(document.result)||!plain(document.result.serverInfo))fail('invalid MCP discovery document');
 const serverInfo=document.result.serverInfo;
 if(typeof serverInfo.name!=='string'||serverInfo.name.length<2||serverInfo.name.length>100||typeof serverInfo.version!=='string'||serverInfo.version.length>30)fail('invalid advertised backend identity');
 return {endpoint,serverName:serverInfo.name,version:serverInfo.version,trust:'DISCOVERY_ONLY',backendAuthorized:false,capabilitiesVerified:false,hardwareAttested:false};
}
function verifyDeterministicReceipt({request,response,ownerPublicKey,actPublicKey,expectedActFingerprint,nowMs=Date.now()}) {
 if(!SHA.test(expectedActFingerprint)||!Number.isSafeInteger(nowMs))fail('invalid backend identity or time');
 if(fed.fp(actPublicKey)!==expectedActFingerprint)fail('ACT public key fingerprint mismatch');
 const ownerFingerprint=fed.fp(ownerPublicKey);
 if(ownerFingerprint===expectedActFingerprint)fail('backend must have separate owner identity');
 if(!exact(request,['auth','body'])||!exact(response,['auth','body']))fail('signed backend request and response envelope required');
 const req=request.auth, reply=response.auth,job=request.body,body=response.body;
 if(!exact(req,['schema','from','to','method','route','bodySha256','nonce','issuedAtMs','signature'])||
 req.schema!=='mikaya.federation.request.v1'||req.from!==ownerFingerprint||req.to!==expectedActFingerprint||req.method!=='POST'||req.route!=='/v1/task'||
 !NONCE.test(req.nonce)||!Number.isSafeInteger(req.issuedAtMs)||Math.abs(nowMs-req.issuedAtMs)>60000||
 req.bodySha256!==fed.sha(fed.canonical(job))||!validSignature(ownerPublicKey,'REQ',req))fail('owner signed backend request invalid, expired or tampered');
 const expected=fed.computeJob(job);
 if(!exact(body,['schema','jobId','capability','workerFingerprint','requestSha256','result'])||
 body.schema!=='mikaya.federation.result.v1'||body.jobId!==job.id||body.capability!==job.capability||
 body.workerFingerprint!==expectedActFingerprint||body.requestSha256!==fed.sha(fed.canonical(job))||body.result!==expected)fail('ACT backend computation result inconsistent');
 if(!exact(reply,['schema','from','to','inReplyTo','bodySha256','issuedAtMs','signature'])||
 reply.schema!=='mikaya.federation.response.v1'||reply.from!==expectedActFingerprint||reply.to!==ownerFingerprint||
 reply.inReplyTo!==req.nonce||reply.bodySha256!==fed.sha(fed.canonical(body))||
 !Number.isSafeInteger(reply.issuedAtMs)||Math.abs(nowMs-reply.issuedAtMs)>60000||reply.issuedAtMs<req.issuedAtMs-1000||
 !validSignature(actPublicKey,'RES',reply))fail('ACT backend response signature, origin or nonce invalid');
 return Object.freeze({verified:true,result:expected,capability:job.capability,workerFingerprint:expectedActFingerprint,requestDigest:req.bodySha256,hardwareAttested:false,paymentSettled:false,executionAuthorized:false});
}
module.exports={inspectCatalog,verifyDeterministicReceipt,PUBLIC_MCP_ENDPOINT};
