#!/usr/bin/env node
'use strict';
/**
 * MIKAYA sovereign one-hop broker. A bounded test-only route; NO real ACT-Omega
 * admission, monetary settlement, firmware writes, credential forwarding or shell.
 * Both the gateway and the worker sign independent, verifiable receipts.
 */
const fs=require('node:fs');
const http=require('node:http');
const https=require('node:https');
const crypto=require('node:crypto');
const path=require('node:path');
const fed=require('./federation-node.cjs');
const ownerAuth=require('./owner-authorization.cjs');
const HEX=/^[0-9a-f]{64}$/;
const DOMAIN='MIKAYA-INDEPENDENT-FEDERATION/1\n';
const SCOPES=new Set(['compute.dot.v1','compute.sha256.v1']);
const PAY='UNPAID_TEST_ONLY';
const isPlain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
const exact=(o,fields)=>isPlain(o)&&Object.keys(o).sort().join('|')===[...fields].sort().join('|');
const validSig=(sig,bytes,key)=>typeof sig==='string'&&sig.length<180&&/^[A-Za-z0-9+/]+={0,2}$/.test(sig)&&(()=>{
 const buf=Buffer.from(sig,'base64');return buf.length===64&&buf.toString('base64')===sig&&crypto.verify(null,Buffer.from(bytes),key,buf);
})();
function readFile(file){
 const s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink()||s.size>100000||(s.mode&0o022))throw Error('unsafe broker configuration file');
 return fs.readFileSync(file);
}
function validateV2Policy(p,gateway,options={}){
 if(!exact(p,['schema','enabled','testOnly','allowedUpstream','downstream','maxRequestsInFlight','authorization'])||
 p.schema!=='mikaya.federation.broker-policy.v2'||typeof p.enabled!=='boolean'||p.testOnly!==false||
 !isPlain(p.allowedUpstream)||!exact(p.downstream,['fingerprint','url'])||p.maxRequestsInFlight!==1)
  throw Error('signed owner authorization broker policy invalid');
 if(!gateway||gateway.meta?.owner!=='MIKAYA'||typeof options.dir!=='string'||options.dir!==gateway.dir)
  throw Error('gateway identity and owner state mismatch');
 const worker=p.downstream.fingerprint;
 if(!HEX.test(worker)||!gateway.peers[worker]||gateway.peers[worker].enabled!==true||gateway.peers[worker].owner!=='MOTOROLA')
  throw Error('downstream worker not independently pinned');
 const target=fed.validateUrl(p.downstream.url);
 if(target.protocol!=='https:'||p.downstream.url.length>256)
  throw Error('off-host ACT relay requires restricted authenticated HTTPS');
 const upstream=Object.keys(p.allowedUpstream);
 if(!p.enabled){
  if(upstream.length!==0||p.authorization!==null)throw Error('held broker must contain no grants');
  return p;
 }
 if(upstream.length!==1||!HEX.test(upstream[0])||upstream[0]===worker||
 !gateway.peers[upstream[0]]||gateway.peers[upstream[0]].enabled!==true||gateway.peers[upstream[0]].owner!=='ACT-OMEGA')
  throw Error('ACT identity must be independently pinned and allowed');
 const caps=p.allowedUpstream[upstream[0]];
 if(!Array.isArray(caps)||caps.length<1||caps.length>2||new Set(caps).size!==caps.length||caps.some(c=>!SCOPES.has(c)))
  throw Error('ACT capability scope forbidden');
 const review=p.authorization;
 if(!exact(review,['grant','securityReport','verifierFingerprint'])||!HEX.test(review.verifierFingerprint))
  throw Error('ACT cannot be admitted without two signatures');
 const reviewerDir=path.join(options.dir,'reviewers');
 const st=fs.lstatSync(reviewerDir);
 if(st.isSymbolicLink()||!st.isDirectory()||(st.mode&0o077))
  throw Error('independent verifier trust store unsafe');
 const reviewerPublicKey=readFile(path.join(reviewerDir,review.verifierFingerprint+'.pem'));
 if(fed.fp(reviewerPublicKey)!==review.verifierFingerprint)throw Error('reviewer key not the pinned identity');
 const permission=ownerAuth.verifyGrant({dir:options.dir,grant:review.grant,report:review.securityReport,
  reviewerPublicKey,nowMs:options.nowMs??Date.now()});
 if(permission.peerFingerprint!==upstream[0]||
  fed.canonical([...caps].sort())!==fed.canonical([...permission.capabilities].sort()))
  throw Error('owner grant and broker scope differ');
 return p;
}
function validatePolicy(p,gateway,options={}){
 if(p?.schema==='mikaya.federation.broker-policy.v2')return validateV2Policy(p,gateway,options);
 if(!exact(p,['schema','enabled','testOnly','allowedUpstream','downstream','maxRequestsInFlight'])||p.schema!=='mikaya.federation.broker-policy.v1'||typeof p.enabled!=='boolean'||p.testOnly!==true||!isPlain(p.allowedUpstream)||!exact(p.downstream,['fingerprint','url'])||!Number.isSafeInteger(p.maxRequestsInFlight)||p.maxRequestsInFlight!==1)throw Error('test-only broker policy schema refused');
 if(Object.keys(p.allowedUpstream).length>2||(p.enabled&&Object.keys(p.allowedUpstream).length<1))throw Error('unbounded upstream policy');
 const worker=p.downstream.fingerprint;if(!HEX.test(worker)||!gateway.peers[worker]||gateway.peers[worker].enabled!==true||gateway.peers[worker].owner!=='MOTOROLA')throw Error('downstream worker not pinned');
 fed.validateUrl(p.downstream.url);if(p.downstream.url.length>256)throw Error('downstream transport URL too long');
 for(const [fp,scopes] of Object.entries(p.allowedUpstream)){
  if(!HEX.test(fp)||!gateway.peers[fp]||gateway.peers[fp].enabled!==true||!['LAB-PEER','MOTOROLA'].includes(gateway.peers[fp].owner))throw Error('unknown upstream peer or hardware attestation HOLD');
  if(fp===worker)throw Error('upstream and worker identities must be independent');
  if(!Array.isArray(scopes)||scopes.length<1||scopes.length>2||new Set(scopes).size!==scopes.length||scopes.some(c=>!SCOPES.has(c)))throw Error('invalid capability scope');
 }
 return p;
}
function policyFromFile(dir,file){const n=fed.loadNode(dir),p=JSON.parse(readFile(file));return validatePolicy(p,n,{dir});}
function readLimited(req){return new Promise((resolve,reject)=>{
 let n=0,arr=[],bad=false;
 req.on('data',chunk=>{n+=chunk.length;if(n>8192){bad=true;arr=[];reject(Error('request body too large'));req.destroy();}else if(!bad)arr.push(chunk);});
 req.on('end',()=>{if(!bad)resolve(Buffer.concat(arr));});req.on('error',err=>{if(!bad)reject(err);});
});}
function signServiceResponse(dir,to,nonce,body){const n=fed.loadNode(dir);
 const msg={schema:'mikaya.federation.response.v1',from:n.meta.fingerprint,to,inReplyTo:nonce,bodySha256:fed.sha(fed.canonical(body)),issuedAtMs:Date.now()};
 const signature=crypto.sign(null,Buffer.from(DOMAIN+'RES\n'+fed.canonical(msg)),n.privateKey).toString('base64');
 return {...msg,signature};}
function validateSignedAuth(auth,expected,fromKey,body){
 if(!exact(auth,['schema','from','to','inReplyTo','bodySha256','issuedAtMs','signature'])||auth.schema!=='mikaya.federation.response.v1'||auth.from!==expected.from||auth.to!==expected.to||auth.inReplyTo!==expected.inReplyTo||auth.bodySha256!==fed.sha(fed.canonical(body))||!Number.isSafeInteger(auth.issuedAtMs)||Math.abs(Date.now()-auth.issuedAtMs)>120000)throw Error('signed response receipt mismatch');
 const {signature,...message}=auth;
 if(!validSig(signature,DOMAIN+'RES\n'+fed.canonical(message),fromKey))throw Error('signed response receipt invalid');
}
function verifyRelayedResult({proof,job,gatewayPublicKey,workerPublicKey,upstreamFingerprint}){
 if(!exact(proof,['schema','gatewayFingerprint','workerFingerprint','upstreamFingerprint','jobSha256','paymentStatus','authorizesExecution','authorizesSettlement','workerRequestAuth','workerRequestBody','workerResponseAuth','workerResponseBody'])||proof.schema!=='mikaya.federation.relay-result.v1'||proof.paymentStatus!==PAY||proof.authorizesExecution!==false||proof.authorizesSettlement!==false)throw Error('invalid unpaid test-only relay result');
 const g=fed.fp(gatewayPublicKey),w=fed.fp(workerPublicKey);
 if(g===w||g!==proof.gatewayFingerprint||w!==proof.workerFingerprint||proof.upstreamFingerprint!==upstreamFingerprint||proof.jobSha256!==fed.sha(fed.canonical(job))||fed.canonical(job)!==fed.canonical(proof.workerRequestBody))throw Error('broker or worker identity and job mismatch');
 const req=proof.workerRequestAuth;
 if(!exact(req,['schema','from','to','method','route','bodySha256','nonce','issuedAtMs','signature'])||req.schema!=='mikaya.federation.request.v1'||req.from!==g||req.to!==w||req.method!=='POST'||req.route!=='/v1/task'||req.bodySha256!==proof.jobSha256||!(/^[0-9a-f]{32}$/.test(req.nonce)))throw Error('broker forwarding request mismatch');
 const {signature,...reqUnsigned}=req;
 if(!validSig(signature,DOMAIN+'REQ\n'+fed.canonical(reqUnsigned),gatewayPublicKey))throw Error('broker forwarding request signature invalid');
 validateSignedAuth(proof.workerResponseAuth,{from:w,to:g,inReplyTo:req.nonce},workerPublicKey,proof.workerResponseBody);
 const b=proof.workerResponseBody;
 if(!exact(b,['schema','jobId','capability','workerFingerprint','requestSha256','result'])||b.schema!=='mikaya.federation.result.v1'||b.jobId!==job.id||b.capability!==job.capability||b.workerFingerprint!==w||b.requestSha256!==proof.jobSha256||b.result!==fed.computeJob(job))throw Error('independent worker result mismatch');
 return {verified:true,result:b.result,gatewayFingerprint:g,workerFingerprint:w,paymentVerified:false,authorizesExecution:false};
}
function startBroker({dir,policyFile,port,host='127.0.0.1',certPath=null,keyPath=null}){
 if(!Number.isSafeInteger(port)||port<1024||port>65535)throw Error('invalid broker port');
 policyFromFile(dir,policyFile);
 const loopback=host==='127.0.0.1'||host==='::1';
 if(!loopback&&(!certPath||!keyPath))throw Error('remote broker requires TLS');
 if(keyPath){const st=fs.lstatSync(keyPath);if(st.isSymbolicLink()||!st.isFile()||(st.mode&0o077))throw Error('private TLS key permissions must be 0600');}
 let running=0;
 const handler=async(req,res)=>{
  const send=(code,data)=>{if(res.headersSent||res.writableEnded)return;const b=Buffer.from(fed.canonical(data));res.writeHead(code,{'Content-Type':'application/json','Content-Length':b.length,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(b);};
  if(req.method==='GET'&&req.url==='/v1/broker-health'){
   let policy;try{policy=policyFromFile(dir,policyFile);}catch{return send(503,{error:'policy_integrity_hold'});}
   return send(200,{schema:'mikaya.federation.broker-health.v1',status:policy.enabled?'ready':'held',routingEnabled:policy.enabled,testOnly:policy.testOnly,paymentEnabled:false});
  }
  if(req.method!=='POST'||req.url!=='/v1/task')return send(404,{error:'route_refused'});
  let p;try{p=policyFromFile(dir,policyFile);}catch{return send(503,{error:'policy_integrity_hold'});}
  if(!p.enabled)return send(403,{error:'owner_policy_disabled'});
  if(running>=p.maxRequestsInFlight)return send(429,{error:'broker_busy'});
  running++;
  try{
   const reqbuf=await readLimited(req);let envelope;
   try{envelope=JSON.parse(reqbuf.toString('utf8'));}catch{return send(400,{error:'invalid_json'});}
   if(!exact(envelope,['auth','body']))return send(400,{error:'invalid_envelope'});
   let peer;try{peer=fed.verifyRequest({dir,auth:envelope.auth,method:'POST',route:'/v1/task',body:envelope.body});}
   catch{return send(401,{error:'signed_peer_authorization_required'});}
   const allow=p.allowedUpstream[peer.fingerprint];
   if(!allow||!allow.includes(envelope.body?.capability))return send(403,{error:'upstream_capability_denied'});
   try{fed.computeJob(envelope.body);}catch{return send(422,{error:'invalid_bounded_job'});}
   let work;
   try{work=await fed.clientCall({dir,url:p.downstream.url,expectedPeer:p.downstream.fingerprint,route:'/v1/task',body:envelope.body});}
   catch{return send(502,{error:'internal_worker_unavailable'});}
   const n=fed.loadNode(dir);
   const proof={schema:'mikaya.federation.relay-result.v1',gatewayFingerprint:n.meta.fingerprint,workerFingerprint:p.downstream.fingerprint,upstreamFingerprint:peer.fingerprint,jobSha256:fed.sha(fed.canonical(envelope.body)),paymentStatus:PAY,authorizesExecution:false,authorizesSettlement:false,workerRequestAuth:work.requestAuth,workerRequestBody:work.requestBody,workerResponseAuth:work.auth,workerResponseBody:work.body};
   try{verifyRelayedResult({proof,job:envelope.body,gatewayPublicKey:n.publicKey,workerPublicKey:readFile(path.join(dir,'trust',p.downstream.fingerprint+'.pem')),upstreamFingerprint:peer.fingerprint});}
   catch{return send(502,{error:'worker_receipt_invalid'});}
   const signed=signServiceResponse(dir,peer.fingerprint,envelope.auth.nonce,proof);
   return send(200,{auth:signed,body:proof});
  }catch{return send(400,{error:'invalid_bounded_request'});}finally{running--;}
 };
 const server=certPath&&keyPath?https.createServer({cert:readFile(certPath),key:readFile(keyPath),minVersion:'TLSv1.2'},handler):http.createServer(handler);
 server.requestTimeout=8000;server.headersTimeout=7000;server.maxHeadersCount=24;
 server.listen(port,host,()=>console.log('MIKAYA_BROKER_READY '+fed.canonical({host,port,testOnly:true,externalTls:!!certPath})));
 return server;
}
async function callBroker({dir,url,expectedGateway,expectedWorkerPublicKey,job}){
 const n=fed.loadNode(dir),parsed=fed.validateUrl(url);
 if(!HEX.test(expectedGateway)||!n.peers[expectedGateway]?.enabled)throw Error('gateway not pinned');
 fed.computeJob(job);
 const auth=fed.signRequest({dir,to:expectedGateway,method:'POST',route:'/v1/task',body:job});
 const received=await fed.rawPost(parsed.origin+'/v1/task',{auth,body:job});
 if(received.status!==200)throw Error('broker refused request HTTP '+received.status);
 if(!exact(received.json,['auth','body']))throw Error('invalid gateway response');
 fed.verifyResponse({dir,auth:received.json.auth,body:received.json.body,to:expectedGateway,nonce:auth.nonce});
 const workerKey=expectedWorkerPublicKey;
 const result=verifyRelayedResult({proof:received.json.body,job,gatewayPublicKey:readFile(path.join(dir,'trust',expectedGateway+'.pem')),workerPublicKey:workerKey,upstreamFingerprint:n.meta.fingerprint});
 return {...result,proof:received.json.body};
}
module.exports={validatePolicy,verifyRelayedResult,startBroker,callBroker};

if(require.main===module){
 const [command,dir,policyFile,port,host,certPath,keyPath]=process.argv.slice(2);
 if(command!=='serve')throw Error('usage: node federation-broker.cjs serve DIR POLICY_FILE PORT [BIND TLS_CERT TLS_KEY]');
 startBroker({dir,policyFile,port:Number(port),host:host||'127.0.0.1',certPath:certPath||null,keyPath:keyPath||null});
}
