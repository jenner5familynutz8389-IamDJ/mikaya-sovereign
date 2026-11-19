#!/usr/bin/env node
'use strict';
// Owner-local access to the existing signed-ledger verifier. No remote dispatch.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const http=require('node:http');
const fed=require('../live/federation-node.cjs');
const tollbooth=require('../live/security-tollbooth.cjs');
const {createMtgPolicy}=require('../live/mtg-policy.cjs');
const {createNativeMtgPolicy}=require('./native-mtg.cjs');
const collector=require('../../../integrations/security-tollbooth/verified-events/ledger_event_collector.cjs');
const DOMAIN='MIKAYA-MOBILE-EDGE-LOCAL-READ/1\n';
const ROUTE='/v1/mobile/evidence',PORT=4188,WINDOW_MS=60000,MAX_NONCES=256;
const SHA=/^[a-f0-9]{64}$/,NONCE=/^[a-f0-9]{32}$/;
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join('|')===[...keys].sort().join('|');
const fail=message=>{throw Error(message);};
function currentOwner(dir,expectedFingerprint){
 const n=fed.loadNode(dir);
 if(!SHA.test(expectedFingerprint)||n.meta.fingerprint!==expectedFingerprint||!['MIKAYA','MOTOROLA'].includes(n.meta.owner))fail('owner_identity_hold');
 return n;
}
function signatureValid(unsigned,signature,key,kind){
 if(typeof signature!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(signature))return false;
 const bytes=Buffer.from(signature,'base64');
 return bytes.length===64&&bytes.toString('base64')===signature&&crypto.verify(null,Buffer.from(DOMAIN+kind+'\n'+fed.canonical(unsigned)),key,bytes);
}
function sign(unsigned,key,kind){return {...unsigned,signature:crypto.sign(null,Buffer.from(DOMAIN+kind+'\n'+fed.canonical(unsigned)),key).toString('base64')};}
function signRead({dir,expectedFingerprint,bootNonce,nonce=crypto.randomBytes(16).toString('hex'),issuedAtMs=Date.now()}){
 const n=currentOwner(dir,expectedFingerprint);
 if(!SHA.test(bootNonce)||!NONCE.test(nonce)||!Number.isSafeInteger(issuedAtMs)||issuedAtMs<0)fail('invalid_read_request');
 return sign({schema:'mikaya.mobile-edge.read-request.v1',ownerFingerprint:expectedFingerprint,method:'GET',route:ROUTE,bootNonce,nonce,issuedAtMs},n.privateKey,'REQ');
}
function readHeader(request){return 'MIKAYA-READ '+Buffer.from(fed.canonical(request)).toString('base64');}
function parseHeader(value){
 if(typeof value!=='string'||value.length>1600||!value.startsWith('MIKAYA-READ '))fail('owner_signature_required');
 const encoded=value.slice(12),raw=Buffer.from(encoded,'base64');
 if(raw.toString('base64')!==encoded)fail('invalid_authorization');
 return JSON.parse(raw.toString('utf8'));
}
function verifyRead({request,publicKey,expectedFingerprint,bootNonce,nonces,nowMs}){
 if(!exact(request,['schema','ownerFingerprint','method','route','bootNonce','nonce','issuedAtMs','signature'])||
    request.schema!=='mikaya.mobile-edge.read-request.v1'||request.ownerFingerprint!==expectedFingerprint||
    request.method!=='GET'||request.route!==ROUTE||request.bootNonce!==bootNonce||!NONCE.test(request.nonce)||
    !Number.isSafeInteger(request.issuedAtMs)||Math.abs(nowMs-request.issuedAtMs)>WINDOW_MS)fail('invalid_owner_read');
 const {signature,...unsigned}=request;
 if(!signatureValid(unsigned,signature,publicKey,'REQ'))fail('invalid_owner_signature');
 for(const [nonce,expires] of nonces)if(nowMs>expires)nonces.delete(nonce);
 if(nonces.has(request.nonce))fail('read_replay');
 if(nonces.size>=MAX_NONCES)fail('read_nonce_capacity');
 nonces.set(request.nonce,request.issuedAtMs+WINDOW_MS);
 return request;
}
function verifyReply({reply,request,publicKey,expectedFingerprint,nowMs=Date.now()}){
 if(!exact(reply,['auth','body'])||!exact(reply.auth,['schema','ownerFingerprint','bootNonce','inReplyTo','bodySha256','issuedAtMs','signature']))fail('invalid_evidence_reply');
 const a=reply.auth;
 if(fed.fp(publicKey)!==expectedFingerprint||request.ownerFingerprint!==expectedFingerprint||
    a.schema!=='mikaya.mobile-edge.read-response.v1'||a.ownerFingerprint!==expectedFingerprint||
    a.bootNonce!==request.bootNonce||a.inReplyTo!==request.nonce||a.bodySha256!==fed.sha(fed.canonical(reply.body))||
    !Number.isSafeInteger(a.issuedAtMs)||Math.abs(nowMs-a.issuedAtMs)>WINDOW_MS)fail('evidence_reply_mismatch');
 const {signature,...unsigned}=a;
 if(!signatureValid(unsigned,signature,publicKey,'RES'))fail('invalid_evidence_signature');
 const b=reply.body;
 if(!exact(b,['schema','status','ownerFingerprint','source','sourceLatestAtMs','verifiedAtMs','maxAgeMs',
    'recognizedEventCount','newEvents','projectionSha256','measurementClass','hardwareAttested','actAdmission',
    'computeAuthorized','fileTransferAuthorized','paymentAuthorized','deviceControlAuthorized'])||
    b.schema!=='mikaya.mobile-edge.evidence.v1'||b.status!=='VERIFIED_LOCAL_EVIDENCE'||b.ownerFingerprint!==expectedFingerprint||
    b.source!=='existing_signed_sovereign_ledger'||b.maxAgeMs!==60000||!Number.isSafeInteger(b.sourceLatestAtMs)||b.sourceLatestAtMs<0||
    b.sourceLatestAtMs>nowMs+30000||nowMs-b.sourceLatestAtMs>60000||!Number.isSafeInteger(b.verifiedAtMs)||
    Math.abs(nowMs-b.verifiedAtMs)>WINDOW_MS||b.verifiedAtMs>a.issuedAtMs||
    !Number.isSafeInteger(b.recognizedEventCount)||b.recognizedEventCount<1||b.recognizedEventCount>4095||
    !Number.isSafeInteger(b.newEvents)||b.newEvents<0||b.newEvents>b.recognizedEventCount||!SHA.test(b.projectionSha256)||
    b.measurementClass!=='SIGNED_LOCAL_OBSERVATION_DIGESTS'||b.hardwareAttested!==false||b.actAdmission!=='HOLD'||
    b.computeAuthorized!==false||b.fileTransferAuthorized!==false||b.paymentAuthorized!==false||b.deviceControlAuthorized!==false)
  fail('evidence_semantics_or_freshness_hold');
 return reply.body;
}
function validateCollector(c,expectedFingerprint){
 if(!exact(c,['schema','ledger_dir','public_key_path','expected_fingerprint','state_dir','max_age_ms'])||
    c.schema!=='mikaya.verified-ledger-config.v1'||c.expected_fingerprint!==expectedFingerprint||c.max_age_ms!==60000)
  fail('existing_fresh_owner_collector_required');
 // The existing collector owns canonical path, source pin, snapshot, rollback
 // and freshness validation. Never bootstrap or reset its checkpoint here.
 return c;
}
function localEvidence(dir,expectedFingerprint,c){
 currentOwner(dir,expectedFingerprint);
 const receipt=collector.collect(validateCollector(c,expectedFingerprint));
 currentOwner(dir,expectedFingerprint);
 if(Date.now()-receipt.source_latest_at_ms>60000||receipt.source_latest_at_ms>Date.now()+30000)fail('source_freshness_hold');
 return {schema:'mikaya.mobile-edge.evidence.v1',status:'VERIFIED_LOCAL_EVIDENCE',ownerFingerprint:expectedFingerprint,
  source:'existing_signed_sovereign_ledger',sourceLatestAtMs:receipt.source_latest_at_ms,verifiedAtMs:Date.now(),maxAgeMs:60000,
  recognizedEventCount:receipt.recognized_event_count,newEvents:receipt.new_events,projectionSha256:receipt.projection_sha256,
  measurementClass:'SIGNED_LOCAL_OBSERVATION_DIGESTS',hardwareAttested:false,actAdmission:'HOLD',
  computeAuthorized:false,fileTransferAuthorized:false,paymentAuthorized:false,deviceControlAuthorized:false};
}
function startLocalGateway({dir,expectedFingerprint,collectorConfig,port=PORT,host='127.0.0.1',allowWork=createMtgPolicy()}){
 if(host!=='127.0.0.1'||!Number.isInteger(port)||port<0||port>65535)fail('explicit_loopback_only');
 if(typeof allowWork!=='function')fail('native_thermal_policy_required');
 currentOwner(dir,expectedFingerprint);validateCollector(collectorConfig,expectedFingerprint);
 // Copy the caller's configuration so it cannot redirect an active read seam.
 const c=Object.freeze({...collectorConfig}),bootNonce=crypto.randomBytes(32).toString('hex'),nonces=new Map();
 let server;
 const handler=async(req,res)=>{
  const send=(status,value)=>{
   const raw=Buffer.from(fed.canonical(value));
   res.writeHead(status,{'Content-Type':'application/json','Content-Length':raw.length,'Cache-Control':'no-store',
    'X-Content-Type-Options':'nosniff','Connection':'close'});res.end(raw);
  };
  if(req.headers.origin!==undefined||req.headers.host!=='127.0.0.1:'+server.address().port)return send(403,{error:'local_origin_required'});
  try{currentOwner(dir,expectedFingerprint);}catch{return send(503,{error:'owner_policy_hold'});}
  if((await tollbooth.readLimited(req)).length!==0)return send(400,{error:'read_body_refused'});
  if(req.method==='GET'&&req.url==='/healthz')return send(200,{schema:'mikaya.mobile-edge.challenge.v1',bootNonce,actAdmission:'HOLD',ownerReadSignatureRequired:true});
  if(req.method!=='GET'||req.url!==ROUTE)return send(404,{error:'route_refused'});
  let request;
  try{
   const owner=currentOwner(dir,expectedFingerprint);
   request=verifyRead({request:parseHeader(req.headers.authorization),publicKey:owner.publicKey,expectedFingerprint,bootNonce,nonces,nowMs:Date.now()});
  }catch{return send(401,{error:'fresh_owner_signature_required'});}
  try{if(allowWork()!==true)return send(503,{error:'thermal_policy_hold'});}catch{return send(503,{error:'thermal_policy_hold'});}
  try{
   const body=localEvidence(dir,expectedFingerprint,c),owner=currentOwner(dir,expectedFingerprint);
   const auth=sign({schema:'mikaya.mobile-edge.read-response.v1',ownerFingerprint:expectedFingerprint,bootNonce,
    inReplyTo:request.nonce,bodySha256:fed.sha(fed.canonical(body)),issuedAtMs:Date.now()},owner.privateKey,'RES');
   return send(200,{auth,body});
  }catch{return send(503,{error:'verified_source_hold'});}
 };
 // Same lease and process-wide request budget as node/broker. Keep 8192 bytes.
 server=tollbooth.createServer(dir,handler,null,{host,port});
 const listen=server.listen.bind(server);let started=false;
 server.listen=function(requestedPort,requestedHost){
  if(started||arguments.length!==2||requestedHost!=='127.0.0.1'||!Number.isInteger(requestedPort)||requestedPort<0||requestedPort>65535)fail('single_explicit_loopback_listener_required');
  started=true;return listen(requestedPort,requestedHost);
 };
 server.once('close',()=>nonces.clear());
 try{server.listen(port,host);}catch(e){server.close();throw e;}
 return server;
}
function getLocal(port,route,authorization){return new Promise((resolve,reject)=>{
 const request=http.get({hostname:'127.0.0.1',port,path:route,timeout:3000,signal:AbortSignal.timeout(3000),headers:authorization?{Authorization:authorization}:{}},response=>{
  let bytes=0;const parts=[];
  response.on('error',reject);
  response.on('data',chunk=>{bytes+=chunk.length;if(bytes>8192)request.destroy(Error('local_reply_too_large'));else parts.push(chunk);});
  response.on('end',()=>{
   if(response.statusCode!==200)return reject(Error('local_gateway_hold_'+response.statusCode));
   try{resolve(JSON.parse(Buffer.concat(parts).toString('utf8')));}catch{reject(Error('invalid_local_reply'));}
  });
 });request.on('error',reject);request.on('timeout',()=>request.destroy(Error('local_gateway_timeout')));
});}
async function readLocalGateway({dir,expectedFingerprint,port=PORT}){
 if(!Number.isInteger(port)||port<1||port>65535)fail('invalid_local_port');
 const owner=currentOwner(dir,expectedFingerprint),challenge=await getLocal(port,'/healthz');
 if(!exact(challenge,['schema','bootNonce','actAdmission','ownerReadSignatureRequired'])||challenge.schema!=='mikaya.mobile-edge.challenge.v1'||
    challenge.actAdmission!=='HOLD'||challenge.ownerReadSignatureRequired!==true||!SHA.test(challenge.bootNonce))fail('invalid_local_challenge');
 const request=signRead({dir,expectedFingerprint,bootNonce:challenge.bootNonce});
 const reply=await getLocal(port,ROUTE,readHeader(request));
 currentOwner(dir,expectedFingerprint);
 return verifyReply({reply,request,publicKey:owner.publicKey,expectedFingerprint});
}
async function startOwnedRuntime({dir,expectedFingerprint,collectorConfig,nodePort,port=PORT,allowWork=createMtgPolicy()}){
 if(!Number.isInteger(nodePort)||nodePort<1024||nodePort>65535||nodePort===port)fail('distinct_existing_node_port_required');
 currentOwner(dir,expectedFingerprint);validateCollector(collectorConfig,expectedFingerprint);
 // Explicit replacement launcher: both interfaces share the original node,
 // lease and native admission budget. Never start alongside another process.
 tollbooth.configure({allowWork});
 const servers=[];
 const ready=s=>s.listening?Promise.resolve():new Promise((resolve,reject)=>{
  const done=()=>{s.removeListener('error',bad);resolve();};
  const bad=e=>{s.removeListener('listening',done);reject(e);};s.once('listening',done);s.once('error',bad);
 });
 const close=async()=>{await Promise.all(servers.map(s=>s.listening?new Promise(resolve=>s.close(resolve)):Promise.resolve()));};
 try{
  const node=fed.startServer(dir,nodePort,'127.0.0.1');servers.push(node);await ready(node);
  const gateway=startLocalGateway({dir,expectedFingerprint,collectorConfig,port,allowWork});servers.push(gateway);await ready(gateway);
  return {node,gateway,close};
 }catch(e){await close();throw e;}
}
function privateJson(file){
 if(typeof file!=='string'||!path.isAbsolute(file)||path.resolve(file)!==file||fs.realpathSync(file)!==file)fail('canonical_private_config_required');
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 try{
  const st=fs.fstatSync(fd);
  if(!st.isFile()||st.nlink!==1||st.size>8192||(st.mode&0o077)||(process.getuid&&st.uid!==process.getuid()))fail('unsafe_private_config');
  const raw=Buffer.alloc(8193);let size=0,count;
  while(size<raw.length&&(count=fs.readSync(fd,raw,size,raw.length-size,null)))size+=count;
  const end=fs.fstatSync(fd);
  if(size>8192||end.size!==st.size||end.mtimeMs!==st.mtimeMs||end.ctimeMs!==st.ctimeMs)fail('config_changed_or_oversized');
  return JSON.parse(raw.subarray(0,size).toString('utf8'));
 }finally{fs.closeSync(fd);}
}
async function main(args){
 if(args.length!==3||!['serve','serve-with-node','read'].includes(args[0])||args[1]!=='--config')fail('usage: serve|serve-with-node|read --config ABSOLUTE_PRIVATE_JSON');
 const c=privateJson(args[2]);
 const fields=['schema','nodeDir','expectedFingerprint','collectorConfigFile','port'];
 const optional=['nodePort','nativeMtg'].filter(key=>plain(c)&&Object.hasOwn(c,key));
 if(!exact(c,[...fields,...optional])||c.schema!=='mikaya.mobile-edge.local-gateway.v1'||!Number.isInteger(c.port)||c.port<1024||c.port>65535)fail('invalid_local_gateway_config');
 const allowWork=createNativeMtgPolicy(c.nativeMtg);
 if(args[0]==='read'){console.log(fed.canonical(await readLocalGateway({dir:c.nodeDir,expectedFingerprint:c.expectedFingerprint,port:c.port})));return;}
 if(args[0]==='serve-with-node'){
  const runtime=await startOwnedRuntime({dir:c.nodeDir,expectedFingerprint:c.expectedFingerprint,collectorConfig:privateJson(c.collectorConfigFile),port:c.port,nodePort:c.nodePort,allowWork});
  let stopping=false;const stop=()=>{if(!stopping){stopping=true;runtime.close().catch(()=>{process.exitCode=2;});}};
  process.once('SIGTERM',stop);process.once('SIGINT',stop);return;
 }
 const server=startLocalGateway({dir:c.nodeDir,expectedFingerprint:c.expectedFingerprint,collectorConfig:privateJson(c.collectorConfigFile),port:c.port,allowWork});
 let stopping=false;const stop=()=>{if(!stopping){stopping=true;server.close();}};
 process.once('SIGTERM',stop);process.once('SIGINT',stop);
 server.once('close',()=>{process.removeListener('SIGTERM',stop);process.removeListener('SIGINT',stop);});
 server.on('error',()=>{console.error('MIKAYA_MOBILE_EDGE_HOLD');process.exitCode=2;});
 server.once('listening',()=>console.log('MIKAYA_OWNER_LOCAL_EVIDENCE '+server.address().port));
}
if(require.main===module)main(process.argv.slice(2)).catch(()=>{console.error('MIKAYA_MOBILE_EDGE_HOLD');process.exitCode=2;});
module.exports={PORT,ROUTE,WINDOW_MS,MAX_NONCES,startLocalGateway,startOwnedRuntime,readLocalGateway,signRead,readHeader,verifyReply};
