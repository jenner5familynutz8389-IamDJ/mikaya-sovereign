#!/usr/bin/env node
'use strict';
/**
 * MIKAYA independent-node federation transport v1.
 * REAL bounded compute over authenticated request/response; NEVER shell/wallet/OTA.
 * Two owners retain separate keys/policy/journals. Production cross-host traffic
 * requires validated HTTPS; raw HTTP is restricted to localhost.
 * A signed hello authenticates PINNED software identity, NOT OEM hardware attestation.
 */
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const http=require('node:http');
const https=require('node:https');
const {URL}=require('node:url');
const SHA=/^[0-9a-f]{64}$/;
const NONCE=/^[0-9a-f]{32}$/;
const NID=/^[A-Za-z0-9_-]{2,64}$/;
const OWNERS=new Set(['MIKAYA','MOTOROLA','LAB-PEER','ACT-OMEGA']);
const CAPS=['compute.dot.v1','compute.sha256.v1'];
const ROUTES=new Set(['/v1/hello','/v1/task']);
const DOMAIN='MIKAYA-INDEPENDENT-FEDERATION/1\n';
const MAX_INPUT=8192;
const sha=raw=>crypto.createHash('sha256').update(raw).digest('hex');
function fail(message){throw Error(message);}
function plain(x){return x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;}
function exact(o,fields){return plain(o)&&Object.keys(o).sort().join('|')===[...fields].sort().join('|');}
function canonical(x){
 if(x===null||typeof x==='string'||typeof x==='boolean')return JSON.stringify(x);
 if(typeof x==='number'&&Number.isSafeInteger(x))return JSON.stringify(x);
 if(Array.isArray(x))return '['+x.map(canonical).join(',')+']';
 if(plain(x))return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';
 fail('noncanonical data refused');
}
function fp(pem){const key=pem?.type==='public'?pem:crypto.createPublicKey(pem);return sha(key.export({type:'spki',format:'pem'}));}
function safeRead(file){
 const s=fs.lstatSync(file);
 if(!s.isFile()||s.isSymbolicLink()||s.size>100000)fail('unsafe federation file');
 return fs.readFileSync(file);
}
function safeRoot(dir){
 const s=fs.lstatSync(dir);
 if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o077))fail('unsafe federation directory permissions');
 return dir;
}
function writeNew(file,data){fs.writeFileSync(file,data,{encoding:Buffer.isBuffer(data)?undefined:'utf8',flag:'wx',mode:0o600});}
function atomicJson(file,obj){
 const temp=file+'.tmp-'+crypto.randomBytes(8).toString('hex');
 try{writeNew(temp,canonical(obj)+'\n');fs.renameSync(temp,file);}finally{if(fs.existsSync(temp))fs.unlinkSync(temp);}
}
function readJson(file){return JSON.parse(safeRead(file).toString('utf8'));}
function publicMetadata(dir){return readJson(path.join(dir,'node.json'));}
function initNode(dir,owner,nodeId){
 if(!OWNERS.has(owner)||!NID.test(nodeId))fail('invalid federation owner or node');
 fs.mkdirSync(dir,{mode:0o700});
 fs.mkdirSync(path.join(dir,'trust'),{mode:0o700});
 fs.mkdirSync(path.join(dir,'nonces'),{mode:0o700});
 fs.mkdirSync(path.join(dir,'jobs'),{mode:0o700});
 const keys=crypto.generateKeyPairSync('ed25519');
 const privatePem=keys.privateKey.export({type:'pkcs8',format:'pem'});
 const publicPem=keys.publicKey.export({type:'spki',format:'pem'});
 const fingerprint=fp(publicPem);
 writeNew(path.join(dir,'identity-private.pem'),privatePem);
 writeNew(path.join(dir,'identity-public.pem'),publicPem);
 const platform=owner==='MIKAYA'?{os:'android',androidApi:35,arch:'aarch64'}:
  owner==='MOTOROLA'?{os:'android',androidApi:34,arch:'aarch64'}:
  owner==='LAB-PEER'?{os:'lab-simulated',androidApi:null,arch:'aarch64'}:
  {os:'unattested',androidApi:null,arch:'unknown'};
 const meta={schema:'mikaya.federation.node.v1',owner,nodeId,fingerprint,capabilities:CAPS,platform};
 writeNew(path.join(dir,'node.json'),canonical(meta)+'\n');
 writeNew(path.join(dir,'peers.json'),'{}\n');
 writeNew(path.join(dir,'policy.json'),canonical({schema:'mikaya.federation.local-policy.v1',enabled:true,allowedCapabilities:CAPS,maxRequestBytes:MAX_INPUT})+'\n');
 return meta;
}
function loadNode(dir){
 safeRoot(dir);
 const meta=publicMetadata(dir),pub=safeRead(path.join(dir,'identity-public.pem'));
 const privatePath=path.join(dir,'identity-private.pem');const stat=fs.lstatSync(privatePath);
 if(!stat.isFile()||stat.isSymbolicLink()||(stat.mode&0o077))fail('private identity file permissions invalid');
 if(!exact(meta,['schema','owner','nodeId','fingerprint','capabilities','platform'])||meta.schema!=='mikaya.federation.node.v1'||!OWNERS.has(meta.owner)||!NID.test(meta.nodeId)||fp(pub)!==meta.fingerprint)fail('federation identity mismatch');
 const priv=safeRead(privatePath);
 if(fp(crypto.createPublicKey(crypto.createPrivateKey(priv)))!==meta.fingerprint)fail('private and public keys mismatch');
 const peers=readJson(path.join(dir,'peers.json'));
 const policy=readJson(path.join(dir,'policy.json'));
 if(!plain(peers)||Object.keys(peers).length>16||!exact(policy,['schema','enabled','allowedCapabilities','maxRequestBytes'])||policy.schema!=='mikaya.federation.local-policy.v1'||policy.enabled!==true||!Array.isArray(policy.allowedCapabilities)||policy.allowedCapabilities.some(c=>!CAPS.includes(c))||!Number.isSafeInteger(policy.maxRequestBytes)||policy.maxRequestBytes<1||policy.maxRequestBytes>MAX_INPUT)fail('federation policy invalid');
 return {dir,meta,privateKey:priv,publicKey:pub,peers,policy};
}
function pinPeer(dir,publicPath,owner,nodeId,expectedFp){
 if(!OWNERS.has(owner)||!NID.test(nodeId)||!SHA.test(expectedFp))fail('invalid pinned peer identity');
 const n=loadNode(dir);if(n.meta.fingerprint===expectedFp||owner===n.meta.owner)fail('peer must be a separate owner');
 const pub=safeRead(publicPath);const got=fp(pub);
 if(got!==expectedFp)fail('out-of-band peer fingerprint mismatch');
 const peerFile=path.join(dir,'trust',got+'.pem');
 if(fs.existsSync(peerFile)){if(!safeRead(peerFile).equals(pub))fail('pinned public key conflict');}
 else writeNew(peerFile,pub);
 if(n.peers[got]&&(n.peers[got].owner!==owner||n.peers[got].nodeId!==nodeId))fail('peer identity conflict');
 n.peers[got]={owner,nodeId,enabled:true,capabilities:CAPS};
 atomicJson(path.join(dir,'peers.json'),n.peers);
 return {fingerprint:got,owner,nodeId};
}
function revokePeer(dir,peerFingerprint){
 const n=loadNode(dir);
 if(!SHA.test(peerFingerprint)||!n.peers[peerFingerprint])fail('unknown peer for revocation');
 n.peers[peerFingerprint].enabled=false;
 atomicJson(path.join(dir,'peers.json'),n.peers);
 return {fingerprint:peerFingerprint,enabled:false};
}
function signRequest({dir,to,method,route,body,nonce=crypto.randomBytes(16).toString('hex'),issuedAtMs=Date.now()}){
 const n=loadNode(dir);
 if(!SHA.test(to)||!NONCE.test(nonce)||!ROUTES.has(route)||method!=='POST'||!Number.isSafeInteger(issuedAtMs))fail('invalid outbound request');
 if(!n.peers[to]||!n.peers[to].enabled)fail('outbound peer not pinned or revoked');
 const envelope={schema:'mikaya.federation.request.v1',from:n.meta.fingerprint,to,method,route,bodySha256:sha(canonical(body)),nonce,issuedAtMs};
 return {...envelope,signature:crypto.sign(null,Buffer.from(DOMAIN+'REQ\n'+canonical(envelope)),n.privateKey).toString('base64')};
}
function signatureOk(sig,body,key){
 if(typeof sig!=='string'||sig.length>180||!/^[A-Za-z0-9+/]+={0,2}$/.test(sig))return false;
 const b=Buffer.from(sig,'base64');return b.length===64&&b.toString('base64')===sig&&crypto.verify(null,Buffer.from(body),key,b);
}
function nonceOnce(dir,peer,nonce){
 const key=sha('nonce/1/'+peer+'/'+nonce);
 const folder=path.join(dir,'nonces');
 const count=fs.readdirSync(folder).length;
 if(count>=20000)fail('nonce journal capacity reached');
 try{writeNew(path.join(folder,key),String(Date.now())+'\n');return true;}
 catch(e){if(e.code==='EEXIST')fail('request replay refused');throw e;}
}
function verifyRequest({dir,auth,method,route,body,nowMs=Date.now()}){
 const n=loadNode(dir);
 if(!exact(auth,['schema','from','to','method','route','bodySha256','nonce','issuedAtMs','signature'])||auth.schema!=='mikaya.federation.request.v1'||!SHA.test(auth.from)||!SHA.test(auth.to)||auth.to!==n.meta.fingerprint)fail('wrong recipient target or signed request shape');
 if(!NONCE.test(auth.nonce)||!Number.isSafeInteger(auth.issuedAtMs)||Math.abs(nowMs-auth.issuedAtMs)>60000)fail('request expired');
 const peer=n.peers[auth.from];if(!peer)fail('unknown untrusted peer');if(peer.enabled!==true)fail('peer revoked');
 if(method!=='POST'||!ROUTES.has(route)||auth.method!==method||auth.route!==route||auth.bodySha256!==sha(canonical(body)))fail('request path/body mismatch');
 const {signature,...unsigned}=auth;
 const pub=safeRead(path.join(dir,'trust',auth.from+'.pem'));
 if(fp(pub)!==auth.from||!signatureOk(signature,DOMAIN+'REQ\n'+canonical(unsigned),pub))fail('request signature invalid');
 nonceOnce(dir,auth.from,auth.nonce);
 return {fingerprint:auth.from,owner:peer.owner,nodeId:peer.nodeId,capabilities:peer.capabilities};
}
function makeHello(dir){const n=loadNode(dir);return {schema:'mikaya.federation.hello.v1',owner:n.meta.owner,nodeId:n.meta.nodeId,capabilities:n.meta.capabilities,platform:n.meta.platform};}
function validateHello(hello,peer){
 if(!exact(hello,['schema','owner','nodeId','capabilities','platform'])||hello.schema!=='mikaya.federation.hello.v1'||hello.owner!==peer.owner||hello.nodeId!==peer.nodeId||!Array.isArray(hello.capabilities)||hello.capabilities.length>CAPS.length||hello.capabilities.some(c=>!CAPS.includes(c))||!exact(hello.platform,['os','androidApi','arch'])||typeof hello.platform.os!=='string'||hello.platform.os.length>32||typeof hello.platform.arch!=='string'||hello.platform.arch.length>32||!(hello.platform.androidApi===null||(Number.isSafeInteger(hello.platform.androidApi)&&hello.platform.androidApi>0&&hello.platform.androidApi<100)))fail('peer hello capability or owner mismatch');
 return hello;
}
function computeJob(job){
 if(!exact(job,['schema','id','capability','payload'])||job.schema!=='mikaya.federation.job.v1'||!NONCE.test(job.id)||!CAPS.includes(job.capability))fail('job capability or schema refused');
 const p=job.payload;
 if(job.capability==='compute.sha256.v1'){
  if(!exact(p,['challengeHex'])||!SHA.test(p.challengeHex))fail('unbounded hash request');
  return sha(Buffer.from(p.challengeHex,'hex'));
 }
 if(!exact(p,['a','b'])||!Array.isArray(p.a)||!Array.isArray(p.b)||p.a.length<1||p.a.length>16||p.a.length!==p.b.length||
 !p.a.concat(p.b).every(v=>Number.isSafeInteger(v)&&Math.abs(v)<=1000))fail('unbounded dot product');
 return p.a.reduce((sum,v,i)=>sum+v*p.b[i],0);
}
function appendLocalJournal(dir,event){
 if(!verifyLocalJournal(dir))fail('local journal integrity corrupted');
 const journal=path.join(dir,'journal.jsonl');let seq=1,prev='0'.repeat(64);
 if(fs.existsSync(journal)){
  const s=safeRead(journal).toString('utf8').trim();
  if(s){const records=s.split('\n').map(JSON.parse),last=records.at(-1);seq=last.seq+1;prev=last.hash;}
 }
 const unsigned={seq,prev,event};const row={...unsigned,hash:sha(canonical(unsigned))};
 const fd=fs.openSync(journal,fs.constants.O_APPEND|fs.constants.O_CREAT|fs.constants.O_WRONLY,0o600);
 try{fs.writeSync(fd,canonical(row)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
 return row.hash;
}
function verifyLocalJournal(dir){
 const file=path.join(dir,'journal.jsonl');if(!fs.existsSync(file))return true;
 const raw=safeRead(file).toString('utf8');if(!raw.endsWith('\n'))return false;
 let prev='0'.repeat(64),seq=1;
 for(const line of raw.trim().split('\n')){
  const row=JSON.parse(line);
  if(!exact(row,['seq','prev','event','hash'])||row.seq!==seq||row.prev!==prev||row.hash!==sha(canonical({seq,prev,event:row.event})))return false;
  prev=row.hash;seq++;
 }
 return true;
}
function acceptJob(dir,peer,job){
 if(!verifyLocalJournal(dir))fail('local journal integrity corrupted');
 const n=loadNode(dir);
 if(!n.policy.allowedCapabilities.includes(job.capability)||!peer.capabilities.includes(job.capability))fail('local policy denies peer capability');
 const result=computeJob(job);
 const record=path.join(dir,'jobs',sha(peer.fingerprint+':'+job.id)+'.job');
 try{writeNew(record,sha(canonical(job))+'\n');}catch(e){if(e.code==='EEXIST')fail('duplicate job replay refused');throw e;}
 const body={schema:'mikaya.federation.result.v1',jobId:job.id,capability:job.capability,workerFingerprint:n.meta.fingerprint,requestSha256:sha(canonical(job)),result};
 appendLocalJournal(dir,{kind:'job-completed',jobId:job.id,peer:peer.fingerprint,capability:job.capability,requestSha256:body.requestSha256,resultSha256:sha(canonical(result))});
 return body;
}
function signResponse({dir,to,inReplyTo,body,issuedAtMs=Date.now()}){
 const n=loadNode(dir);
 const envelope={schema:'mikaya.federation.response.v1',from:n.meta.fingerprint,to,inReplyTo,bodySha256:sha(canonical(body)),issuedAtMs};
 return {...envelope,signature:crypto.sign(null,Buffer.from(DOMAIN+'RES\n'+canonical(envelope)),n.privateKey).toString('base64')};
}
function verifyResponse({dir,auth,body,to,nonce,nowMs=Date.now()}){
 const n=loadNode(dir);
 if(!exact(auth,['schema','from','to','inReplyTo','bodySha256','issuedAtMs','signature'])||auth.schema!=='mikaya.federation.response.v1'||auth.from!==to||auth.to!==n.meta.fingerprint||auth.inReplyTo!==nonce||auth.bodySha256!==sha(canonical(body))||!Number.isSafeInteger(auth.issuedAtMs)||Math.abs(nowMs-auth.issuedAtMs)>60000)fail('response origin, digest or nonce mismatch');
 if(!n.peers[to]||n.peers[to].enabled!==true)fail('response peer untrusted');
 const {signature,...b}=auth;
 const pub=safeRead(path.join(dir,'trust',to+'.pem'));
 if(fp(pub)!==to||!signatureOk(signature,DOMAIN+'RES\n'+canonical(b),pub))fail('response signature invalid');
 return true;
}
function readLimited(req){return new Promise((resolve,reject)=>{
 let size=0,parts=[],failed=false;
 req.on('data',chunk=>{size+=chunk.length;if(size>MAX_INPUT){failed=true;parts=[];reject(Error('request limit exceeded'));req.destroy();}else if(!failed)parts.push(chunk);});
 req.on('end',()=>{if(!failed)resolve(Buffer.concat(parts));});req.on('error',e=>{if(!failed)reject(e);});
});}
function serverHandler(dir){return async(req,res)=>{
 const send=(status,obj)=>{if(res.headersSent||res.writableEnded)return;const b=Buffer.from(canonical(obj));res.writeHead(status,{'Content-Type':'application/json','Content-Length':b.length,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(b);};
 try{
  if(req.method==='GET'&&req.url==='/v1/health'){
   const n=loadNode(dir);return send(200,{schema:'mikaya.federation.health.v1',status:'ready',owner:n.meta.owner,pairedPeers:Object.values(n.peers).filter(x=>x.enabled).length,executeArbitraryCode:false});
  }
  if(req.method!=='POST'||!ROUTES.has(req.url))return send(404,{error:'route_refused'});
  const raw=await readLimited(req);let request;
  try{request=JSON.parse(raw.toString('utf8'));}catch{return send(400,{error:'invalid_json'});}
  if(!exact(request,['auth','body']))return send(400,{error:'invalid_envelope'});
  let peer;try{peer=verifyRequest({dir,auth:request.auth,method:req.method,route:req.url,body:request.body});}
  catch{return send(401,{error:'signed_peer_authorization_required'});}
  let out;
  try{
   if(req.url==='/v1/hello'){validateHello(request.body,peer);out=makeHello(dir);appendLocalJournal(dir,{kind:'signed-peer-hello',peer:peer.fingerprint,owner:peer.owner,capabilities:request.body.capabilities});}
   else out=acceptJob(dir,peer,request.body);
  }catch{return send(422,{error:'owner_policy_or_capability_denied'});}
  const auth=signResponse({dir,to:peer.fingerprint,inReplyTo:request.auth.nonce,body:out});
  return send(200,{auth,body:out});
 }catch{return send(400,{error:'invalid_or_unbounded_request'});}
};}
function startServer(dir,port,host='127.0.0.1',certPath=null,keyPath=null){
 safeRoot(dir);loadNode(dir);
 if(!Number.isSafeInteger(port)||port<1024||port>65535)fail('invalid listener port');
 const local=host==='127.0.0.1'||host==='::1';
 if(!local&&(!certPath||!keyPath))fail('external bind requires valid TLS server certificate and key');
 let server;
 if(certPath&&keyPath){server=https.createServer({cert:safeRead(certPath),key:safeRead(keyPath),minVersion:'TLSv1.2'},serverHandler(dir));}
 else server=http.createServer(serverHandler(dir));
 server.requestTimeout=8000;server.headersTimeout=7000;server.maxHeadersCount=24;
 server.listen(port,host,()=>console.log('FEDERATION_READY '+canonical({host,port,transport:certPath?'https':'http',owner:publicMetadata(dir).owner})));
 return server;
}
function validateUrl(raw){
 let u;try{u=new URL(raw);}catch{fail('invalid peer URL');}
 if(u.username||u.password||u.search||u.hash||u.pathname!=='/'||!['http:','https:'].includes(u.protocol))fail('peer transport protocol invalid');
 if(u.protocol==='http:'&&!['127.0.0.1','[::1]'].includes(u.hostname))fail('external HTTP refused: authenticated TLS required');
 return u;
}
function rawPost(target,payload){return new Promise((resolve,reject)=>{
  const u=new URL(target);const base=new URL(u.origin+'/');validateUrl(base.href);
  if(!ROUTES.has(u.pathname)||u.search||u.hash)throw Error('rawPost forbidden path');
  const b=Buffer.from(canonical(payload));if(b.length>MAX_INPUT)throw Error('outbound request too large');
  const lib=u.protocol==='https:'?https:http;
  const req=lib.request({hostname:u.hostname.replace(/^\[|\]$/g,''),port:u.port||undefined,path:u.pathname,method:'POST',timeout:7000,rejectUnauthorized:true,headers:{'Content-Type':'application/json','Content-Length':b.length,'Accept':'application/json'}},res=>{
   let parts=[],size=0;
   res.on('data',chunk=>{size+=chunk.length;if(size>MAX_INPUT){req.destroy(Error('response too large'));}else parts.push(chunk);});
   res.on('end',()=>{try{resolve({status:res.statusCode,json:JSON.parse(Buffer.concat(parts).toString('utf8'))});}catch{reject(Error('invalid peer response'));}});
  });req.on('timeout',()=>req.destroy(Error('peer timeout')));req.on('error',reject);req.end(b);
 });}
async function clientCall({dir,url,expectedPeer,route,body}){
 const u=validateUrl(url);if(!ROUTES.has(route)||!SHA.test(expectedPeer))fail('invalid client call');
 const auth=signRequest({dir,to:expectedPeer,method:'POST',route,body});
 const response=await rawPost(u.origin+route,{auth,body});
 if(response.status!==200)fail('peer refused request HTTP '+response.status);
 if(!exact(response.json,['auth','body']))fail('invalid signed response envelope');
 verifyResponse({dir,auth:response.json.auth,body:response.json.body,to:expectedPeer,nonce:auth.nonce});
 const got=response.json.body;
 if(route==='/v1/hello'){
  const peer=loadNode(dir).peers[expectedPeer];validateHello(got,peer);
 }else{
  const expected=computeJob(body);
  if(!exact(got,['schema','jobId','capability','workerFingerprint','requestSha256','result'])||got.schema!=='mikaya.federation.result.v1'||got.jobId!==body.id||got.capability!==body.capability||got.workerFingerprint!==expectedPeer||got.requestSha256!==sha(canonical(body))||got.result!==expected)fail('peer computation receipt inconsistent');
 }
 return {verified:true,route,requestAuth:auth,requestBody:body,body:got,auth:response.json.auth};
}
/** No private keys or node-state directories cross machine boundaries. Mode is a
 * claimed test arrangement, NOT a cryptographically verified device attestation. */
const EVIDENCE_MODES=new Set(['LOCAL_TWO_PROCESSES_ONE_DEVICE','TWO_PHYSICAL_ANDROID_DEVICES_DIRECT_TLS']);
function buildPublicEvidence({publicKeys,exchanges,mode}){
 if(!EVIDENCE_MODES.has(mode)||!plain(publicKeys)||!Array.isArray(exchanges)||exchanges.length!==2||exchanges.some(e=>e?.verified!==true))fail('unsupported evidence mode or unverified exchange');
 const records=exchanges.map(e=>({route:e.route,requestAuth:e.requestAuth,requestBody:e.requestBody,responseAuth:e.auth,body:e.body}));
 const proof={schema:'mikaya.federation.public-evidence.v1',mode,createdAtMs:Date.now(),publicKeys,exchanges:records};
 verifyEvidence(proof);return proof;
}
function buildEvidence({a,b,exchanges,mode}){
 const A=loadNode(a),B=loadNode(b);
 if(A.meta.fingerprint===B.meta.fingerprint)fail('same owner identity refused');
 const publicKeys={[A.meta.fingerprint]:A.publicKey.toString('utf8'),[B.meta.fingerprint]:B.publicKey.toString('utf8')};
 return buildPublicEvidence({publicKeys,exchanges,mode});
}
function verifyEvidence(proof){
 if(!exact(proof,['schema','mode','createdAtMs','publicKeys','exchanges'])||proof.schema!=='mikaya.federation.public-evidence.v1'||!EVIDENCE_MODES.has(proof.mode)||!Number.isSafeInteger(proof.createdAtMs)||!plain(proof.publicKeys)||Object.keys(proof.publicKeys).length!==2||!Array.isArray(proof.exchanges)||proof.exchanges.length!==2)fail('evidence schema invalid');
 const identities=Object.keys(proof.publicKeys);
 for(const id of identities){if(!SHA.test(id)||typeof proof.publicKeys[id]!=='string'||proof.publicKeys[id].length>4096||fp(proof.publicKeys[id])!==id)fail('evidence public key fingerprint mismatch');}
 const reports=[];
 for(const e of proof.exchanges){
  if(!exact(e,['route','requestAuth','requestBody','responseAuth','body'])||e.route!=='/v1/task')fail('evidence route invalid');
  const req=e.requestAuth,reply=e.responseAuth;
  if(!exact(req,['schema','from','to','method','route','bodySha256','nonce','issuedAtMs','signature'])||req.schema!=='mikaya.federation.request.v1'||req.method!=='POST'||req.route!==e.route||!identities.includes(req.from)||!identities.includes(req.to)||req.from===req.to||!NONCE.test(req.nonce)||!Number.isSafeInteger(req.issuedAtMs)||req.bodySha256!==sha(canonical(e.requestBody)))fail('evidence request mismatch');
  const {signature:requestSignature,...unsignedReq}=req;
  if(!signatureOk(requestSignature,DOMAIN+'REQ\n'+canonical(unsignedReq),proof.publicKeys[req.from]))fail('evidence request signature invalid');
  if(!exact(reply,['schema','from','to','inReplyTo','bodySha256','issuedAtMs','signature'])||reply.schema!=='mikaya.federation.response.v1'||reply.from!==req.to||reply.to!==req.from||reply.inReplyTo!==req.nonce||reply.bodySha256!==sha(canonical(e.body))||!Number.isSafeInteger(reply.issuedAtMs)||Math.abs(reply.issuedAtMs-req.issuedAtMs)>60000)fail('evidence response mismatch');
  const {signature:responseSignature,...unsignedRes}=reply;
  if(!signatureOk(responseSignature,DOMAIN+'RES\n'+canonical(unsignedRes),proof.publicKeys[reply.from]))fail('evidence response signature invalid');
  const expected=computeJob(e.requestBody),body=e.body;
  if(!exact(body,['schema','jobId','capability','workerFingerprint','requestSha256','result'])||body.schema!=='mikaya.federation.result.v1'||body.jobId!==e.requestBody.id||body.capability!==e.requestBody.capability||body.workerFingerprint!==reply.from||body.requestSha256!==sha(canonical(e.requestBody))||body.result!==expected)fail('evidence computation result invalid');
  reports.push({verified:true,body});
 }
 const combined=combineResults(reports);
 return {valid:true,mutuallyAuthenticated:true,participants:combined.participants,jobs:reports.length,combinedSha256:combined.combinedSha256,mode:proof.mode};
}
function combineResults(reports){
 if(!Array.isArray(reports)||reports.length!==2||reports.some(x=>x?.verified!==true||x.body?.schema!=='mikaya.federation.result.v1'||!SHA.test(x.body.workerFingerprint)))fail('two independently verified signed job receipts required');
 if(reports[0].body.workerFingerprint===reports[1].body.workerFingerprint)fail('both computations from same node');
 const ordered=reports.map(x=>({worker:x.body.workerFingerprint,resultDigest:sha(canonical(x.body))})).sort((a,b)=>a.worker.localeCompare(b.worker));
 return {schema:'mikaya.federation.joint-evidence.v1',participants:2,combinedSha256:sha('MIKAYA-SYMBIOSIS/1\n'+canonical(ordered)),workers:ordered};
}
async function main(argv=process.argv.slice(2)){
 const [cmd,...args]=argv;let result;
 if(cmd==='init')result=initNode(args[0],args[1],args[2]);
 else if(cmd==='pin')result=pinPeer(args[0],args[1],args[2],args[3],args[4]);
 else if(cmd==='revoke')result=revokePeer(args[0],args[1]);
 else if(cmd==='health'){const n=loadNode(args[0]);result={owner:n.meta.owner,fingerprint:n.meta.fingerprint,enabledPeers:Object.values(n.peers).filter(x=>x.enabled).length,journalVerified:verifyLocalJournal(args[0])};}
 else if(cmd==='verify-evidence')result=verifyEvidence(JSON.parse(safeRead(args[0]).toString('utf8')));
 else if(cmd==='serve'){startServer(args[0],Number(args[1]),args[2]||'127.0.0.1',args[3]||null,args[4]||null);return;}
 else if(cmd==='hello')result=await clientCall({dir:args[0],url:args[1],expectedPeer:args[2],route:'/v1/hello',body:makeHello(args[0])});
 else if(cmd==='compute'){const payload=JSON.parse(args[4]);const job={schema:'mikaya.federation.job.v1',id:crypto.randomBytes(16).toString('hex'),capability:args[3],payload};result=await clientCall({dir:args[0],url:args[1],expectedPeer:args[2],route:'/v1/task',body:job});}
 else fail('usage: init DIR OWNER NODE_ID | pin DIR PUBLIC_PEM OWNER NODE_ID FINGERPRINT | revoke DIR FINGERPRINT | health DIR | serve DIR PORT [BIND [TLS_CERT TLS_KEY]] | hello DIR PEER_URL PEER_FP | compute DIR PEER_URL PEER_FP CAPABILITY PAYLOAD_JSON');
 console.log(canonical(result));
}
if(require.main===module)main().catch(e=>{console.error('MIKAYA_FEDERATION_REFUSED: '+e.message);process.exitCode=2;});
module.exports={canonical,sha,fp,initNode,loadNode,pinPeer,revokePeer,signRequest,verifyRequest,makeHello,computeJob,verifyResponse,verifyLocalJournal,validateUrl,rawPost,clientCall,combineResults,buildEvidence,buildPublicEvidence,verifyEvidence,acceptJob,startServer,main};
