'use strict';
// One process-wide admission budget; no queue, identity exception or crypto bypass.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const http=require('node:http'),https=require('node:https');
const LOCK_NAME='.mikaya-runtime.lock',BODY=Symbol('bounded-body');
const SHARED=Symbol.for('mikaya.runtime.security-tollbooth.v1');
const defaults={globalCapacity:8,perIpCapacity:4,globalRefillPerSecond:4,perIpRefillPerSecond:2,maxIps:64,bodyTimeoutMs:2000,requestTimeoutMs:8000,maxConnections:8};
function settings(options={}){
 const o={...defaults,...options};
 for(const [k,min,max] of [['globalCapacity',1,64],['perIpCapacity',1,64],['globalRefillPerSecond',0.01,100],['perIpRefillPerSecond',0.01,100],['maxIps',1,256],['bodyTimeoutMs',50,5000],['requestTimeoutMs',100,15000],['maxConnections',1,32]]){
  if(!Number.isFinite(o[k])||o[k]<min||o[k]>max||(!k.includes('Refill')&&!Number.isInteger(o[k])))throw Error('invalid admission setting '+k);
 }
 if(o.bodyTimeoutMs>o.requestTimeoutMs)throw Error('body timeout exceeds request timeout');
 if(o.allowWork!==undefined&&typeof o.allowWork!=='function')throw Error('allowWork must be a synchronous policy callback');
 if(o.now!==undefined&&typeof o.now!=='function')throw Error('clock must be a function');
 return o;
}
function createAdmission(options={}){
 const o=settings(options),now=o.now||(()=>performance.now()),ips=new Map();let inFlight=0;
 const bucket=(capacity,t)=>({tokens:capacity,at:t,used:t});const global=bucket(o.globalCapacity,now());
 function refill(b,capacity,rate,t){b.tokens=Math.min(capacity,b.tokens+Math.max(0,t-b.at)*rate/1000);b.at=Math.max(t,b.at);}
 function deny(reason,status=429,retryAfter=1){return {ok:false,reason,status,retryAfter};}
 return {options:o,snapshot:()=>({inFlight,trackedIps:ips.size}),admit(ip){
  const t=now();if(!Number.isFinite(t))return deny('clock_hold',503);
  refill(global,o.globalCapacity,o.globalRefillPerSecond,t);
  if(global.tokens<1)return deny('global_budget',429,Math.max(1,Math.ceil((1-global.tokens)/o.globalRefillPerSecond)));
  let b=ips.get(ip);
  if(!b){
   if(ips.size>=o.maxIps)for(const [key,value] of ips)if(t-value.used>=120000)ips.delete(key);
   if(ips.size>=o.maxIps)return deny('ip_capacity');
   b=bucket(o.perIpCapacity,t);ips.set(ip,b);
  }
  refill(b,o.perIpCapacity,o.perIpRefillPerSecond,t);b.used=t;
  if(b.tokens<1)return deny('peer_budget',429,Math.max(1,Math.ceil((1-b.tokens)/o.perIpRefillPerSecond)));
  global.tokens--;b.tokens--;
  if(inFlight)return deny('busy');
  try{if(o.allowWork&&o.allowWork()!==true)return deny('thermal_policy_hold',503);}catch{return deny('thermal_policy_hold',503);}
  inFlight=1;let released=false;
  return {ok:true,release(){if(!released){released=true;inFlight=0;}}};
 }};
}
const shared=globalThis[SHARED]||(globalThis[SHARED]={leases:new Map(),listeners:new Set(),admission:createAdmission()});
function configure(options={}){
 if(shared.leases.size)throw Error('HOLD: cannot reconfigure active runtime admission');
 shared.admission=createAdmission(options);return shared.admission.options;
}
function acquireLease(dir){
 const canonical=fs.realpathSync(dir),st=fs.statSync(canonical);
 if(!st.isDirectory()||(st.mode&0o077)||(process.getuid&&st.uid!==process.getuid()))throw Error('private state directory ownership/permissions invalid');
 let lease=shared.leases.get(canonical);
 if(!lease){
  const lock=path.join(canonical,LOCK_NAME),token=crypto.randomBytes(24).toString('hex');
  try{fs.mkdirSync(lock,{mode:0o700});}catch(e){if(e.code==='EEXIST')throw Error('HOLD: writer lease exists; active or stale requires explicit manual review');throw e;}
  try{fs.writeFileSync(path.join(lock,'owner.json'),JSON.stringify({schema:'mikaya.runtime.writer-lease.v1',pid:process.pid,token,startedAtMs:Date.now()})+'\n',{flag:'wx',mode:0o600});}
  catch(e){try{fs.rmdirSync(lock);}catch{}throw e;}
  lease={canonical,lock,token,inode:fs.lstatSync(lock).ino,refs:0,active:0};shared.leases.set(canonical,lease);
 }
 if(lease.hold)throw Error('HOLD: writer lease changed; explicit manual review required');
 lease.refs++;let released=false;
 function clean(){
  if(lease.refs||lease.active)return;
  try{
   const s=fs.lstatSync(lease.lock),file=path.join(lease.lock,'owner.json'),f=fs.lstatSync(file);
   if(s.isSymbolicLink()||s.ino!==lease.inode||!f.isFile()||f.isSymbolicLink()||f.size>2048)throw Error('lease changed');
   const owner=JSON.parse(fs.readFileSync(file,'utf8'));
   if(owner.token!==lease.token||owner.pid!==process.pid)throw Error('lease ownership changed');
   fs.unlinkSync(file);fs.rmdirSync(lease.lock);shared.leases.delete(canonical);
  }catch{ // Leave a tampered/foreign/crashed lease in HOLD; never guess by PID.
   lease.hold=true;
  }
 }
 return {canonical,enter(){lease.active++;},leave(){lease.active--;clean();},release(){if(!released){released=true;lease.refs--;clean();}}};
}
function sendFailure(req,res,status,error,retryAfter){
 if(res.headersSent||res.writableEnded||res.destroyed)return;
 const body=JSON.stringify({error});
 res.writeHead(status,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),'Cache-Control':'no-store','Connection':'close',...(retryAfter?{'Retry-After':String(retryAfter)}:{})});
 res.once('finish',()=>req.socket.destroy());res.end(body);
}
function readBody(req,timeoutMs,maxBodyBytes=8192){return new Promise((resolve,reject)=>{
 let size=0,parts=[],done=false;
 const finish=(err,value)=>{if(done)return;done=true;clearTimeout(timer);req.removeListener('data',data);req.removeListener('end',end);req.removeListener('error',error);req.removeListener('aborted',aborted);parts=[];err?reject(err):resolve(value);};
 const error=e=>finish(e),aborted=()=>finish(Object.assign(Error('request aborted'),{status:400}));
 const data=chunk=>{size+=chunk.length;if(size>maxBodyBytes)finish(Object.assign(Error('request_too_large'),{status:413}));else parts.push(chunk);};
 const end=()=>finish(null,Buffer.concat(parts));
 const timer=setTimeout(()=>finish(Object.assign(Error('request_body_timeout'),{status:408})),timeoutMs);
 req.on('data',data);req.once('end',end);req.once('error',error);req.once('aborted',aborted);
});}
function readLimited(req){if(!Buffer.isBuffer(req[BODY]))return Promise.reject(Error('request did not pass runtime admission'));return Promise.resolve(req[BODY]);}
function localAddresses(){const os=require('node:os'),out=new Set(['127.0.0.1','::1','localhost',os.hostname()]);for(const rows of Object.values(os.networkInterfaces()))for(const row of rows||[])out.add(row.address);return out;}
function assertExternalDownstream(raw,extra=[]){
 const u=new URL(raw),host=u.hostname.replace(/^\[|\]$/g,'');
 const endpoints=[...shared.listeners,...extra];
 if(localAddresses().has(host)&&endpoints.some(e=>e.port===Number(u.port||(u.protocol==='https:'?443:80))))throw Error('broker downstream targets same runtime; use separately owned external worker');
}
function createServer(dir,handler,tlsOptions=null,endpoint,limits={}){
 const maxBodyBytes=limits.maxBodyBytes===undefined?8192:limits.maxBodyBytes;
 if(!Number.isInteger(maxBodyBytes)||maxBodyBytes<1||maxBodyBytes>65536)throw Error('invalid per-server body limit');
 const lease=acquireLease(dir),admission=shared.admission,o=admission.options;
 const wrapped=async(req,res)=>{
  const permit=admission.admit(req.socket.remoteAddress||'unknown');
  if(!permit.ok){sendFailure(req,res,permit.status,permit.reason,permit.retryAfter);return;}
  lease.enter();let expired=false;
  const timeout=setTimeout(()=>{expired=true;sendFailure(req,res,408,'request_timeout');},o.requestTimeoutMs);
  try{
   const length=req.headers['content-length'];
   if(length!==undefined&&(!/^\d+$/.test(length)||Number(length)>maxBodyBytes)){sendFailure(req,res,413,'request_too_large');return;}
   req[BODY]=await readBody(req,o.bodyTimeoutMs,maxBodyBytes);
   if(!expired&&!res.destroyed)await handler(req,res);
  }catch(e){sendFailure(req,res,e.status||500,e.status===413?'request_too_large':e.status===408?'request_body_timeout':'bounded_request_refused');}
  finally{clearTimeout(timeout);delete req[BODY];lease.leave();permit.release();}
 };
 let server;
 try{server=tlsOptions?https.createServer({...tlsOptions,maxHeaderSize:4096,handshakeTimeout:2000},wrapped):http.createServer({maxHeaderSize:4096},wrapped);}
 catch(e){lease.release();throw e;}
 server.requestTimeout=o.requestTimeoutMs;server.headersTimeout=Math.min(2000,o.requestTimeoutMs);server.timeout=o.requestTimeoutMs;server.keepAliveTimeout=1000;server.maxHeadersCount=24;server.maxConnections=o.maxConnections;server.maxRequestsPerSocket=4;
 server.on('connection',socket=>socket.setTimeout(o.requestTimeoutMs,()=>socket.destroy()));
 const entry=endpoint||{};shared.listeners.add(entry);
 let closed=false;const release=()=>{if(!closed){closed=true;shared.listeners.delete(entry);lease.release();}};
 server.once('close',release);server.on('error',()=>{if(!server.listening)release();});
 return server;
}
module.exports={LOCK_NAME,createAdmission,configure,acquireLease,createServer,readLimited,assertExternalDownstream,localAddresses};
