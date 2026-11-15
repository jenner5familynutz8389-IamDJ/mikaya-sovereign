'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const os = require('node:os');
const { URL } = require('node:url');
const net = require('node:net');
const gate = require('../../federation/live/security-tollbooth.cjs');
const { createMtgPolicy } = require('../../federation/live/mtg-policy.cjs');
const MAX_BODY=64*1024, MAX_PAGE=500, MAX_BATCH=200;
const MAX_LEDGER_BYTES=8*1024*1024, MAX_LEDGER_ROWS=10000;

function bindConfig(host,port){
 const octets=host.split('.').map(Number);
 const overlay=net.isIP(host)===4 && octets.length===4 && octets.every(n=>Number.isInteger(n)&&n>=0&&n<=255)
  && octets[0]===100 && octets[1]>=64 && octets[1]<=127;
 if(host!=='127.0.0.1'&&!overlay)throw Error('Bridge bind must be loopback or private overlay');
 if(!Number.isInteger(port)||port<1024||port>65535)throw Error('Invalid bridge port');
}
function privateRoot(dir){
 const s=fs.lstatSync(dir);
 if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o077)||(process.getuid&&s.uid!==process.getuid()))throw Error('Private ledger directory required');
 return fs.realpathSync(dir);
}
function boundedFile(file,maxBytes,{secret=false,missing=false}={}){
 let fd;
 try{fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);}
 catch(e){if(missing&&e.code==='ENOENT')return null;throw e;}
 try{
  const s=fs.fstatSync(fd);
  if(!s.isFile()||s.nlink!==1||s.size>maxBytes||(s.mode&(secret?0o077:0o022))||(process.getuid&&s.uid!==process.getuid()))throw Error('Unsafe or oversized ledger file');
  const raw=Buffer.alloc(s.size);let at=0;
  while(at<raw.length){const n=fs.readSync(fd,raw,at,raw.length-at,null);if(!n)throw Error('Ledger changed while reading');at+=n;}
  const end=fs.fstatSync(fd);
  if(fs.readSync(fd,Buffer.alloc(1),0,1,null)||end.size!==s.size||end.mtimeMs!==s.mtimeMs)throw Error('Ledger changed while reading');
  return {raw,identity:{dev:s.dev,ino:s.ino,size:s.size}};
 }finally{fs.closeSync(fd);}
}
function readLedger(file){
 const data=boundedFile(file,MAX_LEDGER_BYTES,{missing:true});
 if(!data)return {events:[],bytes:0,identity:null};
 const raw=new TextDecoder('utf-8',{fatal:true}).decode(data.raw);
 if(raw&&!raw.endsWith('\n'))throw Error('Truncated ledger; explicit recovery required');
 const lines=raw?raw.slice(0,-1).split('\n'):[];
 if(lines.length>MAX_LEDGER_ROWS)throw Error('Ledger capacity reached');
 const events=[];let seq=0;
 for(const line of lines){
  if(!line||Buffer.byteLength(line)>MAX_BODY+2048)throw Error('Invalid ledger row');
  const e=JSON.parse(line);
  if(!e||typeof e!=='object'||Array.isArray(e)||!Number.isSafeInteger(e.serverSeq)||e.serverSeq!==seq+1||
     !e.payload||typeof e.payload!=='object'||Array.isArray(e.payload))throw Error('Invalid ledger sequence or payload');
  events.push(e);seq=e.serverSeq;
 }
 return {events,bytes:data.raw.length,identity:data.identity};
}
function appendBatch(file,ledger,entries){
 const raw=Buffer.from(entries.map(e=>JSON.stringify(e)+'\n').join(''));
 if(ledger.events.length+entries.length>MAX_LEDGER_ROWS||ledger.bytes+raw.length>MAX_LEDGER_BYTES)throw Error('Ledger capacity reached');
 const flags=fs.constants.O_WRONLY|fs.constants.O_APPEND|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK|
  (ledger.identity?0:(fs.constants.O_CREAT|fs.constants.O_EXCL));
 const fd=fs.openSync(file,flags,0o600);
 try{
  const s=fs.fstatSync(fd),old=ledger.identity;
  if(!s.isFile()||s.nlink!==1||s.size!==ledger.bytes||(old&&(s.dev!==old.dev||s.ino!==old.ino)))throw Error('Ledger changed before append');
  let at=0;
  while(at<raw.length){const n=fs.writeSync(fd,raw,at,raw.length-at);if(!n)throw Error('Incomplete ledger write');at+=n;}
  // Fence duplicate-only retries too: an earlier append may have failed its fsync.
  fs.fsyncSync(fd);
  const parent=fs.openSync(path.dirname(file),fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
  try{fs.fsyncSync(parent);}finally{fs.closeSync(parent);}
 }finally{fs.closeSync(fd);}
}
function createBridge({base=path.join(os.homedir(),'sovereign_exec'),host='127.0.0.1',port=43823}={}){
 bindConfig(host,port);
 const dir=privateRoot(path.join(base,'ledger')),log=path.join(dir,'mesh-events.jsonl');
 const key=boundedFile(path.join(dir,'.mesh_token'),128,{secret:true});
 const token=key.raw.toString('utf8').trim();
 if(!/^[a-f0-9]{64}$/i.test(token))throw Error('Mesh key format invalid; refusing to start');
 const expected=Buffer.from('Bearer '+token);
 function authorized(req){const s=Buffer.from(req.headers.authorization||'');return s.length===expected.length&&crypto.timingSafeEqual(s,expected);}
 return gate.createServer(dir,async(req,res)=>{
  res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');
  const send=(status,value)=>{res.writeHead(status);res.end(JSON.stringify(value));};
  const url=new URL(req.url,'http://127.0.0.1');
  if(req.method==='GET'&&url.pathname==='/health')return send(200,{status:'ok',service:'mesh-bridge-secure-test',recoverySync:true,durableOutbox:true});
  if(!authorized(req))return send(401,{error:'unauthorized'});
  if(req.method==='GET'&&url.pathname==='/sync'){
   let ledger;try{ledger=readLedger(log).events;}catch{return send(503,{error:'ledger_unavailable'});}
   const currentSeq=ledger.length?ledger.at(-1).serverSeq:0;
   if(url.searchParams.has('after')){
    const after=Math.max(0,Number.parseInt(url.searchParams.get('after'),10)||0),limit=Math.max(1,Math.min(MAX_PAGE,Number.parseInt(url.searchParams.get('limit')||'200',10)||200));
    const events=ledger.filter(e=>e.serverSeq>after).slice(0,limit),last=events.length?events.at(-1).serverSeq:after;
    return send(200,{currentSeq,after,events,nextAfter:last,hasMore:ledger.some(e=>e.serverSeq>last)});
   }
   return send(200,{currentSeq,history:ledger.slice(-50)});
  }
  if(req.method!=='POST'||url.pathname!=='/events')return send(404,{error:'not_found'});
  let parsed;try{parsed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await gate.readLimited(req)));}catch{return send(400,{error:'invalid_json'});}
  const batch=Array.isArray(parsed)?parsed:[parsed];
  if(!batch.length||batch.length>MAX_BATCH||batch.some(p=>!p||typeof p!=='object'||Array.isArray(p)))return send(400,{error:'invalid_event_batch',maxBatch:MAX_BATCH});
  try{
   const ledger=readLedger(log),events=ledger.events;
   let seq=events.length?events.at(-1).serverSeq:0;
   const byId=new Map();for(const e of events){const id=e.payload.eventId;if(id)byId.set(id,e.serverSeq);}
   let accepted=0,duplicates=0,lastSeq=seq;const entries=[];
   for(const payload of batch){
    const id=typeof payload.eventId==='string'?payload.eventId:null;
    if(id&&byId.has(id)){duplicates++;lastSeq=byId.get(id);continue;}
    const entry={serverSeq:++seq,timestamp:new Date().toISOString(),remoteAddress:req.socket.remoteAddress,payload};
    entries.push(entry);if(id)byId.set(id,entry.serverSeq);accepted++;lastSeq=entry.serverSeq;
   }
   appendBatch(log,ledger,entries);
   return send(200,{status:'ACK',serverSeq:lastSeq,accepted,duplicates,batchSize:batch.length});
  }catch{return send(503,{error:'ledger_write_failed'});}
 },null,{host,port},{maxBodyBytes:MAX_BODY});
}
function startFromEnvironment(){
 const host=process.env.MESH_BRIDGE_BIND||'127.0.0.1',port=Number(process.env.MESH_BRIDGE_PORT||43823);
 os.setPriority(0,Math.max(15,os.getPriority(0)));
 gate.configure({allowWork:createMtgPolicy()});
 const server=createBridge({base:path.join(os.homedir(),'sovereign_exec'),host,port});
 server.listen(port,host,()=>console.log('Authenticated recovery/outbox bridge listening on http://'+host+':'+port));
 let stopping=false;
 const stop=()=>{if(!stopping){stopping=true;server.close();server.closeIdleConnections();}};
 process.once('SIGINT',stop);process.once('SIGTERM',stop);
 server.on('error',err=>{console.error('Bridge error:',err.message);process.exitCode=1;});
 return server;
}
if(require.main===module){try{startFromEnvironment();}catch(err){console.error('MESH_BRIDGE_HOLD: '+err.message);process.exitCode=1;}}
module.exports={createBridge,validateBindConfig:bindConfig,MAX_BODY,MAX_BATCH,MAX_PAGE,MAX_LEDGER_BYTES,MAX_LEDGER_ROWS};
