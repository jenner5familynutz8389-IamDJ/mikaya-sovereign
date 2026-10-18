'use strict';
/* AHAVA peer reconciliation: signed encrypted content only, idempotent retry. */
const fs=require('fs'),path=require('path'),http=require('http');
const core=require('./core');
const ROOT=core.DIR,STATE=path.join(ROOT,'sync-state.json');
const token=fs.readFileSync(path.join(process.env.HOME,'sovereign_exec','ledger','.mesh_token'),'utf8').trim();
if(!/^[a-f0-9]{64}$/i.test(token))throw Error('Missing mesh key');
const target=process.env.AHAVA_PEER_URL;
if(!target)throw Error('AHAVA_PEER_URL required for synchronization');
const peer=new URL(target),host=peer.hostname;
const a=host.split('.').map(Number);
const tailnet=a.length===4&&a[0]===100&&a[1]>=64&&a[1]<=127;
if(peer.protocol!=='http:'||!(tailnet||host==='127.0.0.1'||host==='localhost'))throw Error('Peer must be on private tailnet or loopback');
const MAX_RESPONSE=250000;
const save=x=>{const tmp=STATE+'.tmp';fs.writeFileSync(tmp,JSON.stringify(x)+'\n',{mode:0o600});fs.renameSync(tmp,STATE);};
function request(method,endpoint,data){
 return new Promise((resolve,reject)=>{
  const payload=data===undefined?null:JSON.stringify(data);
  const req=http.request({hostname:peer.hostname,port:Number(peer.port||43824),
   path:(peer.pathname.replace(/\/$/,'')+endpoint),method,timeout:15000,
   headers:{authorization:'Bearer '+token,...(payload?{'content-type':'application/json','content-length':Buffer.byteLength(payload)}:{})}},
   res=>{let size=0,chunks=[];res.on('data',b=>{size+=b.length;if(size>MAX_RESPONSE){req.destroy(Error('response too large'));return;}chunks.push(b);});
    res.on('end',()=>{let o;try{o=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{return reject(Error('invalid response JSON'));}
      if(res.statusCode<200||res.statusCode>=300)return reject(Error('peer '+method+' '+endpoint+' '+res.statusCode+' '+String(o.error||o.reason).slice(0,70)));
      resolve(o);});
   });
  req.on('timeout',()=>req.destroy(Error('peer timeout')));req.on('error',reject);
  if(payload)req.end(payload);else req.end();
 });
}
const readLocal=id=>JSON.parse(fs.readFileSync(path.join(ROOT,'manifests',id+'.json'),'utf8'));
async function push(id){
 const m=readLocal(id);
 for(const ch of m.chunks){
  const file=fs.readFileSync(path.join(ROOT,'chunks',ch.id+'.bin'));
  if(core.sha(file)!==ch.id)throw Error('local chunk corrupted '+ch.id);
  await request('PUT','/ahava/chunk/'+ch.id,{data:file.toString('base64')});
 }
 const ack=await request('PUT','/ahava/manifest/'+id,{id,manifest:m});
 if(!ack.ok||ack.id!==id)throw Error('peer did not verify manifest '+id);
 return id;
}
async function pull(id){
 const data=await request('GET','/ahava/manifest/'+id);
 if(data.id!==id)throw Error('remote manifest id mismatch');
 const m=data.manifest,chunks=[];
 if(!Array.isArray(m?.chunks))throw Error('missing chunk list');
 for(const ch of m.chunks){
  const r=await request('GET','/ahava/chunk/'+ch.id);
  if(r.id!==ch.id)throw Error('remote chunk id mismatch');
  chunks.push({id:r.id,base64:r.data});
 }
 const imported=core.importPack({schema:'ahava.replication.v1',id,manifest:m,chunks});
 if(imported.id!==id)throw Error('import mismatch');
 return id;
}
async function cycle(){
 const remote=await request('GET','/ahava/index');
 if(remote.schema!=='ahava.index.v1'||!Array.isArray(remote.ids))throw Error('unrecognized index');
 const local=new Set(core.list()),other=new Set(remote.ids.filter(x=>/^[a-f0-9]{64}$/.test(x)));
 const toPush=[...local].filter(x=>!other.has(x)).slice(0,12);
 const toPull=[...other].filter(x=>!local.has(x)).slice(0,12);
 const pushed=[],pulled=[];
 for(const id of toPush)pushed.push(await push(id));
 for(const id of toPull)pulled.push(await pull(id));
 const state={ok:true,node:core.NODE,peer:host,lastSuccess:new Date().toISOString(),sent:pushed,received:pulled,localCount:core.list().length,remoteCount:other.size};
 save(state);console.log(JSON.stringify(state));return state;
}
async function once(){
 try{await cycle();return true;}
 catch(e){let previous={};try{previous=JSON.parse(fs.readFileSync(STATE,'utf8'));}catch{}
   const state={...previous,ok:false,node:core.NODE,peer:host,lastError:e.message.slice(0,170),lastAttempt:new Date().toISOString()};
   save(state);console.error('AHAVA_SYNC_RETRY',state.lastError);return false;}
}
if(process.argv.includes('--once'))once().then(ok=>{if(!ok)process.exitCode=2;});
else{async function loop(){await once();setTimeout(loop,60000);}loop();}
