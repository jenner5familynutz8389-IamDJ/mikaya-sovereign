'use strict';
/* AHAVA peer reconciliation: signed encrypted content only, idempotent retry. */
const fs=require('fs'),path=require('path'),http=require('http'),https=require('https');
const transport=require('./transport-policy');
const defaultCore=require('./core');
const MAX_RESPONSE=250000;
// Import is inert. Credentials, timers and network work begin only when the
// owner explicitly creates/starts a synchronizer (the existing CLI does so).
function createSynchronizer({core=defaultCore,target=process.env.AHAVA_PEER_URL,request:customRequest,log=console.log,logError=console.error}={}){
const ROOT=core.DIR,STATE=path.join(ROOT,'sync-state.json');
if(!target)throw Error('AHAVA_PEER_URL required for synchronization');
const route=transport.clientFor(target,process.env);
const peer=route.peer,host=peer.hostname;
if(customRequest!==undefined&&typeof customRequest!=='function')throw Error('Invalid transport');
let token;
if(!customRequest){token=fs.readFileSync(path.join(path.dirname(ROOT),'ledger','.mesh_token'),'utf8').trim();if(!/^[a-f0-9]{64}$/i.test(token))throw Error('Missing mesh key');}
const save=x=>{const tmp=STATE+'.tmp';fs.writeFileSync(tmp,JSON.stringify(x)+'\n',{mode:0o600});fs.renameSync(tmp,STATE);};
function httpRequest(method,endpoint,data){
 return new Promise((resolve,reject)=>{
  const payload=data===undefined?null:JSON.stringify(data);
  const req=(route.requestModule==='https'?https:http).request({hostname:peer.hostname,port:Number(peer.port||(route.requestModule==='https'?443:43824)),
   ...(route.options||{}),
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
const request=customRequest||httpRequest;
const checkedId=id=>{if(typeof id!=='string'||!/^[a-f0-9]{64}$/.test(id))throw Error('bad content identifier');return id;};
const readLocal=id=>JSON.parse(fs.readFileSync(path.join(ROOT,'manifests',id+'.json'),'utf8'));
async function push(id){
 checkedId(id);
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
 checkedId(id);
 const data=await request('GET','/ahava/manifest/'+id);
 if(data.id!==id)throw Error('remote manifest id mismatch');
 const download=core.prepareDownload(id,data.manifest);
 for(const ch of download.missing){
  const r=await request('GET','/ahava/chunk/'+ch.id);
  if(r.id!==ch.id)throw Error('remote chunk id mismatch');
  download.acceptChunk(ch.index,r.data);
 }
 const imported=download.complete();
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
 save(state);log(JSON.stringify(state));return state;
}
async function once(){
 try{await cycle();return true;}
 catch(e){let previous={};try{previous=JSON.parse(fs.readFileSync(STATE,'utf8'));}catch{}
   const state={...previous,ok:false,node:core.NODE,peer:host,lastError:e.message.slice(0,170),lastAttempt:new Date().toISOString()};
   save(state);logError('AHAVA_SYNC_RETRY',state.lastError);return false;}
}
return {push,pull,cycle,once};
}
function governedSyncMs(state,now=Date.now()){
 if(!state||typeof state.at!=='string'||!Number.isFinite(Date.parse(state.at))||Math.abs(now-Date.parse(state.at))>180000)return 180000;
 const ms=Number(state.syncMs);
 return Number.isFinite(ms)?Math.min(600000,Math.max(60000,ms)):180000;
}
function readGovernedSyncMs(){
 try{return governedSyncMs(JSON.parse(fs.readFileSync(path.join(process.env.HOME,'sovereign_exec','ledger','thermal-governor-state.json'),'utf8')));}
 catch{return 180000;}
}
module.exports={createSynchronizer,governedSyncMs};
if(require.main===module){
 try{const sync=createSynchronizer();
  if(process.argv.includes('--once'))sync.once().then(ok=>{if(!ok)process.exitCode=2;});
  else{async function loop(){await sync.once();setTimeout(loop,readGovernedSyncMs());}loop();}
 }catch(e){console.error('AHAVA_SYNC_HOLD',e.message);process.exitCode=2;}
}
