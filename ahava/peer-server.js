'use strict';
/* AHAVA signed encrypted chunk transport. Requires a private overlay network. */
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const core=require('./core');
const HOME=process.env.HOME,LEDGER=path.join(HOME,'sovereign_exec','ledger');
const SECRET=fs.readFileSync(path.join(LEDGER,'.mesh_token'),'utf8').trim();
if(!/^[0-9a-f]{64}$/i.test(SECRET))throw Error('Invalid mesh secret');
const BIND=process.env.AHAVA_BIND||'127.0.0.1',PORT=Number(process.env.AHAVA_PORT||43824);
const MAX_BODY=180000,MAX_CHUNK=65536,ROOT=core.DIR;
const safeId=x=>{if(!/^[0-9a-f]{64}$/.test(x||''))throw Error('invalid content id');return x;};
const output=(res,code,obj)=>{res.writeHead(code,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(obj));};
const same=(a,b)=>{const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&crypto.timingSafeEqual(x,y);};
const auth=req=>same(req.headers.authorization||'','Bearer '+SECRET);
function readBody(req){
 return new Promise((resolve,reject)=>{
  let size=0,parts=[];
  req.on('data',ch=>{size+=ch.length;if(size>MAX_BODY){reject(Error('request too large'));req.destroy();return;}parts.push(ch);});
  req.on('end',()=>{try{resolve(JSON.parse(Buffer.concat(parts).toString('utf8')));}catch(e){reject(e);}});
  req.on('error',reject);
 });
}
function readChunks(man){
 const store=path.join(ROOT,'chunks');return man.chunks.map(c=>({id:c.id,base64:fs.readFileSync(path.join(store,safeId(c.id)+'.bin')).toString('base64')}));
}
async function handler(req,res){
 try{
  const u=new URL(req.url,'http://localhost'),parts=u.pathname.split('/').filter(Boolean);
  if(req.method==='GET'&&u.pathname==='/health')return output(res,200,{status:'ok',service:'ahava-peer',node:core.NODE});
  if(!auth(req))return output(res,401,{error:'unauthorized'});
  if(parts[0]!=='ahava')return output(res,404,{error:'not_found'});
  if(req.method==='GET'&&parts[1]==='index')return output(res,200,{schema:'ahava.index.v1',node:core.NODE,ids:core.list().slice(0,2000)});
  if(parts.length!==3)return output(res,404,{error:'not_found'});
  const id=safeId(parts[2]);
  if(req.method==='GET'&&parts[1]==='manifest'){
   const man=JSON.parse(fs.readFileSync(path.join(ROOT,'manifests',id+'.json'),'utf8'));
   return output(res,200,{schema:'ahava.manifest-transfer.v1',id,manifest:man});
  }
  if(req.method==='GET'&&parts[1]==='chunk'){
   const b=fs.readFileSync(path.join(ROOT,'chunks',id+'.bin'));
   if(b.length>MAX_CHUNK||core.sha(b)!==id)throw Error('local chunk invalid');
   return output(res,200,{id,data:b.toString('base64')});
  }
  if(req.method==='PUT'&&parts[1]==='chunk'){
   const obj=await readBody(req),buf=Buffer.from(obj.data||'','base64');
   if(buf.length>MAX_CHUNK||core.sha(buf)!==id)return output(res,422,{error:'invalid_chunk_digest'});
   const dest=path.join(ROOT,'chunks',id+'.bin');
   if(fs.existsSync(dest)){if(core.sha(fs.readFileSync(dest))!==id)throw Error('conflicting chunk');}
   else{const fd=fs.openSync(dest,fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_WRONLY,0o600);try{fs.writeSync(fd,buf);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
   return output(res,200,{ok:true,id});
  }
  if(req.method==='PUT'&&parts[1]==='manifest'){
   const obj=await readBody(req);
   if(obj.id!==id||!obj.manifest||!Array.isArray(obj.manifest.chunks))return output(res,422,{error:'invalid_manifest'});
   const result=core.importPack({schema:'ahava.replication.v1',id,manifest:obj.manifest,chunks:readChunks(obj.manifest)});
   return output(res,200,{ok:true,id:result.id,bytes:result.bytes});
  }
  return output(res,405,{error:'method_not_allowed'});
 }catch(e){return output(res,e.code==='ENOENT'?404:422,{error:'verification_failed',reason:e.message.slice(0,120)});}
}
core.init();
http.createServer((req,res)=>{handler(req,res).catch(e=>output(res,500,{error:'handler_failed',detail:e.message.slice(0,80)}));})
 .listen(PORT,BIND,()=>console.log('AHAVA peer ready '+BIND+':'+PORT+'; node='+core.NODE));
