'use strict';
/* MIKAYA-SOVEREIGN / AHAVA v1: encrypted chunks, signed manifests, pinned peers. */
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const BASE=path.join(process.env.HOME||'.','sovereign_exec');
const DIR=path.join(BASE,'ahava'),STORE=path.join(DIR,'chunks'),MAN=path.join(DIR,'manifests'),TRUST=path.join(DIR,'trusted');
const KEYDIR=path.join(DIR,'identity');
const NODE=process.env.AHAVA_NODE||'unassigned';
const CHUNK_SIZE=65536,MAX_FILE=32*1024*1024,MAX_BUNDLE=40*1024*1024;
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const stable=o=>JSON.stringify(o,(key,v)=>v&&!Array.isArray(v)&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
const mkdir=d=>{fs.mkdirSync(d,{recursive:true,mode:0o700});fs.chmodSync(d,0o700);};
function init(){
 [DIR,STORE,MAN,TRUST,KEYDIR].forEach(mkdir);
 const pr=path.join(KEYDIR,'node-ed25519-private.pem'),pu=path.join(KEYDIR,'node-ed25519-public.pem');
 if(fs.existsSync(pr)!==fs.existsSync(pu))throw Error('identity file mismatch; refuse key regeneration');
 if(!fs.existsSync(pr)){
  const pair=crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(pr,pair.privateKey.export({type:'pkcs8',format:'pem'}),{flag:'wx',mode:0o600});
  fs.writeFileSync(pu,pair.publicKey.export({type:'spki',format:'pem'}),{flag:'wx',mode:0o600});
 }
 fs.chmodSync(pr,0o600);
 return {private:fs.readFileSync(pr),public:fs.readFileSync(pu)};
}
function identity(){
 const k=init(),fingerprint=sha(k.public);return {node:NODE,fingerprint,publicKey:k.public.toString()};
}
function sharedKey(){
 const p=path.join(BASE,'ledger','.mesh_token');
 const secret=fs.readFileSync(p,'utf8').trim();
 if(!/^[0-9a-f]{64}$/i.test(secret))throw Error('shared mesh secret missing or malformed');
 return Buffer.from(crypto.hkdfSync('sha256',Buffer.from(secret,'hex'),Buffer.from('AHAVA-v1-chunk-encryption'),Buffer.from('aes-256-gcm'),32));
}
function safeId(id){if(!/^[a-f0-9]{64}$/.test(String(id)))throw Error('bad content identifier');return id;}
function safeWrite(location,buffer){
 if(fs.existsSync(location)){
  if(sha(fs.readFileSync(location))!==sha(buffer))throw Error('content-address conflict');
  return false;
 }
 const fd=fs.openSync(location,fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_WRONLY,0o600);
 try{fs.writeSync(fd,buffer);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
 return true;
}
function trust(publicKey){
 init();const pub=crypto.createPublicKey(publicKey).export({type:'spki',format:'pem'});
 const id=sha(pub);safeWrite(path.join(TRUST,id+'.pem'),Buffer.from(pub));return{id};
}
function isTrusted(publicKey){
 const pub=crypto.createPublicKey(publicKey).export({type:'spki',format:'pem'});
 const id=sha(pub),p=path.join(TRUST,id+'.pem');
 return fs.existsSync(p)&&fs.readFileSync(p,'utf8')===pub;
}
function seal(data,key){
 const nonce=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key,nonce);
 const ciphertext=Buffer.concat([cipher.update(data),cipher.final()]);
 return {ciphertext,nonce:nonce.toString('hex'),tag:cipher.getAuthTag().toString('hex')};
}
function unseal(ciphertext,key,chunk){
 const decipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(chunk.nonce,'hex'));
 decipher.setAuthTag(Buffer.from(chunk.tag,'hex'));
 return Buffer.concat([decipher.update(ciphertext),decipher.final()]);
}
function store(input){
 init();const stat=fs.statSync(input);
 if(!stat.isFile()||stat.size>MAX_FILE)throw Error('file must be regular and <=32MiB');
 const buf=fs.readFileSync(input),key=sharedKey(),chunks=[];
 for(let i=0;i<buf.length;i+=CHUNK_SIZE){
  const part=buf.subarray(i,i+CHUNK_SIZE),s=seal(part,key),id=sha(s.ciphertext);
  safeWrite(path.join(STORE,id+'.bin'),s.ciphertext);
  chunks.push({id,nonce:s.nonce,tag:s.tag,plainSha256:sha(part),length:part.length});
 }
 const kp=init(),pub=kp.public.toString();
 const body={schema:'ahava.signed-manifest.v1',node:NODE,createdAt:new Date().toISOString(),
  name:path.basename(input),length:buf.length,plainSha256:sha(buf),chunkSize:CHUNK_SIZE,
  chunks,publicKey:pub,signer:sha(kp.public)};
 const signature=crypto.sign(null,Buffer.from(stable(body)),kp.private).toString('base64');
 const signed={...body,signature},raw=Buffer.from(stable(signed)),id=sha(raw);
 safeWrite(path.join(MAN,id+'.json'),raw);
 return {id,node:NODE,chunks:chunks.length,length:buf.length,signatureVerified:verify(id).ok};
}
function verifySigned(manifest,requireTrust=true){
 if(!manifest||manifest.schema!=='ahava.signed-manifest.v1'||!Array.isArray(manifest.chunks))throw Error('invalid signed manifest');
 const {signature,...body}=manifest;
 if(typeof signature!=='string'||sha(Buffer.from(body.publicKey))!==body.signer)throw Error('signer mismatch');
 if(requireTrust&&!isTrusted(body.publicKey))throw Error('untrusted signing key');
 if(!crypto.verify(null,Buffer.from(stable(body)),body.publicKey,Buffer.from(signature,'base64')))throw Error('bad signature');
 if(body.length>MAX_FILE||body.chunks.length>MAX_FILE/CHUNK_SIZE+1||body.length<0)throw Error('oversize signed manifest');
 for(const ch of body.chunks){
  safeId(ch.id);
  if(!/^[a-f0-9]{24}$/.test(ch.nonce)||!/^[a-f0-9]{32}$/.test(ch.tag)||!/^[a-f0-9]{64}$/.test(ch.plainSha256)||ch.length<0||ch.length>CHUNK_SIZE)throw Error('bad chunk');
 }
 return true;
}
function verify(id){
 init();safeId(id);
 const raw=fs.readFileSync(path.join(MAN,id+'.json'));
 if(sha(raw)!==id)throw Error('manifest digest mismatch');
 const man=JSON.parse(raw);
 verifySigned(man,false);
 const key=sharedKey(),parts=[];
 for(const ch of man.chunks){
  const cipher=fs.readFileSync(path.join(STORE,ch.id+'.bin'));
  if(sha(cipher)!==ch.id)throw Error('ciphertext digest mismatch '+ch.id);
  const plain=unseal(cipher,key,ch);
  if(sha(plain)!==ch.plainSha256||plain.length!==ch.length)throw Error('chunk authentication mismatch');
  parts.push(plain);
 }
 const file=Buffer.concat(parts);
 if(file.length!==man.length||sha(file)!==man.plainSha256)throw Error('full-file digest mismatch');
 return {ok:true,manifest:man,buffer:file};
}
function restore(id,dest){
 const v=verify(id);
 const output=path.resolve(dest);
 if(fs.existsSync(output))throw Error('destination exists; will not overwrite');
 safeWrite(output,v.buffer);
 return {ok:true,id,path:output,bytes:v.buffer.length};
}
function pack(id){
 init();const verified=verify(id),manifest=verified.manifest;
 return {schema:'ahava.replication.v1',id,manifest,
  chunks:manifest.chunks.map(ch=>({id:ch.id,base64:fs.readFileSync(path.join(STORE,ch.id+'.bin')).toString('base64')}))};
}
function importPack(pack){
 init();if(pack.schema!=='ahava.replication.v1'||!pack.manifest||!Array.isArray(pack.chunks))throw Error('invalid bundle');
 const id=safeId(pack.id),raw=Buffer.from(stable(pack.manifest));
 if(sha(raw)!==id)throw Error('manifest transport hash mismatch');
 verifySigned(pack.manifest,true);
 if(pack.chunks.length!==pack.manifest.chunks.length)throw Error('missing chunks');
 const chunks=new Map(pack.chunks.map(x=>[x.id,x.base64]));
 const key=sharedKey(),parts=[];
 for(const meta of pack.manifest.chunks){
  const b64=chunks.get(meta.id);
  if(typeof b64!=='string'||b64.length>CHUNK_SIZE*2)throw Error('bundle chunk absent');
  const binary=Buffer.from(b64,'base64');
  if(sha(binary)!==meta.id)throw Error('bad ciphertext digest');
  const plain=unseal(binary,key,meta);
  if(sha(plain)!==meta.plainSha256||plain.length!==meta.length)throw Error('authentication failed');
  parts.push(plain);
 }
 const reconstructed=Buffer.concat(parts);
 if(reconstructed.length!==pack.manifest.length||sha(reconstructed)!==pack.manifest.plainSha256)throw Error('object hash mismatch');
 for(const ch of pack.chunks)safeWrite(path.join(STORE,ch.id+'.bin'),Buffer.from(ch.base64,'base64'));
 safeWrite(path.join(MAN,id+'.json'),raw);
 return {ok:true,id,from:pack.manifest.node,bytes:reconstructed.length};
}
function list(){init();return fs.readdirSync(MAN).filter(n=>/^[a-f0-9]{64}\.json$/.test(n)).map(n=>n.slice(0,-5));}
module.exports={init,identity,trust,store,verify,restore,pack,importPack,list,MAX_BUNDLE,DIR,NODE,sha};
if(require.main===module){
 try{
  const a=process.argv,op=a[2];let result;
  if(op==='identity')result=identity();
  else if(op==='trust')result=trust(fs.readFileSync(a[3],'utf8'));
  else if(op==='put')result=store(a[3]);
  else if(op==='verify'){const v=verify(a[3]);result={ok:v.ok,bytes:v.buffer.length,node:v.manifest.node};}
  else if(op==='restore')result=restore(a[3],a[4]);
  else if(op==='list')result={ids:list()};
  else if(op==='export'){const data=Buffer.from(JSON.stringify(pack(a[3])));if(data.length>MAX_BUNDLE)throw Error('bundle too large');safeWrite(a[4],data);result={ok:true,path:a[4],bytes:data.length};}
  else if(op==='import')result=importPack(JSON.parse(fs.readFileSync(a[3],'utf8')));
  else throw Error('usage: identity|trust PEM|put FILE|verify ID|restore ID DEST|list|export ID DEST|import BUNDLE');
  console.log(JSON.stringify(result));
 }catch(e){console.error('AHAVA_ERROR',e.message);process.exitCode=1;}
}
