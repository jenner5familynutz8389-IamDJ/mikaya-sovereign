'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {spawnSync}=require('node:child_process');
const corePath=path.resolve(__dirname,'../ahava/core.js'),syncPath=path.resolve(__dirname,'../ahava/sync.js');
const TOKEN='cd'.repeat(32),CHUNK=65536;
function loadCore(home,node){
 const oldHome=process.env.HOME,oldNode=process.env.AHAVA_NODE;
 try{process.env.HOME=home;process.env.AHAVA_NODE=node;delete require.cache[corePath];return require(corePath);}
 finally{if(oldHome===undefined)delete process.env.HOME;else process.env.HOME=oldHome;if(oldNode===undefined)delete process.env.AHAVA_NODE;else process.env.AHAVA_NODE=oldNode;}
}
function fixture(t,{bytes=CHUNK*2+37,trusted=true}={}){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ahava-resume-')),source=path.join(dir,'source'),target=path.join(dir,'target');
 t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 for(const home of [source,target]){const ledger=path.join(home,'sovereign_exec','ledger');fs.mkdirSync(ledger,{recursive:true,mode:0o700});fs.writeFileSync(path.join(ledger,'.mesh_token'),TOKEN+'\n',{mode:0o600});}
 const sender=loadCore(source,'synthetic-source'),receiver=loadCore(target,'synthetic-receiver');
 const input=path.join(source,'fixture.bin'),payload=Buffer.alloc(bytes);for(let i=0;i<bytes;i++)payload[i]=i%251;
 fs.writeFileSync(input,payload,{mode:0o600});const stored=sender.store(input),pack=sender.pack(stored.id);
 receiver.init();if(trusted)receiver.trust(sender.identity().publicKey);
 const paths=pack.chunks.map(ch=>path.join(receiver.DIR,'chunks',ch.id+'.bin'));
 return {dir,source,target,sender,receiver,pack,payload,paths,manifestPath:path.join(receiver.DIR,'manifests',pack.id+'.json')};
}
function transport(f,{interruptAfter=Infinity,transform}={}){
 const requests=[],stats={chunkBytes:0,chunkRequests:0};
 const request=async(method,endpoint)=>{
  requests.push({method,endpoint});assert.equal(method,'GET');
  if(endpoint==='/ahava/manifest/'+f.pack.id)return {id:f.pack.id,manifest:structuredClone(f.pack.manifest)};
  const id=endpoint.replace('/ahava/chunk/',''),ch=f.pack.chunks.find(c=>c.id===id);assert.ok(ch,'unexpected endpoint '+endpoint);
  if(stats.chunkRequests>=interruptAfter)throw Error('synthetic interrupted connection');
  stats.chunkRequests++;const data=transform?transform(ch.base64,stats.chunkRequests):ch.base64;
  stats.chunkBytes+=Buffer.from(data,'base64').length;return {id,data};
 };
 return {request,requests,stats};
}
function synchronizer(f,request){return require(syncPath).createSynchronizer({core:f.receiver,target:'http://127.0.0.1:43824',request,log:()=>{}});}
const cache=(f,index)=>fs.writeFileSync(f.paths[index],Buffer.from(f.pack.chunks[index].base64,'base64'),{flag:'wx',mode:0o600});
function signManifest(f,mutate){
 const manifest=structuredClone(f.pack.manifest);mutate(manifest);
 const key=fs.readFileSync(path.join(f.sender.DIR,'identity','node-ed25519-private.pem'));
 const stable=o=>JSON.stringify(o,(k,v)=>v&&!Array.isArray(v)&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
 const {signature,...body}=manifest;manifest.signature=crypto.sign(null,Buffer.from(stable(body)),key).toString('base64');
 f.pack.manifest=manifest;f.pack.id=f.receiver.sha(Buffer.from(stable(manifest)));
 f.manifestPath=path.join(f.receiver.DIR,'manifests',f.pack.id+'.json');
}

test('importing AHAVA synchronization neither reads private credentials nor initializes state or timers',t=>{
 const home=fs.mkdtempSync(path.join(os.tmpdir(),'ahava-import-'));t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const result=spawnSync(process.execPath,['-e','require(process.argv[1]);console.log("IMPORT_ONLY")',syncPath],{env:{...process.env,HOME:home,AHAVA_PEER_URL:''},encoding:'utf8',timeout:2000});
 assert.equal(result.status,0,result.stderr);assert.equal(result.stdout.trim(),'IMPORT_ONLY');assert.deepEqual(fs.readdirSync(home),[]);
});

test('fresh download preserves complete plaintext and encrypted signed wire contract',async t=>{
 const f=fixture(t),remote=transport(f);assert.equal(await synchronizer(f,remote.request).pull(f.pack.id),f.pack.id);
 assert.equal(remote.stats.chunkRequests,3);assert.equal(remote.stats.chunkBytes,f.payload.length);
 assert.deepEqual(f.receiver.verify(f.pack.id).buffer,f.payload);assert.equal(f.receiver.verify(f.pack.id).manifest.signature,f.pack.manifest.signature);
});

test('interrupted pull retains verified chunks; retry transfers only missing ciphertext',async t=>{
 const f=fixture(t),first=transport(f,{interruptAfter:1});
 await assert.rejects(synchronizer(f,first.request).pull(f.pack.id),/interrupted/);
 assert.equal(first.stats.chunkBytes,CHUNK);assert.equal(fs.existsSync(f.paths[0]),true);assert.equal(fs.existsSync(f.manifestPath),false);
 const retained=fs.statSync(f.paths[0]),retry=transport(f);
 assert.equal(await synchronizer(f,retry.request).pull(f.pack.id),f.pack.id);
 assert.equal(retry.stats.chunkRequests,2);assert.equal(retry.stats.chunkBytes,CHUNK+37);
 assert.equal(f.payload.length-retry.stats.chunkBytes,CHUNK);
 assert.equal(first.stats.chunkBytes+retry.stats.chunkBytes,f.payload.length);
 assert.equal(fs.statSync(f.paths[0]).ino,retained.ino);assert.equal(fs.statSync(f.paths[0]).mtimeMs,retained.mtimeMs);
 assert.deepEqual(f.receiver.verify(f.pack.id).buffer,f.payload);
});

test('fully cached content needs no chunk GET and still verifies the complete object',async t=>{
 const f=fixture(t);f.paths.forEach((_,i)=>cache(f,i));const remote=transport(f);
 await synchronizer(f,remote.request).pull(f.pack.id);
 assert.equal(remote.stats.chunkRequests,0);assert.equal(remote.stats.chunkBytes,0);assert.equal(remote.requests.length,1);
 assert.deepEqual(f.receiver.verify(f.pack.id).buffer,f.payload);
});

test('corrupt cached ciphertext holds before missing downloads and preserves original evidence',async t=>{
 const f=fixture(t);cache(f,1);const invalid=fs.readFileSync(f.paths[1]);invalid[0]^=1;fs.writeFileSync(f.paths[1],invalid);
 const remote=transport(f);await assert.rejects(synchronizer(f,remote.request).pull(f.pack.id),/ciphertext|cache|digest/);
 assert.equal(remote.stats.chunkRequests,0);assert.deepEqual(fs.readFileSync(f.paths[1]),invalid);assert.equal(fs.existsSync(f.manifestPath),false);assert.equal(fs.existsSync(f.paths[0]),false);
});

for(const kind of ['symlink','hardlink','permissions','oversized'])test('unsafe '+kind+' cached ciphertext is not reused or replaced',async t=>{
 const f=fixture(t),original=Buffer.from(f.pack.chunks[0].base64,'base64'),foreign=path.join(f.dir,'foreign.bin');
 fs.writeFileSync(foreign,original,{mode:0o600});
 if(kind==='symlink')fs.symlinkSync(foreign,f.paths[0]);
 else if(kind==='hardlink')fs.linkSync(foreign,f.paths[0]);
 else{cache(f,0);if(kind==='permissions')fs.chmodSync(f.paths[0],0o644);else fs.truncateSync(f.paths[0],CHUNK+1);}
 const before=fs.readFileSync(f.paths[0]),remote=transport(f);
 await assert.rejects(synchronizer(f,remote.request).pull(f.pack.id),/unsafe|cache|size/);
 assert.equal(remote.stats.chunkRequests,0);assert.deepEqual(fs.readFileSync(f.paths[0]),before);assert.deepEqual(fs.readFileSync(foreign),original);
});

test('untrusted or tampered manifest refuses before any chunk read or transfer',async t=>{
 const f=fixture(t,{trusted:false}),remote=transport(f);
 await assert.rejects(synchronizer(f,remote.request).pull(f.pack.id),/untrusted/);assert.equal(remote.stats.chunkRequests,0);
 f.receiver.trust(f.sender.identity().publicKey);f.pack.manifest.name='tampered.bin';
 await assert.rejects(synchronizer(f,remote.request).pull(f.pack.id),/manifest.*hash/);assert.equal(remote.stats.chunkRequests,0);
});

test('authenticated manifest with wrong GCM tag rejects cached ciphertext despite matching content hash',async t=>{
 const f=fixture(t);cache(f,0);signManifest(f,m=>{m.chunks[0].tag='00'.repeat(16);});const remote=transport(f);
 await assert.rejects(synchronizer(f,remote.request).pull(f.pack.id),/authenticat|Unsupported state/);
 assert.equal(remote.stats.chunkRequests,0);assert.deepEqual(fs.readFileSync(f.paths[0]),Buffer.from(f.pack.chunks[0].base64,'base64'));
});

test('corrupt downloaded ciphertext is refused and never cached',async t=>{
 const f=fixture(t),remote=transport(f,{transform:b64=>{const b=Buffer.from(b64,'base64');b[0]^=1;return b.toString('base64');}});
 await assert.rejects(synchronizer(f,remote.request).pull(f.pack.id),/ciphertext|digest/);
 assert.equal(fs.existsSync(f.paths[0]),false);assert.equal(fs.existsSync(f.manifestPath),false);
});

test('revocation during a pull blocks completed object acceptance',async t=>{
 const f=fixture(t),remote=transport(f);let calls=0;
 const request=async(...args)=>{const result=await remote.request(...args);if(args[1].startsWith('/ahava/chunk/')&&++calls===3)fs.unlinkSync(path.join(f.receiver.DIR,'trusted',f.pack.manifest.signer+'.pem'));return result;};
 await assert.rejects(synchronizer(f,request).pull(f.pack.id),/untrusted/);assert.equal(fs.existsSync(f.manifestPath),false);
});

test('fresh push retains existing PUT routes and final acknowledgement contract',async t=>{
 const f=fixture(t),requests=[];
 const sync=require(syncPath).createSynchronizer({core:f.sender,target:'http://127.0.0.1:43824',log:()=>{},request:async(method,endpoint,data)=>{requests.push({method,endpoint,data});return {ok:true,id: endpoint.slice(endpoint.lastIndexOf('/')+1)};}});
 assert.equal(await sync.push(f.pack.id),f.pack.id);assert.equal(requests.length,4);
 assert.ok(requests.every(r=>r.method==='PUT'));assert.equal(requests.at(-1).endpoint,'/ahava/manifest/'+f.pack.id);
 assert.equal(requests.at(-1).data.manifest.signature,f.pack.manifest.signature);
});

test('changed cached bytes during download cannot become an accepted object',async t=>{
 const f=fixture(t);cache(f,0);const remote=transport(f);
 const request=async(...args)=>{const result=await remote.request(...args);if(args[1].startsWith('/ahava/chunk/')){const damaged=fs.readFileSync(f.paths[0]);damaged[0]^=1;fs.writeFileSync(f.paths[0],damaged);}return result;};
 // Change on one response only; the original cache buffer remains in memory.
 let changed=false;const once=async(...args)=>{if(!changed&&args[1].startsWith('/ahava/chunk/')){changed=true;return request(...args);}return remote.request(...args);};
 await assert.rejects(synchronizer(f,once).pull(f.pack.id),/ciphertext.*digest/);assert.equal(fs.existsSync(f.manifestPath),false);
});

test('complete object digest is independently checked after all individual chunks pass',async t=>{
 const f=fixture(t);signManifest(f,m=>{m.plainSha256='00'.repeat(32);});const remote=transport(f);
 await assert.rejects(synchronizer(f,remote.request).pull(f.pack.id),/object hash mismatch/);assert.equal(fs.existsSync(f.manifestPath),false);
 assert.equal(remote.stats.chunkBytes,f.payload.length);assert.equal(f.paths.every(p=>fs.existsSync(p)),true);
});

test('empty signed objects preserve original behavior without chunk traffic',async t=>{
 const f=fixture(t,{bytes:0}),remote=transport(f);await synchronizer(f,remote.request).pull(f.pack.id);
 assert.equal(remote.stats.chunkRequests,0);assert.equal(f.receiver.verify(f.pack.id).buffer.length,0);
});

test('private route validation rejects public URLs and lookalike hostnames before transport',t=>{
 const f=fixture(t);let called=false;
 for(const target of ['http://100.64.attacker.test','http://example.com','http://127.0.0.1/?secret=x','http://user:secret@127.0.0.1/'])
  assert.throws(()=>require(syncPath).createSynchronizer({core:f.receiver,target,request:()=>{called=true;}}),/private tailnet or loopback/);
 assert.equal(called,false);
});

test('ordinary reconciliation still records the original successful state contract',async t=>{
 const f=fixture(t),remote=transport(f),logs=[];
 const request=(method,endpoint)=>endpoint==='/ahava/index'?{schema:'ahava.index.v1',ids:[f.pack.id]}:remote.request(method,endpoint);
 const sync=require(syncPath).createSynchronizer({core:f.receiver,target:'http://127.0.0.1:43824',request,log:s=>logs.push(s)});
 const result=await sync.cycle(),saved=JSON.parse(fs.readFileSync(path.join(f.receiver.DIR,'sync-state.json'),'utf8'));
 assert.equal(result.ok,true);assert.deepEqual(saved,result);assert.deepEqual(result.received,[f.pack.id]);assert.deepEqual(result.sent,[]);
 assert.equal(result.localCount,1);assert.equal(result.remoteCount,1);assert.equal(logs.length,1);
});
