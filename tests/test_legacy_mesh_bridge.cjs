'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const http=require('node:http'),net=require('node:net'),crypto=require('node:crypto');
const {spawn,spawnSync}=require('node:child_process'),{once}=require('node:events');
const root=path.resolve(__dirname,'..'),bridgePath=path.join(root,'engineering/f110-runtime/boot/mesh_bridge_secure.js');
const gate=require('../engineering/federation/live/security-tollbooth.cjs');
const bridge=require(bridgePath),{createMtgPolicy}=require('../engineering/federation/live/mtg-policy.cjs');
const token='AB'.repeat(32),auth={Authorization:'Bearer '+token};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
function configure(extra={}){gate.configure({globalCapacity:64,perIpCapacity:64,globalRefillPerSecond:100,perIpRefillPerSecond:100,...extra});}
function fixture(){const base=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-mesh-test-')),dir=path.join(base,'ledger');fs.mkdirSync(dir,{mode:0o700});fs.writeFileSync(path.join(dir,'.mesh_token'),token+'\n',{mode:0o600});return {base,dir,log:path.join(dir,'mesh-events.jsonl'),clean(){fs.rmSync(base,{recursive:true,force:true});}};}
async function listen(server){server.listen(0,'127.0.0.1');await once(server,'listening');return server.address().port;}
async function close(server){await new Promise(r=>{server.close(r);server.closeAllConnections();});}
async function request(port,{method='GET',route='/health',body,headers={},chunks}={}){
 const raw=body===undefined?undefined:Buffer.isBuffer(body)?body:Buffer.from(JSON.stringify(body));
 return new Promise((resolve,reject)=>{
  const req=http.request({host:'127.0.0.1',port,path:route,method,agent:false,headers:{...headers,...(raw?{'Content-Length':raw.length}:{})}},res=>{
   const parts=[];res.on('data',b=>parts.push(b));res.on('end',()=>{const text=Buffer.concat(parts).toString();let json;try{json=JSON.parse(text);}catch{}resolve({status:res.statusCode,json,text});});
  });req.once('error',reject);if(chunks){for(const part of chunks)req.write(part);req.end();}else req.end(raw);
 });
}
async function running(t,config={}){const f=fixture();configure(config);const s=bridge.createBridge({base:f.base});const port=await listen(s);t.after(async()=>{await close(s);f.clean();});return {...f,s,port};}
function row(seq,payload={}){return JSON.stringify({serverSeq:seq,timestamp:'2026-11-15T00:00:00.000Z',remoteAddress:'127.0.0.1',payload})+'\n';}

test('public health and authenticated ACK, batches, pagination and dedupe retain wire contract',async t=>{
 const f=await running(t);
 assert.deepEqual((await request(f.port)).json,{status:'ok',service:'mesh-bridge-secure-test',recoverySync:true,durableOutbox:true});
 assert.equal((await request(f.port,{route:'/sync'})).status,401);
 assert.equal((await request(f.port,{method:'POST',route:'/events',headers:auth,body:Buffer.from('{')})).status,400);
 const ack=await request(f.port,{method:'POST',route:'/events',headers:auth,body:[{eventId:'a',value:1},{eventId:'b'},{eventId:'a',value:2}]});
 assert.deepEqual(ack.json,{status:'ACK',serverSeq:1,accepted:2,duplicates:1,batchSize:3});
 const page=await request(f.port,{route:'/sync?after=0&limit=1',headers:auth});
 assert.deepEqual(Object.keys(page.json).sort(),['after','currentSeq','events','hasMore','nextAfter']);
 assert.equal(page.json.currentSeq,2);assert.equal(page.json.nextAfter,1);assert.equal(page.json.hasMore,true);
 assert.deepEqual((await request(f.port,{route:'/sync?after=1&limit=1',headers:auth})).json.events[0].payload,{eventId:'b'});
 assert.equal((await request(f.port,{method:'POST',route:'/events',headers:{Authorization:'Bearer '+'ab'.repeat(32)},body:{}})).status,401);
});

test('bridge accepts exact64KiB raw JSON, fragmented UTF8 and original200 event batch limit',async t=>{
 const f=await running(t),prefix=Buffer.byteLength(JSON.stringify({value:''}));
 const full=Buffer.from(JSON.stringify({value:'x'.repeat(bridge.MAX_BODY-prefix)}));assert.equal(full.length,bridge.MAX_BODY);
 assert.equal((await request(f.port,{method:'POST',route:'/events',headers:auth,body:full})).status,200);
 const unicode=Buffer.from(JSON.stringify({eventId:'utf8',value:'😀漢'}));
 const out=await request(f.port,{method:'POST',route:'/events',headers:auth,chunks:[unicode.subarray(0,27),unicode.subarray(27,28),unicode.subarray(28)]});
 assert.equal(out.status,200);const lines=fs.readFileSync(f.log,'utf8').trim().split('\n').map(JSON.parse);assert.equal(lines.at(-1).payload.value,'😀漢');
 assert.equal((await request(f.port,{method:'POST',route:'/events',headers:auth,body:Array.from({length:200},(_,i)=>({eventId:'n'+i}))})).json.accepted,200);
 assert.equal((await request(f.port,{method:'POST',route:'/events',headers:auth,body:Array.from({length:201},()=>({}))})).status,400);
});

test('shared gate default8192 remains while explicit bridge cap refuses65537 bytes',async t=>{
 const f=await running(t),dir=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-default-gate-'));fs.chmodSync(dir,0o700);
 const s=gate.createServer(dir,async(req,res)=>{await gate.readLimited(req);res.end('{}');});const port=await listen(s);
 t.after(async()=>{await close(s);fs.rmSync(dir,{recursive:true,force:true});});
 assert.equal((await request(port,{method:'POST',body:Buffer.alloc(8193,32)})).status,413);
 assert.equal((await request(f.port,{method:'POST',route:'/events',headers:auth,body:Buffer.alloc(65537,32)})).status,413);
 assert.equal(fs.existsSync(f.log),false);
});

test('body timeout and shared in-flight admission across two servers do not append',async t=>{
 const f=await running(t,{bodyTimeoutMs:150,requestTimeoutMs:1000});
 const other=fixture(),s=bridge.createBridge({base:other.base}),port=await listen(s);t.after(async()=>{await close(s);other.clean();});
 const pending=new Promise((resolve,reject)=>{const req=http.request({host:'127.0.0.1',port:f.port,path:'/events',method:'POST',agent:false,headers:{...auth,'Content-Length':100}},res=>{res.resume();res.once('end',()=>resolve(res.statusCode));});req.on('error',reject);req.write('{');});
 await sleep(25);assert.equal((await request(port)).status,429);assert.equal(await pending,408);assert.equal(fs.existsSync(f.log),false);
 assert.equal((await request(port)).status,200);
});

test('aborted body releases shared request admission without appending',async t=>{
 const f=await running(t,{bodyTimeoutMs:150,requestTimeoutMs:1000});
 const req=http.request({host:'127.0.0.1',port:f.port,path:'/events',method:'POST',headers:{...auth,'Content-Length':100}});req.on('error',()=>{});req.write('{');await sleep(20);req.destroy();await sleep(25);
 assert.equal(fs.existsSync(f.log),false);assert.equal((await request(f.port)).status,200);
});

test('existing MTG callback requires two safe readings, then re-holds without writing',async t=>{
 const files=fixture();const command=path.join(files.base,'nice'),policyFile=path.join(files.base,'policy');fs.writeFileSync(command,'test',{mode:0o700});fs.writeFileSync(policyFile,'test',{mode:0o600});
 let now=0,severity=0;const allowWork=createMtgPolicy({command,policyFile,now:()=>now,execute:()=>({status:0,signal:null,stderr:'',stdout:JSON.stringify({android_thermal_severity:severity,decision_for_optional_jobs:'ALLOW',nice_increase:15,poll_interval_seconds:10,resume_requires:'two consecutive samples with severity 0 or 1',factory_throttling_modified:false,adb_required:false})})});
 const f=await running(t,{allowWork});t.after(()=>files.clean());
 assert.equal((await request(f.port)).status,503);now=10000;assert.equal((await request(f.port)).status,200);
 now=20000;severity=2;assert.equal((await request(f.port,{method:'POST',route:'/events',headers:auth,body:{}})).status,503);assert.equal(fs.existsSync(f.log),false);
 now=30000;severity=0;assert.equal((await request(f.port)).status,503);now=40000;assert.equal((await request(f.port)).status,200);
});

for(const kind of ['malformed','truncated','sequence-gap','oversized','symlink']){
 test('existing '+kind+' ledger fails closed unchanged for sync and append',async t=>{
  const f=await running(t);
  if(kind==='malformed')fs.writeFileSync(f.log,'not-json\n',{mode:0o600});
  if(kind==='truncated')fs.writeFileSync(f.log,row(1).trimEnd(),{mode:0o600});
  if(kind==='sequence-gap')fs.writeFileSync(f.log,row(2),{mode:0o600});
  if(kind==='oversized'){fs.writeFileSync(f.log,'',{mode:0o600});fs.truncateSync(f.log,bridge.MAX_LEDGER_BYTES+1);}
  let foreign;
  if(kind==='symlink'){foreign=path.join(f.base,'foreign');fs.writeFileSync(foreign,'private\n',{mode:0o600});fs.symlinkSync(foreign,f.log);}
  const before=fs.readFileSync(f.log),hash=crypto.createHash('sha256').update(before).digest('hex');
  assert.equal((await request(f.port,{route:'/sync',headers:auth})).status,503);
  assert.equal((await request(f.port,{method:'POST',route:'/events',headers:auth,body:{eventId:'new'}})).status,503);
  assert.equal(crypto.createHash('sha256').update(fs.readFileSync(f.log)).digest('hex'),hash);
  if(foreign)assert.equal(fs.lstatSync(f.log).isSymbolicLink(),true);
 });
}

test('capacity rejection preflights entire batch; duplicate ACK at capacity and500 page cap remain',async t=>{
 const f=await running(t);const rows=Array.from({length:bridge.MAX_LEDGER_ROWS-1},(_,i)=>row(i+1,{eventId:'old'+i})).join('');fs.writeFileSync(f.log,rows,{mode:0o600});
 assert.equal((await request(f.port,{method:'POST',route:'/events',headers:auth,body:[{eventId:'new1'},{eventId:'new2'}]})).status,503);assert.equal(fs.readFileSync(f.log,'utf8'),rows);
 assert.equal((await request(f.port,{method:'POST',route:'/events',headers:auth,body:{eventId:'new1'}})).json.accepted,1);
 assert.deepEqual((await request(f.port,{method:'POST',route:'/events',headers:auth,body:{eventId:'new1'}})).json,{status:'ACK',serverSeq:10000,accepted:0,duplicates:1,batchSize:1});
 assert.equal((await request(f.port,{route:'/sync?after=0&limit=9999',headers:auth})).json.events.length,500);
});

test('writer lease refuses another process and releases on close; dedupe persists over restart',async t=>{
 const f=fixture();configure();let s=bridge.createBridge({base:f.base}),port=await listen(s);
 t.after(async()=>{if(s.listening)await close(s);f.clean();});
 await request(port,{method:'POST',route:'/events',headers:auth,body:{eventId:'persist'}});
 const script='try{require(process.argv[1]).createBridge({base:process.argv[2]});process.exit(0)}catch(e){console.log(e.message);process.exit(2)}';
 const child=spawnSync(process.execPath,['-e',script,bridgePath,f.base],{encoding:'utf8',timeout:2000});assert.equal(child.status,2);assert.match(child.stdout,/writer lease exists/);
 await close(s);assert.equal(fs.existsSync(path.join(f.dir,gate.LOCK_NAME)),false);
 configure();s=bridge.createBridge({base:f.base});port=await listen(s);
 assert.deepEqual((await request(port,{method:'POST',route:'/events',headers:auth,body:{eventId:'persist'}})).json,{status:'ACK',serverSeq:1,accepted:0,duplicates:1,batchSize:1});
});

test('durable batch fsync occurs before ACK',async t=>{
 const f=await running(t);let calls=0;const original=fs.fsyncSync;fs.fsyncSync=(...args)=>{calls++;return original(...args);};
 try{const out=await request(f.port,{method:'POST',route:'/events',headers:auth,body:{eventId:'durable'}});assert.equal(out.status,200);assert.equal(calls,2);}finally{fs.fsyncSync=original;}
});

test('invalid per-server caps refuse before lease acquisition',()=>{
 configure();const f=fixture();try{for(const maxBodyBytes of [0,65537,1.5,NaN])assert.throws(()=>gate.createServer(f.dir,()=>{},null,null,{maxBodyBytes}),/body limit/);assert.equal(fs.existsSync(path.join(f.dir,gate.LOCK_NAME)),false);}finally{f.clean();}
});

test('CLI uses actual priorityfloor15, thermal fail-closed and clean TERM lease release',async t=>{
 const home=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-mesh-cli-')),base=path.join(home,'sovereign_exec'),dir=path.join(base,'ledger');fs.mkdirSync(dir,{recursive:true,mode:0o700});fs.writeFileSync(path.join(dir,'.mesh_token'),token,{mode:0o600});
 const probe=net.createServer();await listen(probe);const port=probe.address().port;await new Promise(r=>probe.close(r));
 const child=spawn(process.execPath,[bridgePath],{env:{...process.env,HOME:home,MESH_BRIDGE_BIND:'127.0.0.1',MESH_BRIDGE_PORT:String(port)},stdio:['ignore','pipe','pipe']});
 let exited=false;child.once('exit',()=>{exited=true;});t.after(()=>{if(!exited)child.kill('SIGKILL');fs.rmSync(home,{recursive:true,force:true});});
 await Promise.race([once(child.stdout,'data'),once(child,'exit').then(()=>{throw Error('CLI exited before listener');}),sleep(2000).then(()=>{throw Error('CLI startup deadline');})]);
 assert.equal(os.getPriority(child.pid),15);assert.equal((await request(port)).status,503);
 const done=once(child,'exit');child.kill('SIGTERM');assert.equal((await done)[0],0);assert.equal(fs.existsSync(path.join(dir,gate.LOCK_NAME)),false);
});

for(const target of ['file','directory']){
 test(target+' fsync failure refuses ACK until duplicate retry durably fences without appending again',async t=>{
  const f=await running(t),original=fs.fsyncSync;
  fs.fsyncSync=(fd)=>{const isDir=fs.fstatSync(fd).isDirectory();if(isDir===(target==='directory'))throw Error('injected fsync failure');return original(fd);};
  try{
   for(let attempt=0;attempt<2;attempt++){
    const out=await request(f.port,{method:'POST',route:'/events',headers:auth,body:{eventId:'retry-fence'}});
    assert.equal(out.status,503);assert.equal(fs.readFileSync(f.log,'utf8').trim().split('\n').length,1);
   }
  }finally{fs.fsyncSync=original;}
  const retry=await request(f.port,{method:'POST',route:'/events',headers:auth,body:{eventId:'retry-fence'}});
  assert.deepEqual(retry.json,{status:'ACK',serverSeq:1,accepted:0,duplicates:1,batchSize:1});
  assert.equal(fs.readFileSync(f.log,'utf8').trim().split('\n').length,1);
 });
}

test('noncanonical numeric and nonoverlay binds refuse before state lease',()=>{
 configure();const f=fixture();
 try{for(const host of ['100.064.0.1',' 100.64.0.1','localhost','0x64400001','192.168.0.1','0.0.0.0']){
  assert.throws(()=>bridge.createBridge({base:f.base,host}),/Bridge bind/);
  assert.equal(fs.existsSync(path.join(f.dir,gate.LOCK_NAME)),false);
 }}finally{f.clean();}
});

const supervisorPath=path.join(root,'engineering/f110-runtime/supervise_mesh_secure.sh');
function supervisorFixture(t,{port,host='127.0.0.1',validToken=true,extraEnv={}}){
 const home=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-supervisor-test-')),base=path.join(home,'sovereign_exec'),dir=path.join(base,'ledger');
 fs.mkdirSync(dir,{recursive:true,mode:0o700});fs.writeFileSync(path.join(dir,'.mesh_token'),validToken?token:'invalid',{mode:0o600});
 const child=spawn('sh',[supervisorPath],{env:{...process.env,HOME:home,MESH_BRIDGE_BIND:host,MESH_BRIDGE_PORT:String(port),...extraEnv},stdio:['ignore','pipe','pipe']});
 const exit=once(child,'exit');let done=false;exit.then(()=>{done=true;});t.after(()=>{if(!done)child.kill('SIGKILL');fs.rmSync(home,{recursive:true,force:true});});
 return {home,base,dir,child,exit,runtimeLog:path.join(dir,'secure-bridge-runtime.log'),ownerLog:path.join(dir,'receiver-supervisor.log')};
}
async function boundedExit(f,ms=3500){
 let timer;try{return await Promise.race([f.exit,new Promise((_,reject)=>{timer=setTimeout(()=>{f.child.kill('SIGKILL');reject(Error('supervisor did not settle within bounded startup'));},ms);})]);}finally{clearTimeout(timer);}
}
async function unusedPort(){const s=net.createServer();await listen(s);const port=s.address().port;await new Promise(r=>s.close(r));return port;}

for(const status of [200,401,404,429,503]){
 test('supervisor HTTP'+status+' observes an existing listener without competing start',async t=>{
  let requests=0;const s=http.createServer((_req,res)=>{requests++;res.writeHead(status);res.end('existing');});
  const port=await listen(s);t.after(()=>close(s));const f=supervisorFixture(t,{port});
  assert.equal((await boundedExit(f))[0],2);assert.equal(requests,1);assert.equal(fs.existsSync(f.runtimeLog),false);
  assert.match(fs.readFileSync(f.ownerLog,'utf8'),/HOLD existing HTTP listener/);
 });
}

test('supervisor timeout on an accepting nonHTTP listener holds without starting',async t=>{
 const sockets=new Set(),s=net.createServer(socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});
 const port=await listen(s);t.after(async()=>{for(const socket of sockets)socket.destroy();await new Promise(r=>s.close(r));});
 const f=supervisorFixture(t,{port});assert.equal((await boundedExit(f))[0],2);assert.equal(fs.existsSync(f.runtimeLog),false);
 assert.match(fs.readFileSync(f.ownerLog,'utf8'),/availability unresolved/);
});

test('supervisor makes one foreground start only after refusal, retaining PID on MTG503',async t=>{
 const port=await unusedPort(),f=supervisorFixture(t,{port});const deadline=Date.now()+3000;
 while(Date.now()<deadline&&(!fs.existsSync(f.runtimeLog)||!fs.readFileSync(f.runtimeLog,'utf8').includes('listening on'))){if(f.child.exitCode!==null)throw Error('owner exited before listener');await sleep(15);}
 assert.ok(fs.readFileSync(f.runtimeLog,'utf8').includes('listening on'));assert.equal(os.getPriority(f.child.pid),15);
 assert.ok(fs.readFileSync(path.join('/proc',String(f.child.pid),'cmdline'),'utf8').includes('mesh_bridge_secure.js'));
 assert.equal((await request(port)).status,503);await sleep(50);assert.equal(f.child.exitCode,null);
 assert.equal(fs.readFileSync(f.ownerLog,'utf8').trim().split('\n').length,1);
 f.child.kill('SIGTERM');assert.equal((await boundedExit(f))[0],0);assert.equal(fs.existsSync(path.join(f.dir,gate.LOCK_NAME)),false);
});

test('supervisor invalid bind holds before probe or start',async t=>{
 const f=supervisorFixture(t,{port:43823,host:'100.064.0.1'});assert.equal((await boundedExit(f))[0],2);
 assert.equal(fs.existsSync(f.runtimeLog),false);assert.match(fs.readFileSync(f.ownerLog,'utf8'),/invalid or unavailable bridge configuration/);
});

test('supervisor failed startup exits after one attempt rather than retrying every2seconds',async t=>{
 const f=supervisorFixture(t,{port:await unusedPort(),validToken:false});assert.equal((await boundedExit(f))[0],1);
 assert.equal(fs.readFileSync(f.ownerLog,'utf8').trim().split('\n').length,1);
 assert.match(fs.readFileSync(f.runtimeLog,'utf8'),/Mesh key format invalid/);
});

test('supervisor ambiguous curl7 requires actual TCP refusal and preserves an existing listener',async t=>{
 let connections=0;const sockets=new Set(),server=net.createServer(socket=>{connections++;sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});
 const port=await listen(server);t.after(async()=>{for(const socket of sockets)socket.destroy();await new Promise(r=>server.close(r));});
 const bin=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-curl-stub-'));fs.writeFileSync(path.join(bin,'curl'),'#!/bin/sh\nprintf 000\nexit 7\n',{mode:0o700});t.after(()=>fs.rmSync(bin,{recursive:true,force:true}));
 const f=supervisorFixture(t,{port,extraEnv:{PATH:bin+path.delimiter+process.env.PATH}});assert.equal((await boundedExit(f))[0],2);
 assert.equal(connections,1);assert.equal(fs.existsSync(f.runtimeLog),false);assert.match(fs.readFileSync(f.ownerLog,'utf8'),/TCP listener absence unproven/);
});
