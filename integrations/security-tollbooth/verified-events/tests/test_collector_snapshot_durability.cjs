'use strict';
// Synthetic storage-boundary evidence; no phone, timeout reproduction or device keys.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const Module=require('node:module'),{fork}=require('node:child_process');
const COLLECTOR=path.resolve(__dirname,'../ledger_event_collector.cjs');
const BASELINE=path.resolve(__dirname,'fixtures/ledger_event_collector.v1.cjs');
const BASELINE_SHA='a2f59a12691b718efa7c84c593e1c0bc486db3544a0b90666f5c9557ccd7238f';
const DOMAIN='MIKAYA-SOVEREIGN-LOCAL-EVENT-SPINE/1\n';
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const filename=index=>String(index).padStart(6,'0')+'.json';
const snapshotFile=file=>typeof file==='string'&&path.basename(path.dirname(file)).startsWith('.verify-')&&/^\d{6}\.json$/.test(path.basename(file));

// Inject only the filesystem boundary into a fresh module. No shared global patches.
function instrument(file,{beforeWrite,afterWrite}={}){
 const facade=Object.create(fs),open=new Map(),events=[];
 facade.openSync=(name,...args)=>{const fd=fs.openSync(name,...args);open.set(fd,String(name));return fd;};
 facade.closeSync=fd=>{try{return fs.closeSync(fd);}finally{open.delete(fd);}};
 facade.writeFileSync=(target,...args)=>{
  const name=typeof target==='number'?open.get(target):String(target);
  if(beforeWrite)beforeWrite(name);
  const result=fs.writeFileSync(target,...args);
  if(afterWrite)afterWrite(name);
  return result;
 };
 facade.fsyncSync=fd=>{events.push({kind:'fsync',path:open.get(fd),directory:fs.fstatSync(fd).isDirectory()});return fs.fsyncSync(fd);};
 facade.renameSync=(from,to)=>{events.push({kind:'rename',from:String(from),to:String(to)});return fs.renameSync(from,to);};
 // Both unchanged verifier dependency closures live beside the current collector.
 const nativeRequire=Module.createRequire(COLLECTOR),mod=new Module(COLLECTOR);
 mod.filename=COLLECTOR;
 mod.require=name=>name==='node:fs'?facade:nativeRequire(name);
 mod._compile(fs.readFileSync(file,'utf8'),COLLECTOR);
 return {collector:mod.exports,events};
}

function snapshotBytes(dir){return new Map(fs.readdirSync(dir).sort().map(name=>[name,fs.readFileSync(path.join(dir,name))]));}
function assertSourceUnchanged(dir,before){
 assert.deepEqual(fs.readdirSync(dir).sort(),[...before.keys()]);
 for(const [name,bytes] of before)assert.deepEqual(fs.readFileSync(path.join(dir,name)),bytes,'source row changed: '+name);
}
function appendFixtureRow(x,index){
 const prev=JSON.parse(fs.readFileSync(path.join(x.config.ledger_dir,filename(index-1))));
 const unsigned={schema:'mikaya.sovereign.event.v1',index,prevHash:prev.entryHash,nodeFingerprint:x.config.expected_fingerprint,
  kind:'DEVICE_HEALTH_OBSERVED',payloadSha256:sha('synthetic-observation-'+index),issuedAtMs:x.time+index,
  nonce:index.toString(16).padStart(32,'0')};
 const entryHash=sha(DOMAIN+'HASH\n'+x.fed.canonical(unsigned));
 const row={...unsigned,entryHash,signature:crypto.sign(null,Buffer.from(DOMAIN+'SIGN\n'+entryHash),x.fixturePrivateKey).toString('base64')};
 fs.writeFileSync(path.join(x.config.ledger_dir,filename(index)),x.fed.canonical(row)+'\n',{flag:'wx',mode:0o600});
}
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-snapshot-durability-'));fs.chmodSync(root,0o700);
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const collector=require(COLLECTOR),{ledger,fed}=collector.loadVerifier();
 const node=path.join(root,'synthetic-node'),meta=fed.initNode(node,'LAB-PEER','durability-fixture');
 const config={schema:'mikaya.verified-ledger-config.v1',ledger_dir:path.join(root,'source'),
  public_key_path:path.join(node,'identity-public.pem'),expected_fingerprint:meta.fingerprint,
  state_dir:path.join(root,'projection-state'),max_age_ms:60000};
 const time=Date.now()-10000;
 ledger.initializeLedger({nodeDir:node,ledgerDir:config.ledger_dir,nowMs:time});
 const x={root,config,time,fed,ledger,fixturePrivateKey:fed.loadNode(node).privateKey};
 // Build a full signed chain directly to avoid quadratic append-and-verify setup.
 for(let i=1;i<320;i++)appendFixtureRow(x,i);
 collector.collect(config,{initialize:true,nowMs:time+319});
 x.checkpoint=path.join(config.state_dir,'projection.jsonl');
 x.committed=fs.readFileSync(x.checkpoint);
 assert.equal(JSON.parse(x.committed.toString().split('\n')[0]).headIndex,319);
 appendFixtureRow(x,320);
 assert.equal(ledger.verifyLedger({ledgerDir:config.ledger_dir,publicPem:fs.readFileSync(config.public_key_path)}).entries,321);
 x.source=snapshotBytes(config.ledger_dir);
 return x;
}
function assertNoSnapshotFlush(events){
 assert.equal(events.filter(e=>e.kind==='fsync'&&snapshotFile(e.path)).length,0,'disposable snapshot files must not be fsynced');
}
function assertCommittedFlush(events,x){
 const fileIndex=events.findIndex(e=>e.kind==='fsync'&&!e.directory&&path.dirname(e.path)===x.config.state_dir&&path.basename(e.path).startsWith('.projection-'));
 const renameIndex=events.findIndex(e=>e.kind==='rename'&&e.to===x.checkpoint);
 const directoryIndex=events.findIndex(e=>e.kind==='fsync'&&e.directory&&e.path===x.config.state_dir);
 assert.ok(fileIndex>=0,'committed projection contents must be fsynced');
 assert.ok(renameIndex>fileIndex,'checkpoint replacement must follow contents fsync');
 assert.ok(directoryIndex>renameIndex,'state directory must be fsynced after replacement');
}

function pausedChild(configPath,marker){
 const config=JSON.parse(fs.readFileSync(configPath,'utf8'));
 const {collector}=instrument(COLLECTOR,{afterWrite(file){
  if(snapshotFile(file)&&path.basename(file)==='000020.json'){
   fs.writeFileSync(marker,'snapshot-written',{flag:'wx',mode:0o600});
   // The parent owns this fixture child and sends SIGKILL at this exact boundary.
   process.kill(process.pid,'SIGSTOP');
  }
 }});
 collector.collect(config);
 process.exitCode=3; // Reaching commit rather than the injected pause is a test error.
}

if(process.argv[2]==='--snapshot-kill-child'){
 try{pausedChild(process.argv[3],process.argv[4]);}catch{process.exitCode=4;}
}else{
 test('321-row update omits disposable flushes while preserving checkpoint durability',t=>{
  const x=fixture(t),{collector,events}=instrument(COLLECTOR);
  const result=collector.collect(x.config,{nowMs:x.time+320});
  assert.equal(result.recognized_event_count,320);assert.equal(result.new_events,1);
  assertNoSnapshotFlush(events);assertCommittedFlush(events,x);
  assert.notDeepEqual(fs.readFileSync(x.checkpoint),x.committed);
  assert.equal(JSON.parse(fs.readFileSync(x.checkpoint,'utf8').split('\n')[0]).headIndex,320);
  assertSourceUnchanged(x.config.ledger_dir,x.source);
  assert.deepEqual(fs.readdirSync(x.config.state_dir),['projection.jsonl']);
 });

 test('frozen old collector deterministically violates the snapshot-flush contract',t=>{
  assert.equal(sha(fs.readFileSync(BASELINE)),BASELINE_SHA,'historical comparison must use the frozen reviewed collector');
  const x=fixture(t),{collector,events}=instrument(BASELINE);
  collector.collect(x.config,{nowMs:x.time+320});
  const count=events.filter(e=>e.kind==='fsync'&&snapshotFile(e.path)).length;
  assert.equal(count,321);
  assert.throws(()=>assertNoSnapshotFlush(events),{name:'AssertionError'});
  assertCommittedFlush(events,x);
  t.diagnostic('Frozen baseline: 321 disposable-file fsyncs; revised contract requires zero. This is not a timeout reproduction.');
 });

 test('snapshot write exception preserves source and committed checkpoint, cleans its lease, and permits retry',t=>{
  const x=fixture(t);let injected=false;
  const {collector,events}=instrument(COLLECTOR,{beforeWrite(file){
   if(snapshotFile(file)&&path.basename(file)==='000017.json'){
    injected=true;throw Object.assign(Error('synthetic_snapshot_write_failure'),{code:'EIO'});
   }
  }});
  assert.throws(()=>collector.collect(x.config,{nowMs:x.time+320}),/synthetic_snapshot_write_failure/);
  assert.equal(injected,true);assert.deepEqual(fs.readFileSync(x.checkpoint),x.committed);
  assertSourceUnchanged(x.config.ledger_dir,x.source);
  assert.equal(events.some(e=>e.kind==='rename'),false,'failed snapshot must not replace committed state');
  assert.deepEqual(fs.readdirSync(x.config.state_dir),['projection.jsonl']);
  const retry=require(COLLECTOR).collect(x.config,{nowMs:x.time+320});
  assert.equal(retry.new_events,1);assert.equal(retry.recognized_event_count,320);
  assert.deepEqual(fs.readdirSync(x.config.state_dir),['projection.jsonl']);
  assertSourceUnchanged(x.config.ledger_dir,x.source);
 });

 test('SIGKILL during snapshot preserves committed evidence and retains a conservative recovery HOLD',async t=>{
  const x=fixture(t),configPath=path.join(x.root,'child-config.json'),marker=path.join(x.root,'child-boundary');
  fs.writeFileSync(configPath,JSON.stringify(x.config),{flag:'wx',mode:0o600});
  let child,watcher,timer,boundary=false,stderr='';
  try{
   const exited=new Promise((resolve,reject)=>{
    watcher=fs.watch(x.root,()=>{
     if(boundary||!child||!fs.existsSync(marker))return;
     if(fs.readFileSync(marker,'utf8')!=='snapshot-written')return;
     boundary=true;
     child.kill('SIGKILL');
    });
    child=fork(__filename,['--snapshot-kill-child',configPath,marker],{stdio:['ignore','ignore','pipe','ipc']});
    child.stderr.on('data',raw=>{stderr=(stderr+raw.toString()).slice(0,8192);});
    child.once('error',reject);
    child.once('exit',(code,signal)=>resolve({code,signal}));
    timer=setTimeout(()=>{child.kill('SIGKILL');reject(Error('synthetic child did not reach snapshot boundary: '+stderr));},5000);
   });
   const result=await exited;
   assert.equal(boundary,true);assert.equal(result.code,null);assert.equal(result.signal,'SIGKILL');
  }finally{
   clearTimeout(timer);if(watcher)watcher.close();
   if(child&&child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');
  }
  assert.deepEqual(fs.readFileSync(x.checkpoint),x.committed);
  assertSourceUnchanged(x.config.ledger_dir,x.source);
  const lock=path.join(x.config.state_dir,'.collector.lock');
  assert.equal(fs.lstatSync(lock).isDirectory(),true);
  const snapshots=fs.readdirSync(x.config.state_dir).filter(name=>name.startsWith('.verify-'));
  assert.equal(snapshots.length,1);
  assert.equal(fs.existsSync(path.join(x.config.state_dir,snapshots[0],'000020.json')),true);
  assert.throws(()=>require(COLLECTOR).collect(x.config,{nowMs:x.time+320}),/EEXIST/);
  assert.equal(fs.existsSync(lock),true,'unexplained crashed lease must never be silently cleared');
  assert.deepEqual(fs.readFileSync(x.checkpoint),x.committed);
  assertSourceUnchanged(x.config.ledger_dir,x.source);
 });
}
