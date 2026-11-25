'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {spawnSync}=require('node:child_process');
const collector=require('../../../../integrations/security-tollbooth/verified-events/ledger_event_collector.cjs');
const producer=require('../motorola-observation-producer.cjs');
const {produce,LIMITS,PROBES}=producer;
const sha=raw=>crypto.createHash('sha256').update(raw).digest('hex');
const values={'ro.product.model':'moto g power 5G - 2023','ro.board.platform':'mt6855','ro.build.version.release':'14'};

function fixture(t,owner='MOTOROLA'){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-motorola-observation-'));fs.chmodSync(root,0o700);
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const {fed,ledger}=collector.loadVerifier(),node=path.join(root,'existing-node');
 const meta=fed.initNode(node,owner,'existing-motorola-a14');
 fs.writeFileSync(path.join(node,'journal.jsonl'),'historical compute journal fixture\n',{mode:0o600});
 const oldSpine=path.join(root,'historical-event-spine.jsonl');
 fs.writeFileSync(oldSpine,'{"type":"OLD_UNSIGNED_OBSERVATION","value":"retain"}\n',{mode:0o600});
 const config={schema:'mikaya.motorola-observation-config.v1',node_dir:node,ledger_dir:path.join(root,'motorola-signed-events'),
  receipt_dir:path.join(root,'motorola-receipts'),expected_fingerprint:meta.fingerprint};
 const calls=[],now=Date.now();
 const runner=(command,args,options)=>{calls.push({command,args,options});return {status:0,signal:null,
  stdout:Buffer.from(values[args[0]]+'\n'),stderr:Buffer.alloc(0)};};
 return {root,config,fed,ledger,meta,calls,runner,now,oldSpine};
}
function start(x,options={}){return produce(x.config,{initialize:true,nowMs:x.now,runner:x.runner,...options});}
function immutableOwner(x){
 const files=['identity-private.pem','identity-public.pem','node.json','policy.json','peers.json','journal.jsonl'];
 return {...Object.fromEntries(files.map(name=>[name,fs.readFileSync(path.join(x.config.node_dir,name)).toString('base64')])),
  oldSpine:fs.readFileSync(x.oldSpine).toString('base64')};
}
function receipt(x,now=x.now){return {schema:'mikaya.motorola-observation.v1',observedAtMs:now,model:values['ro.product.model'],
 platform:values['ro.board.platform'],androidRelease:values['ro.build.version.release']};}
function noNewState(x){assert.equal(fs.existsSync(x.config.ledger_dir),false);assert.equal(fs.existsSync(x.config.receipt_dir),false);}
function collectorConfig(x){return {schema:'mikaya.verified-ledger-config.v1',ledger_dir:x.config.ledger_dir,
 public_key_path:path.join(x.config.node_dir,'identity-public.pem'),expected_fingerprint:x.meta.fingerprint,
 state_dir:path.join(x.root,'verified-projection'),max_age_ms:60000};}

test('fixed Motorola observations use the existing owner key and unchanged collector without touching historical journals',t=>{
 const x=fixture(t),before=immutableOwner(x),out=start(x);
 assert.equal(out.schema,'mikaya.motorola-observation-production.v1');assert.equal(out.status,'DEVICE_OBSERVATION_SIGNED');
 assert.equal(out.index,1);assert.equal(out.initialized,true);assert.equal(out.already_recorded,false);
 assert.deepEqual(x.calls.map(c=>[c.command,...c.args]),[
  ['/system/bin/getprop','ro.product.model'],['/system/bin/getprop','ro.board.platform'],['/system/bin/getprop','ro.build.version.release']]);
 for(const call of x.calls){assert.equal(call.options.timeout,1000);assert.equal(call.options.maxBuffer,256);
  assert.equal(call.options.shell,false);assert.deepEqual(call.options.env,{PATH:'/system/bin'});}
 const serialized=x.fed.canonical(receipt(x)),digest=sha(serialized);assert.equal(out.payload_sha256,digest);
 const file=path.join(x.config.receipt_dir,digest+'.json');
 assert.equal(fs.readFileSync(file,'utf8'),serialized+'\n');assert.equal(fs.statSync(file).mode&0o777,0o600);
 const row=JSON.parse(fs.readFileSync(path.join(x.config.ledger_dir,'000001.json')));
 assert.equal(row.kind,'DEVICE_HEALTH_OBSERVED');assert.equal(row.payloadSha256,digest);assert.equal(row.nodeFingerprint,x.meta.fingerprint);
 const publicPem=fs.readFileSync(path.join(x.config.node_dir,'identity-public.pem'));
 const verified=x.ledger.verifyLedger({ledgerDir:x.config.ledger_dir,publicPem});
 assert.equal(verified.entries,2);assert.equal(verified.ownerFingerprint,x.meta.fingerprint);assert.equal(verified.ownerPermissionsGranted,false);
 const projected=collector.collect(collectorConfig(x),{initialize:true});
 assert.equal(projected.recognized_event_count,1);assert.equal(projected.hardware_attested,false);assert.equal(projected.payment_authorized,false);
 assert.equal(collector.collect(collectorConfig(x)).unchanged,true);assert.deepEqual(immutableOwner(x),before);
 assert.equal(out.hardware_attested,false);assert.equal(out.payment_authorized,false);
 assert.doesNotMatch(JSON.stringify(out),/PRIVATE KEY|PUBLIC KEY|privateKey|identity-private|node_dir|receipt_dir/);
});

test('normal mode never initializes and first bootstrap refuses any existing source or receipt entry',t=>{
 const x=fixture(t);assert.throws(()=>produce(x.config,{runner:x.runner}),/initialization_required/);noNewState(x);
 start(x);x.calls.length=0;assert.throws(()=>start(x),/initialization_refuses_existing_ledger/);assert.equal(x.calls.length,0);
 for(const kind of ['ledger-directory','receipt-directory','ledger-file','dangling-ledger-link','dangling-receipt-link']){
  const f=fixture(t),target=kind.includes('receipt')?f.config.receipt_dir:f.config.ledger_dir;
  if(kind.endsWith('directory'))fs.mkdirSync(target,{mode:0o700});
  else if(kind==='ledger-file')fs.writeFileSync(target,'existing source stays here\n',{mode:0o600});
  else fs.symlinkSync(path.join(f.root,'absent-target'),target);
  const before=fs.lstatSync(target);
  assert.throws(()=>start(f),/initialization_refuses_existing_/);
  assert.equal(f.calls.length,0);assert.equal(fs.lstatSync(target).ino,before.ino);
  assert.equal(fs.lstatSync(target).isSymbolicLink(),before.isSymbolicLink());
 }
});

test('wrong fingerprint, F110 or foreign owners and contradictory node metadata refuse before native probes',t=>{
 const wrong=fixture(t);wrong.config.expected_fingerprint='0'.repeat(64);
 assert.throws(()=>start(wrong),/native_identity_pin_failed/);assert.equal(wrong.calls.length,0);noNewState(wrong);
 for(const owner of ['MIKAYA','ACT-OMEGA','LAB-PEER']){
  const x=fixture(t,owner),before=immutableOwner(x);
  assert.throws(()=>start(x),/native_device_metadata_failed/);assert.equal(x.calls.length,0);noNewState(x);assert.deepEqual(immutableOwner(x),before);
 }
 for(const change of [{androidApi:35},{arch:'x86_64'},{os:'linux'}]){
  const x=fixture(t),file=path.join(x.config.node_dir,'node.json'),meta=JSON.parse(fs.readFileSync(file));
  Object.assign(meta.platform,change);fs.writeFileSync(file,x.fed.canonical(meta)+'\n');
  assert.throws(()=>start(x),/native_device_metadata_failed/);assert.equal(x.calls.length,0);noNewState(x);
 }
});

test('F110 property values and failed, empty, oversized or non-UTF8 probe results cannot create source state',t=>{
 for(const [property,bad] of [['ro.product.model','F110 Pro'],['ro.board.platform','mt6835'],['ro.build.version.release','15']]){
  const x=fixture(t),runner=(command,args,options)=>{const out=x.runner(command,args,options);if(args[0]===property)out.stdout=Buffer.from(bad+'\n');return out;};
  assert.throws(()=>start(x,{runner}),/device_observation_mismatch/);noNewState(x);
 }
 for(const result of [{status:0,stdout:Buffer.alloc(0),stderr:Buffer.alloc(0)},
  {status:null,error:Error('timeout'),stdout:Buffer.from(values['ro.product.model']),stderr:Buffer.alloc(0)},
  {status:0,stdout:Buffer.alloc(257,65),stderr:Buffer.alloc(0)},
  {status:0,stdout:Buffer.from([0xff]),stderr:Buffer.alloc(0)},
  {status:0,stdout:Buffer.from(values['ro.product.model']),stderr:Buffer.from('native warning')}]){
  const x=fixture(t);assert.throws(()=>start(x,{runner:()=>result}),/probe_/);noNewState(x);
 }
});

test('Motorola config rejects F110 schemas, profile overrides, overlapping paths and symlinked owner state',t=>{
 const x=fixture(t);
 for(const config of [{...x.config,schema:'mikaya.device-observation-config.v1'},
  {...x.config,model:values['ro.product.model']},{...x.config,runner:'/unreviewed/probe'},
  {...x.config,receipt_dir:x.config.node_dir},{...x.config,ledger_dir:path.join(x.config.node_dir,'events')}])
  assert.throws(()=>produce(config,{initialize:true,runner:x.runner}),/invalid_config|separate/);
 const link=path.join(x.root,'node-link');fs.symlinkSync(x.config.node_dir,link);
 assert.throws(()=>produce({...x.config,node_dir:link},{initialize:true,runner:x.runner}),/canonical|unsafe/);
 assert.equal(x.calls.length,0);noNewState(x);
});

test('existing owner kill switch is checked before probes and again after native reads',t=>{
 const x=fixture(t),policyFile=path.join(x.config.node_dir,'policy.json'),policy=JSON.parse(fs.readFileSync(policyFile));
 policy.enabled=false;fs.writeFileSync(policyFile,x.fed.canonical(policy)+'\n');
 assert.throws(()=>start(x),/policy/);assert.equal(x.calls.length,0);noNewState(x);
 const y=fixture(t),file=path.join(y.config.node_dir,'policy.json');
 const runner=(command,args,options)=>{
  const out=y.runner(command,args,options);
  if(args[0]==='ro.build.version.release'){const current=JSON.parse(fs.readFileSync(file));current.enabled=false;fs.writeFileSync(file,y.fed.canonical(current)+'\n');}
  return out;
 };
 assert.throws(()=>start(y,{runner}),/policy/);assert.equal(y.calls.length,3);noNewState(y);
 assert.equal(JSON.parse(fs.readFileSync(file)).enabled,false);
});

test('stale, future and rollback clocks cannot relabel observations',t=>{
 const x=fixture(t);
 for(const nowMs of [x.now-LIMITS.observationAgeMs-1000,x.now+LIMITS.futureSkewMs+1000])
  assert.throws(()=>start(x,{nowMs}),/observation_clock/);
 assert.equal(x.calls.length,0);noNewState(x);start(x);x.calls.length=0;
 assert.throws(()=>produce(x.config,{nowMs:x.now-1,runner:x.runner}),/observation_clock_rollback/);assert.equal(x.calls.length,0);
});

test('identical receipts are idempotent and a valid immutable orphan can be reused',t=>{
 const x=fixture(t),out=start(x),before=immutableOwner(x);
 assert.equal(produce(x.config,{nowMs:x.now,runner:x.runner}).already_recorded,true);
 assert.equal(fs.readdirSync(x.config.ledger_dir).length,2);assert.equal(fs.readdirSync(x.config.receipt_dir).length,1);
 const at=x.now+1,serialized=x.fed.canonical(receipt(x,at)),digest=sha(serialized);
 const orphan=path.join(x.config.receipt_dir,digest+'.json');fs.writeFileSync(orphan,serialized+'\n',{mode:0o600,flag:'wx'});
 const inode=fs.statSync(orphan).ino,result=produce(x.config,{nowMs:at,runner:x.runner});
 assert.equal(result.index,2);assert.equal(result.payload_sha256,digest);assert.notEqual(result.payload_sha256,out.payload_sha256);
 assert.equal(fs.statSync(orphan).ino,inode);assert.deepEqual(immutableOwner(x),before);
});

test('receipt tampering, F110 receipt schemas and oversized records hold without overwriting evidence',t=>{
 for(const kind of ['changed-time','F110-schema','oversized','noncanonical']){
  const x=fixture(t),out=start(x),file=path.join(x.config.receipt_dir,out.payload_sha256+'.json');
  const value=receipt(x);
  if(kind==='changed-time')value.observedAtMs++;
  if(kind==='F110-schema')value.schema='mikaya.device-observation.v1';
  const raw=kind==='oversized'?Buffer.alloc(LIMITS.receiptBytes+1):Buffer.from(kind==='noncanonical'?JSON.stringify(value,null,2)+'\n':x.fed.canonical(value)+'\n');
  fs.writeFileSync(file,raw);x.calls.length=0;
  assert.throws(()=>produce(x.config,{nowMs:x.now+1,runner:x.runner}),/receipt|unsafe_input/);
  assert.equal(x.calls.length,0);assert.deepEqual(fs.readFileSync(file),raw);assert.equal(fs.readdirSync(x.config.ledger_dir).length,2);
 }
});

test('corrupt signed source refuses before probes and preserves the existing journals and damaged row',t=>{
 const x=fixture(t);start(x);x.calls.length=0;
 const file=path.join(x.config.ledger_dir,'000001.json'),row=JSON.parse(fs.readFileSync(file));
 row.payloadSha256='f'.repeat(64);const raw=x.fed.canonical(row)+'\n';fs.writeFileSync(file,raw);
 const before=immutableOwner(x),receipts=fs.readdirSync(x.config.receipt_dir);
 assert.throws(()=>produce(x.config,{nowMs:x.now+1,runner:x.runner}),/hash|signature|digest/);
 assert.equal(x.calls.length,0);assert.equal(fs.readFileSync(file,'utf8'),raw);
 assert.deepEqual(fs.readdirSync(x.config.receipt_dir),receipts);assert.deepEqual(immutableOwner(x),before);
});

test('even correctly re-signed source rows cannot replay a prior ledger nonce',t=>{
 const x=fixture(t);start(x);produce(x.config,{nowMs:x.now+1,runner:x.runner});x.calls.length=0;
 const previous=JSON.parse(fs.readFileSync(path.join(x.config.ledger_dir,'000001.json'))),file=path.join(x.config.ledger_dir,'000002.json');
 const row=JSON.parse(fs.readFileSync(file));row.nonce=previous.nonce;
 const {entryHash,signature,...unsigned}=row;
 row.entryHash=sha('MIKAYA-SOVEREIGN-LOCAL-EVENT-SPINE/1\nHASH\n'+x.fed.canonical(unsigned));
 row.signature=crypto.sign(null,Buffer.from('MIKAYA-SOVEREIGN-LOCAL-EVENT-SPINE/1\nSIGN\n'+row.entryHash),x.fed.loadNode(x.config.node_dir).privateKey).toString('base64');
 const raw=x.fed.canonical(row)+'\n';fs.writeFileSync(file,raw);
 assert.throws(()=>produce(x.config,{nowMs:x.now+2,runner:x.runner}),/nonce|replay/);
 assert.equal(x.calls.length,0);assert.equal(fs.readFileSync(file,'utf8'),raw);
});

test('duplicate signed receipt digests are refused instead of receiving another signature',t=>{
 const x=fixture(t),out=start(x);
 x.ledger.appendDigest({nodeDir:x.config.node_dir,ledgerDir:x.config.ledger_dir,kind:'DEVICE_HEALTH_OBSERVED',payloadSha256:out.payload_sha256,nowMs:x.now});
 assert.throws(()=>produce(x.config,{nowMs:x.now,runner:x.runner}),/receipt_ledger_ambiguity/);
 assert.equal(fs.readdirSync(x.config.ledger_dir).length,3);assert.equal(fs.readdirSync(x.config.receipt_dir).length,1);
});

test('an idempotent retry rechecks source rather than reporting success after concurrent corruption',t=>{
 const x=fixture(t);start(x);const file=path.join(x.config.ledger_dir,'000001.json');
 const runner=(command,args,options)=>{
  const out=x.runner(command,args,options);
  if(args[0]==='ro.build.version.release'){const row=JSON.parse(fs.readFileSync(file));row.payloadSha256='f'.repeat(64);fs.writeFileSync(file,x.fed.canonical(row)+'\n');}
  return out;
 };
 assert.throws(()=>produce(x.config,{nowMs:x.now,runner}),/hash|signature|digest/);
 assert.equal(fs.readdirSync(x.config.ledger_dir).length,2);
});

test('existing producer and append locks remain in place and prevent a second writer',t=>{
 for(const which of ['producer','append']){
  const x=fixture(t);start(x);x.calls.length=0;
  const lock=which==='producer'?path.join(x.config.receipt_dir,'.producer.lock'):path.join(x.config.ledger_dir,'.append.lock');
  if(which==='producer')fs.mkdirSync(lock,{mode:0o700});else fs.writeFileSync(lock,'existing owner lock\n',{mode:0o600});
  const inode=fs.lstatSync(lock).ino;
  assert.throws(()=>produce(x.config,{nowMs:x.now+1,runner:x.runner}),/busy|locked/);
  assert.equal(x.calls.length,0);assert.equal(fs.lstatSync(lock).ino,inode);
  assert.equal(fs.existsSync(path.join(x.config.ledger_dir,'000002.json')),false);
 }
});

test('append conflict preserves an orphan receipt and supports only an explicit later retry',t=>{
 const x=fixture(t);start(x);const at=x.now+1,lock=path.join(x.config.ledger_dir,'.append.lock');
 const runner=(command,args,options)=>{const out=x.runner(command,args,options);
  if(args[0]==='ro.build.version.release')fs.writeFileSync(lock,'synthetic concurrent append\n',{mode:0o600,flag:'wx'});return out;};
 assert.throws(()=>produce(x.config,{nowMs:at,runner}),/locked|busy/);
 assert.equal(fs.readFileSync(lock,'utf8'),'synthetic concurrent append\n');
 assert.equal(fs.existsSync(path.join(x.config.ledger_dir,'000002.json')),false);assert.equal(fs.readdirSync(x.config.receipt_dir).length,2);
 // Only this synthetic fixture simulates an operator resolving its own lock.
 fs.unlinkSync(lock);const out=produce(x.config,{nowMs:at,runner:x.runner});
 assert.equal(out.index,2);assert.equal(out.already_recorded,false);assert.equal(fs.readdirSync(x.config.receipt_dir).length,2);
});

test('receipt directory sync failure does not sign a new row and retry re-establishes durability',t=>{
 const x=fixture(t);start(x);const at=x.now+1,realSync=fs.fsyncSync;
 let injected=false;
 const syncMock=t.mock.method(fs,'fsyncSync',fd=>{
  if(!injected&&fs.readlinkSync('/proc/self/fd/'+fd)===x.config.receipt_dir){injected=true;throw Error('injected receipt directory sync failure');}
  return realSync(fd);
 });
 assert.throws(()=>produce(x.config,{nowMs:at,runner:x.runner}),/injected receipt directory sync failure/);syncMock.mock.restore();
 assert.equal(injected,true);assert.equal(fs.existsSync(path.join(x.config.ledger_dir,'000002.json')),false);
 assert.equal(fs.readdirSync(x.config.receipt_dir).length,2);
 assert.equal(produce(x.config,{nowMs:at,runner:x.runner}).index,2);
});

test('receipt count exhaustion is rejected before receipt reads or native probes',t=>{
 const x=fixture(t);start(x);x.calls.length=0;
 for(let i=0;i<LIMITS.receipts;i++)fs.writeFileSync(path.join(x.config.receipt_dir,i.toString(16).padStart(64,'0')+'.json'),'',{mode:0o600});
 assert.throws(()=>produce(x.config,{nowMs:x.now+1,runner:x.runner}),/receipt_capacity/);
 assert.equal(x.calls.length,0);assert.equal(fs.readdirSync(x.config.ledger_dir).length,2);
});

for(const kind of ['symlink','hardlink','oversized'])test('signed row refuses '+kind,t=>{
  const x=fixture(t);start(x);x.calls.length=0;const row=path.join(x.config.ledger_dir,'000001.json'),other=path.join(x.root,'preserved-row');
  if(kind==='symlink'){fs.renameSync(row,other);fs.symlinkSync(other,row);}
  if(kind==='hardlink'){
   const original=fs.readFileSync(row);
   try{fs.linkSync(row,other);}catch(e){
    if((process.platform==='android'||process.execPath.startsWith('/data/data/com.termux/files/usr/bin/')) && ['EACCES','EPERM','ENOTSUP','EOPNOTSUPP'].includes(e.code)){
     assert.equal(fs.existsSync(other),false);assert.equal(fs.statSync(row).nlink,1);
     assert.deepEqual(fs.readFileSync(row),original);assert.equal(x.calls.length,0);
     t.skip('Android refused hard-link fixture; application rejection not exercised');return;
    }throw e;
   }assert.equal(fs.statSync(row).nlink,2);
  }
  if(kind==='oversized')fs.writeFileSync(row,Buffer.alloc(LIMITS.rowBytes+1));
  const before=fs.readFileSync(row);
  assert.throws(()=>produce(x.config,{nowMs:x.now+1,runner:x.runner}),/unsafe_input/);
  assert.equal(x.calls.length,0);assert.deepEqual(fs.readFileSync(row),before);
});

test('CLI missing-state HOLD and strict arguments cannot bootstrap or override the fixed native profile',t=>{
 const x=fixture(t),file=path.join(x.root,'motorola-observation.json');
 fs.writeFileSync(file,JSON.stringify(x.config),{mode:0o600});
 const command=path.resolve(__dirname,'../motorola-observation-producer.cjs');
 for(const args of [['--config',file],['--config',file,'--initialize-new','--model','F110 Pro']]){
  const result=spawnSync(process.execPath,[command,...args],{encoding:'utf8',timeout:3000});
  assert.equal(result.status,2);assert.equal(JSON.parse(result.stderr).status,'HOLD');noNewState(x);
 }
});

test('the original F110 producer and the fixed Motorola probe API remain separate',()=>{
 const original=path.resolve(__dirname,'../../../../integrations/security-tollbooth/verified-events/device_observation_producer.cjs');
 assert.equal(sha(fs.readFileSync(original)),'6e48e74d0a1a448cd260e4d5383399668642000a7d8c39eb9f308fc45b4446d6');
 assert.deepEqual(Object.keys(producer).sort(),['LIMITS','PROBES','produce']);
 assert.equal(PROBES.length,3);assert.equal(Object.isFrozen(PROBES),true);
 assert.equal(PROBES.every(Object.isFrozen),true);
 assert.deepEqual(PROBES.map(p=>p.expected),['moto g power 5G - 2023','mt6855','14']);
});
