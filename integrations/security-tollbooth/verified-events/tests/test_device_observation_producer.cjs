'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {loadVerifier}=require('../ledger_event_collector.cjs');
const {produce,LIMITS,PROBES}=require('../device_observation_producer.cjs');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
function fixture(t,owner='MIKAYA'){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-observer-test-'));fs.chmodSync(root,0o700);
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const {fed,ledger}=loadVerifier(),node=path.join(root,'fixture-node');
 const meta=fed.initNode(node,owner,'fixture-f110-a15');
 const config={schema:'mikaya.device-observation-config.v1',node_dir:node,ledger_dir:path.join(root,'signed-events'),receipt_dir:path.join(root,'receipts'),expected_fingerprint:meta.fingerprint};
 const calls=[],now=Date.now();
 const runner=(command,args,options)=>{calls.push({command,args,options});return {status:0,signal:null,stdout:Buffer.from({'ro.product.model':'F110 Pro','ro.board.platform':'mt6835','ro.build.version.release':'15'}[args[0]]+'\n'),stderr:Buffer.alloc(0)};};
 return {root,config,fed,ledger,calls,runner,now};
}
function start(x){return produce(x.config,{initialize:true,nowMs:x.now,runner:x.runner});}
test('fixed probes produce a receipt and a real owner-signed native ledger row',t=>{
 const x=fixture(t),out=start(x);
 assert.equal(out.status,'DEVICE_OBSERVATION_SIGNED');assert.equal(out.index,1);
 assert.deepEqual(x.calls.map(c=>[c.command,...c.args]),[
  ['/system/bin/getprop','ro.product.model'],['/system/bin/getprop','ro.board.platform'],['/system/bin/getprop','ro.build.version.release']]);
 for(const c of x.calls){assert.equal(c.options.timeout,1000);assert.equal(c.options.maxBuffer,256);assert.equal(c.options.shell,false);}
 const receipt={schema:'mikaya.device-observation.v1',observedAtMs:x.now,model:'F110 Pro',platform:'mt6835',androidRelease:'15'};
 const digest=sha(x.fed.canonical(receipt));assert.equal(out.payload_sha256,digest);
 const file=path.join(x.config.receipt_dir,digest+'.json');
 assert.equal(fs.readFileSync(file,'utf8'),x.fed.canonical(receipt)+'\n');assert.equal(fs.statSync(file).mode&0o777,0o600);
 const row=JSON.parse(fs.readFileSync(path.join(x.config.ledger_dir,'000001.json')));
 assert.equal(row.kind,'DEVICE_HEALTH_OBSERVED');assert.equal(row.payloadSha256,digest);assert.equal(row.issuedAtMs,x.now);
 const publicPem=fs.readFileSync(path.join(x.config.node_dir,'identity-public.pem'));
 assert.equal(x.ledger.verifyLedger({ledgerDir:x.config.ledger_dir,publicPem}).entries,2);
 assert.equal(out.hardware_attested,false);assert.equal(out.payment_authorized,false);
});
test('normal production requires initialized native ledger and explicit init refuses replacement',t=>{
 const x=fixture(t);assert.throws(()=>produce(x.config,{runner:x.runner}),/initialization_required/);
 assert.equal(x.calls.length,0);start(x);
 assert.throws(()=>start(x),/initialization_refuses_existing_ledger/);
});
test('wrong configured fingerprint refuses before probes or ledger creation',t=>{
 const x=fixture(t);x.config.expected_fingerprint='0'.repeat(64);
 assert.throws(()=>start(x),/native_identity_pin_failed/);assert.equal(x.calls.length,0);assert.equal(fs.existsSync(x.config.ledger_dir),false);
});
test('independent owner identity cannot be used as MIKAYA observation signer',t=>{
 const x=fixture(t,'MOTOROLA');assert.throws(()=>start(x),/native_device_metadata_failed/);assert.equal(x.calls.length,0);
});
test('tampered native device metadata refuses before probes',t=>{
 const x=fixture(t),file=path.join(x.config.node_dir,'node.json'),meta=JSON.parse(fs.readFileSync(file));
 meta.platform.androidApi=34;fs.writeFileSync(file,x.fed.canonical(meta)+'\n');
 assert.throws(()=>start(x),/native_device_metadata_failed/);assert.equal(x.calls.length,0);
});
test('wrong device and incomplete, failed, oversized or non-UTF8 probes hold without genesis',t=>{
 for(const result of [{status:0,stdout:Buffer.from('Other phone\n'),stderr:Buffer.alloc(0)},
  {status:0,stdout:Buffer.alloc(0),stderr:Buffer.alloc(0)},
  {status:null,error:Error('timeout'),stdout:Buffer.from('F110 Pro\n'),stderr:Buffer.alloc(0)},
  {status:0,stdout:Buffer.alloc(257,65),stderr:Buffer.alloc(0)},
  {status:0,stdout:Buffer.from([0xff]),stderr:Buffer.alloc(0)}]){
  const x=fixture(t);assert.throws(()=>produce(x.config,{initialize:true,runner:()=>result}),/probe_|device_observation_mismatch/);
  assert.equal(fs.existsSync(x.config.ledger_dir),false);
 }
});
test('stale or future caller clock cannot relabel an observation as current',t=>{
 const x=fixture(t);
 for(const nowMs of [x.now-LIMITS.observationAgeMs-1000,x.now+LIMITS.futureSkewMs+1000])assert.throws(()=>produce(x.config,{initialize:true,nowMs,runner:x.runner}),/observation_clock/);
 assert.equal(x.calls.length,0);
});
test('tampered signed ledger refuses before probes and leaves receipts unchanged',t=>{
 const x=fixture(t);start(x);x.calls.length=0;
 const file=path.join(x.config.ledger_dir,'000001.json'),row=JSON.parse(fs.readFileSync(file));row.payloadSha256='f'.repeat(64);fs.writeFileSync(file,x.fed.canonical(row)+'\n');
 const names=fs.readdirSync(x.config.receipt_dir);
 assert.throws(()=>produce(x.config,{nowMs:x.now+1,runner:x.runner}),/hash|signature|digest/);
 assert.equal(x.calls.length,0);assert.deepEqual(fs.readdirSync(x.config.receipt_dir),names);
});
test('identical signed receipt is idempotent and uncommitted receipt can be reused',t=>{
 const x=fixture(t);const out=start(x);
 assert.equal(produce(x.config,{nowMs:x.now,runner:x.runner}).already_recorded,true);
 assert.equal(fs.readdirSync(x.config.ledger_dir).length,2);
 const at=x.now+1,receipt={schema:'mikaya.device-observation.v1',observedAtMs:at,model:'F110 Pro',platform:'mt6835',androidRelease:'15'},digest=sha(x.fed.canonical(receipt));
 fs.writeFileSync(path.join(x.config.receipt_dir,digest+'.json'),x.fed.canonical(receipt)+'\n',{flag:'wx',mode:0o600});
 const fresh=produce(x.config,{nowMs:at,runner:x.runner});assert.equal(fresh.index,2);assert.equal(fresh.payload_sha256,digest);
 assert.notEqual(fresh.payload_sha256,out.payload_sha256);
});
test('failed native append preserves an unsigned orphan receipt for retry',t=>{
 const x=fixture(t);start(x);const at=x.now+1,foreignLock=path.join(x.config.ledger_dir,'.append.lock');
 const runner=(command,args,options)=>{const out=x.runner(command,args,options);if(args[0]==='ro.build.version.release')fs.writeFileSync(foreignLock,'',{flag:'wx',mode:0o600});return out;};
 assert.throws(()=>produce(x.config,{nowMs:at,runner}),/locked|busy/);
 assert.equal(fs.existsSync(foreignLock),true);assert.equal(fs.existsSync(path.join(x.config.ledger_dir,'000002.json')),false);
 assert.equal(fs.readdirSync(x.config.receipt_dir).length,2);
 fs.unlinkSync(foreignLock);const out=produce(x.config,{nowMs:at,runner:x.runner});
 assert.equal(out.index,2);assert.equal(out.already_recorded,false);assert.equal(fs.readdirSync(x.config.receipt_dir).length,2);
});
test('receipt bounds and malformed orphan receipts hold without another signature',t=>{
 for(const raw of [Buffer.alloc(LIMITS.receiptBytes+1),Buffer.from('{}\n')]){
  const x=fixture(t);start(x);const names=fs.readdirSync(x.config.ledger_dir);
  fs.writeFileSync(path.join(x.config.receipt_dir,'a'.repeat(64)+'.json'),raw,{mode:0o600});
  assert.throws(()=>produce(x.config,{nowMs:x.now+1,runner:x.runner}),/receipt|unsafe_input/);
  assert.deepEqual(fs.readdirSync(x.config.ledger_dir),names);
 }
});
test('receipt count exhaustion is rejected before reading files or probing',t=>{
 const x=fixture(t);start(x);x.calls.length=0;
 for(let i=0;i<LIMITS.receipts;i++)fs.writeFileSync(path.join(x.config.receipt_dir,i.toString(16).padStart(64,'0')+'.json'),'',{mode:0o600});
 assert.throws(()=>produce(x.config,{nowMs:x.now+1,runner:x.runner}),/receipt_capacity/);assert.equal(x.calls.length,0);
 assert.equal(fs.readdirSync(x.config.ledger_dir).length,2);
});
test('symlinks, overlapping directories and arbitrary config claims are refused',t=>{
 const x=fixture(t);assert.throws(()=>start({...x,config:{...x.config,model:'F110 Pro'}}),/invalid_config/);
 assert.throws(()=>start({...x,config:{...x.config,receipt_dir:x.config.node_dir}}),/separate/);
 const link=path.join(x.root,'node-link');fs.symlinkSync(x.config.node_dir,link);
 assert.throws(()=>start({...x,config:{...x.config,node_dir:link}}),/canonical|unsafe/);
});
test('exclusive producer lock refuses concurrent writer',t=>{
 const x=fixture(t);start(x);fs.mkdirSync(path.join(x.config.receipt_dir,'.producer.lock'),{mode:0o700});
 assert.throws(()=>produce(x.config,{runner:x.runner}),/producer_busy/);
 assert.equal(fs.existsSync(path.join(x.config.receipt_dir,'.producer.lock')),true);
});
test('producer returns no key, credential, file content or extraction API',t=>{
 const x=fixture(t),out=start(x),raw=JSON.stringify(out);
 assert.doesNotMatch(raw,/PRIVATE KEY|PUBLIC KEY|privateKey|privatePem|identity-private|node_dir|receipt_dir/);
 assert.deepEqual(Object.keys(require('../device_observation_producer.cjs')).sort(),['LIMITS','PROBES','produce']);
 assert.equal(PROBES.length,3);
});
