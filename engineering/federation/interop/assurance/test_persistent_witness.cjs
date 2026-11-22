'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const cp=require('node:child_process');
const audit=require('./rotating-audit.cjs');
const vault=require('./persistent-witness.cjs');

const sha=s=>crypto.createHash('sha256').update(String(s)).digest('hex');
function fixture(t) {
  const base=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-witness-persist-'));
  t.after(()=>fs.rmSync(base,{recursive:true,force:true}));
  const dir=path.join(base,'vault');
  const root=crypto.generateKeyPairSync('ed25519');
  const witness=crypto.generateKeyPairSync('ed25519');
  const event=n=>({schema:'mikaya.audit.caveat-receipt.v1',
    kind:'SIGNED_COMPUTE_RECEIPT',jobSha256:sha('job'+n),
    receiptSha256:sha('result'+n),ownerGrantSha256:sha('grant'+n),
    macaroonSha256:sha('macaroon'+n),policySha256:sha('policy'),
    capability:'compute.sha256.v1',paymentAuthorized:false,actAdmitted:false});
  const entries=[];
  for(let i=0;i<3;i++)entries.push(audit.append({entries,rootPrivateKey:root.privateKey,event:event(i),issuedAtMs:1000+i}));
  return {base,dir,entries,root,witness};
}
const write=(f,entries,extra={})=>vault.record({dir:f.dir,entries,rootPublicKey:f.root.publicKey,
  witnessPrivateKey:f.witness.privateKey,issuedAtMs:2000+entries.length,...extra});
const read=(f,entries,extra={})=>vault.inspect({dir:f.dir,entries,rootPublicKey:f.root.publicKey,
  witnessPublicKey:f.witness.publicKey,...extra});
test('missing vault is fail-closed until an explicit first observation',t=>{
  const f=fixture(t);
  assert.throws(()=>read(f,f.entries),/VAULT_UNINITIALIZED/);
  assert.throws(()=>write(f,f.entries),/VAULT_UNINITIALIZED/);
  assert.equal(fs.existsSync(f.dir),false);
});
test('bootstrap writes durable private checkpoint without serializing any signing key',t=>{
  const f=fixture(t);
  const result=write(f,f.entries,{bootstrap:true});
  const report=read(f,f.entries);
  assert.equal(report.ledgerEntries,3);
  assert.equal(report.highWaterSequence,3);
  assert.equal(report.latestReceiptDigest,result.receiptDigest);
  assert.equal(report.externalCustodyVerified,false);
  assert.equal(report.independentHardwareConfirmed,false);
  const p=path.join(f.dir,'checkpoint-state.json');
  assert.equal(fs.statSync(f.dir).mode&0o077,0);
  assert.equal(fs.statSync(p).mode&0o077,0);
  assert.equal(fs.existsSync(path.join(f.dir,'checkpoint-state.json.lock')),false);
  const raw=fs.readFileSync(p,'utf8');
  assert.equal(raw.includes('BEGIN PRIVATE KEY'),false);
  assert.equal(raw.includes('privateKey'),false);
});
test('advancing from seq 1 to 3 retains complete predecessor checkpoint digest across process restart',t=>{
  const f=fixture(t);
  const first=write(f,f.entries.slice(0,1),{bootstrap:true});
  const next=write(f,f.entries,{expectedPriorDigest:first.receiptDigest});
  assert.equal(next.previousCheckpointDigest,first.receiptDigest);
  const report=read(f,f.entries,{expectedMinimumSequence:3,expectedLatestDigest:next.receiptDigest});
  assert.equal(report.highWaterSequence,3);
  assert.equal(report.witnessCheckpoints,2);
  const input=path.join(f.base,'chain.json');
  fs.writeFileSync(input,JSON.stringify(f.entries),{mode:0o600});
  const rootDer=f.root.publicKey.export({format:'der',type:'spki'}).toString('base64');
  const witnessDer=f.witness.publicKey.export({format:'der',type:'spki'}).toString('base64');
  const program="const fs=require('node:fs');const c=require(process.argv[1]);const crypto=require('node:crypto');const pk=b=>crypto.createPublicKey({key:Buffer.from(b,'base64'),format:'der',type:'spki'});const a=c.inspect({dir:process.argv[2],entries:JSON.parse(fs.readFileSync(process.argv[3])),rootPublicKey:pk(process.argv[4]),witnessPublicKey:pk(process.argv[5]),expectedMinimumSequence:3,expectedLatestDigest:process.argv[6]});console.log(JSON.stringify({verified:a.verified,sequence:a.highWaterSequence}));";
  const run=cp.spawnSync(process.execPath,['-e',program,path.join(__dirname,'persistent-witness.cjs'),f.dir,input,rootDer,witnessDer,next.receiptDigest],{encoding:'utf8',timeout:5000});
  assert.equal(run.status,0,run.stderr);
  assert.deepEqual(JSON.parse(run.stdout),{verified:true,sequence:3});
});
test('an older ledger is rejected after a later signed checkpoint was retained',t=>{
  const f=fixture(t);
  write(f,f.entries,{bootstrap:true});
  assert.throws(()=>read(f,f.entries.slice(0,2)),/VAULT_ROLLBACK/);
});
test('restoring a historically valid older vault file is rejected against a separately pinned digest',t=>{
  const f=fixture(t);
  write(f,f.entries.slice(0,1),{bootstrap:true});
  const file=path.join(f.dir,'checkpoint-state.json');
  const old=fs.readFileSync(file);
  const newest=write(f,f.entries);
  fs.writeFileSync(file,old,{mode:0o600});
  assert.throws(()=>read(f,f.entries,{expectedMinimumSequence:3,expectedLatestDigest:newest.receiptDigest}),/VAULT_/);
  assert.throws(()=>write(f,f.entries,{expectedPriorDigest:newest.receiptDigest}),/VAULT_/);
});
test('corrupted vault is refused without erasing or silently resetting history',t=>{
  const f=fixture(t);write(f,f.entries,{bootstrap:true});
  const p=path.join(f.dir,'checkpoint-state.json');
  fs.appendFileSync(p,'garbage');
  assert.throws(()=>read(f,f.entries),/VAULT_/);
  assert.throws(()=>write(f,f.entries,{bootstrap:true}),/VAULT_/);
  assert.match(fs.readFileSync(p,'utf8'),/garbage$/);
});
test('wrong witness and wrong owner roots are refused',t=>{
  const f=fixture(t);write(f,f.entries,{bootstrap:true});
  const bad=crypto.generateKeyPairSync('ed25519');
  assert.throws(()=>vault.inspect({dir:f.dir,entries:f.entries,rootPublicKey:f.root.publicKey,witnessPublicKey:bad.publicKey}),/VAULT_/);
  assert.throws(()=>vault.inspect({dir:f.dir,entries:f.entries,rootPublicKey:bad.publicKey,witnessPublicKey:f.witness.publicKey}),/VAULT_/);
});
test('same sequence replay and accidental second bootstrap are refused',t=>{
  const f=fixture(t);write(f,f.entries,{bootstrap:true});
  assert.throws(()=>write(f,f.entries),/VAULT_REPLAY/);
  assert.throws(()=>write(f,f.entries,{bootstrap:true}),/VAULT_/);
});
test('symlinked or insecure storage is refused before writing checkpoint state',t=>{
  const f=fixture(t);fs.mkdirSync(f.dir,{mode:0o700});
  const p=path.join(f.dir,'checkpoint-state.json');
  fs.symlinkSync(path.join(f.base,'outside'),p);
  assert.throws(()=>write(f,f.entries,{bootstrap:true}),/VAULT_/);
  fs.unlinkSync(p);fs.chmodSync(f.dir,0o777);
  assert.throws(()=>write(f,f.entries,{bootstrap:true}),/VAULT_/);
});
test('pre-existing exclusive lock refuses concurrent writes without deleting the lock',t=>{
  const f=fixture(t);write(f,f.entries.slice(0,1),{bootstrap:true});
  const l=path.join(f.dir,'checkpoint-state.json.lock');
  fs.writeFileSync(l,'owner process active',{mode:0o600,flag:'wx'});
  assert.throws(()=>write(f,f.entries),/VAULT_LOCKED/);
  assert.equal(fs.existsSync(l),true);
});
test('vault observation cannot grant execution, financial settlement, ACT admission or certification',t=>{
  const f=fixture(t);write(f,f.entries,{bootstrap:true});
  const out=read(f,f.entries);
  for(const k of ['executionAuthorized','financialSettlementVerified','actAdmitted','governmentCertified','independentHardwareConfirmed'])
    assert.equal(out[k],false,k);
});

test('world-readable existing checkpoint file is not accepted',t=>{
  const f=fixture(t);write(f,f.entries,{bootstrap:true});
  const p=path.join(f.dir,'checkpoint-state.json');
  fs.chmodSync(p,0o644);
  assert.throws(()=>read(f,f.entries),/VAULT_STATE_INSECURE/);
  assert.throws(()=>write(f,f.entries),/VAULT_STATE_INSECURE/);
});
test('replacing an existing checkpoint with a symlink fails closed',t=>{
  const f=fixture(t);write(f,f.entries,{bootstrap:true});
  const p=path.join(f.dir,'checkpoint-state.json');
  const outside=path.join(f.base,'outside.json');
  fs.renameSync(p,outside);
  fs.symlinkSync(outside,p);
  assert.throws(()=>read(f,f.entries),/VAULT_STATE_INSECURE/);
});
test('a longer verified ledger remains unobserved until a new signed checkpoint is durably recorded',t=>{
  const f=fixture(t);
  write(f,f.entries.slice(0,1),{bootstrap:true});
  assert.throws(()=>read(f,f.entries),/VAULT_STALE_HEAD/);
});
test('missing checkpoint cannot be silently reinitialized when an external digest is pinned',t=>{
  const f=fixture(t);
  assert.throws(()=>write(f,f.entries,{bootstrap:true,expectedPriorDigest:sha('trusted-remote-checkpoint')}),/VAULT_EXTERNAL_PIN_MISMATCH/);
  assert.equal(fs.existsSync(path.join(f.dir,'checkpoint-state.json')),false);
});
test('failed replay does not change durable bytes or the high-water record',t=>{
  const f=fixture(t);
  const receipt=write(f,f.entries,{bootstrap:true});
  const p=path.join(f.dir,'checkpoint-state.json');
  const original=fs.readFileSync(p);
  assert.throws(()=>write(f,f.entries),/VAULT_REPLAY/);
  assert.deepEqual(fs.readFileSync(p),original);
  assert.equal(read(f,f.entries).latestReceiptDigest,receipt.receiptDigest);
});
