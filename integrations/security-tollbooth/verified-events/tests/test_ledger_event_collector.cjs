'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {collect,loadVerifier}=require('../ledger_event_collector.cjs');
const DOMAIN='MIKAYA-SOVEREIGN-LOCAL-EVENT-SPINE/1\n';
const canonical=x=>x===null||typeof x!=='object'?JSON.stringify(x):Array.isArray(x)?'['+x.map(canonical).join(',')+']':'{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-events-test-'));fs.chmodSync(root,0o700);
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const keys=crypto.generateKeyPairSync('ed25519'),pem=keys.publicKey.export({type:'spki',format:'pem'});
 const fp=hash(pem),ledger=path.join(root,'ledger'),publicFile=path.join(root,'public.pem');
 fs.mkdirSync(ledger,{mode:0o700});fs.writeFileSync(publicFile,pem,{mode:0o600});
 const rows=[],now=1786023300000;
 function append(kind='DEVICE_HEALTH_OBSERVED',overrides={}){
  const body={schema:'mikaya.sovereign.event.v1',index:rows.length,prevHash:rows.at(-1)?.entryHash||'0'.repeat(64),nodeFingerprint:fp,kind,payloadSha256:hash('actual observation fixture'),issuedAtMs:now-1000+rows.length,nonce:crypto.randomBytes(16).toString('hex'),...overrides};
  const entryHash=hash(DOMAIN+'HASH\n'+canonical(body));
  const row={...body,entryHash,signature:crypto.sign(null,Buffer.from(DOMAIN+'SIGN\n'+entryHash),keys.privateKey).toString('base64')};
  rows.push(row);write(row);return row;
 }
 function write(row){fs.writeFileSync(path.join(ledger,String(row.index).padStart(6,'0')+'.json'),canonical(row)+'\n',{mode:0o600});}
 append('GENESIS');append();
 const config={schema:'mikaya.verified-ledger-config.v1',ledger_dir:ledger,public_key_path:publicFile,expected_fingerprint:fp,state_dir:path.join(root,'adapter-state'),max_age_ms:300000};
 return {root,keys,rows,now,append,write,config};
}
test('real Ed25519 verification projects only redacted watcher evidence and deterministic retries',t=>{
 const x=fixture(t),a=collect(x.config,{initialize:true,nowMs:x.now});
 const lines=fs.readFileSync(a.projection_path,'utf8').trim().split('\n').map(JSON.parse);
 assert.equal(a.recognized_event_count,1);assert.equal(lines[1].type,'INTERNAL_WATCHER');
 assert.equal(lines[1].ts,new Date(x.rows[1].issuedAtMs).toISOString());
 assert.deepEqual(Object.keys(lines[1].data).sort(),['entry_sha256','index','kind','payload_sha256','source']);
 assert.equal(a.payment_authorized,false);assert.equal(a.hardware_attested,false);
 const b=collect(x.config,{nowMs:x.now+500});assert.equal(b.new_events,0);assert.equal(b.projection_sha256,a.projection_sha256);assert.equal(b.unchanged,true);
 x.append('TOYBOX_CHAIN_OBSERVED');const c=collect(x.config,{nowMs:x.now+1000});assert.equal(c.new_events,1);assert.equal(c.recognized_event_count,2);
 assert(!fs.readFileSync(c.projection_path,'utf8').includes('MINT_GATE'));
});
test('rejects wrong public pin, altered signature and replayed signed nonce',t=>{
 const x=fixture(t);assert.throws(()=>collect({...x.config,expected_fingerprint:'a'.repeat(64)},{initialize:true,nowMs:x.now}),/identity_pin/);
 x.config.state_dir=path.join(x.root,'second');x.rows[1].payloadSha256='b'.repeat(64);x.write(x.rows[1]);
 assert.throws(()=>collect(x.config,{initialize:true,nowMs:x.now}),/hash|signature/);
 const y=fixture(t);y.append('DEVICE_HEALTH_OBSERVED',{nonce:y.rows[1].nonce});
 assert.throws(()=>collect(y.config,{initialize:true,nowMs:y.now}),/nonce|replay/);
});
test('rejects valid signed truncation or replacement beyond checkpoint',t=>{
 const x=fixture(t);x.append();collect(x.config,{initialize:true,nowMs:x.now});
 fs.unlinkSync(path.join(x.config.ledger_dir,'000002.json'));
 assert.throws(()=>collect(x.config,{nowMs:x.now}),/rollback/);
 // Create another same-owner valid branch with a newer tip. Prefix continuity still refuses it.
 x.rows.pop();x.rows.pop();x.append('OWNER_EVIDENCE_REVIEWED');x.append('DEVICE_HEALTH_OBSERVED');
 assert.throws(()=>collect(x.config,{nowMs:x.now}),/rollback|replacement/);
});
test('normal collection never silently initializes a deleted checkpoint',t=>{
 const x=fixture(t);assert.throws(()=>collect(x.config,{nowMs:x.now}));
 collect(x.config,{initialize:true,nowMs:x.now});fs.unlinkSync(path.join(x.config.state_dir,'projection.jsonl'));
 assert.throws(()=>collect(x.config,{nowMs:x.now}));
 assert.throws(()=>collect(x.config,{initialize:true,nowMs:x.now}),/EEXIST/);
});
test('failed first initialization leaves no final checkpoint and permits explicit retry',t=>{
 const x=fixture(t);
 assert.throws(()=>collect({...x.config,expected_fingerprint:'b'.repeat(64)},{initialize:true,nowMs:x.now}),/identity_pin/);
 assert.equal(fs.existsSync(x.config.state_dir),false);
 assert(!fs.readdirSync(x.root).some(n=>n.startsWith('.initialize-events-')||n.endsWith('.initialize.lock')));
 assert.equal(collect(x.config,{initialize:true,nowMs:x.now}).recognized_event_count,1);
});
test('stale or future source holds without replacing accepted checkpoint',t=>{
 const x=fixture(t),a=collect(x.config,{initialize:true,nowMs:x.now});
 assert.throws(()=>collect(x.config,{nowMs:x.now+400000}),/stale/);
 assert.equal(hash(fs.readFileSync(a.projection_path)),a.projection_sha256);
 const y=fixture(t);y.append('DEVICE_HEALTH_OBSERVED',{issuedAtMs:y.now+30001});
 assert.throws(()=>collect(y.config,{initialize:true,nowMs:y.now}),/future/);
});
test('genesis alone, partial append, bad UTF8 and oversized rows hold',t=>{
 const x=fixture(t);fs.unlinkSync(path.join(x.config.ledger_dir,'000001.json'));
 assert.throws(()=>collect(x.config,{initialize:true,nowMs:x.now}),/missing_busy/);
 const y=fixture(t);fs.writeFileSync(path.join(y.config.ledger_dir,'.append.lock'),'');
 assert.throws(()=>collect(y.config,{initialize:true,nowMs:y.now}),/missing_busy/);
 const z=fixture(t);fs.writeFileSync(path.join(z.config.ledger_dir,'000001.json'),Buffer.from([255]));
 assert.throws(()=>collect(z.config,{initialize:true,nowMs:z.now}));
 const w=fixture(t);fs.writeFileSync(path.join(w.config.ledger_dir,'000001.json'),' '.repeat(2201));
 assert.throws(()=>collect(w.config,{initialize:true,nowMs:w.now}),/unsafe_input/);
});
test('rejects private PEM, symlink, unsafe permissions and concurrent producer lock',t=>{
 const x=fixture(t);fs.writeFileSync(x.config.public_key_path,x.keys.privateKey.export({type:'pkcs8',format:'pem'}));
 assert.throws(()=>collect(x.config,{initialize:true,nowMs:x.now}),/public_spki/);
 const y=fixture(t);const row=path.join(y.config.ledger_dir,'000001.json');fs.renameSync(row,row+'.real');fs.symlinkSync(row+'.real',row);
 assert.throws(()=>collect(y.config,{initialize:true,nowMs:y.now}));
 const z=fixture(t);fs.chmodSync(path.join(z.config.ledger_dir,'000001.json'),0o644);
 assert.throws(()=>collect(z.config,{initialize:true,nowMs:z.now}),/unsafe_input/);
 const w=fixture(t);collect(w.config,{initialize:true,nowMs:w.now});fs.mkdirSync(path.join(w.config.state_dir,'.collector.lock'),{mode:0o700});
 assert.throws(()=>collect(w.config,{nowMs:w.now}),/EEXIST/);
});
test('executes only the exact reused verifier dependency bytes',t=>{
 const x=fixture(t),dir=path.join(x.root,'package');fs.mkdirSync(dir);fs.mkdirSync(path.join(dir,'vendor'));
 for(const file of ['ledger_event_collector.cjs','vendor/federation-node.cjs','vendor/sovereign-event-ledger.cjs'])fs.copyFileSync(path.join(__dirname,'..',file),path.join(dir,file));
 fs.appendFileSync(path.join(dir,'vendor/federation-node.cjs'),'\n// altered\n');
 assert.throws(()=>require(path.join(dir,'ledger_event_collector.cjs')).loadVerifier(),/source_pin/);
 assert.equal(typeof loadVerifier().ledger.verifyLedger,'function');
});
