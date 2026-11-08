'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const crypto=require('node:crypto');
const fed=require('../federation-node.cjs');
const ledger=require('../sovereign-event-ledger.cjs');
const hex=x=>crypto.createHash('sha256').update(x).digest('hex');
const NOW=Date.parse('2026-11-08T20:00:00.000Z');
function lab(t,owner='MIKAYA'){
 const base=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-event-ledger-'));
 t.after(()=>fs.rmSync(base,{recursive:true,force:true}));
 const nodeDir=path.join(base,'node');
 const meta=fed.initNode(nodeDir,owner,'ledger-test-node');
 const ledgerDir=path.join(base,'events');
 const publicPem=fs.readFileSync(path.join(nodeDir,'identity-public.pem'));
 return {base,nodeDir,ledgerDir,publicPem,meta};
}
test('genesis is signed by locally held sovereign identity and independently verified with public PEM',t=>{
 const x=lab(t);
 const created=ledger.initializeLedger({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,nowMs:NOW});
 assert.equal(created.entries,1);
 assert.equal(created.ownerFingerprint,x.meta.fingerprint);
 const verified=ledger.verifyLedger({ledgerDir:x.ledgerDir,publicPem:x.publicPem});
 assert.equal(verified.verified,true);
 assert.equal(verified.entries,1);
 assert.equal(verified.ownerFingerprint,x.meta.fingerprint);
 assert.match(verified.latestHash,/^[a-f0-9]{64}$/);
 assert.equal(fs.statSync(x.ledgerDir).mode&0o077,0);
 const entry=JSON.parse(fs.readFileSync(path.join(x.ledgerDir,'000000.json'),'utf8'));
 assert.equal(entry.kind,'GENESIS');
 assert.equal(entry.index,0);
 assert.equal(entry.prevHash,'0'.repeat(64));
 assert.ok(!JSON.stringify(entry).includes('PRIVATE KEY'));
});
test('event hashes link signed digests with monotonically ordered indices, no payload records',t=>{
 const x=lab(t);ledger.initializeLedger({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,nowMs:NOW});
 const first=ledger.appendDigest({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,kind:'TOYBOX_CHAIN_OBSERVED',payloadSha256:hex('public signed Toybox evidence'),nowMs:NOW+1});
 const second=ledger.appendDigest({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,kind:'OWNER_CORRECTION_DRAFTED',payloadSha256:hex('owner reviewed draft kept off GitHub'),nowMs:NOW+2});
 assert.equal(first.index,1);assert.equal(second.index,2);
 assert.equal(second.prevHash,first.entryHash);
 const proof=ledger.verifyLedger({ledgerDir:x.ledgerDir,publicPem:x.publicPem});
 assert.equal(proof.entries,3);assert.equal(proof.verified,true);
 const record=fs.readFileSync(path.join(x.ledgerDir,'000002.json'),'utf8');
 assert.ok(!record.includes('owner reviewed draft kept off GitHub'));
 assert.ok(!record.includes('wallet')); // source data never stored
});
test('tampering with payload digest or signature is rejected',t=>{
 const x=lab(t);ledger.initializeLedger({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,nowMs:NOW});
 ledger.appendDigest({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,kind:'DEVICE_HEALTH_OBSERVED',payloadSha256:hex('health'),nowMs:NOW+1});
 const file=path.join(x.ledgerDir,'000001.json');const o=JSON.parse(fs.readFileSync(file));o.payloadSha256='f'.repeat(64);fs.writeFileSync(file,JSON.stringify(o)+'\n');
 assert.throws(()=>ledger.verifyLedger({ledgerDir:x.ledgerDir,publicPem:x.publicPem}),/hash|signature|tamper|digest/i);
});
test('removal of indexed record, reordering and gaps are refused',t=>{
 const x=lab(t);ledger.initializeLedger({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,nowMs:NOW});
 ledger.appendDigest({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,kind:'DEVICE_HEALTH_OBSERVED',payloadSha256:hex('one'),nowMs:NOW+1});
 ledger.appendDigest({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,kind:'TOYBOX_CHAIN_OBSERVED',payloadSha256:hex('two'),nowMs:NOW+2});
 fs.unlinkSync(path.join(x.ledgerDir,'000001.json'));
 assert.throws(()=>ledger.verifyLedger({ledgerDir:x.ledgerDir,publicPem:x.publicPem}),/gap|index|missing|sequence/i);
});
test('wrong public identity, extra JSON fields and untrusted event kind fail closed',t=>{
 const x=lab(t),y=lab(t,'MOTOROLA');ledger.initializeLedger({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,nowMs:NOW});
 assert.throws(()=>ledger.verifyLedger({ledgerDir:x.ledgerDir,publicPem:y.publicPem}),/signature|identity|fingerprint/i);
 assert.throws(()=>ledger.appendDigest({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,kind:'FIRMWARE_FLASHED',payloadSha256:hex('fake'),nowMs:NOW+1}),/kind|event|forbidden/i);
 const file=path.join(x.ledgerDir,'000000.json'),o=JSON.parse(fs.readFileSync(file));o.claimedAuthority='court';fs.writeFileSync(file,JSON.stringify(o)+'\n');
 assert.throws(()=>ledger.verifyLedger({ledgerDir:x.ledgerDir,publicPem:x.publicPem}),/field|shape|schema|unexpected/i);
});
test('raw identity, stake, device and legal claim fields are rejected at entrypoint',t=>{
 const x=lab(t);ledger.initializeLedger({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,nowMs:NOW});
 assert.throws(()=>ledger.appendDigest({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,kind:'OWNER_CORRECTION_DRAFTED',payloadSha256:hex('x'),person:'Sensitive Name'}),/field|unknown|unsupported/i);
 assert.throws(()=>ledger.appendDigest({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,kind:'OWNER_CORRECTION_DRAFTED',payloadSha256:hex('x'),stake_amount:139}),/field|unknown|unsupported/i);
 assert.throws(()=>ledger.appendDigest({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,kind:'OWNER_CORRECTION_DRAFTED',payloadSha256:'not-a-digest'}),/digest|sha|invalid/i);
});
test('symlinked ledger and unsafe world-readable directory are rejected',t=>{
 const x=lab(t);ledger.initializeLedger({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,nowMs:NOW});
 const alias=path.join(x.base,'ledger-link');fs.symlinkSync(x.ledgerDir,alias);
 assert.throws(()=>ledger.verifyLedger({ledgerDir:alias,publicPem:x.publicPem}),/unsafe|symlink|permission/i);
 fs.chmodSync(x.ledgerDir,0o755);
 assert.throws(()=>ledger.verifyLedger({ledgerDir:x.ledgerDir,publicPem:x.publicPem}),/unsafe|permission/i);
});
test('time rollback and attempts to append while ledger locked fail without altering verified chain',t=>{
 const x=lab(t);ledger.initializeLedger({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,nowMs:NOW});
 assert.throws(()=>ledger.appendDigest({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,kind:'DEVICE_HEALTH_OBSERVED',payloadSha256:hex('clock'),nowMs:NOW-1}),/time|clock|rollback/i);
 fs.writeFileSync(path.join(x.ledgerDir,'.append.lock'),'locked',{flag:'wx',mode:0o600});
 assert.throws(()=>ledger.appendDigest({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,kind:'DEVICE_HEALTH_OBSERVED',payloadSha256:hex('late'),nowMs:NOW+1}),/lock|busy|blocked/i);
 fs.unlinkSync(path.join(x.ledgerDir,'.append.lock'));
 assert.equal(ledger.verifyLedger({ledgerDir:x.ledgerDir,publicPem:x.publicPem}).entries,1);
});
test('unexpected files, malformed JSON and torn/unfinalized bytes are a HOLD',t=>{
 const x=lab(t);ledger.initializeLedger({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,nowMs:NOW});
 fs.writeFileSync(path.join(x.ledgerDir,'000001.json'),'{' ,{mode:0o600});
 assert.throws(()=>ledger.verifyLedger({ledgerDir:x.ledgerDir,publicPem:x.publicPem}),/json|invalid|malformed|parse/i);
 fs.unlinkSync(path.join(x.ledgerDir,'000001.json'));
 fs.writeFileSync(path.join(x.ledgerDir,'orphan.tmp'),'trailing',{mode:0o600});
 assert.throws(()=>ledger.verifyLedger({ledgerDir:x.ledgerDir,publicPem:x.publicPem}),/file|unexpected|orphan|unsafe/i);
});
test('ledger carries no court/legal/payout authority and has distinct signed owner history',t=>{
 const x=lab(t),y=lab(t,'MOTOROLA');
 ledger.initializeLedger({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,nowMs:NOW});
 ledger.initializeLedger({nodeDir:y.nodeDir,ledgerDir:y.ledgerDir,nowMs:NOW});
 ledger.appendDigest({nodeDir:x.nodeDir,ledgerDir:x.ledgerDir,kind:'OWNER_CORRECTION_DRAFTED',payloadSha256:hex('draft evidence'),nowMs:NOW+3});
 assert.notEqual(ledger.verifyLedger({ledgerDir:x.ledgerDir,publicPem:x.publicPem}).ownerFingerprint,ledger.verifyLedger({ledgerDir:y.ledgerDir,publicPem:y.publicPem}).ownerFingerprint);
 const entries=fs.readdirSync(x.ledgerDir).filter(f=>f.endsWith('.json')).map(f=>JSON.parse(fs.readFileSync(path.join(x.ledgerDir,f))));
 assert.ok(entries.every(e=>!('authorizedPayment' in e)&&!('legalImmunity' in e)&&!('soul_id' in e)&&!('device_id' in e)));
});