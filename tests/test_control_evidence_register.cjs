'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const ROOT=path.resolve(__dirname,'..');
function register(){return JSON.parse(fs.readFileSync(path.join(ROOT,'docs/security/CONTROL_EVIDENCE_20261121.json'),'utf8'));}
test('government audit register refuses unearned government certifications',()=>{
 const d=register();assert.equal(d.schema,'mikaya.control-evidence-register.v1');
 assert.equal(d.governmentCertified,false);assert.equal(d.fedrampAuthorized,false);
 assert.equal(d.actAdmission,false);assert.equal(d.paymentSettlementVerified,false);
});
test('covers all six NIST CSF 2.0 functions and separate privacy, AI and supply-chain control families',()=>{
 const d=register(),entries=d.controls;
 assert.ok(entries.length>=14);
 const f=new Set(entries.flatMap(e=>e.frameworks));
 for(const x of ['NIST-CSF-GV','NIST-CSF-ID','NIST-CSF-PR','NIST-CSF-DE','NIST-CSF-RS','NIST-CSF-RC',
  'NIST-SSDF','NIST-AI-RMF','ISO-27001','ISO-42001','GDPR','EU-CRA','US-FEDERAL-SCOPE'])
  assert.ok(f.has(x),'missing '+x);
});
test('every claim resolves to a checked-in, non-symlink public source and distinguishes evidence classes',()=>{
 const d=register(),seen=new Set();
 for(const e of d.controls){
  assert.match(e.id,/^[A-Z][A-Z0-9_]{3,56}$/);
  assert.ok(!seen.has(e.id));seen.add(e.id);
  assert.ok(['SOURCE_IMPLEMENTED','HISTORICAL_EVIDENCE','REQUIRED_EXTERNAL'].includes(e.status));
  assert.ok(e.scope.length>=10 && e.nextEvidence.length>=15);
  assert.ok(Array.isArray(e.sourcePaths)&&e.sourcePaths.length>0);
  for(const rel of e.sourcePaths){
   assert.ok(!rel.startsWith('/')&&!rel.includes('..')&&!rel.includes('\\'));
   const p=path.join(ROOT,rel);
   assert.ok(fs.statSync(p).isFile(),rel);
   assert.equal(fs.lstatSync(p).isSymbolicLink(),false);
  }
  if(e.status==='REQUIRED_EXTERNAL')assert.equal(e.certified,false);
 }
});
test('nonmonetary compute receipts and historical Toybox anchors never certify settled dividends',()=>{
 const d=register();
 const economic=d.controls.find(e=>e.id==='FINANCIAL_SETTLEMENT_SCOPE');
 assert.ok(economic);assert.equal(economic.status,'REQUIRED_EXTERNAL');
 assert.match(economic.scope,/one shared 5% pool/i);
 assert.equal(economic.certified,false);
});
test('future ACT admission is distinct from currently proven owner-phone transport',()=>{
 const d=register();
 const a=d.controls.find(e=>e.id==='ACT_PARTNER_ADMISSION');
 assert.equal(a.status,'REQUIRED_EXTERNAL');assert.equal(d.actAdmission,false);
 const b=d.controls.find(e=>e.id==='PHYSICAL_TWO_DEVICE_EVIDENCE');
 assert.equal(b.status,'HISTORICAL_EVIDENCE');
});
