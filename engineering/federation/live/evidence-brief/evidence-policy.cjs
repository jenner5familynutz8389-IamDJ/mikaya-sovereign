'use strict';
/** Public MIKAYA evidence brief: schema and minimum-disclosure gates.
 * A status is a citation to evidence of a defined type, not automatic attestation.
 */
const fs=require('node:fs');
const path=require('node:path');
const STATES=new Set(['TESTED_AT_DATE','HISTORICAL_SOURCE','DESIGN','NEEDS_REPRODUCTION','BLOCKED','OWNER_REVIEW','COUNSEL_REVIEW']);
const SECTIONS=['provable','vision','gaps','ip'];
const SCHEMA='mikaya.sovereign.evidence-brief.v1';
const isObject=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const exact=(obj,keys)=>isObject(obj)&&Object.keys(obj).sort().join('|')===keys.slice().sort().join('|');
function requireText(text,label,max=1600){if(typeof text!=='string'||text.trim().length===0||text.length>max)throw Error('invalid '+label);}
function assertPublicData(doc){
 const raw=JSON.stringify(doc);
 if(/\b(?:IMEI|IMSI|ICCID|macaroon|seed phrase|private key|admin\.macaroon|account_topology\.json)\b/i.test(raw))throw Error('private-identifying or credential field in public brief');
 if(/\bbc1[qp][a-z0-9]{20,90}\b/i.test(raw))throw Error('Bitcoin address not allowed in public evidence brief');
 if(/\b(?:\d[ -]?){15,16}\b/.test(raw))throw Error('long numeric identifier not allowed in public evidence brief');
 return true;
}
function validateBrief(doc){
 if(!exact(doc,['schema','title','subtitle','preparedAt','publication','verificationNote','sections']))throw Error('brief top-level schema invalid');
 if(doc.schema!==SCHEMA||doc.publication!=='PUBLIC_REVIEW_ONLY'||!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(doc.preparedAt))throw Error('brief metadata invalid');
 for(const k of ['title','subtitle','verificationNote'])requireText(doc[k],k);
 if(!Array.isArray(doc.sections)||doc.sections.length!==4||doc.sections.map(x=>x.id).join('|')!==SECTIONS.join('|'))throw Error('four original sections required');
 const seen=new Set();
 for(const section of doc.sections){
  if(!exact(section,['id','label','intro','items'])||!Array.isArray(section.items)||section.items.length<1)throw Error('section invalid');
  requireText(section.label,'section label');requireText(section.intro,'section intro');
  for(const item of section.items){
   if(!exact(item,['id','claim','status','detail','evidence','next'])||!/^[a-z][a-z0-9-]{1,40}$/.test(item.id)||seen.has(item.id))throw Error('claim schema or duplicate invalid');
   seen.add(item.id);for(const k of ['claim','detail','evidence','next'])requireText(item[k],k);
   if(!STATES.has(item.status))throw Error('unknown claim status');
   if(item.status==='TESTED_AT_DATE'&&!/test|verified|signed|checked|MR !97/i.test(item.evidence+' '+item.detail))throw Error('tested claim requires stated evidence');
  }
 }
 assertPublicData(doc);
 return {valid:true,sections:doc.sections.length,items:seen.size,publication:doc.publication};
}
function loadBrief(file=path.join(__dirname,'evidence-brief.json')){const doc=JSON.parse(fs.readFileSync(file,'utf8'));validateBrief(doc);return doc;}
if(require.main===module){try{console.log(JSON.stringify(validateBrief(loadBrief(process.argv[2]))))}catch(e){console.error('EVIDENCE_BRIEF_HOLD: '+e.message);process.exitCode=2;}}
module.exports={validateBrief,loadBrief,assertPublicData,STATES};
