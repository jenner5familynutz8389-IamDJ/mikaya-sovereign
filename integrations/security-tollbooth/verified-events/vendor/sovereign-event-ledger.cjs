#!/usr/bin/env node
'use strict';
/**
 * MIKAYA sovereign event-spine v1 — source-reproducible integrity-only ledger.
 * All private signing keys remain inside an existing owner-controlled local node.
 * Never records raw identity, medical, dispute, wallet or financial data.
 * A SHA digest or signature does not prove that its underlying assertion is true.
 * This code does not auto-file, issue refunds, grant legal immunity, or spend funds.
 */
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const fed=require('./federation-node.cjs');
const DOMAIN='MIKAYA-SOVEREIGN-LOCAL-EVENT-SPINE/1\n';
const FIELDS=['schema','index','prevHash','nodeFingerprint','kind','payloadSha256','issuedAtMs','nonce','entryHash','signature'];
const UNSIGNED=FIELDS.filter(x=>!['signature','entryHash'].includes(x));
const KINDS=new Set(['GENESIS','DEVICE_HEALTH_OBSERVED','TOYBOX_CHAIN_OBSERVED',
 'FEDERATION_COMPUTE_OBSERVED','OWNER_CORRECTION_DRAFTED','OWNER_EVIDENCE_REVIEWED']);
const SHA=/^[a-f0-9]{64}$/;
const NONCE=/^[a-f0-9]{32}$/;
const FILE=/^([0-9]{6})\.json$/;
const O=fs.constants;
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const fail=s=>{throw Error(s);};
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,fields)=>plain(x)&&Object.keys(x).sort().join('|')===[...fields].sort().join('|');
const filename=i=>String(i).padStart(6,'0')+'.json';
function secureDir(dir){
 const st=fs.lstatSync(dir);
 if(!st.isDirectory()||st.isSymbolicLink()||(st.mode&0o077))fail('unsafe ledger directory permissions or symlink');
 return dir;
}
function secureFile(file){
 const st=fs.lstatSync(file);
 if(!st.isFile()||st.isSymbolicLink()||(st.mode&0o077)||st.size>2200)fail('unsafe ledger entry file permissions or size');
 return fs.readFileSync(file,'utf8');
}
function activeNames(ledgerDir){
 secureDir(ledgerDir);
 const names=fs.readdirSync(ledgerDir);
 if(names.length>4097)fail('ledger too large');
 const entries=[];
 for(const name of names){
  if(name==='.append.lock')continue;
  if(!FILE.test(name))fail('unexpected ledger file or unfinished atomic write');
  entries.push(name);
 }
 return entries.sort();
}
function verifyLedger({ledgerDir,publicPem}){
 if(arguments.length!==1||!plain(arguments[0])||!exact(arguments[0],['ledgerDir','publicPem']))fail('unsupported verification field');
 if(!Buffer.isBuffer(publicPem)&&typeof publicPem!=='string')fail('public PEM required');
 const pub=crypto.createPublicKey(publicPem);
 const fp=fed.fp(pub);
 const files=activeNames(ledgerDir);
 if(!files.length)fail('missing ledger genesis');
 let lastHash='0'.repeat(64),lastTime=-1;
 const nonces=new Set();
 for(let i=0;i<files.length;i++){
  const file=files[i];
  if(file!==filename(i))fail('ledger index gap or sequence mismatch');
  const txt=secureFile(path.join(ledgerDir,file));
  let row;
  try{row=JSON.parse(txt);}catch{fail('malformed ledger JSON entry');}
  if(!exact(row,FIELDS)||row.schema!=='mikaya.sovereign.event.v1')fail('unexpected ledger entry field or schema');
  if(txt!==fed.canonical(row)+'\n')fail('noncanonical entry digest serialization refused');
  if(row.index!==i||!Number.isSafeInteger(row.index)||row.prevHash!==lastHash||!SHA.test(row.prevHash))fail('ledger index or previous hash mismatch');
  if(row.nodeFingerprint!==fp||!SHA.test(row.nodeFingerprint))fail('ledger owner public identity fingerprint mismatch');
  if(!KINDS.has(row.kind)||(i===0)!==(row.kind==='GENESIS'))fail('ledger event kind invalid');
  if(!SHA.test(row.payloadSha256)||!Number.isSafeInteger(row.issuedAtMs)||row.issuedAtMs<lastTime||row.issuedAtMs<0)fail('event digest or time rollback invalid');
  if(!NONCE.test(row.nonce)||nonces.has(row.nonce))fail('ledger nonce invalid or replay');
  nonces.add(row.nonce);
  const unsigned={};for(const k of UNSIGNED)unsigned[k]=row[k];
  const expected=sha(DOMAIN+'HASH\n'+fed.canonical(unsigned));
  if(row.entryHash!==expected)fail('ledger entry hash digest mismatch');
  if(typeof row.signature!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(row.signature))fail('ledger signature malformed');
  const sig=Buffer.from(row.signature,'base64');
  if(sig.length!==64||sig.toString('base64')!==row.signature||
   !crypto.verify(null,Buffer.from(DOMAIN+'SIGN\n'+row.entryHash),pub,sig))fail('ledger signature invalid');
  lastHash=row.entryHash;lastTime=row.issuedAtMs;
 }
 return {schema:'mikaya.sovereign.event-verification.v1',verified:true,entries:files.length,
  ownerFingerprint:fp,latestHash:lastHash,latestAtMs:lastTime,hardwareAttested:false,
  ownerPermissionsGranted:false,paymentAuthorized:false,legalEffect:'NONE_FROM_CRYPTOGRAPHIC_LEDGER'};
}
function writeEvent(ledgerDir,row){
 const name=filename(row.index),dest=path.join(ledgerDir,name);
 const tmp=path.join(ledgerDir,'.'+name+'.'+row.nonce+'.tmp');
 let fd;
 try{
  fd=fs.openSync(tmp,O.O_WRONLY|O.O_CREAT|O.O_EXCL|(O.O_NOFOLLOW||0),0o600);
  fs.writeFileSync(fd,fed.canonical(row)+'\n','utf8');
  fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
  // An existing target means a concurrent appender is active or data was modified.
  if(fs.existsSync(dest))fail('ledger index race; refusing overwrite');
  fs.renameSync(tmp,dest);
 }catch(e){if(fd!==undefined)fs.closeSync(fd);if(fs.existsSync(tmp))fs.unlinkSync(tmp);throw e;}
}
function signedRow({node,index,prevHash,kind,payloadSha256,issuedAtMs}){
 const unsigned={schema:'mikaya.sovereign.event.v1',index,prevHash,
  nodeFingerprint:node.meta.fingerprint,kind,payloadSha256,issuedAtMs,
  nonce:crypto.randomBytes(16).toString('hex')};
 const entryHash=sha(DOMAIN+'HASH\n'+fed.canonical(unsigned));
 const signature=crypto.sign(null,Buffer.from(DOMAIN+'SIGN\n'+entryHash),node.privateKey).toString('base64');
 return {...unsigned,entryHash,signature};
}
function initializeLedger(input){
 if(!exact(input,['nodeDir','ledgerDir','nowMs'])&&!exact(input,['nodeDir','ledgerDir']))fail('unsupported initialization field');
 const {nodeDir,ledgerDir,nowMs=Date.now()}=input;
 if(!Number.isSafeInteger(nowMs)||nowMs<0)fail('invalid genesis time');
 const node=fed.loadNode(nodeDir);
 // Exclusive directory creation prevents overwriting a prior ledger.
 fs.mkdirSync(ledgerDir,{mode:0o700});secureDir(ledgerDir);
 const genesis=signedRow({node,index:0,prevHash:'0'.repeat(64),kind:'GENESIS',
  payloadSha256:sha(DOMAIN+'GENESIS:'+node.meta.fingerprint),issuedAtMs:nowMs});
 writeEvent(ledgerDir,genesis);
 return verifyLedger({ledgerDir,publicPem:node.publicKey});
}
function appendDigest(input){
 if(!exact(input,['nodeDir','ledgerDir','kind','payloadSha256'])&&
 !exact(input,['nodeDir','ledgerDir','kind','payloadSha256','nowMs']))fail('unknown or unsupported input field');
 const {nodeDir,ledgerDir,kind,payloadSha256,nowMs=Date.now()}=input;
 if(!KINDS.has(kind)||kind==='GENESIS')fail('forbidden event kind');
 if(!SHA.test(payloadSha256))fail('payload SHA-256 digest invalid');
 if(!Number.isSafeInteger(nowMs)||nowMs<0)fail('invalid event time');
 secureDir(ledgerDir);
 const lock=path.join(ledgerDir,'.append.lock');
 let fd;
 try{fd=fs.openSync(lock,O.O_WRONLY|O.O_CREAT|O.O_EXCL|(O.O_NOFOLLOW||0),0o600);fs.closeSync(fd);fd=undefined;}
 catch{fail('ledger append locked or busy');}
 try{
  const node=fed.loadNode(nodeDir);
  const last=verifyLedger({ledgerDir,publicPem:node.publicKey});
  if(nowMs<last.latestAtMs)fail('ledger clock rollback refused');
  if(last.entries>=4096)fail('ledger full; start a newly signed successor ledger');
  const row=signedRow({node,index:last.entries,prevHash:last.latestHash,kind,payloadSha256,issuedAtMs:nowMs});
  writeEvent(ledgerDir,row);
  return {schema:row.schema,index:row.index,prevHash:row.prevHash,entryHash:row.entryHash,
    ownerFingerprint:row.nodeFingerprint,paymentAuthorized:false};
 }finally{fs.unlinkSync(lock);}
}
function main(args=process.argv.slice(2)){
 const [cmd,...rest]=args;
 if(cmd==='init'&&rest.length===2)return console.log(fed.canonical(initializeLedger({nodeDir:rest[0],ledgerDir:rest[1]})));
 if(cmd==='append'&&rest.length===4)return console.log(fed.canonical(appendDigest({nodeDir:rest[0],ledgerDir:rest[1],kind:rest[2],payloadSha256:rest[3]})));
 if(cmd==='verify'&&rest.length===2)return console.log(fed.canonical(verifyLedger({ledgerDir:rest[0],publicPem:fs.readFileSync(rest[1])})));
 fail('usage: init NODE_DIR PRIVATE_LEDGER_DIR | append NODE_DIR LEDGER_DIR ALLOWED_EVENT_KIND PUBLIC_SHA256 | verify LEDGER_DIR PINNED_PUBLIC_PEM');
}
if(require.main===module){try{main();}catch(e){console.error('MIKAYA_LEDGER_HOLD: '+e.message);process.exitCode=2;}}
module.exports={initializeLedger,appendDigest,verifyLedger};