#!/usr/bin/env node
'use strict';
// Owner-local staged certificate continuity. No automatic peer trust, restart,
// clearing of the kill switch, identity replacement, payment or ACT admission.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),cp=require('node:child_process');
const direct=require('./direct-transport.cjs'),fed=require('../live/federation-node.cjs');
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const ensure=(x,m)=>{if(!x)throw Error(m)};
const names=['tls-public.pem','public-peer.json','pinned-peer.json','owner-policy.json'];
const journal='certificate-rotation-journal.json';
function dirFor(state){
 ensure(path.isAbsolute(state),'absolute state directory required');
 for(const p of [state,path.join(state,'direct-transport')]){
  const s=fs.lstatSync(p);ensure(s.isDirectory()&&!s.isSymbolicLink()&&!(s.mode&0o077)&&s.uid===process.getuid(),'private state directory required');
 }
 return path.join(state,'direct-transport');
}
function read(p,max=262144){
 const fd=fs.openSync(p,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{const st=fs.fstatSync(fd);ensure(st.isFile()&&st.nlink===1&&!(st.mode&0o077)&&st.uid===process.getuid()&&st.size<=max,'unsafe rotation input');const b=fs.readFileSync(fd);ensure(b.length<=max,'input grew');return b}finally{fs.closeSync(fd)}
}
function json(p){return JSON.parse(read(p).toString('utf8'))}
function syncDir(d){const fd=fs.openSync(d,fs.constants.O_RDONLY);try{fs.fsyncSync(fd)}finally{fs.closeSync(fd)}}
function writeNew(p,b){const fd=fs.openSync(p,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);try{fs.writeFileSync(fd,b);fs.fsyncSync(fd)}finally{fs.closeSync(fd)}}
function replace(p,b){read(p);const t=p+'.rotation-'+crypto.randomBytes(12).toString('hex');try{writeNew(t,b);fs.renameSync(t,p);syncDir(path.dirname(p))}finally{if(fs.existsSync(t))fs.unlinkSync(t)}}
const cert=p=>new crypto.X509Certificate(p.tlsCertificatePem);
const der=k=>k.export({type:'spki',format:'der'});
function historical(p){const c=cert(p);return direct.validatePeer(p,Date.parse(c.validFrom))}
function identity(state,d,old){
 const k=crypto.createPrivateKey(json(path.join(state,'synthetic-keys.json')).privateKey);
 const tls=crypto.createPrivateKey(read(path.join(d,'tls-private.pem')));
 ensure(der(crypto.createPublicKey(k)).equals(der(crypto.createPublicKey(old.publicKey)))&&cert(old).checkPrivateKey(tls),'local identity continuity failed');
 return {k,tls};
}
function renew(state,days=7){
 ensure(Number.isInteger(days)&&days>=1&&days<=14,'certificate lifetime refused');
 const d=dirFor(state),old=historical(json(path.join(d,'public-peer.json'))),{k}=identity(state,d,old);
 const r=cp.spawnSync('openssl',['req','-new','-x509','-key',path.join(d,'tls-private.pem'),'-days',String(days),'-config',path.join(d,'certificate.conf')],{encoding:'utf8',timeout:10000,maxBuffer:8192});
 ensure(r.status===0,'certificate issuance failed');
 const {signature,...base}=old,c=new crypto.X509Certificate(r.stdout);
 const body={...base,tlsCertificatePem:r.stdout,tlsCertificateSha256:hash(c.raw)};
 const result={...body,signature:crypto.sign(null,Buffer.from('MIKAYA-INTEROP-DIRECT/1\nPEER\n'+fed.canonical(body)),k).toString('base64')};
 transition(old,result);return result;
}
function transition(old,next){
 historical(old);direct.validatePeer(next);
 ensure(old.fingerprint===next.fingerprint&&old.publicKey===next.publicKey&&old.profileSha256===next.profileSha256&&der(cert(old).publicKey).equals(der(cert(next).publicKey)),'identity continuity refused');
 ensure(old.tlsCertificateSha256!==next.tlsCertificateSha256&&Date.parse(cert(next).validTo)>Date.parse(cert(old).validTo),'certificate must advance');
}
function offline(d){
 const p=direct.validatePolicy(json(path.join(d,'owner-policy.json')));
 ensure(p.enabled===false&&fs.existsSync(path.join(d,'kill-switch'))&&!fs.existsSync(path.join(d,'server.lock'))&&!fs.existsSync(path.join(d,'supervisor.json')),'offline rotation requires verified stopped service and existing kill marker');
 read(path.join(d,'kill-switch'));return p;
}
const encode=b=>Buffer.from(b).toString('base64');
const bytes=x=>Buffer.from(x,'base64');
const jsonBytes=x=>Buffer.from(JSON.stringify(x,null,2)+'\n');
function plan(state,ownNext,peerNext){
 const d=dirFor(state),p=offline(d),own=historical(json(path.join(d,'public-peer.json'))),peer=historical(json(path.join(d,'pinned-peer.json')));
 ensure(p.peerFingerprint===peer.fingerprint&&p.peerCertificateSha256===peer.tlsCertificateSha256&&own.fingerprint!==peer.fingerprint,'existing pair mismatch');
 ensure(hash(new crypto.X509Certificate(read(path.join(d,'tls-public.pem'))).raw)===own.tlsCertificateSha256,'local certificate mismatch');
 const {tls}=identity(state,d,own);transition(own,ownNext);transition(peer,peerNext);ensure(cert(ownNext).checkPrivateKey(tls),'renewed local certificate key mismatch');
 const replacements=[Buffer.from(ownNext.tlsCertificatePem),jsonBytes(ownNext),jsonBytes(peerNext),jsonBytes({...p,peerCertificateSha256:peerNext.tlsCertificateSha256})];
 const body={schema:'mikaya.interop.offline-rotation.v1',files:Object.fromEntries(names.map((n,i)=>[n,{before:encode(read(path.join(d,n))),after:encode(replacements[i])}]))};
 return {...body,digest:hash(fed.canonical(body))};
}
function apply(state,ownNext,peerNext,expected){
 const d=dirFor(state),p=plan(state,ownNext,peerNext);
 ensure(expected===p.digest,'rotation plan digest mismatch');
 writeNew(path.join(d,journal),jsonBytes(p));syncDir(d);
 for(const n of names){offline(d);const f=path.join(d,n);ensure(read(f).equals(bytes(p.files[n].before)),'concurrent state change refused');replace(f,bytes(p.files[n].after))}
 const own=direct.loadOwn(state),auth=direct.loadAuthority(own,false);ensure(!auth.policy.enabled&&auth.peer.tlsCertificateSha256===peerNext.tlsCertificateSha256,'post-rotation validation failed');
 return {status:'ROTATED_DISABLED',digest:p.digest,killSwitchPreserved:true};
}
function rollback(state,expected){
 const d=dirFor(state);offline(d);const p=json(path.join(d,journal));
 const {digest,...body}=p;ensure(digest===expected&&digest===hash(fed.canonical(body))&&p.schema==='mikaya.interop.offline-rotation.v1'&&Object.keys(p.files).sort().join('|')===[...names].sort().join('|'),'rollback digest mismatch');
 for(const n of names){const b=read(path.join(d,n)),r=p.files[n];ensure(b.equals(bytes(r.before))||b.equals(bytes(r.after)),'unexpected concurrent state; manual reconciliation required')}
 for(const n of names){offline(d);replace(path.join(d,n),bytes(p.files[n].before))}
 return {status:'ROLLED_BACK_DISABLED',digest,killSwitchPreserved:true};
}
if(require.main===module){
 try{
  const [cmd,state,a,b,c]=process.argv.slice(2);
  if(cmd==='renew'){ensure(a&& !b,'renew requires new public output path');writeNew(path.resolve(a),jsonBytes(renew(state)));console.log(JSON.stringify({status:'STAGED_NOT_ACTIVATED'}))}
  else if(cmd==='plan'){const p=plan(state,json(path.resolve(a)),json(path.resolve(b)));console.log(JSON.stringify({status:'PLAN_ONLY',digest:p.digest,killSwitchPreserved:true}))}
  else if(cmd==='apply')console.log(JSON.stringify(apply(state,json(path.resolve(a)),json(path.resolve(b)),c)));
  else if(cmd==='rollback')console.log(JSON.stringify(rollback(state,a)));
  else throw Error('usage: renew STATE NEW_PUBLIC_FILE | plan STATE OWN_PUBLIC PEER_PUBLIC | apply STATE OWN_PUBLIC PEER_PUBLIC DIGEST | rollback STATE DIGEST');
 }catch(e){console.error(JSON.stringify({status:'HOLD',reason:String(e.message).slice(0,200)}));process.exitCode=2}
}
module.exports={renew,plan,apply,rollback};
