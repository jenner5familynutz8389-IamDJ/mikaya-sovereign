#!/usr/bin/env node
'use strict';
/**
 * MIKAYA TOYBOX: public/read-only, dual-explorer confirmed chain anchor.
 * Uses the same LOCAL Ed25519 identity as sovereign federation for signing.
 * No wallet/UTXO operation, no transaction broadcast, no L402/macaroon proof,
 * no private-key movement, no remote execution, no automatic monitoring.
 * Historical confirmed tx is NOT in today's unconfirmed mempool.
 */
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const HASH=/^[0-9a-f]{64}$/;
const DOMAIN='MIKAYA-TOYBOX-PUBLIC-CHAIN-EVENT/1\n';
const TXID='8cd0125081b40e01df124fd66adc68638b552c0693bccceb15d4485bdb47c9c8';
const BLOCK='00000000000000000001dc4084eff84a44b5be05eca6f2c0fc231588afc085ae';
const HEIGHT=961297;
const OUTPUT_INDEX=1,AMOUNT=18369,FEE=617,BLOCK_TIME=1786023233;
const PROVIDERS=Object.freeze(['https://mempool.space/api','https://blockstream.info/api']);
const MAX_BODY=200000;
function fail(x){throw Error(x)}
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&Object.getPrototypeOf(x)===Object.prototype;
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join('|')===[...keys].sort().join('|');
function canonical(x){
 if(x===null||typeof x==='string'||typeof x==='boolean')return JSON.stringify(x);
 if(typeof x==='number'&&Number.isSafeInteger(x))return JSON.stringify(x);
 if(Array.isArray(x))return '['+x.map(canonical).join(',')+']';
 if(plain(x))return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';
 fail('noncanonical value');
}
function sha(x){return crypto.createHash('sha256').update(x).digest('hex')}
function fingerprint(pem){const key=pem?.type==='public'?pem:crypto.createPublicKey(pem);return sha(key.export({format:'pem',type:'spki'}))}
function safeFile(file,max=MAX_BODY){const st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||st.size>max||(st.mode&0o022))fail('unsafe file type or permissions');return fs.readFileSync(file)}
function loadLocalIdentity(dir){
 const st=fs.lstatSync(dir);if(!st.isDirectory()||st.isSymbolicLink()||(st.mode&0o077))fail('unsafe owner directory');
 const pub=safeFile(path.join(dir,'identity-public.pem'),4096),privFile=path.join(dir,'identity-private.pem'),ps=fs.lstatSync(privFile);
 if(!ps.isFile()||ps.isSymbolicLink()||(ps.mode&0o077))fail('owner private key permissions unsafe');
 const priv=safeFile(privFile,4096),meta=JSON.parse(safeFile(path.join(dir,'node.json'),4096));
 const fp=fingerprint(pub);
 if(!exact(meta,['schema','owner','nodeId','fingerprint','capabilities','platform'])||meta.schema!=='mikaya.federation.node.v1'||
 !['MIKAYA','MOTOROLA','ACT-OMEGA'].includes(meta.owner)||!/^[-_A-Za-z0-9]{2,64}$/.test(meta.nodeId)||meta.fingerprint!==fp||
 fingerprint(crypto.createPublicKey(crypto.createPrivateKey(priv)))!==fp)fail('sovereign identity mismatch');
 return {fp,owner:meta.owner,nodeId:meta.nodeId,publicKey:pub,privateKey:priv};
}
async function fetchBounded(fetchImpl,url){
 const u=new URL(url);
 if(u.protocol!=='https:'||!PROVIDERS.some(p=>u.origin===new URL(p).origin)||u.username||u.password||u.search||u.hash)fail('unapproved explorer endpoint');
 const res=await fetchImpl(url,{method:'GET',redirect:'error',signal:AbortSignal.timeout(10000),headers:{'Accept':'application/json, text/plain'}});
 if(!res||res.ok!==true||res.status!==200)fail('explorer HTTP or redirect response refused');
 let s;
 if(res.body&&typeof res.body.getReader==='function'){
  const reader=res.body.getReader();let total=0,parts=[];
  try{while(true){const {done,value}=await reader.read();if(done)break;total+=value.length;if(total>MAX_BODY)fail('explorer body too large');parts.push(Buffer.from(value));}}
  finally{reader.releaseLock()}
  s=Buffer.concat(parts).toString('utf8');
 }else if(typeof res.text==='function'){s=await res.text();if(Buffer.byteLength(s)>MAX_BODY)fail('explorer body too large');}
 else fail('unsupported explorer response');
 if(s.length===0)fail('explorer returned empty response');return s;
}
function validatedTx(tx,label){
 if(!plain(tx)||tx.txid!==TXID)fail(label+' transaction mismatch');
 const st=tx.status;
 if(!plain(st)||st.confirmed!==true)fail(label+' transaction is unconfirmed');
 if(st.block_height!==HEIGHT||st.block_hash!==BLOCK||st.block_time!==BLOCK_TIME)fail(label+' block anchor mismatch');
 if(tx.fee!==FEE||!Array.isArray(tx.vout)||tx.vout.length>100000)fail(label+' fee or outputs invalid');
 // The public peer bridge binds the already-established TXID and output
 // position/amount without publishing the owner's receiving wallet address.
 // Address ownership, if required, is separately reviewed in the private
 // source receipt; this public observation does NOT prove wallet control.
 const output=tx.vout[OUTPUT_INDEX];
 if(!plain(output)||output.value!==AMOUNT||typeof output.scriptpubkey!=='string'&&typeof output.scriptpubkey_address!=='string')
  fail(label+' expected recipient output index or amount mismatch');
 return {txid:TXID,blockHash:BLOCK,blockHeight:HEIGHT,blockTime:BLOCK_TIME,feeSats:FEE,outputIndex:OUTPUT_INDEX,amountSats:AMOUNT};
}
async function providerSnapshot(base,fetchImpl){
 const tx=JSON.parse(await fetchBounded(fetchImpl,base+'/tx/'+TXID));
 const t=validatedTx(tx,new URL(base).hostname);
 const canonicalHash=(await fetchBounded(fetchImpl,base+'/block-height/'+HEIGHT)).trim();
 if(canonicalHash!==BLOCK)fail('reorg or block height hash mismatch');
 const status=JSON.parse(await fetchBounded(fetchImpl,base+'/block/'+BLOCK+'/status'));
 if(!plain(status)||status.in_best_chain!==true)fail('reorg or block missing from best chain');
 const tipString=(await fetchBounded(fetchImpl,base+'/blocks/tip/height')).trim();
 if(!/^\d{1,9}$/.test(tipString))fail('invalid explorer chain tip');
 const tip=Number(tipString);
 if(!Number.isSafeInteger(tip)||tip<HEIGHT+5)fail('insufficient chain confirmations');
 return {...t,tipHeight:tip,confirmations:tip-HEIGHT+1};
}
async function observeToybox({fetchImpl=fetch,nowMs=Date.now()}={}){
 if(typeof fetchImpl!=='function'||!Number.isSafeInteger(nowMs)||nowMs<=0)fail('invalid read-only observation configuration');
 const a=await providerSnapshot(PROVIDERS[0],fetchImpl);
 const b=await providerSnapshot(PROVIDERS[1],fetchImpl);
 if(canonical(a)!==canonical(b))fail('independent explorer providers disagree on chain anchor or tip');
 return {schema:'mikaya.toybox.chain-observation.v1',alias:'MIKAYA-TOYBOX',chain:'bitcoin-mainnet',
  scope:'HISTORICAL_ONCHAIN_ANCHOR_NOT_CURRENT_MEMPOOL_ITEM',status:'CONFIRMED_BEST_CHAIN',
  anchor:{txid:a.txid,height:a.blockHeight,blockHash:a.blockHash,blockTime:a.blockTime,
   confirmations:a.confirmations,tipHeight:a.tipHeight,receivedSats:a.amountSats,outputIndex:a.outputIndex,feeSats:a.feeSats},
  checkedAtMs:nowMs,sourceCount:2,paymentAuthorization:'NONE',settlementVerified:false,
  executableAuthority:false,walletAccess:false,anchorOwnerVerified:false};
}
const OB_KEYS=['schema','alias','chain','scope','status','anchor','checkedAtMs','sourceCount','paymentAuthorization','settlementVerified','executableAuthority','walletAccess','anchorOwnerVerified'];
const AN_KEYS=['txid','height','blockHash','blockTime','confirmations','tipHeight','receivedSats','outputIndex','feeSats'];
function validateObservation(ob){
 if(!exact(ob,OB_KEYS)||ob.schema!=='mikaya.toybox.chain-observation.v1'||ob.alias!=='MIKAYA-TOYBOX'||ob.chain!=='bitcoin-mainnet'||
 ob.scope!=='HISTORICAL_ONCHAIN_ANCHOR_NOT_CURRENT_MEMPOOL_ITEM'||ob.status!=='CONFIRMED_BEST_CHAIN'||
 ob.paymentAuthorization!=='NONE'||ob.settlementVerified!==false||ob.executableAuthority!==false||ob.walletAccess!==false||ob.anchorOwnerVerified!==false||
 ob.sourceCount!==2||!Number.isSafeInteger(ob.checkedAtMs)||ob.checkedAtMs<=0||!exact(ob.anchor,AN_KEYS))fail('invalid or sensitive Toybox observation shape');
 const a=ob.anchor;
 if(a.txid!==TXID||a.blockHash!==BLOCK||a.height!==HEIGHT||a.blockTime!==BLOCK_TIME||a.receivedSats!==AMOUNT||a.outputIndex!==OUTPUT_INDEX||a.feeSats!==FEE||
 !Number.isSafeInteger(a.tipHeight)||a.tipHeight<HEIGHT+5||a.confirmations!==a.tipHeight-HEIGHT+1)fail('Toybox chain anchor altered');
 return true;
}
const SIGNED_KEYS=['schema','owner','nodeId','signerFingerprint','issuedAtMs','observation','signature'];
function signObservation({dir,observation,nowMs=Date.now()}){
 validateObservation(observation);
 if(!Number.isSafeInteger(nowMs)||Math.abs(observation.checkedAtMs-nowMs)>120000)fail('stale local chain observation');
 const n=loadLocalIdentity(dir);
 const unsigned={schema:'mikaya.toybox.signed-event.v1',owner:n.owner,nodeId:n.nodeId,signerFingerprint:n.fp,issuedAtMs:nowMs,observation};
 return {...unsigned,signature:crypto.sign(null,Buffer.from(DOMAIN+canonical(unsigned)),n.privateKey).toString('base64')};
}
function verifyObservation({proof,pinnedPublicKey,expectedFingerprint,nowMs=Date.now()}){
 if(!exact(proof,SIGNED_KEYS)||proof.schema!=='mikaya.toybox.signed-event.v1'||
 !['MIKAYA','MOTOROLA','ACT-OMEGA'].includes(proof.owner)||!/^[-_A-Za-z0-9]{2,64}$/.test(proof.nodeId)||
 !HASH.test(expectedFingerprint)||proof.signerFingerprint!==expectedFingerprint||fingerprint(pinnedPublicKey)!==expectedFingerprint)fail('pinned signer fingerprint or proof identity mismatch');
 validateObservation(proof.observation);
 if(!Number.isSafeInteger(proof.issuedAtMs)||!Number.isSafeInteger(nowMs)||Math.abs(nowMs-proof.issuedAtMs)>120000||
 Math.abs(proof.issuedAtMs-proof.observation.checkedAtMs)>120000)fail('stale or expired signed observation');
 const {signature,...body}=proof;
 if(typeof signature!=='string'||signature.length!==88||!/^[a-zA-Z0-9+/]+={0,2}$/.test(signature))fail('invalid signature shape');
 const bytes=Buffer.from(signature,'base64');
 if(bytes.length!==64||bytes.toString('base64')!==signature||!crypto.verify(null,Buffer.from(DOMAIN+canonical(body)),pinnedPublicKey,bytes))fail('Toybox signature verification failed');
 return {verified:true,softwareIdentityVerified:true,hardwareAttested:false,paymentAuthorized:false,signerFingerprint:expectedFingerprint};
}
function verifyJointObservations({a,b,pinnedA,pinnedB,nowMs=Date.now()}){
 const fa=fingerprint(pinnedA),fb=fingerprint(pinnedB);
 if(fa===fb)fail('two sovereign participants must be distinct');
 verifyObservation({proof:a,pinnedPublicKey:pinnedA,expectedFingerprint:fa,nowMs});
 verifyObservation({proof:b,pinnedPublicKey:pinnedB,expectedFingerprint:fb,nowMs});
 if(a.owner===b.owner)fail('two sovereign owners must be independent');
 if(canonical(a.observation.anchor)!==canonical(b.observation.anchor)||a.observation.chain!==b.observation.chain)fail('joint chain anchor mismatch');
 const parts=[{owner:a.owner,fingerprint:fa,observationSha256:sha(canonical(a.observation))},
 {owner:b.owner,fingerprint:fb,observationSha256:sha(canonical(b.observation))}].sort((x,y)=>x.fingerprint.localeCompare(y.fingerprint));
 return {schema:'mikaya.toybox.cross-owner-agreement.v1',independentSigners:2,sameChainAnchor:true,
  chain:'bitcoin-mainnet',txid:TXID,height:HEIGHT,blockHash:BLOCK,
  agreementSha256:sha('MIKAYA-TOYBOX-CROSS-OWNER/1\n'+canonical(parts)),hardwareAttested:false,paymentAuthorized:false};
}
async function independentVerify({proof,pinnedPublicKey,expectedFingerprint,fetchImpl=fetch,nowMs=Date.now()}){
 verifyObservation({proof,pinnedPublicKey,expectedFingerprint,nowMs});
 const observed=await observeToybox({fetchImpl,nowMs});
 if(canonical(observed.anchor)!==canonical(proof.observation.anchor))fail('independent live chain recheck disagreed');
 return {verified:true,independentlyRechecked:true,paymentAuthorized:false,hardwareAttested:false};
}
function readProof(pathname){const raw=safeFile(pathname,50000);return JSON.parse(raw.toString('utf8'))}
async function main(args=process.argv.slice(2)){
 const [cmd,...rest]=args;
 if(cmd==='inspect'){console.log(canonical(await observeToybox()));return;}
 if(cmd==='once'){
  if(rest.length!==2)fail('usage: once NODE_DIR OUTPUT_JSON');
  const observation=await observeToybox(),proof=signObservation({dir:rest[0],observation});
  fs.writeFileSync(rest[1],canonical(proof)+'\n',{flag:'wx',mode:0o600});
  console.log(canonical({verifiedLocal:true,outputFile:rest[1],signerFingerprint:proof.signerFingerprint,blockHeight:proof.observation.anchor.height,paymentAuthorized:false}));return;
 }
 if(cmd==='verify'){
  if(rest.length!==3)fail('usage: verify PUBLIC_REPORT_JSON PINNED_PUBLIC_PEM EXPECTED_FINGERPRINT');
  console.log(canonical(verifyObservation({proof:readProof(rest[0]),pinnedPublicKey:safeFile(rest[1],4096),expectedFingerprint:rest[2]})));return;
 }
 if(cmd==='independent-verify'){
  if(rest.length!==3)fail('usage: independent-verify PUBLIC_REPORT_JSON PINNED_PUBLIC_PEM EXPECTED_FINGERPRINT');
  console.log(canonical(await independentVerify({proof:readProof(rest[0]),pinnedPublicKey:safeFile(rest[1],4096),expectedFingerprint:rest[2]})));return;
 }
 if(cmd==='compare'){
  if(rest.length!==4)fail('usage: compare REPORT_A PUBLIC_KEY_A REPORT_B PUBLIC_KEY_B');
  console.log(canonical(verifyJointObservations({a:readProof(rest[0]),b:readProof(rest[2]),pinnedA:safeFile(rest[1],4096),pinnedB:safeFile(rest[3],4096)})));return;
 }
 fail('usage: inspect | once NODE_DIR OUTPUT_JSON | verify REPORT PUBLIC_PEM FP | independent-verify REPORT PUBLIC_PEM FP | compare REPORT_A PUB_A REPORT_B PUB_B');
}
if(require.main===module)main().catch(err=>{console.error('MIKAYA_TOYBOX_HOLD: '+err.message);process.exitCode=2});
module.exports={observeToybox,validatedTx,validateObservation,signObservation,verifyObservation,verifyJointObservations,independentVerify,fingerprint,sha,canonical};