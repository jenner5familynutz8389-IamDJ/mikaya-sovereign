'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const tb=require('../toybox-mempool-bridge.cjs');
const TX='8cd0125081b40e01df124fd66adc68638b552c0693bccceb15d4485bdb47c9c8';
const HASH='00000000000000000001dc4084eff84a44b5be05eca6f2c0fc231588afc085ae';
const ADDR='bc1qmockaddressforunitfixtureonlynotwallet';
const HEIGHT=961297,TIP=965000;
const clone=v=>JSON.parse(JSON.stringify(v));
function mockFetch({alter={},off={},status=200}={}){
 const urls=[];
 const f=async(url,opts)=>{
   urls.push(url);
   if(!/^https:\/\/(mempool.space|blockstream.info)\/api\//.test(url))throw Error('INVALID_TEST_URL');
   const host=new URL(url).host;
   let data;
   if(url.endsWith('/tx/'+TX))data={txid:TX,status:{confirmed:true,block_height:HEIGHT,block_hash:HASH,block_time:1786023233},fee:617,vout:[{scriptpubkey_address:'bc1qother',value:1000},{scriptpubkey_address:ADDR,value:18369}]};
   else if(url.endsWith('/block-height/'+HEIGHT))data=HASH;
   else if(url.endsWith('/block/'+HASH+'/status'))data={in_best_chain:true};
   else if(url.endsWith('/blocks/tip/height'))data=String(TIP);
   else throw Error('unexpected url '+url);
   if(alter[host])data=alter[host](data,url);
   if(off[host])throw Error('offline');
   return {ok:status===200,status,headers:{get:(key)=>'application/json'},text:async()=>typeof data==='string'?data:JSON.stringify(data)};
 };
 f.urls=urls;return f;
}
function fixtureNode(owner='MIKAYA'){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'toybox-federation-'));
 const keys=crypto.generateKeyPairSync('ed25519');
 const priv=keys.privateKey.export({format:'pem',type:'pkcs8'}),pub=keys.publicKey.export({format:'pem',type:'spki'});
 fs.writeFileSync(path.join(dir,'identity-private.pem'),priv,{mode:0o600});fs.writeFileSync(path.join(dir,'identity-public.pem'),pub,{mode:0o600});
 const fp=tb.fingerprint(pub);
 fs.writeFileSync(path.join(dir,'node.json'),JSON.stringify({schema:'mikaya.federation.node.v1',owner,nodeId:'mock-node',fingerprint:fp,capabilities:['compute.dot.v1'],platform:{os:'android',androidApi:35,arch:'aarch64'}})+'\n',{mode:0o600});
 fs.chmodSync(dir,0o700);return {dir,pub,fp};
}
const NOW=1794162000000;
test('two independent mainnet explorers match exact historical Toybox anchor and best-chain height',async()=>{
 const f=mockFetch();const o=await tb.observeToybox({fetchImpl:f,nowMs:NOW});
 assert.equal(o.status,'CONFIRMED_BEST_CHAIN');assert.equal(o.anchor.txid,TX);assert.equal(o.anchor.blockHash,HASH);
 assert.equal(o.anchor.height,HEIGHT);assert.equal(o.anchor.confirmations,TIP-HEIGHT+1);
 assert.equal(o.walletAccess,false);assert.equal(o.settlementVerified,false);assert.equal(o.executableAuthority,false);
 assert.equal(o.scope,'HISTORICAL_ONCHAIN_ANCHOR_NOT_CURRENT_MEMPOOL_ITEM');
 assert.ok(!JSON.stringify(o).includes(ADDR));
 assert.equal(f.urls.length,8);assert.ok(f.urls.every(x=>x.startsWith('https://')));
});
test('wrong amount, txid or output index refuse',async()=>{
 for(const method of ['amount','txid','index']){
 const f=mockFetch({alter:{'mempool.space':(v,url)=>{if(url.endsWith('/tx/'+TX)){v=clone(v);if(method==='amount')v.vout[1].value=8;else if(method==='txid')v.txid='0'.repeat(64);else v.vout.reverse();}return v;}}});
 await assert.rejects(()=>tb.observeToybox({fetchImpl:f,nowMs:NOW}),/transaction|output|recipient|anchor/i);
 }
});
test('reorg best-chain false refuses',async()=>{
 const f=mockFetch({alter:{'blockstream.info':(v,url)=>url.endsWith('/status')?{in_best_chain:false}:v}});
 await assert.rejects(()=>tb.observeToybox({fetchImpl:f,nowMs:NOW}),/reorg|best.chain/i);
});
test('height reassigns to another hash refuses',async()=>{
 const f=mockFetch({alter:{'mempool.space':(v,url)=>url.includes('/block-height/')?'f'.repeat(64):v}});
 await assert.rejects(()=>tb.observeToybox({fetchImpl:f,nowMs:NOW}),/height|hash|reorg/i);
});
test('independent providers disagreeing on tip prevents accepted joint snapshot',async()=>{
 const f=mockFetch({alter:{'blockstream.info':(v,url)=>url.endsWith('/tip/height')?String(TIP+2):v}});
 await assert.rejects(()=>tb.observeToybox({fetchImpl:f,nowMs:NOW}),/disagree|tip/i);
});
test('unconfirmed transaction, fabricated block and low confirmations refused',async()=>{
 const f=mockFetch({alter:{'mempool.space':(v,url)=>url.endsWith('/tx/'+TX)?{...v,status:{confirmed:false}}:v}});
 await assert.rejects(()=>tb.observeToybox({fetchImpl:f,nowMs:NOW}),/confirm/i);
 const low=mockFetch({alter:{'blockstream.info':(v,url)=>url.endsWith('/tip/height')?String(HEIGHT):v}});
 await assert.rejects(()=>tb.observeToybox({fetchImpl:low,nowMs:NOW}),/disagree|confirm/i);
});
test('HTTP/redirect/timeout/proxy failure refuse not fallback to one provider',async()=>{
 await assert.rejects(()=>tb.observeToybox({fetchImpl:mockFetch({off:{'blockstream.info':true}}),nowMs:NOW}),/offline/);
 await assert.rejects(()=>tb.observeToybox({fetchImpl:mockFetch({status:302}),nowMs:NOW}),/HTTP|redirect|response/i);
});
test('domain-separated Ed25519 on-device signature and recipient verification, no keys in report',async()=>{
 const node=fixtureNode(),ob=await tb.observeToybox({fetchImpl:mockFetch(),nowMs:NOW});
 const proof=tb.signObservation({dir:node.dir,observation:ob,nowMs:NOW});
 assert.equal(proof.schema,'mikaya.toybox.signed-event.v1');
 assert.equal(proof.signerFingerprint,node.fp);
 assert.deepEqual(tb.verifyObservation({proof,pinnedPublicKey:node.pub,expectedFingerprint:node.fp,nowMs:NOW}).verified,true);
 assert.ok(!JSON.stringify(proof).includes('PRIVATE KEY'));
 assert.ok(!JSON.stringify(proof).includes(ADDR));
 assert.equal(proof.observation.settlementVerified,false);
});
test('forged signature, false signer, stale observation, extra sensitive fields fail',async()=>{
 const node=fixtureNode(),ob=await tb.observeToybox({fetchImpl:mockFetch(),nowMs:NOW});
 const proof=tb.signObservation({dir:node.dir,observation:ob,nowMs:NOW});
 const x=clone(proof);x.observation.anchor.height++;assert.throws(()=>tb.verifyObservation({proof:x,pinnedPublicKey:node.pub,expectedFingerprint:node.fp,nowMs:NOW}),/signature|proof|digest|anchor/i);
 assert.throws(()=>tb.verifyObservation({proof,pinnedPublicKey:node.pub,expectedFingerprint:'0'.repeat(64),nowMs:NOW}),/fingerprint|pinned/i);
 assert.throws(()=>tb.verifyObservation({proof,pinnedPublicKey:node.pub,expectedFingerprint:node.fp,nowMs:NOW+600001}),/stale|expired/i);
 const y=clone(proof);y.observation.walletSeed='xx';assert.throws(()=>tb.verifyObservation({proof:y,pinnedPublicKey:node.pub,expectedFingerprint:node.fp,nowMs:NOW}),/shape|field|unexpected|invalid/i);
});
test('two separate signers can produce a joint cross-owner Toybox agreement without wallet access',async()=>{
 const a=fixtureNode(),b=fixtureNode('MOTOROLA'),ob=await tb.observeToybox({fetchImpl:mockFetch(),nowMs:NOW});
 const A=tb.signObservation({dir:a.dir,observation:ob,nowMs:NOW});
 const B=tb.signObservation({dir:b.dir,observation:ob,nowMs:NOW});
 const v=tb.verifyJointObservations({a:A,b:B,pinnedA:a.pub,pinnedB:b.pub,nowMs:NOW});
 assert.equal(v.independentSigners,2);assert.equal(v.sameChainAnchor,true);assert.equal(v.paymentAuthorized,false);
 const altered=clone(B);altered.observation.anchor.blockHash='f'.repeat(64);assert.throws(()=>tb.verifyJointObservations({a:A,b:altered,pinnedA:a.pub,pinnedB:b.pub,nowMs:NOW}),/signature|mismatch|anchor/i);
});
test('publishable Toybox adapter does not hardcode the receiving address',()=>{
 const src=fs.readFileSync(path.join(__dirname,'..','toybox-mempool-bridge.cjs'),'utf8');
 assert.ok(!src.includes(ADDR),'public bridge must not reveal receiving address');
});
test('known Bitcoin mainnet anchor is never a Lightning invoice or wallet ownership proof',async()=>{
 const ob=await tb.observeToybox({fetchImpl:mockFetch(),nowMs:NOW});
 assert.equal(ob.paymentAuthorization,'NONE');assert.equal(ob.anchorOwnerVerified,false);
 assert.equal(ob.chain,'bitcoin-mainnet');
 assert.equal(ob.walletAccess,false);
});
