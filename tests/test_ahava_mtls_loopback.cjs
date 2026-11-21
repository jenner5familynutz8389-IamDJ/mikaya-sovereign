'use strict';
// Real owner-local TLS 1.3 handshake test with ephemeral synthetic keys.
// Does not touch live AHAVA state, open a remote listener or contact ACT.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),https=require('node:https'),crypto=require('node:crypto');
const {execFileSync}=require('node:child_process');
const {clientFor,serverFor,clientIdentityOk}=require('../ahava/transport-policy');
function setup(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'mikaya-ahava-mtls-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const openssl=(...args)=>execFileSync('openssl',args,{cwd:root,stdio:'pipe',timeout:12000});
 function key(name){openssl('genpkey','-algorithm','Ed25519','-out',name+'.key');}
 key('ca');openssl('req','-new','-x509','-key','ca.key','-out','ca.pem','-days','1','-subj','/CN=MIKAYA Isolated Test CA');
 function cert(name,subject,alt,role){
  key(name);openssl('req','-new','-key',name+'.key','-out',name+'.csr','-subj','/CN='+subject);
  const ext=name+'.ext';fs.writeFileSync(path.join(root,ext),'subjectAltName='+alt+'\nextendedKeyUsage='+role+'\n');
  openssl('x509','-req','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out',name+'.pem','-days','1','-extfile',ext);
 }
 cert('server','localhost','IP:127.0.0.1','serverAuth');
 cert('client','mikaya-test-client','DNS:client.test','clientAuth');
 const f=name=>{const full=path.join(root,name);fs.chmodSync(full,0o600);return full;};
 const pin=name=>crypto.createHash('sha256').update(new crypto.X509Certificate(fs.readFileSync(f(name))).raw).digest('hex');
 return {AHAVA_TLS_CA_FILE:f('ca.pem'),AHAVA_TLS_CERT_FILE:f('client.pem'),AHAVA_TLS_KEY_FILE:f('client.key'),
  AHAVA_TLS_CLIENT_CA_FILE:f('ca.pem'),AHAVA_TLS_PEER_CERT_SHA256:pin('server.pem'),AHAVA_TLS_CLIENT_CERT_SHA256:pin('client.pem'),
  serverCert:f('server.pem'),serverKey:f('server.key')};
}
test('real mutual-TLS 1.3 loopback handshake accepts exact pinned client and refuses wrong server pin',async t=>{
 const env=setup(t);
 const srvEnv={...env,AHAVA_TLS_CERT_FILE:env.serverCert,AHAVA_TLS_KEY_FILE:env.serverKey};
 const policy=serverFor('100.64.6.5',srvEnv);
 const server=https.createServer(policy.options,(req,res)=>{
  if(!req.socket.authorized||!clientIdentityOk(req.socket.getPeerCertificate(),policy.clientPin)){res.writeHead(401);res.end('denied');return;}
  res.end('pinned-ok');
 });
 t.after(()=>server.close());
 await new Promise((resolve,reject)=>server.listen(0,'127.0.0.1',err=>err?reject(err):resolve()));
 async function requestWith(config){
  const {options}=clientFor('https://127.0.0.1',config);
  return new Promise((resolve,reject)=>{
   const req=https.request({...options,host:'127.0.0.1',port:server.address().port,path:'/',timeout:2000},r=>{
    let txt='';r.on('data',b=>txt+=b);r.on('end',()=>resolve({code:r.statusCode,body:txt}));
   });
   req.once('error',reject);req.end();
  });
 }
 const ok=await requestWith(env);assert.equal(ok.code,200);assert.equal(ok.body,'pinned-ok');
 await assert.rejects(requestWith({...env,AHAVA_TLS_PEER_CERT_SHA256:'0'.repeat(64)}),/AHAVA_PIN_MISMATCH/);
});
