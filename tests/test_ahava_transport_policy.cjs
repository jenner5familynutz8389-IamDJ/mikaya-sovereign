'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {clientFor,serverFor}=require('../ahava/transport-policy');
function sample(t){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ahava-tls-'));
 t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const file=name=>{const p=path.join(dir,name);fs.writeFileSync(p,'test credential',{mode:0o600});return p;};
 return {AHAVA_TLS_CA_FILE:file('ca.pem'),AHAVA_TLS_CERT_FILE:file('identity.pem'),AHAVA_TLS_KEY_FILE:file('identity.key'),AHAVA_TLS_CLIENT_CA_FILE:file('client-ca.pem'),AHAVA_TLS_PEER_CERT_SHA256:crypto.createHash('sha256').update('expected-der').digest('hex'),AHAVA_TLS_CLIENT_CERT_SHA256:crypto.createHash('sha256').update('client-der').digest('hex')};
}
test('loopback HTTP is permitted, without ambient key loading',()=>{
 const cfg=clientFor('http://127.0.0.1:43824',{});
 assert.equal(cfg.peer.protocol,'http:');assert.equal(cfg.requestModule,'http');assert.equal(cfg.options,null);
 assert.equal(serverFor('127.0.0.1',{}).serverModule,'http');
});
test('all nonloopback plaintext HTTP is refused, including nominal tailnet range',()=>{
 for(const u of ['http://100.64.7.3:43824','http://192.168.1.8:43824','http://8.8.8.8:43824'])
 assert.throws(()=>clientFor(u,{}),/AHAVA_REMOTE_TLS_REQUIRED/);
 assert.throws(()=>serverFor('100.64.7.3',{}),/AHAVA_REMOTE_MTLS_REQUIRED/);
});
test('unsupported routes and credential-bearing URLs are refused',()=>{
 for(const u of ['http://user:pass@127.0.0.1/','http://127.0.0.1/?x=1','http://100.64.example.test/','ftp://127.0.0.1/'])
 assert.throws(()=>clientFor(u,{}),/AHAVA_ROUTE_INVALID|AHAVA_REMOTE_TLS_REQUIRED/);
});
test('remote HTTPS fails closed without mutual TLS material and exact fingerprint',()=>{
 assert.throws(()=>clientFor('https://100.64.7.3:43824',{}),/AHAVA_TLS_CONFIGURATION_INVALID/);
 assert.throws(()=>serverFor('100.64.7.3',{}),/AHAVA_REMOTE_MTLS_REQUIRED/);
});
test('remote HTTPS is pinned and forbids TLS below 1.3',t=>{
 const env=sample(t);
 const c=clientFor('https://100.64.7.3:43824',env),s=serverFor('100.64.7.3',env);
 assert.equal(c.requestModule,'https');assert.equal(c.options.minVersion,'TLSv1.3');
 assert.equal(c.options.rejectUnauthorized,true);
 assert.equal(s.serverModule,'https');assert.equal(s.options.requestCert,true);
 assert.equal(s.options.rejectUnauthorized,true);assert.equal(s.options.minVersion,'TLSv1.3');
 const certificate={raw:Buffer.from('wrong-der'),subjectaltname:'IP Address:100.64.7.3'};
 assert.ok(c.options.checkServerIdentity('100.64.7.3',certificate) instanceof Error);
});
test('world-readable TLS key and symlinked credential files are rejected',t=>{
 const env=sample(t);fs.chmodSync(env.AHAVA_TLS_KEY_FILE,0o644);
 assert.throws(()=>clientFor('https://100.64.7.3:43824',env),/AHAVA_TLS_CREDENTIAL_INVALID/);
});
test('remote mTLS server requires a pinned client leaf certificate',t=>{
 const env=sample(t);delete env.AHAVA_TLS_CLIENT_CERT_SHA256;
 assert.throws(()=>serverFor('100.64.7.3',env),/AHAVA_REMOTE_MTLS_REQUIRED/);
});

test('client certificate must match exact owner-pinned DER digest',t=>{
 const env=sample(t);const policy=require('../ahava/transport-policy');
 const pin=policy.serverFor('100.64.7.3',env).clientPin;
 assert.equal(policy.clientIdentityOk({raw:Buffer.from('client-der')},pin),true);
 assert.equal(policy.clientIdentityOk({raw:Buffer.from('unknown-peer')},pin),false);
 assert.equal(policy.clientIdentityOk({},pin),false);
});
test('remote health endpoint may not disclose node metadata to an unpinned mTLS client',t=>{
 const env=sample(t),p=serverFor('100.64.7.3',env);
 const {remoteClientAllowed}=require('../ahava/transport-policy');
 const pinned={authorized:true,getPeerCertificate:()=>({raw:Buffer.from('client-der')})};
 const unknown={authorized:true,getPeerCertificate:()=>({raw:Buffer.from('other-client')})};
 assert.equal(remoteClientAllowed(pinned,p),true);
 assert.equal(remoteClientAllowed(unknown,p),false);
 assert.equal(remoteClientAllowed({...pinned,authorized:false},p),false);
 assert.equal(remoteClientAllowed(null,p),false);
 assert.equal(remoteClientAllowed(null,serverFor('127.0.0.1',{})),true);
});
