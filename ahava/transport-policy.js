'use strict';
// Independent AHAVA v1 transport boundary. Never infer an encrypted channel
// from a private-looking IP address; remote routes require mTLS and exact pins.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),tls=require('node:tls');
const HEX=/^[a-f0-9]{64}$/;
function hold(reason){throw Error(reason);}
function loopback(host){return host==='localhost'||host==='127.0.0.1'||host==='[::1]'||host==='::1';}
function trustedFile(name){
 if(typeof name!=='string'||!path.isAbsolute(name))hold('AHAVA_TLS_CONFIGURATION_INVALID');
 let fd;
 try{
  const s=fs.lstatSync(name);
  if(!s.isFile()||s.isSymbolicLink()||s.size<1||s.size>16384||
     (s.mode&0o077)!==0||(process.getuid&&s.uid!==process.getuid()))hold('AHAVA_TLS_CREDENTIAL_INVALID');
  fd=fs.openSync(name,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));
  const actual=fs.fstatSync(fd);
  if(!actual.isFile()||actual.ino!==s.ino||actual.dev!==s.dev)hold('AHAVA_TLS_CREDENTIAL_INVALID');
  return fs.readFileSync(fd);
 }catch(e){if(/^AHAVA_/.test(e.message))throw e;hold('AHAVA_TLS_CREDENTIAL_INVALID');}
 finally{if(fd!==undefined)fs.closeSync(fd);}
}
function url(input){
 let peer;
 try{peer=new URL(input);}catch{hold('AHAVA_ROUTE_INVALID');}
 if(peer.username||peer.password||peer.search||peer.hash||!['http:','https:'].includes(peer.protocol)||
 peer.pathname.includes('..')||peer.port && (!/^\d+$/.test(peer.port)||Number(peer.port)>65535))
 hold('AHAVA_ROUTE_INVALID');
 if(!peer.hostname)hold('AHAVA_ROUTE_INVALID');
 return peer;
}
function clientFor(target,env={}){
 const peer=url(target);
 if(peer.protocol==='http:'){
  if(!loopback(peer.hostname))hold('AHAVA_REMOTE_TLS_REQUIRED');
  return {peer,requestModule:'http',options:null};
 }
 if(!HEX.test(env.AHAVA_TLS_PEER_CERT_SHA256||''))hold('AHAVA_TLS_CONFIGURATION_INVALID');
 const ca=trustedFile(env.AHAVA_TLS_CA_FILE),cert=trustedFile(env.AHAVA_TLS_CERT_FILE),key=trustedFile(env.AHAVA_TLS_KEY_FILE);
 const pin=Buffer.from(env.AHAVA_TLS_PEER_CERT_SHA256,'hex');
 const options={ca,cert,key,minVersion:'TLSv1.3',rejectUnauthorized:true,
  checkServerIdentity:(hostname,certificate)=>{
   const ordinary=tls.checkServerIdentity(hostname,certificate);
   if(ordinary)return ordinary;
   if(!certificate.raw)return Error('AHAVA_PIN_MISMATCH');
   const actual=crypto.createHash('sha256').update(certificate.raw).digest();
   return crypto.timingSafeEqual(actual,pin)?undefined:Error('AHAVA_PIN_MISMATCH');
  }};
 return {peer,requestModule:'https',options};
}
function serverFor(bind,env={}){
 if(loopback(bind))return {serverModule:'http',options:null};
 if(typeof bind!=='string'||!bind||bind==='0.0.0.0'||bind==='::')hold('AHAVA_REMOTE_MTLS_REQUIRED');
 if(!env.AHAVA_TLS_CERT_FILE||!env.AHAVA_TLS_KEY_FILE||!env.AHAVA_TLS_CLIENT_CA_FILE||
    !HEX.test(env.AHAVA_TLS_CLIENT_CERT_SHA256||''))hold('AHAVA_REMOTE_MTLS_REQUIRED');
 const cert=trustedFile(env.AHAVA_TLS_CERT_FILE),key=trustedFile(env.AHAVA_TLS_KEY_FILE),ca=trustedFile(env.AHAVA_TLS_CLIENT_CA_FILE);
 return {serverModule:'https',options:{cert,key,ca,requestCert:true,rejectUnauthorized:true,minVersion:'TLSv1.3'},
  clientPin:Buffer.from(env.AHAVA_TLS_CLIENT_CERT_SHA256,'hex')};
}
function clientIdentityOk(cert,pin){
 if(!cert||!Buffer.isBuffer(cert.raw)||!Buffer.isBuffer(pin)||pin.length!==32)return false;
 return crypto.timingSafeEqual(crypto.createHash('sha256').update(cert.raw).digest(),pin);
}
module.exports={clientFor,serverFor,clientIdentityOk};
