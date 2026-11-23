'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync, spawn } = require('node:child_process');
const cap = require('../capability-macaroons.cjs');

// Independent byte-for-byte vectors from go-macaroon/js-macaroon, NOT generated
// by this implementation. Upstream source Git blobs pin the reviewed bytes:
// test/serialize-binary.js: 937ce6f54df0a729b124859b0ef19a549ea48774
// test/macaroon.js: 2c18fa0aaedff45d6fe9f6a2f89f86c911d0fc80
// https://github.com/go-macaroon/js-macaroon/blob/master/test/serialize-binary.js
// https://github.com/go-macaroon/js-macaroon/blob/master/test/macaroon.js
// Copyright Roger Peppe 2015, BSD-3-Clause; see MACAROON-VECTORS-LICENSE.txt.
const VECTORS = [
  'AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAAYgfN7nklEcW8b1KEhYBd_psk54XijiqZMB-dcRxgnjjvc',
  'AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAhRhY2NvdW50ID0gMzczNTkyODU1OQAABiD1SAf23G7fiL8PcwazgiVio2JTPb9zObphdl2kvSWdhw',
  'AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAhRhY2NvdW50ID0gMzczNTkyODU1OQACDHVzZXIgPSBhbGljZQAABiBL6WfNHqDGsmuvakqU7psFsViG2guoXoxCqTyNDhJe_A'
];
const PUBLIC_CAVEATS = ['account = 3735928559','user = alice'];
for (let count = 0; count < 3; count++) {
  test('independent upstream V2 wire vector with ' + count + ' caveats', () => {
    const minted = cap.mintMacaroon({ rootKey: 'this is the key', identifier: 'keyid', location: 'http://example.org/', caveats: PUBLIC_CAVEATS.slice(0,count) });
    assert.equal(minted, VECTORS[count]);
    const decoded = cap.verifyMacaroonIntegrity(VECTORS[count], 'this is the key');
    assert.equal(cap.encodeMacaroon(decoded), VECTORS[count]);
    assert.equal(decoded.caveats.length, count);
    assert.deepEqual(decoded.caveats.map(x => x.toString('utf8')), PUBLIC_CAVEATS.slice(0,count));
    if (count) assert.equal(cap.addFirstPartyCaveat(VECTORS[count-1], PUBLIC_CAVEATS[count-1]), VECTORS[count]);
  });
}
test('independent upstream chained-HMAC signatures match', () => {
  let m = cap.mintMacaroon({ rootKey: 'secret', identifier: 'some id', location: 'a location' });
  assert.equal(cap.decodeMacaroon(m).signature.toString('hex'), 'd916ce6f9b62dc4a080ce5d4a660956471f19b860da4242b0852727331c1033d');
  m = cap.addFirstPartyCaveat(cap.addFirstPartyCaveat(m,'a caveat'),'another caveat');
  assert.equal(cap.decodeMacaroon(m).signature.toString('hex'), 'c934e6af642ee55a4e4cfc56e07706cf1c6c94dc2192e5582943cddd88dc99d8');
});
function fixture(t, overrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mikaya-macaroon-'));
  fs.chmodSync(dir, 0o700); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  cap.initializeReplayState(dir);
  const now = 1900000000000, rootKey = crypto.randomBytes(32);
  const options = { rootKey, identifier: '0'.repeat(64), holderKeySha256: 'a'.repeat(64), audience: 'mikaya.test', profileSha256: 'b'.repeat(64),
    operation: 'compute.sha256.v1', bodySha256: 'c'.repeat(64), issuedAtMs: now, expiresAtMs: now + 60000,
    maxUses: 3, maxBytes: 1024, ...overrides };
  const token = cap.mintTestCapability(options);
  const context = { holderKeySha256: options.holderKeySha256, audience: options.audience, profileSha256: options.profileSha256,
    operation: options.operation, bodySha256: options.bodySha256, requestNonce: 'd'.repeat(32), requestBytes: 100 };
  return { dir, now, rootKey, options, token, context,
    verify: (changes = {}) => cap.verifyCapability({ token, rootKey, context, nowMs: now, stateDir: dir, ...changes }) };
}
test('strict bound test capability verifies and consumes no live authority', t => {
  const f = fixture(t), result = f.verify();
  assert.equal(result.verified, true); assert.equal(result.testOnly, true);
  assert.equal(result.liveAdmission, false); assert.equal(result.paymentAuthorized, false); assert.equal(result.hardwareAttested, false);
  assert.deepEqual(result.consumed, { uses: 1, bytes: 100 });
});
for (const field of ['holderKeySha256','audience','profileSha256','operation','bodySha256']) {
  test('rejects authenticated-context ' + field + ' mismatch', t => {
    const f = fixture(t);
    assert.throws(() => f.verify({ context: { ...f.context, [field]: 'wrong' } }), /mismatch/);
    assert.equal(f.verify().consumed.uses, 1, 'rejected request must not consume budget');
  });
}
test('signature, identifier, and caveat tampering fail', t => {
  const f = fixture(t);
  for (const part of ['signature','identifier','caveat']) {
    const m = cap.decodeMacaroon(f.token);
    if (part === 'signature') m.signature[0] ^= 1;
    else if (part === 'identifier') m.identifier[0] ^= 1;
    else m.caveats[5][m.caveats[5].length-1] ^= 1;
    assert.throws(() => f.verify({ token: cap.encodeMacaroon(m) }), /signature invalid/);
  }
  assert.throws(() => f.verify({ rootKey: crypto.randomBytes(32) }), /signature invalid/);
});
test('location is an unauthenticated hint and cannot replace the audience caveat', t => {
  const f = fixture(t), m = cap.decodeMacaroon(f.token); m.location = 'different.example';
  assert.doesNotThrow(() => cap.verifyMacaroonIntegrity(cap.encodeMacaroon(m), f.rootKey));
  assert.throws(() => f.verify({ token: cap.encodeMacaroon(m), context: { ...f.context, audience: 'different.example' } }), /audience mismatch/);
});
test('unknown and duplicate critical caveats are rejected even with valid HMAC', t => {
  const f = fixture(t);
  for (const caveat of ['owner_approved = yes', 'holder = ' + f.options.holderKeySha256, 'profile = ' + cap.PROFILE, 'audience = mikaya.test']) {
    const token = cap.addFirstPartyCaveat(f.token, caveat);
    assert.doesNotThrow(() => cap.verifyMacaroonIntegrity(token, f.rootKey));
    assert.throws(() => f.verify({ token }), /unknown|duplicate/);
  }
});
test('expiry and maximum lifetime are enforced', t => {
  const f = fixture(t);
  assert.throws(() => f.verify({ nowMs: f.now-1 }), /not yet valid/);
  assert.throws(() => f.verify({ nowMs: f.options.expiresAtMs }), /expired/);
  assert.throws(() => cap.mintTestCapability({ ...f.options, expiresAtMs: f.now + cap.MAX_DURATION_MS + 1 }), /duration/);
});
test('holder may attenuate without the root key and all earlier restrictions remain', t => {
  const f = fixture(t);
  let token = cap.attenuateCapability(f.token, { expiresAtMs: f.now+30000, maxUses: 2, maxBytes: 800 });
  token = cap.attenuateCapability(token, { expiresAtMs: f.now+20000, maxUses: 1, maxBytes: 500 });
  assert.doesNotThrow(() => cap.verifyMacaroonIntegrity(token, f.rootKey));
  assert.equal(f.verify({ token }).expiresAtMs, f.now+20000);
  assert.throws(() => f.verify({ token, context: { ...f.context, requestNonce: 'e'.repeat(32) } }), /use budget/);
});
test('broadening and duplicate attenuation predicates fail at issuer API and verifier', t => {
  const f = fixture(t);
  for (const restriction of [{ expiresAtMs: f.now+70000 }, { maxUses: 4 }, { maxBytes: 1025 }, { maxUses: 3 }, { audience: 'other' }]) {
    assert.throws(() => cap.attenuateCapability(f.token, restriction), /attenuation|unsupported/);
  }
  for (const caveat of ['limit = max_uses:100','limit = expires_ms:'+(f.now+70000),'limit = max_bytes:1024','limit = wallet_pay:0']) {
    assert.throws(() => f.verify({ token: cap.addFirstPartyCaveat(f.token,caveat) }), /attenuation|unknown/);
  }
});
test('removing a restriction from an attenuated token breaks its HMAC', t => {
  const f = fixture(t), m = cap.decodeMacaroon(cap.attenuateCapability(f.token,{ maxUses: 1 }));
  m.caveats.pop(); assert.throws(() => f.verify({ token: cap.encodeMacaroon(m) }), /signature invalid/);
});
test('all descendants consume the same cumulative byte/use budget', t => {
  const f = fixture(t,{ maxBytes: 250 });
  const token = cap.attenuateCapability(f.token,{ maxBytes: 200 });
  assert.equal(f.verify().consumed.bytes, 100);
  assert.equal(f.verify({ token, context: { ...f.context, requestNonce: 'e'.repeat(32) } }).consumed.bytes, 200);
  assert.throws(() => f.verify({ token, context: { ...f.context, requestNonce: 'f'.repeat(32), requestBytes: 1 } }), /byte budget/);
  assert.throws(() => f.verify({ context: { ...f.context, requestNonce: 'f'.repeat(32), requestBytes: 100 } }), /byte budget/);
});
test('replay rejects copied tokens and attenuated descendants', t => {
  const f = fixture(t); f.verify();
  assert.throws(() => f.verify(), /replay/);
  assert.throws(() => f.verify({ token: cap.attenuateCapability(f.token,{ maxUses: 2 }) }), /replay/);
});
test('replay and cumulative budget persist across a new Node process', t => {
  const f = fixture(t,{ maxUses: 1 }); f.verify();
  const script = `const cap=require(process.env.CAP_MODULE); const o=JSON.parse(process.env.CAP_INPUT);o.rootKey=Buffer.from(o.rootKey,'hex');try{cap.verifyCapability(o);process.exitCode=2;}catch(e){process.stdout.write(e.message);}`;
  const input = { token: f.token, rootKey: f.rootKey.toString('hex'), context: f.context, nowMs: f.now, stateDir: f.dir };
  let child = spawnSync(process.execPath,['-e',script],{encoding:'utf8',env:{...process.env,CAP_MODULE:require.resolve('../capability-macaroons.cjs'),CAP_INPUT:JSON.stringify(input)}});
  assert.equal(child.status,0); assert.match(child.stdout,/replay/);
  input.context = { ...f.context, requestNonce: 'e'.repeat(32) };
  child = spawnSync(process.execPath,['-e',script],{encoding:'utf8',env:{...process.env,CAP_MODULE:require.resolve('../capability-macaroons.cjs'),CAP_INPUT:JSON.stringify(input)}});
  assert.equal(child.status,0); assert.match(child.stdout,/use budget/);
});
test('independent concurrent processes cannot spend a one-use budget twice', async t => {
  const f=fixture(t,{maxUses:1});
  const script=`const cap=require(process.env.CAP_MODULE);const o=JSON.parse(process.env.CAP_INPUT);o.rootKey=Buffer.from(o.rootKey,'hex');try{cap.verifyCapability(o);process.stdout.write('ACCEPT');}catch(e){process.stdout.write('DENY:'+e.message);}`;
  function child(nonce) {
    return new Promise((resolve,reject) => {
      const input={token:f.token,rootKey:f.rootKey.toString('hex'),context:{...f.context,requestNonce:nonce},nowMs:f.now,stateDir:f.dir};
      const p=spawn(process.execPath,['-e',script],{env:{...process.env,CAP_MODULE:require.resolve('../capability-macaroons.cjs'),CAP_INPUT:JSON.stringify(input)}});
      let out='',err='';p.stdout.on('data',x=>{out+=x});p.stderr.on('data',x=>{err+=x});p.on('error',reject);
      p.on('close',code=>code===0?resolve(out):reject(new Error(err||'child failed')));
    });
  }
  const results=await Promise.all([child('1'.repeat(32)),child('2'.repeat(32))]);
  assert.equal(results.filter(x=>x==='ACCEPT').length,1);
  assert.equal(results.filter(x=>/^DENY:.*(use budget|EEXIST)/.test(x)).length,1);
});
test('missing, malformed or busy durable state fails closed', t => {
  const f = fixture(t), state = path.join(f.dir,'capability-state.json');
  assert.throws(() => f.verify({ stateDir: undefined }), /durable/);
  fs.writeFileSync(path.join(f.dir,'capability-state.lock'),'',{mode:0o600});
  assert.throws(() => f.verify(), /EEXIST/);
  fs.unlinkSync(path.join(f.dir,'capability-state.lock'));
  fs.writeFileSync(state,'{broken',{mode:0o600});
  assert.throws(() => f.verify(), /JSON|property name/);
  fs.unlinkSync(state); assert.throws(() => f.verify(), /ENOENT/);
});
test('state initializer refuses to reset replay history', t => {
  const f = fixture(t); f.verify();
  assert.throws(() => cap.initializeReplayState(f.dir), /EEXIST/);
  assert.throws(() => f.verify(), /replay/);
});
test('world-readable state and symbolic links are rejected', t => {
  const f = fixture(t), state = path.join(f.dir,'capability-state.json');
  fs.chmodSync(state,0o644); assert.throws(() => f.verify(), /unsafe replay/); fs.chmodSync(state,0o600);
  fs.renameSync(state,state+'.saved'); fs.symlinkSync(state+'.saved',state);
  assert.throws(() => f.verify(), /ELOOP|symbolic/);
});
test('wire parser rejects truncation, trailing data, excess size and noncanonical varints', () => {
  const b = Buffer.from(VECTORS[1],'base64url');
  for (let i=0;i<b.length;i++) assert.throws(() => cap.decodeMacaroon(b.subarray(0,i)));
  assert.throws(() => cap.decodeMacaroon(Buffer.concat([b,Buffer.from([0])])), /trailing/);
  assert.throws(() => cap.decodeMacaroon('A'.repeat(30000)), /encoding|large/);
  assert.throws(() => cap.decodeMacaroon(VECTORS[1]+'='), /encoding/);
  // Canonical field length 0x13 must not accept the alternate 0x93 0x00.
  assert.throws(() => cap.decodeMacaroon(Buffer.concat([b.subarray(0,2),Buffer.from([0x93,0]),b.subarray(3)])), /noncanonical/);
});
test('third-party caveat fields explicitly reject rather than being ignored', () => {
  const b=Buffer.from(VECTORS[1],'base64url'), signature=b.lastIndexOf(Buffer.from([6,32]));
  const caveatEnd=signature-2;
  const changed=Buffer.concat([b.subarray(0,caveatEnd),Buffer.from([4,1,7]),b.subarray(caveatEnd)]);
  assert.throws(() => cap.decodeMacaroon(changed), /third-party|unsupported/);
});
test('untrusted numeric/context coercion is rejected', t => {
  const f=fixture(t);
  assert.throws(() => f.verify({context:{...f.context,requestBytes:'100'}}),/range/);
  assert.throws(() => f.verify({context:{...f.context,requestBytes:-1}}),/range/);
  assert.throws(() => f.verify({context:{...f.context,requestNonce:'bad'}}),/nonce/);
  assert.throws(() => f.verify({context:{...f.context,authenticated:true}}),/shape/);
  assert.throws(() => cap.mintTestCapability({...f.options,operation:undefined}),/required/);
});
