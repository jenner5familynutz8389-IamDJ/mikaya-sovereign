'use strict';
const fs = require('node:fs');
const path = require('node:path');
const {openPrivateStore, canonical} = require('./transaction-journal.cjs');
const {sha, exact, fail} = require('./protocol.cjs');
function createRuntimeState({directory, initialize = false}) {
  function validate(p) {
    if (!exact(p, ['lastObservedMs', 'nonces', 'events']) || !Number.isSafeInteger(p.lastObservedMs) || p.lastObservedMs < 0 ||
        !Array.isArray(p.nonces) || p.nonces.length > 4096 || !Array.isArray(p.events) || p.events.length > 2048) fail('RUNTIME_STATE_INVALID');
    const seen = new Set();
    for (const n of p.nonces) {
      if (!exact(n, ['key', 'expiresAtMs']) || !/^[0-9a-f]{64}$/.test(n.key) || !Number.isSafeInteger(n.expiresAtMs) || seen.has(n.key)) fail('NONCE_STATE_INVALID');
      seen.add(n.key);
    }
    let previous = '0'.repeat(64);
    for (let i = 0; i < p.events.length; i++) {
      const row = p.events[i];
      if (!exact(row, ['sequence', 'previous', 'event', 'digest']) || row.sequence !== i + 1 || row.previous !== previous ||
          row.digest !== sha(canonical({sequence: row.sequence, previous: row.previous, event: row.event}))) fail('TELEMETRY_CHAIN_INVALID');
      previous = row.digest;
    }
  }
  const store = openPrivateStore({directory, initialize, schema: 'mikaya.act.runtime-state.v1',
    initialPayload: {lastObservedMs: 0, nonces: [], events: []}, validatePayload: validate});
  function current(nowMs) {
    const p = store.snapshot();
    if (!Number.isSafeInteger(nowMs) || nowMs < p.lastObservedMs) fail('CLOCK_ROLLBACK_HOLD');
    p.lastObservedMs = nowMs; return p;
  }
  function nonceOnce({peer, nonce, issuedAtMs, nowMs = Date.now()}) {
    const p = current(nowMs), key = sha(peer + ':' + nonce);
    p.nonces = p.nonces.filter(n => n.expiresAtMs >= nowMs);
    if (p.nonces.some(n => n.key === key)) fail('REQUEST_REPLAY_REFUSED');
    if (p.nonces.length >= 4096) fail('NONCE_CAPACITY_HOLD');
    p.nonces.push({key, expiresAtMs: issuedAtMs + 60000}); store.commit(p);
  }
  function audit({decision, code, peer = null, transactionId = null, operation = null, intentSha256 = null, transport = null, nowMs = Date.now()}) {
    const p = current(nowMs);
    if (p.events.length >= 2048) fail('TELEMETRY_CAPACITY_HOLD');
    if (!['allow', 'deny', 'hold', 'startup', 'shutdown'].includes(decision) || !/^[A-Z0-9_]{1,64}$/.test(code)) fail('AUDIT_VALUE_INVALID');
    peer = typeof peer === 'string' && /^[0-9a-f]{64}$/.test(peer) ? peer : null;
    transactionId = typeof transactionId === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(transactionId) ? transactionId : null;
    operation = typeof operation === 'string' && /^[a-z][a-z0-9.]{1,63}$/.test(operation) ? operation : null;
    intentSha256 = typeof intentSha256 === 'string' && /^[0-9a-f]{64}$/.test(intentSha256) ? intentSha256 : null;
    transport = ['h2-TLS1.3-mTLS', 'http1.1-TLS1.3-mTLS'].includes(transport) ? transport : null;
    const event = {schema: 'mikaya.act.security-event.v1', atMs: nowMs, decision, code, peer, transactionId, operation, intentSha256, transport};
    const body = {sequence: p.events.length + 1, previous: p.events.at(-1)?.digest || '0'.repeat(64), event};
    const row = {...body, digest: sha(canonical(body))}; p.events.push(row); store.commit(p); return row.digest;
  }
  return {nonceOnce, audit, snapshot: store.snapshot, close: store.close};
}
function safeBytes(file, max = 100000, privateOnly = true) {
  if (typeof file !== 'string' || !path.isAbsolute(file) || fs.realpathSync(file) !== file) fail('FILE_PATH_UNSAFE');
  const s = fs.lstatSync(file);
  const valid = s => s.isFile() && !s.isSymbolicLink() && s.nlink === 1 && s.size <= max &&
    !(s.mode & (privateOnly ? 0o077 : 0o022)) && (typeof process.getuid !== 'function' || s.uid === process.getuid());
  if (!valid(s)) fail('FILE_PERMISSIONS_UNSAFE');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const opened = fs.fstatSync(fd);
    const unchanged = n => valid(n) && n.ino === s.ino && n.dev === s.dev && n.size === s.size && n.mtimeMs === s.mtimeMs && n.ctimeMs === s.ctimeMs;
    if (!unchanged(opened)) fail('FILE_CHANGED_HOLD');
    const b = Buffer.alloc(s.size + 1); let length = 0;
    while (length < b.length) { const n = fs.readSync(fd, b, length, b.length - length, null); if (!n) break; length += n; }
    if (length !== s.size || !unchanged(fs.fstatSync(fd)) || !unchanged(fs.lstatSync(file))) fail('FILE_CHANGED_HOLD');
    return b.subarray(0, length);
  } finally { fs.closeSync(fd); }
}
module.exports = {createRuntimeState, safeBytes};
