'use strict';

// A private protocol journal, separate from the preserved device evidence ledger.
// This module records acceptance and digests; it never executes work or signs on
// behalf of another component. Its checksum detects changed bytes, not attacks
// by an actor already able to replace all owner-private state and checkpoints.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const F = fs.constants;
const HEX = /^[0-9a-f]{64}$/;
const MAX_STATE = 4 * 1024 * 1024;
const MAX_RECORDS = 2048;
const INTENT_KEYS = ['schema', 'transactionId', 'sender', 'recipient', 'operation', 'resource', 'payloadSha256', 'policyVersion', 'expiresAtMs'];
const RECEIPT_KEYS = ['schema', 'transactionId', 'sender', 'recipient', 'operation', 'resource', 'intentSha256', 'state', 'acceptedAtMs', 'updatedAtMs', 'resultSha256', 'reason'];

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).sort().join('|') === [...keys].sort().join('|'); }
function canonical(value, depth = 0) {
  if (depth > 16) fail('JSON_DEPTH_REFUSED');
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) {
    if (value.length > 8192) fail('JSON_ARRAY_REFUSED');
    if (Object.keys(value).length !== value.length || value.some((_, index) => !Object.hasOwn(value, index))) fail('JSON_ARRAY_REFUSED');
    return '[' + value.map(item => canonical(item, depth + 1)).join(',') + ']';
  }
  if (plain(value)) {
    const keys = Object.keys(value).sort();
    if (keys.length > 64) fail('JSON_OBJECT_REFUSED');
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (['__proto__', 'constructor', 'prototype'].includes(key) || !descriptor || !Object.hasOwn(descriptor, 'value')) fail('JSON_KEY_REFUSED');
    }
    return '{' + keys.map(key => JSON.stringify(key) + ':' + canonical(value[key], depth + 1)).join(',') + '}';
  }
  fail('JSON_VALUE_REFUSED');
}
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const copy = value => JSON.parse(canonical(value));
const positiveTime = value => Number.isSafeInteger(value) && value > 0;
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value);
const resourceId = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$/.test(value);
const operationId = value => typeof value === 'string' && /^[a-z][a-z0-9.]{1,63}$/.test(value);

function validateIntent(intent) {
  if (!exact(intent, INTENT_KEYS) || intent.schema !== 'mikaya.act.transaction-intent.v1' ||
      !identifier(intent.transactionId) || !HEX.test(intent.sender) || !HEX.test(intent.recipient) ||
      !operationId(intent.operation) || !resourceId(intent.resource) || !HEX.test(intent.payloadSha256) ||
      !identifier(intent.policyVersion) || !positiveTime(intent.expiresAtMs)) fail('INTENT_INVALID');
  // Intent is immutable. Nonces, connection IDs, request times and signatures
  // belong to the outer authentication envelope, so legitimate retries keep it.
  const encoded = canonical(intent);
  if (Buffer.byteLength(encoded) > 4096) fail('INTENT_TOO_LARGE');
  return sha(encoded);
}
function transactionKey({sender, operation, transactionId}) {
  if (!HEX.test(sender) || !operationId(operation) || !identifier(transactionId)) fail('TRANSACTION_KEY_INVALID');
  return canonical([sender, operation, transactionId]);
}
function statIdentity(stat) { return [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs, stat.nlink].map(String).join(':'); }
function privateFile(stat) {
  return stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1n &&
    (Number(stat.mode) & 0o777) === 0o600 &&
    (typeof process.getuid !== 'function' || stat.uid === BigInt(process.getuid()));
}
function readPrivateFile(file, maxBytes) {
  const before = fs.lstatSync(file, {bigint: true});
  if (!privateFile(before) || before.size > BigInt(maxBytes)) fail('STATE_FILE_UNSAFE');
  const fd = fs.openSync(file, F.O_RDONLY | F.O_NOFOLLOW | F.O_NONBLOCK);
  try {
    const opened = fs.fstatSync(fd, {bigint: true});
    if (!privateFile(opened) || statIdentity(before) !== statIdentity(opened)) fail('STATE_FILE_CHANGED');
    const expectedSize = Number(before.size);
    const output = Buffer.alloc(expectedSize + 1);
    let length = 0;
    while (length < output.length) {
      const count = fs.readSync(fd, output, length, output.length - length, null);
      if (!count) break;
      length += count;
    }
    if (length !== expectedSize || statIdentity(before) !== statIdentity(fs.fstatSync(fd, {bigint: true})) ||
        statIdentity(before) !== statIdentity(fs.lstatSync(file, {bigint: true}))) fail('STATE_FILE_CHANGED');
    return output.subarray(0, length);
  } finally { fs.closeSync(fd); }
}

// Used by the artifact freshness policy too. Caller schemas never share a state
// directory. No stale lock or partial initialization is automatically repaired.
function openPrivateStore({directory, initialize = false, schema, initialPayload, validatePayload}) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || path.resolve(directory) !== directory ||
      typeof initialize !== 'boolean' || typeof schema !== 'string' || typeof validatePayload !== 'function' ||
      !Number.isInteger(F.O_NOFOLLOW) || !Number.isInteger(F.O_DIRECTORY)) fail('STATE_CONFIGURATION_INVALID');
  const parent = path.dirname(directory);
  if (fs.realpathSync(parent) !== parent) fail('STATE_PARENT_UNSAFE');
  if (initialize) {
    try { fs.lstatSync(directory); fail('STATE_INITIALIZATION_REFUSED'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    fs.mkdirSync(directory, {mode: 0o700});
    const parentFd = fs.openSync(parent, F.O_RDONLY | F.O_DIRECTORY | F.O_NOFOLLOW);
    try { fs.fsyncSync(parentFd); } finally { fs.closeSync(parentFd); }
  }
  const initialDir = fs.lstatSync(directory, {bigint: true});
  function assertDirectory() {
    const current = fs.lstatSync(directory, {bigint: true});
    if (!current.isDirectory() || current.isSymbolicLink() || (Number(current.mode) & 0o777) !== 0o700 ||
        current.dev !== initialDir.dev || current.ino !== initialDir.ino ||
        (typeof process.getuid === 'function' && current.uid !== BigInt(process.getuid())) ||
        fs.realpathSync(directory) !== directory) fail('STATE_DIRECTORY_UNSAFE');
  }
  assertDirectory();
  const dirFd = fs.openSync(directory, F.O_RDONLY | F.O_DIRECTORY | F.O_NOFOLLOW);
  const lockFile = path.join(directory, 'writer.lock');
  const stateFile = path.join(directory, 'state.json');
  const lockBytes = Buffer.from(canonical({schema: 'mikaya.act.private-writer.v1', pid: process.pid, token: crypto.randomBytes(24).toString('hex')}));
  let lockFd;
  try { lockFd = fs.openSync(lockFile, F.O_WRONLY | F.O_CREAT | F.O_EXCL | F.O_NOFOLLOW, 0o600); }
  catch (error) { fs.closeSync(dirFd); if (error.code === 'EEXIST') fail('WRITER_LEASE_HOLD'); throw error; }
  let closed = false, uncertain = false, current, lockIdentity;
  try {
    fs.writeFileSync(lockFd, lockBytes); fs.fsyncSync(lockFd); fs.fsyncSync(dirFd);
    lockIdentity = statIdentity(fs.fstatSync(lockFd, {bigint: true}));
  }
  catch (error) { uncertain = true; fs.closeSync(dirFd); throw error; }
  finally { fs.closeSync(lockFd); }

  function assertLease() {
    if (closed) fail('JOURNAL_CLOSED');
    if (uncertain) fail('DURABILITY_UNCERTAIN_HOLD');
    assertDirectory();
    if (statIdentity(fs.lstatSync(lockFile, {bigint: true})) !== lockIdentity) fail('WRITER_LEASE_CHANGED_HOLD');
    if (!readPrivateFile(lockFile, 512).equals(lockBytes)) fail('WRITER_LEASE_CHANGED_HOLD');
  }
  function pack(payload, revision) {
    validatePayload(payload);
    const body = {schema, revision, payload};
    const result = {...body, digest: sha(canonical(body))};
    if (Buffer.byteLength(canonical(result)) > MAX_STATE) fail('JOURNAL_CAPACITY_HOLD');
    return result;
  }
  function readState() {
    let parsed, text;
    try { text = readPrivateFile(stateFile, MAX_STATE).toString('utf8'); parsed = JSON.parse(text); }
    catch (error) { if (error instanceof SyntaxError) fail('STATE_PARSE_HOLD'); throw error; }
    if (!exact(parsed, ['schema', 'revision', 'payload', 'digest']) || parsed.schema !== schema ||
        !Number.isSafeInteger(parsed.revision) || parsed.revision < 0 || !HEX.test(parsed.digest)) fail('STATE_SHAPE_HOLD');
    if (pack(parsed.payload, parsed.revision).digest !== parsed.digest) fail('STATE_INTEGRITY_HOLD');
    if (canonical(parsed) !== text) fail('STATE_ENCODING_HOLD');
    return parsed;
  }
  function persist(next, initializing = false) {
    assertLease();
    if (!initializing) {
      const observed = readState();
      if (observed.digest !== current.digest || observed.revision !== current.revision) fail('STATE_CHANGED_HOLD');
    }
    const temp = path.join(directory, '.state-' + crypto.randomBytes(16).toString('hex') + '.tmp');
    let fd;
    try {
      fd = fs.openSync(temp, F.O_WRONLY | F.O_CREAT | F.O_EXCL | F.O_NOFOLLOW, 0o600);
      fs.writeFileSync(fd, canonical(next));
      fs.fsyncSync(fd);
      fs.closeSync(fd); fd = undefined;
      assertLease();
      if (!initializing) {
        const observed = readState();
        if (observed.digest !== current.digest || observed.revision !== current.revision) fail('STATE_CHANGED_HOLD');
      } else if (fs.existsSync(stateFile)) fail('STATE_CHANGED_HOLD');
      fs.renameSync(temp, stateFile);
      fs.fsyncSync(dirFd);
      current = next;
    } catch (error) {
      uncertain = true;
      if (fd !== undefined) fs.closeSync(fd);
      // Preserve temp bytes and writer lease for deliberate recovery. A failed
      // fsync cannot be reported as rejected or blindly retried.
      fail('DURABILITY_UNCERTAIN_HOLD');
    }
  }
  try {
    if (initialize) persist(pack(copy(initialPayload), 0), true);
    else current = readState();
  } catch (error) {
    if (!uncertain) {
      try { assertLease(); fs.unlinkSync(lockFile); fs.fsyncSync(dirFd); } catch { /* preserve uncertain lease */ }
    }
    fs.closeSync(dirFd);
    closed = true;
    throw error;
  }
  function snapshot() {
    assertLease();
    const observed = readState();
    if (observed.digest !== current.digest || observed.revision !== current.revision) fail('STATE_CHANGED_HOLD');
    return copy(current.payload);
  }
  function commit(payload) {
    snapshot();
    persist(pack(copy(payload), current.revision + 1));
    return {revision: current.revision, digest: current.digest};
  }
  function close() {
    if (closed) return;
    try {
      if (uncertain) fail('DURABILITY_UNCERTAIN_HOLD');
      assertLease();
      fs.unlinkSync(lockFile);
      fs.fsyncSync(dirFd);
    } finally { fs.closeSync(dirFd); closed = true; }
  }
  return Object.freeze({snapshot, commit, close});
}

function validateJournal(payload) {
  if (!exact(payload, ['lastObservedMs', 'transactions', 'quotas']) || !Number.isSafeInteger(payload.lastObservedMs) ||
      payload.lastObservedMs < 0 || !Array.isArray(payload.transactions) || !Array.isArray(payload.quotas) ||
      payload.transactions.length > MAX_RECORDS || payload.quotas.length > MAX_RECORDS) fail('JOURNAL_SHAPE_HOLD');
  const keys = new Set(), counts = new Map();
  for (const row of payload.transactions) {
    if (!exact(row, ['intent', 'intentSha256', 'grantId', 'receipt']) || !resourceId(row.grantId) ||
        validateIntent(row.intent) !== row.intentSha256) fail('JOURNAL_INTENT_HOLD');
    const key = transactionKey(row.intent);
    if (keys.has(key)) fail('JOURNAL_DUPLICATE_HOLD');
    keys.add(key); counts.set(row.grantId, (counts.get(row.grantId) || 0) + 1);
    const receipt = row.receipt;
    if (!exact(receipt, RECEIPT_KEYS) || receipt.schema !== 'mikaya.act.transaction-receipt.v1' ||
        !['accepted', 'completed', 'uncertain'].includes(receipt.state) ||
        receipt.intentSha256 !== row.intentSha256 || !positiveTime(receipt.acceptedAtMs) ||
        !positiveTime(receipt.updatedAtMs) || receipt.updatedAtMs < receipt.acceptedAtMs ||
        receipt.updatedAtMs > payload.lastObservedMs ||
        ['sender', 'recipient', 'operation', 'resource', 'transactionId'].some(field => receipt[field] !== row.intent[field]) ||
        (receipt.state === 'completed' ? !HEX.test(receipt.resultSha256) : receipt.resultSha256 !== null) ||
        (receipt.state === 'uncertain' ? !identifier(receipt.reason) : receipt.reason !== null)) fail('JOURNAL_RECEIPT_HOLD');
  }
  const quotaIds = new Set();
  for (const quota of payload.quotas) {
    if (!exact(quota, ['id', 'limit', 'used']) || !resourceId(quota.id) || quotaIds.has(quota.id) ||
        !Number.isSafeInteger(quota.limit) || quota.limit < 1 || quota.limit > MAX_RECORDS ||
        !Number.isSafeInteger(quota.used) || quota.used < 1 || quota.used > quota.limit ||
        quota.used !== counts.get(quota.id)) fail('JOURNAL_QUOTA_HOLD');
    quotaIds.add(quota.id);
  }
  if (quotaIds.size !== counts.size) fail('JOURNAL_QUOTA_HOLD');
}

function createJournal({directory, initialize = false}) {
  const store = openPrivateStore({directory, initialize, schema: 'mikaya.act.transaction-journal.v1',
    initialPayload: {lastObservedMs: 0, transactions: [], quotas: []}, validatePayload: validateJournal});
  function at(payload, nowMs) {
    if (!positiveTime(nowMs) || nowMs < payload.lastObservedMs) fail('CLOCK_ROLLBACK_HOLD');
  }
  function result(receipt, duplicate) {
    return {duplicate, receipt: copy(receipt), receiptSha256: sha(canonical(receipt))};
  }
  function accept({intent, grantId, usageLimit, effectiveUsageLimit = usageLimit, expiresAtMs, nowMs = Date.now()}) {
    const intentSha256 = validateIntent(intent), payload = store.snapshot();
    at(payload, nowMs);
    if (!resourceId(grantId) || !Number.isSafeInteger(usageLimit) || usageLimit < 1 || usageLimit > MAX_RECORDS ||
        !Number.isSafeInteger(effectiveUsageLimit) || effectiveUsageLimit < 1 || effectiveUsageLimit > usageLimit ||
        !positiveTime(expiresAtMs) || nowMs >= expiresAtMs || nowMs >= intent.expiresAtMs) fail('GRANT_OR_INTENT_INVALID');
    const key = transactionKey(intent), existing = payload.transactions.find(row => transactionKey(row.intent) === key);
    if (existing) {
      if (existing.intentSha256 !== intentSha256) fail('TRANSACTION_CONFLICT');
      return result(existing.receipt, true);
    }
    if (payload.transactions.length >= MAX_RECORDS) fail('JOURNAL_CAPACITY_HOLD');
    let quota = payload.quotas.find(item => item.id === grantId);
    if (quota && quota.limit !== usageLimit) fail('GRANT_BUDGET_CHANGED');
    if (quota && (quota.used >= quota.limit || quota.used >= effectiveUsageLimit)) fail('GRANT_EXHAUSTED');
    if (!quota) { quota = {id: grantId, limit: usageLimit, used: 0}; payload.quotas.push(quota); }
    const receipt = {schema: 'mikaya.act.transaction-receipt.v1', transactionId: intent.transactionId,
      sender: intent.sender, recipient: intent.recipient, operation: intent.operation, resource: intent.resource,
      intentSha256, state: 'accepted', acceptedAtMs: nowMs, updatedAtMs: nowMs, resultSha256: null, reason: null};
    quota.used++;
    payload.transactions.push({intent: copy(intent), intentSha256, grantId, receipt});
    payload.lastObservedMs = nowMs;
    store.commit(payload);
    return result(receipt, false);
  }
  function get(key) {
    const wanted = transactionKey(key);
    const row = store.snapshot().transactions.find(item => transactionKey(item.intent) === wanted);
    return row ? copy(row.receipt) : null;
  }
  function transition({sender, operation, transactionId, result, reason, nowMs = Date.now()}, state) {
    const key = transactionKey({sender, operation, transactionId}), payload = store.snapshot();
    at(payload, nowMs);
    const row = payload.transactions.find(item => transactionKey(item.intent) === key);
    if (!row) fail('TRANSACTION_NOT_FOUND');
    let resultSha256 = null;
    if (state === 'completed') {
      const encoded = canonical(result);
      if (Buffer.byteLength(encoded) > 8192) fail('RESULT_TOO_LARGE');
      resultSha256 = sha(encoded);
    } else if (!identifier(reason)) fail('UNCERTAINTY_REASON_INVALID');
    if (row.receipt.state === state && row.receipt.resultSha256 === resultSha256 &&
        row.receipt.reason === (state === 'uncertain' ? reason : null)) return {duplicate: true, receipt: copy(row.receipt), receiptSha256: sha(canonical(row.receipt))};
    if (row.receipt.state !== 'accepted') fail('TRANSACTION_STATE_HOLD');
    row.receipt = {...row.receipt, state, updatedAtMs: nowMs, resultSha256, reason: state === 'uncertain' ? reason : null};
    payload.lastObservedMs = nowMs;
    store.commit(payload);
    return {duplicate: false, receipt: copy(row.receipt), receiptSha256: sha(canonical(row.receipt))};
  }
  return Object.freeze({accept, get,
    complete: input => transition(input, 'completed'),
    markUncertain: input => transition(input, 'uncertain'),
    close: store.close});
}

module.exports = {createJournal, validateIntent, canonical, sha, openPrivateStore};
