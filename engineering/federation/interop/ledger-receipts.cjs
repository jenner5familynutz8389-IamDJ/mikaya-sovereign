'use strict';
/**
 * Separate owner-local signed receipt ledgers and nonmonetary accounting.
 * Verifies the existing signed work/profile contract before recording it.
 * Never treats compute units as satoshis, settlement, mining rewards or grants.
 * Checkpoints retained outside this directory detect rollback/truncation.
 * An owner controlling both private key and all retained checkpoints can still
 * replace history; this is not hardware monotonic storage or consensus.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const fed = require('../live/federation-node.cjs');
const session = require('./session-adapter.cjs');
const DOMAIN = 'MIKAYA-INTEROP-RECEIPT-LEDGER/1\n';
const UNIT = 'NONMONETARY_COMPUTE_UNIT';
const MAX_ENTRIES = 1024;
const MAX_ENTRY_BYTES = 65536;
const HASH = /^[a-f0-9]{64}$/;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const FILE = /^[0-9]{6}\.json$/;
const CAPS = new Set(['compute.dot.v1', 'compute.sha256.v1']);
const ROW_FIELDS = ['schema', 'ledgerId', 'index', 'prevHash', 'ownerFingerprint', 'kind', 'recordedAtMs', 'payload', 'entryHash', 'signature'];
const CHECKPOINT_FIELDS = ['schema', 'ledgerId', 'ownerFingerprint', 'entries', 'latestHash', 'policySha256', 'issuedAtMs', 'signature'];
const RECEIPT_FIELDS = ['request', 'response', 'evidence'];
const PAYLOAD_FIELDS = ['receipt', 'holderPublicKey', 'workerPublicKey', 'profileSha256', 'receiptSha256', 'requestKey', 'accounting'];
const O = fs.constants;
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
function ensure(ok, reason) { if (!ok) throw new Error(reason); }
function exact(value, fields) { return value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).sort().join('|') === [...fields].sort().join('|'); }
function uint(value, max = Number.MAX_SAFE_INTEGER) { return Number.isSafeInteger(value) && value >= 0 && value <= max; }
function publicKey(key) { const out = key?.type === 'public' ? key : crypto.createPublicKey(key); ensure(out.asymmetricKeyType === 'ed25519', 'Ed25519 ledger identity required'); return out; }
function privateKey(key) { const out = key?.type === 'private' ? key : crypto.createPrivateKey(key); ensure(out.asymmetricKeyType === 'ed25519', 'Ed25519 ledger signing key required'); return out; }
function pem(key) { return publicKey(key).export({ type: 'spki', format: 'pem' }); }
function digest(value) { return sha(session.boundedCanonical(value, MAX_ENTRY_BYTES)); }
function sign(kind, value, key) { return crypto.sign(null, Buffer.from(DOMAIN + kind + '\n' + fed.canonical(value)), privateKey(key)).toString('base64'); }
function verifySignature(kind, value, signature, key) {
  ensure(typeof signature === 'string' && /^[A-Za-z0-9+/]{86}==$/.test(signature), 'ledger signature encoding refused');
  const bytes = Buffer.from(signature, 'base64');
  ensure(bytes.length === 64 && bytes.toString('base64') === signature && crypto.verify(null, Buffer.from(DOMAIN + kind + '\n' + fed.canonical(value)), publicKey(key), bytes), 'ledger signature refused');
}
function validateDistributionPolicy(policy) {
  session.boundedCanonical(policy, 8192);
  ensure(exact(policy, ['schema', 'policyId', 'unit', 'rates', 'beneficiaries']) && policy.schema === 'mikaya.interop.distribution-policy.v1', 'distribution policy schema refused');
  ensure(typeof policy.policyId === 'string' && NAME.test(policy.policyId) && policy.unit === UNIT, 'explicit nonmonetary distribution policy required');
  ensure(Array.isArray(policy.rates) && policy.rates.length > 0 && policy.rates.length <= CAPS.size, 'distribution rate count refused');
  const caps = new Set();
  for (const rate of policy.rates) {
    ensure(exact(rate, ['capability', 'creditUnits']) && CAPS.has(rate.capability) && !caps.has(rate.capability) && uint(rate.creditUnits, 1000000000) && rate.creditUnits > 0, 'distribution rate refused');
    caps.add(rate.capability);
  }
  ensure(Array.isArray(policy.beneficiaries) && policy.beneficiaries.length === 2, 'two explicitly identified beneficiaries required');
  const identities = new Set(); let points = 0;
  for (const beneficiary of policy.beneficiaries) {
    ensure(exact(beneficiary, ['fingerprint', 'basisPoints']) && typeof beneficiary.fingerprint === 'string' && HASH.test(beneficiary.fingerprint) && !identities.has(beneficiary.fingerprint) && uint(beneficiary.basisPoints, 9999) && beneficiary.basisPoints > 0, 'distribution beneficiary refused');
    identities.add(beneficiary.fingerprint); points += beneficiary.basisPoints;
  }
  ensure(points === 10000, 'distribution basis points must sum to 10000');
  return policy;
}
function accountReceipt({ policy, capability, holderFingerprint, workerFingerprint }) {
  validateDistributionPolicy(policy);
  ensure(typeof holderFingerprint === 'string' && typeof workerFingerprint === 'string' && holderFingerprint !== workerFingerprint && HASH.test(holderFingerprint) && HASH.test(workerFingerprint), 'separate receipt participants required');
  ensure(policy.beneficiaries.every(b => b.fingerprint === holderFingerprint || b.fingerprint === workerFingerprint), 'receipt participants excluded by distribution policy');
  const rate = policy.rates.find(x => x.capability === capability);
  ensure(rate, 'receipt capability excluded by distribution policy');
  const ranked = policy.beneficiaries.map(b => {
    const value = BigInt(rate.creditUnits) * BigInt(b.basisPoints);
    return { fingerprint: b.fingerprint, units: Number(value / 10000n), remainder: Number(value % 10000n) };
  }).sort((a, b) => b.remainder - a.remainder || (a.fingerprint < b.fingerprint ? -1 : 1));
  let left = rate.creditUnits - ranked.reduce((n, b) => n + b.units, 0);
  for (const b of ranked) { if (left === 0) break; b.units++; left--; }
  ensure(left === 0, 'distribution conservation failure');
  const allocations = ranked.sort((a, b) => a.fingerprint < b.fingerprint ? -1 : 1).map(({ fingerprint, units }) => ({ fingerprint, units }));
  return { schema: 'mikaya.interop.compute-accounting.v1', unit: UNIT, capability, creditUnits: rate.creditUnits, allocations, policySha256: digest(policy), paymentSettled: false, bitcoinTransaction: false, miningReward: false, executionAuthorized: false };
}
function secureDirectory(dir) {
  ensure(typeof dir === 'string' && path.isAbsolute(dir), 'absolute receipt ledger path required');
  const st = fs.lstatSync(dir);
  ensure(st.isDirectory() && !st.isSymbolicLink() && !(st.mode & 0o077), 'receipt ledger must be a private directory');
  if (typeof process.getuid === 'function') ensure(st.uid === process.getuid(), 'receipt ledger directory owner mismatch');
}
function readEntry(file) {
  const fd = fs.openSync(file, O.O_RDONLY | O.O_NOFOLLOW);
  try {
    const st = fs.fstatSync(fd);
    ensure(st.isFile() && st.nlink === 1 && !(st.mode & 0o077) && st.size > 0 && st.size <= MAX_ENTRY_BYTES, 'unsafe receipt ledger entry');
    if (typeof process.getuid === 'function') ensure(st.uid === process.getuid(), 'receipt ledger file owner mismatch');
    const raw = fs.readFileSync(fd, 'utf8');
    ensure(Buffer.byteLength(raw) <= MAX_ENTRY_BYTES, 'receipt ledger entry grew');
    const row = JSON.parse(raw);
    ensure(raw === session.boundedCanonical(row, MAX_ENTRY_BYTES) + '\n', 'noncanonical receipt ledger entry');
    return row;
  } finally { fs.closeSync(fd); }
}
function syncDirectory(dir) { const fd = fs.openSync(dir, O.O_RDONLY); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
function filename(index) { return String(index).padStart(6, '0') + '.json'; }
function writeEntry(dir, row) {
  const bytes = session.boundedCanonical(row, MAX_ENTRY_BYTES - 1) + '\n';
  const dest = path.join(dir, filename(row.index));
  // Android app filesystems can prohibit hard links. The durable append lock
  // serializes cooperative readers/writers; exclusive final-path creation
  // prevents overwrite without relying on link/rename support. A failed write
  // leaves the partial entry AND lock for explicit owner-reviewed recovery.
  const fd = fs.openSync(dest, O.O_WRONLY | O.O_CREAT | O.O_EXCL | O.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  syncDirectory(dir);
}
function lockDirectory(dir) {
  secureDirectory(dir);
  const lock = path.join(dir, '.append.lock');
  const fd = fs.openSync(lock, O.O_WRONLY | O.O_CREAT | O.O_EXCL | O.O_NOFOLLOW, 0o600);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  syncDirectory(dir);
  return () => { fs.unlinkSync(lock); syncDirectory(dir); };
}
function signedRow({ ledgerId, index, prevHash, ownerFingerprint, kind, recordedAtMs, payload, key }) {
  const body = { schema: 'mikaya.interop.receipt-ledger-entry.v1', ledgerId, index, prevHash, ownerFingerprint, kind, recordedAtMs, payload };
  const entryHash = sha(DOMAIN + 'HASH\n' + session.boundedCanonical(body, MAX_ENTRY_BYTES));
  return { ...body, entryHash, signature: sign('ENTRY', { entryHash }, key) };
}
function verifyWork({ receipt, holderPublicKey, workerPublicKey, profileSha256, nowMs, policy, ownerFingerprint }) {
  ensure(exact(receipt, RECEIPT_FIELDS), 'receipt fields refused');
  const holder = pem(holderPublicKey), worker = pem(workerPublicKey);
  const holderFingerprint = fed.fp(holder), workerFingerprint = fed.fp(worker);
  ensure(ownerFingerprint === holderFingerprint || ownerFingerprint === workerFingerprint, 'ledger owner must participate in recorded work');
  const verified = session.verifyConformanceReceipt({ ...receipt, holderPublicKey: holder, workerPublicKey: worker, profileSha256, nowMs });
  const accounting = accountReceipt({ policy, capability: verified.capability, holderFingerprint, workerFingerprint });
  return { holder, worker, accounting, requestKey: sha(holderFingerprint + '\n' + workerFingerprint + '\n' + receipt.request.auth.nonce), receiptSha256: digest(receipt) };
}
function verifyReceiptCheckpoint(args) {
  ensure(exact(args, ['checkpoint', 'nodePublicKey']), 'checkpoint verification fields refused');
  const { checkpoint, nodePublicKey } = args;
  session.boundedCanonical(checkpoint, 8192);
  ensure(exact(checkpoint, CHECKPOINT_FIELDS) && checkpoint.schema === 'mikaya.interop.receipt-ledger-checkpoint.v1', 'checkpoint schema refused');
  ensure(typeof checkpoint.ledgerId === 'string' && HASH.test(checkpoint.ledgerId) && typeof checkpoint.ownerFingerprint === 'string' && HASH.test(checkpoint.ownerFingerprint) && checkpoint.ownerFingerprint === fed.fp(publicKey(nodePublicKey)) && typeof checkpoint.latestHash === 'string' && HASH.test(checkpoint.latestHash) && typeof checkpoint.policySha256 === 'string' && HASH.test(checkpoint.policySha256) && uint(checkpoint.entries, MAX_ENTRIES) && checkpoint.entries > 0 && uint(checkpoint.issuedAtMs), 'checkpoint fields or owner refused');
  const { signature, ...body } = checkpoint;
  verifySignature('CHECKPOINT', body, signature, nodePublicKey);
  return { verified: true, ...body, localLedgerConsistencyVerified: false, paymentSettled: false, executionAuthorized: false };
}
function checkLedger({ ledgerDir, nodePublicKey, expectedCheckpoint }, locked = false) {
  secureDirectory(ledgerDir);
  const key = publicKey(nodePublicKey), ownerFingerprint = fed.fp(key);
  const names = fs.readdirSync(ledgerDir);
  ensure(names.length <= MAX_ENTRIES + (locked ? 1 : 0), 'receipt ledger capacity exceeded');
  ensure(locked || !names.includes('.append.lock'), 'receipt ledger append in progress or unrecovered lock');
  const files = names.filter(n => !(locked && n === '.append.lock')).sort();
  ensure(files.length > 0 && files.every(n => FILE.test(n)), 'missing genesis or unfinished receipt ledger write');
  let previous = '0'.repeat(64), previousTime = -1, ledgerId, policy, policySha256;
  const seen = new Set(), rows = [], totals = new Map(), receiptRecords = new Map();
  for (let i = 0; i < files.length; i++) {
    ensure(files[i] === filename(i), 'receipt ledger sequence gap');
    const row = readEntry(path.join(ledgerDir, files[i]));
    ensure(exact(row, ROW_FIELDS) && row.schema === 'mikaya.interop.receipt-ledger-entry.v1' && row.index === i && row.prevHash === previous && row.ownerFingerprint === ownerFingerprint && typeof row.ledgerId === 'string' && HASH.test(row.ledgerId), 'receipt ledger chain or identity mismatch');
    ensure(uint(row.recordedAtMs) && row.recordedAtMs >= previousTime, 'receipt ledger clock rollback');
    const { entryHash, signature, ...body } = row;
    ensure(entryHash === sha(DOMAIN + 'HASH\n' + session.boundedCanonical(body, MAX_ENTRY_BYTES)), 'receipt ledger hash mismatch');
    verifySignature('ENTRY', { entryHash }, signature, key);
    if (i === 0) {
      ensure(row.kind === 'GENESIS' && exact(row.payload, ['policy', 'policySha256']), 'receipt ledger genesis invalid');
      policy = validateDistributionPolicy(row.payload.policy); policySha256 = digest(policy); ledgerId = row.ledgerId;
      ensure(row.payload.policySha256 === policySha256 && policy.beneficiaries.some(b => b.fingerprint === ownerFingerprint), 'genesis policy or owner binding refused');
      for (const b of policy.beneficiaries) totals.set(b.fingerprint, 0);
    } else {
      ensure(row.kind === 'VERIFIED_COMPUTE_RECEIPT' && row.ledgerId === ledgerId && exact(row.payload, PAYLOAD_FIELDS), 'receipt ledger payload schema invalid');
      const p = row.payload, verified = verifyWork({ receipt: p.receipt, holderPublicKey: p.holderPublicKey, workerPublicKey: p.workerPublicKey, profileSha256: p.profileSha256, nowMs: row.recordedAtMs, policy, ownerFingerprint });
      ensure(p.holderPublicKey === verified.holder && p.workerPublicKey === verified.worker && p.receiptSha256 === verified.receiptSha256 && p.requestKey === verified.requestKey && digest(p.accounting) === digest(verified.accounting), 'receipt or accounting altered');
      ensure(!seen.has(p.requestKey), 'duplicate request in receipt ledger'); seen.add(p.requestKey);
      receiptRecords.set(p.requestKey, { receiptSha256: p.receiptSha256, accounting: p.accounting });
      for (const allocation of p.accounting.allocations) { const total = totals.get(allocation.fingerprint) + allocation.units; ensure(uint(total), 'accounting total overflow'); totals.set(allocation.fingerprint, total); }
    }
    previous = entryHash; previousTime = row.recordedAtMs; rows.push(row);
  }
  if (expectedCheckpoint !== undefined) {
    verifyReceiptCheckpoint({ checkpoint: expectedCheckpoint, nodePublicKey: key });
    ensure(expectedCheckpoint.ledgerId === ledgerId && expectedCheckpoint.ownerFingerprint === ownerFingerprint && expectedCheckpoint.policySha256 === policySha256 && uint(expectedCheckpoint.entries, MAX_ENTRIES) && expectedCheckpoint.entries > 0 && uint(expectedCheckpoint.issuedAtMs), 'checkpoint ledger binding refused');
    ensure(rows.length >= expectedCheckpoint.entries && rows[expectedCheckpoint.entries - 1].entryHash === expectedCheckpoint.latestHash && rows[expectedCheckpoint.entries - 1].recordedAtMs === expectedCheckpoint.issuedAtMs, 'receipt ledger rollback or checkpoint mismatch');
  }
  return { ledgerId, ownerFingerprint, entries: rows.length, receipts: rows.length - 1, latestHash: previous, latestAtMs: previousTime, policySha256, policy, seen, receiptRecords, totals: [...totals].sort(([a], [b]) => a < b ? -1 : 1).map(([fingerprint, units]) => ({ fingerprint, units })) };
}
function checkpoint(state, key) {
  const body = { schema: 'mikaya.interop.receipt-ledger-checkpoint.v1', ledgerId: state.ledgerId, ownerFingerprint: state.ownerFingerprint, entries: state.entries, latestHash: state.latestHash, policySha256: state.policySha256, issuedAtMs: state.latestAtMs };
  return { ...body, signature: sign('CHECKPOINT', body, key) };
}
function initializeReceiptLedger(args) {
  ensure(exact(args, ['ledgerDir', 'nodePrivateKey', 'policy']) || exact(args, ['ledgerDir', 'nodePrivateKey', 'policy', 'nowMs']), 'ledger initialization fields refused');
  const { ledgerDir, nodePrivateKey, policy, nowMs = Date.now() } = args;
  ensure(typeof ledgerDir === 'string' && path.isAbsolute(ledgerDir) && uint(nowMs), 'ledger initialization path or time refused');
  const key = privateKey(nodePrivateKey), ownerFingerprint = fed.fp(publicKey(key));
  validateDistributionPolicy(policy);
  ensure(policy.beneficiaries.some(b => b.fingerprint === ownerFingerprint), 'ledger owner excluded by policy');
  fs.mkdirSync(ledgerDir, { mode: 0o700 }); const unlock = lockDirectory(ledgerDir);
  let releaseLock = true;
  try {
    const row = signedRow({ ledgerId: crypto.randomBytes(32).toString('hex'), index: 0, prevHash: '0'.repeat(64), ownerFingerprint, kind: 'GENESIS', recordedAtMs: nowMs, payload: { policy, policySha256: digest(policy) }, key });
    releaseLock = false;
    writeEntry(ledgerDir, row);
    const state = checkLedger({ ledgerDir, nodePublicKey: publicKey(key) }, true);
    const result = { initialized: true, unit: UNIT, checkpoint: checkpoint(state, key), paymentSettled: false };
    releaseLock = true;
    return result;
  } finally { if (releaseLock) unlock(); }
}
function appendReceipt(args) {
  const fields = ['ledgerDir', 'nodePrivateKey', 'policy', 'receipt', 'holderPublicKey', 'workerPublicKey', 'profileSha256'];
  ensure(exact(args, fields) || exact(args, [...fields, 'nowMs']), 'receipt append fields refused');
  const { ledgerDir, nodePrivateKey, policy, receipt, holderPublicKey, workerPublicKey, profileSha256, nowMs = Date.now() } = args;
  ensure(uint(nowMs), 'receipt record time refused');
  const key = privateKey(nodePrivateKey), ownerFingerprint = fed.fp(publicKey(key));
  // Full cryptographic work verification occurs before any disk mutation.
  const verified = verifyWork({ receipt, holderPublicKey, workerPublicKey, profileSha256, nowMs, policy, ownerFingerprint });
  const unlock = lockDirectory(ledgerDir);
  let releaseLock = true;
  try {
    const state = checkLedger({ ledgerDir, nodePublicKey: publicKey(key) }, true);
    ensure(state.policySha256 === digest(policy), 'distribution policy changed; separate successor ledger required');
    ensure(nowMs >= state.latestAtMs, 'receipt ledger clock rollback');
    ensure(state.entries < MAX_ENTRIES, 'receipt ledger full; retain checkpoint and create explicit successor');
    ensure(!state.seen.has(verified.requestKey), 'receipt request replay refused');
    const payload = { receipt, holderPublicKey: verified.holder, workerPublicKey: verified.worker, profileSha256, receiptSha256: verified.receiptSha256, requestKey: verified.requestKey, accounting: verified.accounting };
    const row = signedRow({ ledgerId: state.ledgerId, index: state.entries, prevHash: state.latestHash, ownerFingerprint, kind: 'VERIFIED_COMPUTE_RECEIPT', recordedAtMs: nowMs, payload, key });
    releaseLock = false;
    writeEntry(ledgerDir, row);
    const head = { ...state, entries: state.entries + 1, latestHash: row.entryHash, latestAtMs: nowMs };
    const result = { recorded: true, index: row.index, entryHash: row.entryHash, requestKey: verified.requestKey, receiptSha256: verified.receiptSha256, accounting: verified.accounting, checkpoint: checkpoint(head, key), eventSpineDigest: { kind: 'FEDERATION_COMPUTE_OBSERVED', payloadSha256: row.entryHash }, paymentSettled: false, executionAuthorized: false };
    releaseLock = true;
    return result;
  } finally { if (releaseLock) unlock(); }
}
function verifyReceiptLedger(args) {
  ensure(exact(args, ['ledgerDir', 'nodePublicKey']) || exact(args, ['ledgerDir', 'nodePublicKey', 'expectedCheckpoint']), 'ledger verification fields refused');
  const state = checkLedger(args);
  const { seen, policy, receiptRecords, ...head } = state;
  return { schema: 'mikaya.interop.receipt-ledger-verification.v1', verified: true, ...head, unit: UNIT, rollbackAnchored: args.expectedCheckpoint !== undefined, paymentSettled: false, bitcoinTransaction: false, miningReward: false, hardwareAttested: false, executionAuthorized: false };
}
function reconcileReceiptLedgers(args) {
  ensure(exact(args, ['ledgers']) && Array.isArray(args.ledgers) && args.ledgers.length === 2, 'two independent receipt ledgers required');
  const states = args.ledgers.map(input => {
    ensure(exact(input, ['ledgerDir', 'nodePublicKey']) || exact(input, ['ledgerDir', 'nodePublicKey', 'expectedCheckpoint']), 'reconciliation ledger fields refused');
    return checkLedger(input);
  });
  ensure(states[0].ownerFingerprint !== states[1].ownerFingerprint && states[0].ledgerId !== states[1].ledgerId, 'independent ledger identities required');
  ensure(states[0].policySha256 === states[1].policySha256, 'different distribution policies cannot be reconciled');
  const totals = new Map(states[0].policy.beneficiaries.map(b => [b.fingerprint, 0]));
  const requestKeys = [...new Set(states.flatMap(s => [...s.receiptRecords.keys()]))].sort();
  const matchedRequestKeys = [], unmatchedRecords = [];
  for (const requestKey of requestKeys) {
    const a = states[0].receiptRecords.get(requestKey), b = states[1].receiptRecords.get(requestKey);
    if (!a || !b) { unmatchedRecords.push({ requestKey, recordedBy: a ? states[0].ownerFingerprint : states[1].ownerFingerprint }); continue; }
    ensure(a.receiptSha256 === b.receiptSha256 && digest(a.accounting) === digest(b.accounting), 'conflicting signed receipts for the same request');
    matchedRequestKeys.push(requestKey);
    for (const allocation of a.accounting.allocations) { const next = totals.get(allocation.fingerprint) + allocation.units; ensure(uint(next), 'reconciled accounting overflow'); totals.set(allocation.fingerprint, next); }
  }
  return { schema: 'mikaya.interop.receipt-ledger-reconciliation.v1', verified: true, unit: UNIT, policySha256: states[0].policySha256,
    ledgerHeads: states.map(s => ({ ownerFingerprint: s.ownerFingerprint, ledgerId: s.ledgerId, entries: s.entries, latestHash: s.latestHash })),
    matchedReceipts: matchedRequestKeys.length, matchedRequestKeys, unmatchedRecords, allReceiptsAgreed: unmatchedRecords.length === 0,
    allocations: [...totals].sort(([a], [b]) => a < b ? -1 : 1).map(([fingerprint, units]) => ({ fingerprint, units })),
    paymentSettled: false, bitcoinTransaction: false, miningReward: false, executionAuthorized: false };
}
module.exports = { UNIT, MAX_ENTRIES, validateDistributionPolicy, accountReceipt, initializeReceiptLedger, appendReceipt, verifyReceiptLedger, verifyReceiptCheckpoint, reconcileReceiptLedgers };
