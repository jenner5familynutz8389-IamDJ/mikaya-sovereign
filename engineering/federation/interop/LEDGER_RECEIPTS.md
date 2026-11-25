# Verified work receipts and independent accounting

`ledger-receipts.cjs` connects the verified request/result/profile contract to
separate local receipt ledgers. Each participant signs its own chain. This module
does not share a private key, merge sovereign ledgers, call a wallet, price work
in satoshis, authorize execution, or settle a transaction.

## Existing project integration

The existing `live/mesh-economy.cjs` verifies signed service quotes and keeps
`authorizePaidWork()` false. A quote is not an invoice or settlement receipt.
`live/toybox-mempool-bridge.cjs` observes a fixed historical Bitcoin anchor with
two explorers; it is not a current mempool transaction validator or miner.
`live/sovereign-event-ledger.cjs` signs allowed event digests using an existing
owner node. `live/owner-authorization.cjs` keeps ACT permission dependent on
separate owner and security-review proofs.

The new module verifies accepted computation evidence and provides durable local
accounting without changing those boundaries. Its returned `eventSpineDigest`
has the existing allowed kind `FEDERATION_COMPUTE_OBSERVED` and the signed entry
hash as `payloadSha256`. An owner-controlled caller may explicitly append that
digest through the existing event-spine API. The module itself never opens the
existing production node or its private key.

## Explicit policy

A caller supplies this exact policy structure during ledger initialization and
each append. Beneficiary fingerprints must identify the two actual participants.
The node that signs a ledger must be one of them. Policies are immutable for a
ledger; a change requires an explicit successor ledger and retained checkpoint.

```js
const policy = {
  schema: 'mikaya.interop.distribution-policy.v1',
  policyId: 'explicit-owner-test-accounting',
  unit: 'NONMONETARY_COMPUTE_UNIT',
  rates: [
    { capability: 'compute.dot.v1', creditUnits: 1000 },
    { capability: 'compute.sha256.v1', creditUnits: 1000 }
  ],
  beneficiaries: [
    { fingerprint: holderFingerprint, basisPoints: 5000 },
    { fingerprint: workerFingerprint, basisPoints: 5000 }
  ]
};
```

These example rates and shares are test-accounting parameters, not prices or a
claim of an agreed commercial distribution. No default economic allocation is
inferred from device identity, a signed computation, a star, or a public profile.

Rates are positive safe integers of at most one billion units. Both shares must
be positive integers and sum to 10,000 basis points. Allocation uses exact
integer arithmetic and largest remainders; ties use fingerprint order. It
conserves every unit without floating-point amounts. The accepted unit label is
strictly `NONMONETARY_COMPUTE_UNIT`; BTC, sats, msats and monetary authority fields
are rejected.

## API

```js
const ledger = require('./ledger-receipts.cjs');

const genesis = ledger.initializeReceiptLedger({
  ledgerDir, nodePrivateKey, policy
});

const record = ledger.appendReceipt({
  ledgerDir, nodePrivateKey, policy,
  receipt: { request, response, evidence },
  holderPublicKey, workerPublicKey, profileSha256
});

const local = ledger.verifyReceiptLedger({
  ledgerDir, nodePublicKey,
  expectedCheckpoint: independentlyRetainedCheckpoint
});

const remoteSignature = ledger.verifyReceiptCheckpoint({
  checkpoint: peerCheckpoint,
  nodePublicKey: pinnedPeerPublicKey
});
```

Initialization requires a new absolute directory under an existing parent.
Directories are private and entries use private permissions. Ed25519 private
keys are supplied by the caller and never written by the ledger module.

Append verifies the request signature, response signature and deterministic
result, signed profile binding, exact participant identities, and current
60-second freshness window before writing. The owner must be a participant and
the capability must have an explicit rate. It rejects an already recorded
holder/worker/request nonce even after process restart. The stored record binds
the complete public receipt, exact accounting and immutable policy to an
owner-signed hash-chain entry.

Verification of historical entries uses their signed record timestamps. That
checks the original evidence window; it does not make old requests executable
again. A bare signed checkpoint establishes the signer's statement about a head;
`localLedgerConsistencyVerified: false` explicitly means that remote history was
not inspected. Full chain verification requires the actual ledger entries.

## Reconciliation without double counting

The same work may be recorded once on each node. **Never add both local totals
together as if they represented different jobs.** Given two public ledger
snapshots and their pinned node keys:

```js
const joint = ledger.reconcileReceiptLedgers({
  ledgers: [
    { ledgerDir: firstSnapshot, nodePublicKey: firstPinnedKey,
      expectedCheckpoint: firstRetainedCheckpoint },
    { ledgerDir: secondSnapshot, nodePublicKey: secondPinnedKey,
      expectedCheckpoint: secondRetainedCheckpoint }
  ]
});
```

This independently verifies both chains and their policy agreement. Matching
request identifiers, exact receipt digests and allocations count once.
Unmatched entries remain visible and contribute nothing to the joint total.
Conflicting validly signed receipts for the same request are refused. This is
receipt reconciliation, not a consensus protocol or payment mechanism.

## Persistence and operational limits

Appends use a durable exclusive local lock, exclusive final-path entry creation
(`O_CREAT | O_EXCL | O_NOFOLLOW`), file fsync and directory fsync. They do not
depend on hard-link permission, rename an entry over another, or overwrite an
existing entry. This is a serialized append protocol, not an atomic replacement
of a whole file. Cooperative readers refuse a ledger while the append lock is
present. A failed write or entry fsync preserves its final-path entry and lock,
including when that file is empty or partial. Recovery requires explicit owner
review; retry does not erase or overwrite the uncertain record. Missing/corrupt
ledgers, gaps, partial writes, unsafe permissions, symlinks, outstanding locks,
signature failures, and clock rollback fail closed. A crashed append can require
owner-reviewed recovery; the module does not delete replay evidence or repair a
ledger silently.

Each ledger holds at most 1,024 entries including genesis; each entry is limited
to 64 KiB. Every append verifies existing history. This is bounded audit storage,
not a claim of unlimited throughput. Plan an explicit signed successor before
capacity is reached.

Retain signed checkpoints outside the ledger directory, preferably with the
counterparty. A trusted checkpoint detects truncation below that point or a
different history at that point. An intact prefix without an external checkpoint
cannot prove that no tail was removed. An owner who controls the signing key and
all retained anchors can replace history; software files are not hardware
monotonic storage.

The transport must separately enforce its current owner policy, peer pins and
kill switch before work. Successfully recording a receipt does not authorize
another operation, ACT admission, firmware changes, or payment.

## Tests

```sh
node --test engineering/federation/interop/tests/test_ledger_receipts.cjs
```

The 21 cases exercise real signatures, separate ledgers, work/profile tampering,
replay after module restart, two competing processes, integer conservation,
monetary-label rejection, immutable policy, signed checkpoints and truncation,
chain tampering, unsafe files/locks, stale records, and cross-node reconciliation
with unmatched or conflicting signed work. They also simulate Android hard-link
denial, partial writes, entry-fsync failure and a competing final-path file to
verify compatibility and preservation of failed/uncertain records.
