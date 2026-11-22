# Persistent Witness & Recovery v2 — MIKAYA source acceptance

**Status: source implementation on a real F110 Pro; independent Motorola admission remains unverified.** This is an opt-in local witness-store library, not a background service, production identity provisioning, or ACT-Omega enrollment.

## Integrity and existing source compatibility

The implementation adds `persistent-witness.cjs` alongside the established `rotating-audit.cjs` and `witness-checkpoints.cjs`. It does not modify their original signed entry or checkpoint formats. It preserves the existing owner-ledger full predecessor hash, per-entry fresh key rotation, owner delegation, signed witness checkpoint, and chained previous checkpoint digest.

A witness-controlled storage directory contains `checkpoint-state.json` with public-only signed receipts and a high-water sequence/digest. A new observation verifies the entire owner-signed ledger and the old signed witness checkpoint, rejects replay/rollback, and atomically replaces the state using a unique exclusive private temporary file, `fsync` of the file and directory, and an exclusive lock. Storage with unsafe permissions, symlinks, missing history, invalid witness identities, or corrupt evidence is rejected. A process interrupted while holding the lock leaves a fail-closed lock requiring authorized manual reconciliation; **do not automatically delete lock files or reset a witness vault**.

Neither keys nor credentials are read from environment variables on import. The caller supplies a protected signer; this Node implementation does **not** yet provide Android Keystore/KeyMint backed signatures and does not claim independently protected hardware keys. The *independent witness* must run on a separately controlled device to be physically independent. Two local signing keys are not two physical witnesses.

## Example library integration

The following is API shape only; do not commit owner private keys or test keys to the repository.

```js
const vault=require('./persistent-witness.cjs');
// Witness host, once and only once after independently approving source/identities:
const receipt=vault.record({
  dir: '/absolute/private/witness-directory',
  entries: fullyVerifiedOwnerSignedEntries,
  rootPublicKey: independentlyPinnedOwnerPublicKey,
  witnessPrivateKey: locallyProtectedWitnessSigningKey,
  bootstrap: true,
  issuedAtMs: Date.now()
});
// Retain receipt.receiptDigest through an INDEPENDENT trusted source.
```

For subsequent observations omit `bootstrap` and provide the independently retained `expectedPriorDigest`. Use `inspect` with `expectedMinimumSequence` and `expectedLatestDigest` from an independently controlled witness, not values obtained from the same candidate file. The expected digest is checked but the library cannot prove where the caller obtained it.

## Physical acceptance sequence

1. Confirm the F110 and Motorola each run the same reviewed Git commit and test suite, with no background live-call tracing.
2. Enroll separate owner-approved device identities using locally protected keys; **do not** export private key material into source control or public reports. Review Android Keystore provider support rather than assuming software Ed25519 keys are hardware-backed.
3. Use an explicitly authorized mutually authenticated channel to deliver a bounded public-only ledger and receipt to Motorola. Verify origin and authorized scope before witness signing. Do not reuse any ACT credentials or financial macaroon as device identity.
4. Motorola performs `record` using its local witness identity and private storage, returns its signed checkpoint and digest, and independently retains the high-water mark.
5. F110 intentionally presents a valid older chain: Motorola must reject it even though the older signatures remain valid. Test key renewal, disconnected operation, crash recovery, and rejoining with no silent reset.
6. Only then classify the result as *physically witnessed*, with separately captured source hash, node readbacks, independently signed receipts and an auditable control-evidence entry.

**Cannot be claimed yet:** Motorola physical verification, independent external custody, hardware-backed signing, persistent network service operation, government certification, ACT admission, Toybox payment settlement or funded 5% user dividends. All remain separately approved and verifiable gates.

## Run tests

```sh
node --test engineering/federation/interop/assurance/test_rotating_audit.cjs \
  engineering/federation/interop/assurance/test_witness_checkpoints.cjs \
  engineering/federation/interop/assurance/test_persistent_witness.cjs
```

The persistent-state tests exercise actual filesystem writes and reading the state from a second Node process; they intentionally use disposable test keys and temporary private directories rather than writing to installed MIKAYA services.

## Operational limitation

This is a bounded JSON snapshot store, suitable for a small number of witnessed checkpoint epochs; for centuries-long operation migrate to segmented journals, independently anchored high-water marks, retained key-rotation certificates, and signed cryptographic algorithm transitions. Do not present locally writable state or a caller-supplied digest as rollback-resistant evidence without a separately maintained trusted reference.
