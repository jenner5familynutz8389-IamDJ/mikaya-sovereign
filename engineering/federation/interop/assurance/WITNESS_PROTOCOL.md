# MIKAYA witness checkpoints — opt-in v1

**Source candidate only.** This is a separate evidence layer for the existing ACT-compatible signed receipts. It does not add an ACT network route, new node admission, financial settlement, live listener or firmware operation.

## Design
A ledger already signed through `rotating-audit.cjs` is verified against the owner's pinned public root. A different Ed25519 witness key signs the exact sequence number, full current ledger head hash, owner-root fingerprint, previous witness-checkpoint digest, fresh random nonce and the observation time. Every checkpoint has a full SHA-256 digest and the next checkpoint includes that digest unchanged. This is independent cryptographic *signing*, not proof of separate hardware.

- `observe({entries,rootPublicKey,witnessPrivateKey,previousReceipt,issuedAtMs})` creates a signed observation only after checking the complete owner ledger. The witness private key remains with the caller and is not serialized.
- `verifyStream({entries,rootPublicKey,witnessPublicKey,receipts,expectedLatestDigest})` verifies the complete sequence, both signatures' trust boundaries, full predecessor link, increasing checkpoint sequence, replay and fork attempts, and that the last checkpoint actually covers the current ledger head. `expectedLatestDigest` must be sourced from a separately retained trusted record; re-reading it from the same untrusted bundle does **not** make it rollback-resistant.
- `verifyQuorum({entries,rootPublicKey,witnesses,minimumWitnesses})` checks distinct pinned witness signing identities and a matching latest head for each. Two software signing identities on one phone are **not** evidence of two physically independent nodes.

No external witness was contacted or onboarded during these source tests. The Motorola needs its own owner-approved, authenticated channel, witness identity, protected storage, fresh readback and response signature to establish a genuine second-device acceptance. ACT must separately sign bilateral peer admission and remains on HOLD.

## Negative cases
Tests reject forged fingerprints, altered hashes and signatures, duplicate checkpoints, reversed or missing records, older signed checkpoints presented for a longer chain, same root identity presented as a witness, duplicate witness identities, and a mismatched externally pinned head.

This evidence cannot authorize execution, move money, grant ACT authority, attest hardware or certify government compliance. Historical Bitcoin Toybox observations and the proposed single shared 5% revenue pool remain separate from proof of actual settlement.

## Run
```sh
node --test engineering/federation/interop/assurance/test_rotating_audit.cjs engineering/federation/interop/assurance/test_witness_checkpoints.cjs
```

Next physical acceptance: run the same reviewed source digest on F110 and Motorola, exchange a current signed checkpoint over explicitly owner-authorized mTLS, persist the witness's trusted high-water digest independently, test recovery and conflicting checkpoints, then independently reverify the evidence. Never export secret keys into a public evidence package.

## v2 durable witness store

The opt-in persisted checkpoint module, crash/replay/rollback tests and Motorola acceptance procedure are documented in [PERSISTENT_WITNESS_V2.md](PERSISTENT_WITNESS_V2.md). It does not change the ACT-Omega wire format or enable a live witness service.
