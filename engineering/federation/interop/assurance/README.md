# Optional rotating caveat-receipt evidence — independent review

This is an **opt-in local evidence adaptor**, not a replacement for the existing ACT-Omega / MIKAYA request/response wire schema, L402 monetary macaroon, external hardware review, owner grant, or executable task admission.

`rotating-audit.cjs` binds a public-only claim about an already issued compute work receipt to the full previous entry hash. The proof contains the SHA-256 of the exact original job, receipt, original owner grant, existing macaroon, and policy. This adapter does not independently decode/verify those referenced objects: the caller must use the already-existing federation and macaroon verifiers first. Never accept a user-provided digest by itself as proof of authorization, execution, money or ACT enrollment.

Every entry independently generates a fresh Ed25519 key pair using Node's operating-system cryptographic RNG. The owner's separately controlled root signs a one-entry, one-key delegation bound to the full predecessor hash and signer fingerprint. Only the resulting public key, bounded record, delegation, signatures and entry hash are returned. No derived static private key, payment authority or new listener is created. The process may retain a transient key in memory until collected; there is no claim of hardware-backed custody or secure memory erasure.

Verification checks the full chain, the owner root, per-entry signatures, replayed job IDs, policy claims, key reuse, canonical hash and predecessor links. A supplied `expectedHeadHash` matches a **caller-supplied** checkpoint only; `externalWitnessIndependentlyVerified:false` explicitly remains until a separately trusted off-device witness produces and retains evidence. For multi-year continuity, the permanent root itself will need signed key migration, expiry/revocation rules, segmented checkpoints and independently validated backups. This source does not implement root migration or durable storage.

## Run native tests
```sh
node --test engineering/federation/interop/assurance/test_rotating_audit.cjs
```

## ACT, Toybox and 5% accounting compatibility

No ACT endpoint is called. Existing `compute.sha256.v1`, `compute.dot.v1` and optional aggregate telemetry receipts are referenced without wire changes. Keep ACT peer enrollment and independently approved worker routing on HOLD until both owners validate. Historical confirmed Bitcoin Toybox observations and nonmonetary computing receipts are not settled invoices or pool revenue. The private accounting policy remains **one shared 5% pool of newly verified settled service revenue** split among approved eligible devices, never 5% per node. This module cannot mint, move, allocate or distribute funds.

Government/security assurance requires an independently reviewed threat model, hardware/protected key custody, a rollback-resistant witness, supply-chain provenance and deployed integration acceptance. No certification is implied.
