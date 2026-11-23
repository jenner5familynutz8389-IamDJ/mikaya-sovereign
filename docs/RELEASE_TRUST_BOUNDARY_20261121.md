# MIKAYA release-trust boundary (2026-11-21)

Status: **HOLD** until owner-approved complete source release, independent verification and required production gates. ACT-Omega admission remains separately disabled.

## Executable source-integrity rule
Use `node tools/verify-release-closure.cjs . --require-complete` on the exact candidate checkout before calling its source a complete signed release. `node verify-release.js` now calls this strict verifier and refuses stale file hashes. The verifier checks the independently pinned release public-key fingerprint, Ed25519 attestation, SHA-256 of every declared file, path/symlink safety, and membership of the entire Git-tracked inventory. It does **not** inspect Git history, binary provenance, operating-system trust, or deployed device state.

The historical `RELEASE-SOURCE-MANIFEST.json` covers ten older source files and cannot authorize the current repository or stacked PR #10/#11. Do not rewrite that original signed manifest or invent an owner signature. Produce a new separate complete manifest from the final reviewed Git commit, have the release authority sign it through protected signing custody, verify the exact revision on each target and independently retain its digest.

## Independent operational gates
- Keep historical signed receipts, test fixtures and physical results attributed to their exact source revision. A PR or locally passing test alone is not a deployment.
- Reject transport routes that lack pinned mutual identity, freshness/replay protection, owner capability grants, bounded resources, revocation and signed receipts.
- Preserve original owner rules and the Android thermal governor; do not start any live-call tracing unless explicitly requested.
- No ACT production route, enrollment, payment, wallet control, shell, firmware flash or manufacturer attestation is granted by this change.
- Preserve separate financial states: historical read-only Toybox proof, unpaid L402/Lightning offers, nonmonetary test work, and owner-approved revenue allocation are **not** equivalent to settled payouts.
- The shared user-dividend allocation is one 5% pool of **verified new revenue**, not 5% per participant. No source-integrity test authorizes a distribution.

## Release evidence still required
1. Full reviewed source hashes and pinned release signing key, approved independently of device/peer keys.
2. Successful current application security tests in addition to GitHub Pages; malicious-negative controls and privacy/secret scans.
3. Independent hardware readbacks, source-set parity, rollback/restore tests, key revocation/rotation, witness checkpoints and incident response.
4. Security and privacy evidence-to-control mapping against NIST CSF 2.0 / SP 800-53 and applicable legal/regulatory frameworks. Certification requires independent assessment where mandated.
5. For ACT: separate signed invitation/reply, independent peer pin and hardware review, explicit owner grants, ACT-approved worker route and bilateral tested revoke/replay.

This file is public-safe documentation; no private Termux state or node credentials should be added here.
