# Public execution evidence — 2026-11-19

This directory accompanies the executed two-device deployment in [LIVE_DEPLOYMENT_20261119.md](../../LIVE_DEPLOYMENT_20261119.md). The source and tests are reviewed in [PR #11](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/pull/11).

## Files

- `MIKAYA_EXECUTED_EVIDENCE_20261119.zip`: exact public records and a portable archival verifier.
- `archive-sha256.txt`: SHA-256 of the completed ZIP.
- `evidence-manifest.json`: every archived payload file's byte length and SHA-256; the manifest itself is not self-hashed.
- `independent-verification.json`: final independent archival check, including all three 137-test runs, signed work and ledger reconciliation, and recorded physical owner controls.
- `execution-summary.json`: compact machine-readable result and its evidence limits.
- `failure-history.json`: counts and hashes of the initial failed physical runs; failures are not added to the final pass count.

## Archive layout

| Directory or file | Meaning |
| --- | --- |
| `workspace-final-137/` | Final workspace TAP, source inventories and acceptance record |
| `f110-ready-evidence/acceptance/` | Final F110 137-case execution |
| `motorola-ready-evidence/acceptance/` | Final Motorola 137-case execution |
| Each handset's `network-lan.json` and `benchmark-lan.json` | Final-source, actual private LAN exchanges and ten samples per condition |
| Each handset's `network-overlay.json` and `benchmark-overlay.json` | Earlier actual overlay captures on the 134-case source, twenty samples per condition |
| Each handset's `receipt-ledger/` | Its separate signed 131-entry final ledger; shared work must be deduplicated |
| Each handset's owner-control/hardware/status records | Actual recorded physical lifecycle, allowlisted software observations and final timestamped readiness |
| `historical-134/` | Preserved earlier 134-case acceptance and device snapshots; not presented as final-source test runs |
| `reports/` | Original independent verification, deployment report, summary and failure history |
| `verify-public-evidence.cjs` | Portable archival verification script; it does not run device tests or contact peers |

## Reproduce archival verification

Extract the ZIP and use the reviewed repository checkout containing the exact tested source:

```sh
node evidence-check/verify-public-evidence.cjs evidence-check /path/to/mikaya-sovereign
```

Replace both paths with the actual extracted evidence directory and checkout. The verifier checks exact source/artifact bytes, independently verifies Ed25519 signatures, recalculates deterministic results and benchmark statistics, verifies recorded owner-control outcomes and reconciles the two ledgers. It writes `reproduced-independent-verification.json` in the evidence directory. The original report remains under `reports/independent-verification.json`.

To execute fresh tests on another machine, run from the reviewed repository root:

```sh
node engineering/federation/interop/run-acceptance.cjs --output "$HOME/mikaya-interop-run-001"
```

The destination must be a new absolute directory. Requirements and explicit pairing instructions are in the implementation README and direct-transport guide.

## Source identities and limits

The final 27-file executed source inventory is `76310862197a799269ea6aa9a2c8374538eb0ecabfa2ee74b91742e310c7ed31`. The earlier 134-case inventory is `9a5d9bfb49c12a5b93f9c18cf44114a887c434e9c8f058957f996555baaea5a4`, published in commit `52a1c3a4aa9700506650d2ad9a41f6f40a5e2a7f`. The controller's ten-file runtime inventory is a different, explicitly smaller set.

Archive hashes establish byte consistency. Saved signed proofs establish possession of the recorded application keys and integrity of the signed content. Timing, route labels, TAP and hardware properties are captured operator/device observations, not manufacturer attestation. Offline checks use original captured verification times; they do not renew expired credentials or reconstruct the original live TLS exporter.

All execution here is on the owner's workspace/F110/Motorola. ACT hardware execution, ACT admission, hardware-rooted attestation and monetary settlement are separate unestablished outcomes. Accounting uses `NONMONETARY_COMPUTE_UNIT`. Public records contain only allowlisted observations, public synthetic identities/certificates and nonmonetary receipts; private service state and credentials are not included.
