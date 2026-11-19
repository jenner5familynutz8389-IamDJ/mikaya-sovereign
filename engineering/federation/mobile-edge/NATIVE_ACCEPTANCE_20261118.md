# Native local evidence acceptance

Recorded November 18, 2026, America/New_York; UTC capture dates are November 19. **Both F110 and Motorola completed normal-mode native observation and verified signed gateway reads at runtime source `78a363fd516634cd12331810dbde6a938b157e1b`.** Motorola's dedicated first initialization is also captured. ACT admission remains HOLD. These results establish owner-signed local userspace observations and bounded gateway operation, not TEE/OEM hardware attestation or bilateral collaboration.

Review: [MIKAYA-SOVEREIGN pull request #10](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/pull/10), branch [`review/mobile-edge-gateway-hardening-20261118`](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/tree/review/mobile-edge-gateway-hardening-20261118). Runtime source: [exact commit](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/commit/78a363fd516634cd12331810dbde6a938b157e1b), tree `3666ad8cab99386b1a7450ef93d5c8e849890bb2`.

## Verified operations

| Operation | Result | Captured evidence |
| --- | --- | --- |
| Current source fixtures | **209 passed; zero failed/skipped** | 181 mobile/federation/AHAVA checks plus 28 existing verifier checks; see [source verification](VERIFICATION_20261118.md). |
| F110 final-runtime normal `observe` | **PASS** | Ledger 875 → 876 rows; 875 recognized events; signed read at `2026-11-19T03:17:17.052Z`; source age 5,411 ms. |
| Motorola explicit first initialization and signed read | **PASS** | New dedicated ledger 0 → 2 rows, including genesis; 1 recognized event; signed read at `2026-11-19T03:17:41.199Z`; source age 2,550 ms. |
| Motorola final-runtime normal `observe` | **PASS** | Ledger 2 → 3 rows; 2 recognized events; signed read at `2026-11-19T03:22:32.180Z`; source age 1,326 ms. |

The capture times correspond to **10:17:17.052 p.m.**, **10:17:41.199 p.m.** and **10:22:32.180 p.m. EST** on November 18. Freshness was evaluated at those times under the existing 60-second limit; these historical captures do not assert that a phone remains online or that its current evidence is fresh.

## What actually ran

F110 used the unchanged original producer in normal mode: `initialized:false`, `already_recorded:false`, event index 875. The installed `mikaya-local-evidence observe` returned `VERIFIED_LOCAL_OBSERVATION`; its authenticated reply and the immediate additional signed read matched the new source timestamp and projection. The retained controller result is `REPEATABLE_NATIVE_LOCAL_EVIDENCE_VERIFIED`. It records preservation of the entire prior source prefix, existing identity/policy, gateway PID, default-down markers and original compute/publisher-down state. One new event and receipt were added; no initialization or automatic retry was requested.

Motorola used its separate producer with the actual model `moto g power 5G - 2023`, board `mt6855`, release 14 and existing MOTOROLA/API34/aarch64 identity. Its explicit absent-state bootstrap created genesis and event 1 in the dedicated new ledger, plus one receipt and a new collector checkpoint. The original Motorola journal/history and owner identity were retained. Actual native MTG samples reported severity 0; the first two safe samples were approximately 12.264 seconds apart, with additional safe readings before production, collection and the signed read. The retained result is `MOTOROLA_NATIVE_SIGNED_LOCAL_EVIDENCE_VERIFIED`.

Motorola then completed the installed normal-mode `observe`: `VERIFIED_LOCAL_OBSERVATION`, `initialized:false`, `already_recorded:false`, index 2. Its controller returned `REPEATABLE_NATIVE_LOCAL_EVIDENCE_VERIFIED`, with one added event/receipt, unchanged prior source bytes, preserved identity/policy and gateway PID, and the original compute service still down. The helper's verified reply and the immediate saved proof bind the same new source and projection. This establishes normal-mode operation after initialization without resetting that state.

Earlier Motorola process-binding preflights returned HOLD with source and checkpoint mutation marked `not_attempted`; those records are retained. The Play Termux process was bound to its observed system linker, Node and pinned execution-library mappings, arguments, UID and owner lease. This diagnostic distinction is consistent with the [Termux maintainer's explanation of Play-specific `readlink` patches](https://github.com/termux/termux-packages/discussions/27078). Package bytes and permissions were not changed to force acceptance.

F110's earlier controlled history-recovery record at index 873 and prior native success at index 874 are retained. They are historical operations, not automatic recovery behavior of `read` or `observe`. The final normal-mode result continues that preserved history.

## Public proof verification

The published captures contain public keys, signed requests/replies and timestamps; they contain no private signing key, credential, private configuration or source payload.

| Capture | SHA-256 |
| --- | --- |
| [F110 repeatable proof](evidence/20261118/f110-repeatable-proof.json) | `c99a8f5393c9c22508641efa871c459bfbbb281f51b469660def86ddcea9f01e` |
| [Motorola initial proof](evidence/20261118/motorola-initial-proof.json) | `fe2b318af7f61ebb6b5983f26fc584d34a606df6da744d555118e81ad296c871` |
| [Motorola repeatable proof](evidence/20261118/motorola-repeatable-proof.json) | `9e481149eafa9019cbf9954c0a6891a617dd77ba38067d568cc015dbc95b9f2e` |

From the repository root:

```sh
node engineering/federation/mobile-edge/verify-native-capture.cjs \
  engineering/federation/mobile-edge/evidence/20261118/f110-repeatable-proof.json \
  engineering/federation/mobile-edge/evidence/20261118/motorola-initial-proof.json \
  engineering/federation/mobile-edge/evidence/20261118/motorola-repeatable-proof.json
```

This read-only command was executed successfully for all three files: `SAVED_NATIVE_SIGNATURES_VERIFIED`. It pins the reviewed gateway/federation source, checks the known public owner fingerprint, independently verifies request and response Ed25519 signatures, and validates the exact evidence contract at the recorded verification time. It reports `freshnessScope:CAPTURED_VERIFICATION_TIME_ONLY`; it neither contacts a phone nor merely trusts the stored success flag.

The verifier also requires the exact public capture fields and canonical SPKI public-key PEM. Two additional isolated input checks passed: an extra top-level field was rejected, and a FIFO was rejected without blocking. These checks are separate from the 209-test runtime suite and the three actual native captures.

A verified signature attributes the assertion to the pinned local owner key. It does not independently prove physical provenance, authenticate an OEM/TEE measurement, establish ACT identity or replay the full private-ledger audit. Controller records supporting source/service preservation remain separate from these public signed replies. Retained result hashes:

| Controller result | SHA-256 |
| --- | --- |
| F110 repeatable | `e41adada91f80e525d4ffbb76a90802a6ff68f2cc469a14ee391618af7a9a028` |
| Motorola initial | `bf34fec2752de7ec1ce93829ca3e9c87d69b0a289dd367b37e26fb976b4c09f8` |
| Motorola repeatable | `23ee4f86cc0cc9d5aaf18de3998b3fe97c8402d56680242c288add681ae9ee05` |

## Runtime and operating controls

The final runtime archive SHA-256 is `4f729c74688dee6ccaebfd0d0ff95f28a580aac97379b7a8b90f3bd98e3ac492`; its `RUNTIME-SOURCE.json` is `feb22bd2697ae77c1324d2e61858bcd863454df97bc27a556617ca931c13ca5d`. Its eleven source-file hashes matched the package inventory. This inventory is unsigned; the historical release signature does not attest the new source.

The [exact launcher and proof-reader sources](operations/README.md) retain the bytes and hashes used on the phones. They are installation-specific audit sources, not a general installer.

Each installed evidence service binds only **`127.0.0.1:4188`**. Both were run through one-shot supervisor activation while preserving default-down. Both original compute supervisors and the F110 publisher remain down; the optional combined compute/evidence launcher is not selected.

A subsequent read-only service check observed both final-source evidence processes still running, with their original compute/publisher services still down and default-down markers retained. The native Node versions were F110 `v26.13.1` and Motorola `v26.3.1`; source-fixture tests ran separately on workspace Node `v24.22.3`.

| Installed command | Meaning |
| --- | --- |
| `mikaya-local-evidence start` | Uses `sv once`; preserves default-down without enabling boot activation or automatic restart. |
| `mikaya-local-evidence stop` | Uses `sv down`; graceful shutdown releases only its own lease. |
| `mikaya-local-evidence status` | Reports supervisor state, not current signed freshness. |
| `mikaya-local-evidence read` | Reads existing evidence; it does not create a fresh observation. |
| `mikaya-local-evidence observe` | Makes one native observation and a signed read under the existing thermal/configuration/state checks. |

An idle listener may HOLD until it obtains two fresh safe MTG samples; evidence older than 60 seconds also remains HOLD. `observe` warms the gateway, waits 10.8 seconds, retains the 10–20 second sampling bound and invokes its fixed producer once with an 8-second deadline. It never initializes missing state, clears locks, resets ledgers or retries a possibly completed write. The collector can update its existing private verification projection during a read.

## Preserved authority and limits

Existing owner identities, local key custody, policy kill switches and separate ledgers remain in effect. All three signed bodies retain `actAdmission:HOLD`, with `hardwareAttested`, `computeAuthorized`, `fileTransferAuthorized`, `paymentAuthorized` and `deviceControlAuthorized` all false. Live admission and payments require separate explicit owner authorization.

Authorized remote terminals supported these operations; observed ADB lists remained empty. No wireless-ADB continuity, cold-boot persistence, firmware change, active ACT worker admission or Lightning/L402 settlement is established.

The 209 passing source tests include the synthetic AHAVA retry result: 65,536 of 131,109 ciphertext bytes retained, with 65,573 fetched on retry and complete cryptographic verification retained. This evidence runtime does not activate an AHAVA mesh upgrade on either phone. No physical transfer-speed, battery, thermal-endurance or model-performance benchmark was performed.
