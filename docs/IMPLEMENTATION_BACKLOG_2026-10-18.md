# MIKAYA-SOVEREIGN — implementation backlog and evidence gates

**Prepared:** 2026-10-18
**Owner's working repository:** `jenner5familynutz8389-IamDJ/mikaya-sovereign`
**Status key:** VERIFIED = tested with evidence; PARTIAL = existing component needs acceptance testing; TODO = not yet built; BLOCKED = requires source, permission or hardware access.

This report records **unfinished work**, not proof it has been implemented. Never upload raw device telemetry, passwords, wallet keys or records, authentication macaroons, hardware identifiers, proprietary OEM firmware archives, or private research documents to this public repository.

## Verified foundation

- GitHub `main` and both phone checkouts last verified at `5e3ac1b09e0a424be3cb9545e75431f7caed5c79` with matching `origin/main`.
- The existing public-source Ed25519 **release manifest** verifies on both phones. This does not automatically authenticate later changes.
- FOSSiBOT F110 Pro (MediaTek MT6835) hosts a secure mesh bridge and AHAVA peer; Motorola Moto G Power 5G 2023 (`devonn`, MT6855) runs the mesh client and encrypted-object synchronization.
- AHAVA separately restored and verified 11 signed manifests, 491 encrypted chunks and 31,594,145 reconstructed bytes from each phone's *internal* independent backup set. Tamper simulation rejected modified ciphertext.
- Append-only integrity correction ledgers are locally valid. Preserve their historic records without rewriting.
- **Open discrepancy:** Two FOSSiBOT microSD *manifest copies* failed later content-hash verification. The Motorola microSD was mounted read-only. Neither external card is certified for recovery.
- The hard-coded legacy string `u35140@sovereign.local` identifies an **unverified application principal label**, not a Linux UID or an authenticated device identity.

## P0 — build/test before autonomous deployment

| ID | Work item | State | Acceptance gate |
|---|---|---|---|
| GOV-01 | Linux-style CPU, memory, I/O, network, GPU and thermal observations | TODO | Verified available counters with permission-denied fallbacks; no fabricated GPU/temperature values; bounded sampler overhead |
| GOV-02 | Thermal-aware resource/percent utilization controller | TODO | Normal/warm/severe/unknown simulation, hysteresis, budgets and safe backoff; Android thermal protection remains authoritative |
| GOV-03 | Completion-driven job queue (~38 seconds after prior review) | TODO | Never launch work merely because a timer fired; one job at a time, completion/result/thermal check, append-only decisions and cancellation |
| GOV-04 | Shadow governance active/passive service handoff | PARTIAL | Singleton service ownership; staging kill-and-recover; cooldown and repeated-failure backoff; no duplicate writers or restart storms |
| GOV-05 | Autonomous debugging and bounded self-repair | TODO | Signed/redacted diagnosis, explicit reversible allowlist, failed-fix escalation, before/after evidence and rollback |
| GOV-06 | Sovereign telemetry **Macaroon Forge** | TODO | Device-key binding, issuer, authorized telemetry scope, expiry, revocation, anti-replay tests, separated from Lightning wallet macaroons |
| GOV-07 | Safety-preserving heartbeat/sync spacing | PARTIAL | Offline queue preserves order; reconnect drains without loss/duplication; telemetry slows under thermal stress |
| GOV-08 | Simulated compute-credit micro-units | TODO | Deterministic fixed-point units and transparent quotas; **no claim of transferable satoshis, blockchain settlement, or actual dividends** |
| GOV-09 | Safe CSOB continuity proof-of-concept | TODO | Simulated ECG/behavior scenarios only; physiological variation not accepted as unique identity; independent authentication required |

## P1 — reliability, source and deployment

| ID | Work item | State | Acceptance gate |
|---|---|---|---|
| REL-01 | External microSD recovery audit | BLOCKED | Preserve corrupted FOSSiBOT manifests; diagnose storage; version new encrypted-only backup; independently restore with mismatches rejected |
| REL-02 | Motorola microSD read-only diagnosis | BLOCKED | Non-destructive filesystem/device diagnostics, no forced remount or wipe, recovery check after authorized repair |
| REL-03 | Real cold reboot and app background resilience | PARTIAL | Test boot on both phones, reconnection latency, signed ledger continuity, no duplicate supervisor/bridge and correct Android notification behavior |
| REL-04 | Complete device-specific OEM firmware integration | BLOCKED | Matching full MT6835/MT6855 vendor source, kernel configs, toolchain, SELinux policy checks, image signing, AVB/rollback tests; no unsafe flash |
| SRC-01 | MediaTek/Jenkins/IBM/telecom source lineage | PARTIAL | Reproducible version+diff map; upstream commit references, CVE backport checks, copyright and build attestations |
| SRC-02 | NotebookLM AI Governance 71-source review | BLOCKED | Secure authorized source access, provenance inventory, claim/evidence matrix and corrections |
| SRC-03 | Thermodynamics/RF hypothesis analysis | TODO | Safe independent simulation with reproducible physical model; no offensive RF experiments or claims about remote hardware |
| SRC-04 | GitHub repository topology and privacy routing | PARTIAL | Verify actual contents and repo access, assign code/docs/report owners; do not dump everything into unrelated repositories |

## Specific unresolved Git object

**Reference supplied:** `21c6c0c912b9d8300f0242061925de6b396f0508`
**State:** BLOCKED. No matching commit was returned from the accessible named public repositories inspected; not present in either MIKAYA-SOVEREIGN local checkout. Private/inaccessible or another object type remains possible. **Do not merge or cherry-pick it without repository context and provenance.** Next evidence: exact `owner/repo` URL, ref, object type, linked PR or screenshot showing the object.

## Repository placement audit

- **`mikaya-sovereign`**: confirmed published signed user-space implementation; use for integration code, tests, engineering backlog and security definitions.
- **`docs`**: at inspection this is a Mintlify Starter Kit site, not a verified Sovereign-specific documentation site. Do not overwrite automatically.
- **`refs`, `origin`, `Reports`**: visible public repositories; their roles/content are insufficiently verified to route source code to them automatically.
- **`owncore-native-android`**, **`EEG-Neural-Agent_System_AHAVA-PRIVATE`**: shown in the GitHub app earlier but not accessible via current GitHub connection; do not claim reviewed or copy private data.

## Release rules

1. The old signed source release remains intact; this new backlog needs its **own independent attestation** before publication.
2. Changes are not marked **VERIFIED** until a test passes and outputs are retained.
3. Store raw data and private signing keys locally encrypted. Only curated source, sanitized acceptance tests and public signatures belong in GitHub.
4. Append a correction record giving reason, evidence fingerprint, action, safety fallback and postcheck. Never alter historic event lines.
5. Permission denials from Android sensors, GitHub or vendor builds must be reported, not bypassed.
