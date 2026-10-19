# MIKAYA-SOVEREIGN Fabric Recovery and Shadow Governance — 2026-10-19

**Status:** Verified user-space recovery and monitoring improvement.
**Devices:** FOSSiBOT F110 Pro and Motorola Moto G Power 5G (2023).
**Starting Git revision:** `d98214e800f1ab2b72037d6cdefe6e8b35b61b12`.
**Security scope:** Android application/Termux user space. This is not an OEM firmware update, Linux kernel patch, AVB signature, or root-level thermal controller.

## Work completed and independently checked

1. Both devices' original `cortex/shadow_governance.py` scripts were aligned to a **38-second review loop**. Source SHA-256 on each device: `f6c84fc05b04a33189696045a91765c95b112a8435148e1a2d6d394be04f8ad9`.
2. Old shadow processes were stopped **one by one**, and exactly one running replacement instance was verified on each phone. Both AHAVA and secure mesh endpoints returned HTTP 200 afterward.
3. The 38-second shadow log now appends verified chained entries independently on each phone. Existing governor, shadow and QRI correction histories were preserved; no previous ledger lines were rewritten.
4. Resource governor, QRI scheduler, jitter monitor and shadow decision self-tests passed on both Android Termux environments. These workers already run in the production user-space setup.
5. Two small versioned, code-only recovery snapshots were built from locally reviewed active source. Raw event ledgers, credentials, private keys, wallets, patient data and OEM firmware were **not included**. Each local archive passed its content round-trip verification.
6. Both archives were encrypted into AHAVA content-addressed chunks with signed manifests, then replicated bidirectionally. Both manifest hashes were independently observed on both phones.
7. FOSSiBOT's physical microSD received **new isolated copies** of both encrypted objects, independently read back, Ed25519-verified and AES-256-GCM authenticated. Neither pre-existing corrupt backup manifest nor raw telemetry was overwritten.

## Source snapshot identity

| Device build | AHAVA signed manifest ID | Reconstructed archive SHA-256 | Bytes |
|---|---|---|---:|
| F110 Pro | `9fcd66272771b34645c2b94ebd98cf88e3f764719144b457e4afc7c4e4e83029` | `d0af3060537dd8e78d86d8be91aeb7dbbfbc83ba8538071269b33e8211f9cf2f` | 25,532 |
| Moto G Power 5G | `5614109b4c551be10edb53316a4753e168f6ebd96eee44e416357c2804366ad9` | `e6b43606dc2bd09478a2ebffe377b65ccf2fa1c97279c576808d0c1cd19e9b47` | 26,529 |

Both packages contain individually generated source manifests and a restore-to-**separate-test-directory** instruction. Restore and validate before ever replacing a live implementation.

## Existing source provenance held on FOSSiBOT SD

These original names were inventoried and hashed, but **not executed, imported or altered**. Their provenance and contents must be reviewed before integration.

| Referenced source | SHA-256 |
|---|---|
| `sovereign_link_keeper-v2.py` | `ce512d73591c4698640c2a6a305809d7bad8de098abae86ce859d9d543825a1d` |
| `mikaya_sovereign_master_core-v2.py` | `40afc85104478f9b423ec0b4537ac3d9d6d6fd680ce78ca278cc67774490d884` |
| `mikaya_sovereign_master_core.py` | `0b8cdcdef38bcd2d52e9c6313c2af9c4f37d94c065fe8012e42f1a8a20148474` |
| `The_Sovereign_Fabric_Pledge.docx` | `2de206e86070bccb7246534ace63697765384436a69c342a6c9d0b503823b644` |

The SD filename metadata alone does not prove a source's authorship, functional compatibility or safety.

## Architecture and thermal safety

- FOSSiBOT hosts the secure bridge and encrypted AHAVA peer. Motorola operates the durable mesh client and AHAVA synchronizer. They have separate signing identities.
- Shadow governance uses process-aware singleton checks, two missed health evaluations before recovery, and a cooldown before trying to start a missing role. It must never launch duplicate ledger writers.
- Resource governance and signed QRI observation use approximately 38-second reviews. Optional workload launches are **not periodic**; they must first pass completion, risk and thermal gates.
- Protected Android thermal metrics remain unavailable to the Termux sandbox. `unknown` status therefore conservatively postpones optional work. It does **not** claim that a hot phone has cooled or override Android safety.
- The Motorola removable SD was not mounted or available to Termux at the test. Both encrypted objects exist on Motorola's internal AHAVA store, **not certified on Motorola's SD**.
- Two older FOSSiBOT microSD manifest copies failed content-hash checks. That broader backup set remains **untrusted**; only these new isolated snapshots passed full on-card validation.

## Tooling in this repository

`tools/patch_shadow_review_interval.py` backs up the shadow source, makes the precise 15→38 second review update only when the expected source line occurs once, compiles and runs the decision self-tests.

`tools/restart_shadow_once.py` performs a sequential, process-identity-checked restart of only the shadow user-space observer, verifies exactly one process remains, and does not interrupt mesh or AHAVA endpoints.

`tools/package_fabric_snapshot.py` archives approved operational **source only** with per-file SHA-256 and local round-trip checks. It does not read key material, wallet contents or event logs.

These scripts should be inspected before reusing them on another device; snapshots and original files remain the preferred rollback materials.

## Outstanding acceptance gates

- Android-authorized OS thermal sensor bridge or manufacturer SDK is necessary for accurate current temperature and severity; no sensor permissions were bypassed.
- Physical reboot/power-loss recovery testing and OS firmware patch/SELinux validation are not certified by these user-space tests.
- Independent restore of the **whole** historic microSD backup set is still blocked by older corrupt manifests.
- Motorola's physical SD requires a non-destructive mount/permission repair before a verified second physical SD copy can be made.
- The optional Macaroon Forge capability authority, complete autonomous debugger, and all OEM-level tasks require separate implementation and security testing; existing QRI and health monitoring do not imply those features are complete.
- GitHub publication requires an authenticated GitSync **Push** and verification of the resulting remote commit. Local signed commits do not by themselves prove the remote accepted a push.

## Retention and audit policy

No source history rewrites. Private telemetry stays in encrypted device storage. Any later changes are new signed manifests and append-only correction entries, with original paths and digests retained. Public GitHub receives only this sanitized report and reviewed helper scripts.
