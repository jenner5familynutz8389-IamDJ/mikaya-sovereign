# Sovereign QRI — installed automation and operator handoff

**Implementation date (UTC):** 2026-10-19
**Owners:** Independent FOSSiBOT F110 Pro and Motorola Moto G Power 5G (2023) nodes
**Executable:** `cortex/qri_orchestrator.py`
**Source of queue policy:** independently signed `~/sovereign_exec/cortex/QRI_WORK_QUEUE.json` on each node.

## What the automation actually does

A file-locked observer checks every **38 seconds**. It authenticates its local queue policy against the device's existing Ed25519 public key, inspects the existing thermal-governor snapshot and local Git references, verifies the frozen 2,900-record Motorola event report, and computes an ordered handoff. It saves an atomic status file and a readable project report. Changes are appended to a SHA-256-linked local QRI decision ledger. The original event and correction ledgers are never rewritten.

The observer **does not** start arbitrary queued commands or infer inaccessible Android thermal values. It cannot remove SELinux restrictions, control MediaTek hardware thermals, generate OEM signing keys, repair an inaccessible SD card or create actual cryptocurrency payments. It does not send raw telemetry to public GitHub. Existing health watcher and shadow governance remain the only authorized service recovery mechanisms.

All new optional work is **deferred** when thermal readings are restricted, stale, warm, severe or critical. The task queue is a reliable work register and safety gate, not permission to execute every pending action.

## Where everything is on each phone

| Purpose | On-device location |
|---|---|
| Local QRI executable | `~/sovereign_exec/cortex/qri_orchestrator.py` |
| Signed queue policy | `~/sovereign_exec/cortex/QRI_WORK_QUEUE.json` and `.sig.json` |
| Controller state | `~/sovereign_exec/ledger/qri-automation-state.json` |
| Append-only decisions | `~/sovereign_exec/ledger/qri-automation-events.jsonl` |
| Daemon output | `~/sovereign_exec/ledger/qri-automation-runtime.log` |
| Latest complete machine report | `~/sovereign_exec/docs/QRI_LATEST_HANDOFF.json` |
| Latest operator-readable report | `~/sovereign_exec/docs/QRI_LATEST_HANDOFF.md` |
| Signed Motorola event checkpoint | `~/sovereign_exec/docs/MOTOROLA_EVENT_AUDIT_CHECKPOINT_2900.json` and `.sig.json` |
| Existing governor | `~/sovereign_exec/cortex/resource_governor.py` |
| Existing shadow controller | `~/sovereign_exec/cortex/shadow_governance.py` |
| Existing boot route | `~/.termux/boot/99-secure-mesh` → `~/sovereign_exec/start_sovereign_secure.sh` |

The startup script now invokes the file-locked observer when the Termux boot integration runs. **A real cold reboot remains to be tested on each phone.** Repeated starts do not create additional QRI workers because of the local flock.

## Terminal commands

```sh
cd "$HOME/sovereign_exec"
python cortex/qri_orchestrator.py --self-test
python cortex/qri_orchestrator.py --once   # if no --loop instance owns the lock
cat docs/QRI_LATEST_HANDOFF.md
tail -n 5 ledger/qri-automation-runtime.log
tail -n 3 ledger/qri-automation-events.jsonl
```

Avoid running a second `--loop` manually. The active instance reports `alreadyRunning` and exits. The report is refreshed by the daemon even if a manual `--once` cannot obtain its lock.

## Verified checkpoint and limitations

At fixed sequence 2900, the FOSSiBOT authoritative receiver ledger and Motorola recovered ledger had **identical SHA-256 canonical digest**:
`55c2914fd8c6aaec7ffa4b068b749f259455e2d3a6d902c72f336e5a09a2db7f`.

Both had 2,900 matched records, zero missing records, zero duplicate sequences, zero invalid entries, and no pending Motorola outbox items. Independent report signatures were created per device. **This proves the accessible user-space stream at that checkpoint only**, not completeness of modem/Android/kernel telemetry or historical authenticity before the signing checkpoint.

The governor currently reports `unknown` because Android thermal sensors are restricted in Termux. Unknown does **not** mean that a phone is physically cool; optional workloads must remain deferred.

## Priority and remaining physical or account actions

1. **Motorola privileged sensor events** — obtain manufacturer-authorized OS/vendor integration so thermal, GPU, modem and MediaTek sensor telemetry can be measured without bypassing Android security or SELinux. Run an explicit acceptance test.
2. **Thermal/shadow recovery validation** — after devices are cool, perform supervised real temperature and power-cycle tests. Confirm no duplicate bridge writers or lost event sequence. Do not flash firmware as a test.
3. **microSD storage** — preserve the two mismatched FOSSiBOT backup manifests for investigation and handle Motorola's read-only card non-destructively. Create a new verified backup only after storage is known-good.
4. **GitHub** — only curated source and reports may be published. Check current credentials and use GitSync **Push Origin** for locally signed commits; verify the remote hash afterward. The connected GitHub integration previously returned a 403 for direct file-write requests.
5. **Unknown reference** — identify repository and object type for `21c6c0c912b9d8300f0242061925de6b396f0508` before integration.
6. **Future implementations** — complete Macaroon Forge authorization tests, bounded autonomous debugger, source provenance and device-specific cold-boot verification. These are tracked as unfinished, not mislabeled as deployed.

## Cryptographic and release safety

- The source manifest for this QRI package is separately signed with the local FOSSiBOT Ed25519 key. The private signing key never enters the public repo.
- Signatures and SHA-256 chains are integrity evidence, not claims of external timestamping or blockchain settlement.
- Git revisions must be moved only by ordinary reviewed commits and fast-forwards. Never force-push, alter ledger history, export account secrets, or disable SELinux to clear an error.
