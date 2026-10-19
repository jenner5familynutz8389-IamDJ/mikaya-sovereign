# Sovereign Fabric — Autonomous Self-Debug Observer

**Date:** 2026-10-19 UTC
**Scope:** FOSSiBOT F110 Pro and Motorola Moto G Power 5G (2023), Termux user space.

## Implementation

Source: `cortex/self_debug.py`. Each device installs the matching file to `~/sovereign_exec/cortex/self_debug.py`. The existing single authoritative `start_sovereign_secure.sh` appends a **singleton, flock-guarded** observer launch. The previous launcher is preserved as `start_sovereign_secure.sh.before-self-debug.<timestamp>`.

The observer reviews every approximately **38 seconds, after the previous review finishes**; it is not a launcher for additional work. It checks app-visible process counts for thermal, jitter, QRI, shadow, secure bridge/mesh client, and AHAVA service; detects stale local state; records restricted thermal values as `unknown`; and references the shadow supervisor's reported health. Diagnostic records append to `ledger/self-debug-events.jsonl` under domain `SOVEREIGN-SELF-DEBUG-V1`, with SHA-256 chaining. A read-only current summary appears in `ledger/self-debug-state.json`. These files are private to the Android app and **are not GitHub source assets**.

No sensitive credentials, personal event payloads, private IP addresses, wallet data, or manufacturer firmware are included in the public code. The observer makes no HTTP calls, cannot issue Android privileged commands, and does **not** kill/restart any processes. Recovery authority remains exclusively in `cortex/shadow_governance.py`.

## Acceptance evidence

- Python syntax compiled on FOSSiBOT and Motorola.
- Built-in deterministic self-tests passed independently on both devices.
- `--once` produced a verified first append-only event on both devices, without touching older logs.
- Both worker processes were launched as singleton background observers and live mesh/peer health endpoints returned HTTP 200 immediately afterward.
- Existing thermal governor, shadow and QRI checks had previously passed on both devices.
- Current Android thermal measurements remain restricted. `unknown` mode is **not evidence of cooling**, and optional jobs remain thermal-gated.

## Recovery and remaining gates

Rollback launcher copies are available in each Termux home. Before any runtime source recovery, verify the signed source manifest and restore only to a separate test directory. Do **not** overwrite running code from a ZIP/tarball.

This code is not a signed OEM Android system image, privileged thermal control, self-modifying kernel repair, or proof of physical reboot readiness. The separate FOSSiBOT SD recovery set contains signed encrypted historical fabric snapshots; new source requires a **new versioned snapshot**, not an overwrite. Motorola's physical SD has not been accessible from Termux. The older two failed SD manifests remain quarantined as evidence.

GitHub publication of later commits requires an authorized GitSync Push and remote-SHA verification. App-local telemetry and keys must never be committed.
