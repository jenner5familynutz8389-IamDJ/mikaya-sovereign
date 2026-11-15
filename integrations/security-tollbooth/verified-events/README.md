# Verified local observations for the existing runtime publisher

## V2: disposable snapshot durability correction

V2 removes per-file fsync only from temporary private verification snapshots consumed immediately. Full Ed25519 verification and identity/source pins remain. Committed checkpoint/projection and receipt/source-ledger durability retain their file, rename and directory barriers. Hook/bridge pins and the generic existing-job run path track the exact reviewed V2 source.

The historical eight-second stall was not reproduced. A later isolated old-collector run completed in about 1.182 seconds; temporary-file flush work measured about 181.2 milliseconds. These observations do not establish that temporary flushes caused the historical stall. The change removes unnecessary synchronous work while preserving conservative failure and resource limits; no general speedup or uninterrupted availability is claimed.

The sealed source passed 69 focused tests, including four independently authored durability regressions. Synthetic signed 321-row fixtures show no disposable-file flushes while preserving commit barriers; frozen published V1 source reproduces the old per-row flush criterion. A snapshot-write failure and an owned-child SIGKILL preserve source/checkpoint evidence; an orphan lock conservatively holds the next run. Publication does not run these tests against a phone.

The existing installation's recovery reuses its identity, ledger and checkpoint. Do not run first-bootstrap commands during this upgrade. Coordinator-approved quarantine preserved orphan evidence; the runtime does not automatically clear locks, reset history, rotate identity or initialize a replacement ledger.


This archives the reviewed versioned source used by the coordinator's native verified-event integration. It upgrades the existing bridge's event input while preserving its publisher/dashboard/MTG vendor bytes, HTTPS endpoint, nine-field upload schema, private device token, pending sample idempotency, dashboard lifetime and supervisor. **Publishing or cloning this package performs no installation, bootstrap or activation.** The later bounded native acceptance is recorded separately below. No additional watcher, listener, port or device enrollment is created.

## Fixed data path

After the existing thermal gate has two fresh severity0/1 readings, one logical sample uses:

1. `device_observation_producer.cjs`: fixed `/system/bin/getprop` reads for model, platform and Android release. Only `F110 Pro`, `mt6835`, `15` and the approved existing MIKAYA public identity are accepted. A small immutable private receipt records actual values/time; only its canonical SHA256 digest enters `DEVICE_HEALTH_OBSERVED`. The **existing** `initializeLedger`/`appendDigest` APIs use the existing native signing identity in place. No private key/token is returned, copied, rotated or included in reports.
2. `ledger_event_collector.cjs`: exact pinned existing verifier validates a bounded private snapshot of the signed ledger against an independently configured public PEM/fingerprint. It rejects bad signatures, replayed nonces, malformed/canonicalization failures, wrong identity, gaps, unsafe files, concurrent append markers, stale/future source and rollback/replacement across its saved checkpoint.
3. `verified_ledger_hook.py`: checks the release/configuration pins and uses a Node loader that hashes and compiles the **captured verified source bytes**, including the collector dependency. The committed redacted JSONL is copied into a unique mode0400 cycle file. A read lock protects that path while the existing dashboard consumes it; prior temporary data is removed only when readers finish. Source age is checked again when serving/sending.
4. The copied `mikaya_background_bridge.py` retains its existing server and finite loop. Every non-genesis signed event maps only to `INTERNAL_WATCHER` with the original signed timestamp, allowed kind, index and digests. It does not invent minting, L402 challenges, payment settlement or hardware attestation.

The upload still carries the same nine allowlisted fields. The local signed receipts/ledger, public key, per-event digests, configuration and checkpoint do not cross that boundary. `recognized_event_count` is a cumulative count within this verified bounded ledger; it is not a count of mints, payments, completed federation jobs or device repairs.

## Existing identity and unchanged source

The two reused native verification sources are unchanged copies matching the coordinating agent's native readbacks:

- `vendor/sovereign-event-ledger.cjs`: `56c894c87d6d7d4bb57d90e520b80f968a72a683469defc0b5e7d36c49f13c65`.
- `vendor/federation-node.cjs`: `33ea94880c74c7392535ff443b467a7df79117f2bf42993956a5add4ee7f1827`.

Original `vendor/mikaya_runtime_publish.py`, `vendor/mikaya_unified.py`, and `vendor/mtg_nice_policy.py` remain byte-identical to the November14 bundle. Their existing pins remain unchanged. The new release pins only its own added hook/producer/collector; it does not edit or relax the installed November14 bundle.

Public identity configuration must be derived from the already approved native public key, not accepted from an untrusted event. Config examples deliberately contain a nonfunctional fingerprint placeholder. Keep real configs owned by the native Termux UID, mode0600; private state directories must be canonical, mode0700 and disjoint from the node/source directories. No signing identity is created by these examples.

## First bootstrap and normal operation

The coordinator must first inspect/preserve any pending sample and drain a valid **legacy raw** pending sample through the unchanged baseline bridge before switching. This release refuses to relabel or drop unbound legacy pending data.

After staging the new release/configs under existing ownership and obtaining the existing MTG policy's two safe readings, bootstrap is explicit and one-time:

```sh
node /ABSOLUTE/RELEASE/device_observation_producer.cjs --config /ABSOLUTE/PRIVATE/device-observation.json --initialize-new
node /ABSOLUTE/RELEASE/ledger_event_collector.cjs --config /ABSOLUTE/PRIVATE/verified-ledger.json --initialize-new
```

The producer's first call initializes the existing signed-ledger format and appends one actual guarded observation. The collector stages its first checkpoint privately and commits only after complete verification. Failed collector initialization leaves the final state absent and can be explicitly retried. Normal operation never silently initializes/reset a missing ledger/checkpoint, resets a pin, changes an owner or clears stale locks. An interrupted producer bootstrap may leave a genesis/receipt requiring explicit review; originals are never automatically deleted to force a retry.

The existing supervised publisher selects the new version using `--verified-ledger-config /ABSOLUTE/PRIVATE/verified-event-integration.json`. It cannot also select legacy `--event-spine` arguments. The supplied `runit-template` is staged **down** and points to one new versioned release path. It must replace the command of the existing `mikaya-runtime-telemetry` job, not create another job. Its original finish rule stops only that job on permanent status2. Installation/activation is not performed by this package.

Cadence and bounds remain60seconds, at most120samples and7200seconds per invocation; original body/response limits, endpoint pins, source pins, thermal policy, private log, single publisher lock, retry limits and backoff remain in place. Producer/collector child calls are bounded to8seconds each under the bridge's existing hard wall. Fixed native reads each have a1second/256byte limit and no shell. Optional work retains the existing niceness+15 and severity2+/unknown HOLD policy.

## Retry, restart and rollback

New verified pending state is one atomic private envelope containing the original nine-field summary and its evidence binding (config digest, genesis, source head index/hash and original observation time). The uploaded JSON contains only the unwrapped summary.

- A valid bound pending sample is examined before producing anything. On restart, the collector restores/verifies its signed source prefix **without appending another observation**, and the original UUID/payload is retried unchanged.
- Backoff retries reuse the same prepared projection. Expired or clock-skewed pending observations are resampled using a fresh actual observation, retaining the existing expiry behavior. Stale prepared evidence cannot acquire a fresh summary timestamp merely because thermal work resumes.
- Wrong bindings or legacy unbound pending data HOLD in place. No pending file is cleared merely to make acceptance succeed.
- Original November14 code cannot parse the new private envelope and will HOLD. Before rollback, drain verified pending with this version, or preserve the entire envelope and arrange explicit operator-controlled recovery of its unchanged summary/UUID. Do not simply delete the envelope or feed its wrapper as the cloud payload. The original source/credential and native ledger remain available; source rollback does not erase evidence.

## Persistence and limits

The collector's checkpoint and projection are a single atomic JSONL file: the first metadata line is ignored by the original dashboard collector, followed by deterministic redacted watcher events. Rebuilding rather than appending makes repeated collection duplicate-free. Continuity checks compare the current signed prefix at the previous checkpoint's exact index/hash, not merely an increasing record count. This detects local rollback since initialization; it does **not** resist an attacker rolling back both ledger and checkpoint together or malicious same-UID/root tampering.

Limits:4096ledger rows,2200bytes per row,8MiB aggregate source/projection,4096private observation receipts of at most512bytes each, bounded PEM/config reads and default5minute source freshness with30second future skew. Genesis-only or full ledgers HOLD. No automatic pruning, successor-ledger/key creation or deletion of evidence occurs at capacity. A stale lock or exhausted ledger needs explicit owner review; this is deliberately separate from service restart.

The fixed properties are userspace observations, not silicon/OEM hardware attestation, verified real-world ownership, carrier/IMS repair, firmware signing, slot selection, arbitrary commands, spending authority or an external ACT-OMEGA job. Old unsigned JSONL history remains untouched and is not relabeled as signed evidence.

## Focused verification

Tests use synthetic identities/homes and fake network/native read boundaries; no phone keys, tokens, devices or live endpoints are used. The meaningful source regression is demonstrated: an original signed `kind` row yields zero recognized events in the unchanged dashboard scanner; the verified projection yields a watcher count with all mint/payment counters remaining zero. Cryptographic tests use real Ed25519 signatures and the exact reused verifier.

```sh
node --test tests/test_ledger_event_collector.cjs tests/test_device_observation_producer.cjs tests/test_collector_snapshot_durability.cjs
python -m unittest discover -s tests -p 'test_*.py' -v
```

See `VERIFICATION.json`, `SOURCE_PROVENANCE.json` and `PACKAGE_MANIFEST.json` for the sealed checks and distinct export hashes. The 69 tests were completed on the identical executable/test/template bytes before this export; only documentation, provenance and nonfunctional examples were sanitized. The historical source-check scope is separate from the coordinator acceptance below.


## Dated V2 coordinator acceptance and export boundary

The native coordinator confirmed two foreground uploads with dashboard counts 321 then 322, followed by an initial accepted background upload at 2026-11-15 16:58:28 UTC with count 323. A separate full readback verified all 324 signed chain rows. Counts refer to signed userspace observations, not mints, payments, external jobs or hardware identity. The existing supervised service retained niceness 15; no additional service was created. This bounded acceptance does not guarantee indefinite uptime or future cloud availability.

NATIVE_ACCEPTANCE_SUMMARY.json retains only aggregate results and source hashes. No active signing identity, fingerprint, public-key material, key/token metadata, populated native configuration, device/workspace path, UID, PID, sample UUID or raw receipt is exported. Raw diagnosis, native recovery/coordinator scripts, private watcher and backup helpers, transfer blobs, private operations and raw logs are excluded. Repository publication itself performs no deployment or native recovery.

Previous accepted source and dated evidence remain preserved. V1 public examples stay unchanged nonfunctional absolute-path placeholders. Generic runit templates stay staged down and describe only the existing supervised publisher; they do not authorize a new job. Unchanged vendor/dashboard libraries and their approved public reference evidence retain their hashes without new ownership attribution.

These findings do not establish OEM firmware/carrier acceptance, silicon attestation, ACT-OMEGA enrollment, settlement/spending authority or boot-slot changes. Those authorities are not granted by source publication or a signed userspace ledger.
