# Legacy mesh bridge admission and durable ACK integration

This source change connects the existing mesh_bridge_secure.js entrypoint to the shared security tollbooth. It preserves the existing bearer-token protocol, default loopback port 43823, explicit private-overlay binding, public health JSON, 64 KiB request body, 200-event batch, 500-event page, sequence/ACK fields and event-ID duplicate behavior. Existing valid tokens retain their exact case.

## What changed

- The bridge uses the existing process-wide admission and private writer-lease implementation, with its connection/header/body/request limits. Slow or oversized bodies are rejected before event mutation. Body decoding counts raw bytes and retains fragmented UTF-8 correctly.
- createServer gains an optional fifth argument, {maxBodyBytes}. Its default remains **8192**, and the accepted range is 1–65536. Only the bridge explicitly selects 65536; existing node/broker callers retain their 8 KiB limit.
- The existing JSONL ledger is read through a bounded, owned, non-symlink descriptor: maximum 8 MiB and 10,000 rows. Rows must be complete newline-terminated JSON with the bridge's contiguous positive sequence and object payload. Corrupt, oversized, truncated or unsafe files are held intact instead of silently skipped.
- Whole-batch capacity is checked before any append. The bridge fences both the ledger file and its containing directory before returning ACK, including duplicate-only retries after an earlier fsync failure. A failed fence returns a failure without claiming durable acceptance or adding another copy on retry.
- The executable entrypoint uses the existing unchanged MTG callback and sets this optional process to a priority floor of 15. MTG requires two fresh safe readings; unknown/moderate-or-higher severity holds work. No extra monitoring timer or recovery owner is created.
- Canonical IPv4 validation rejects alternate numeric notation before checking the existing 100.64.0.0/10 overlay range. Defaults and valid canonical overlay addresses remain supported.
- TERM/INT closes the existing server, bounded connections and its lease. Importing the bridge now exposes an inert factory for tests/integration rather than immediately starting a listener.

## Verification

From the repository root, run:

    node --test tests/test_legacy_mesh_bridge.cjs

**29 focused Node checks and three existing Python checks passed**, including actual HTTP traffic, a real child process, unchanged body/batch/page/auth/ACK contracts, exact 64 KiB and fragmented UTF-8, shared admission across servers, slow and aborted requests, MTG two-safe-reading behavior, unsafe/corrupt ledger holds, capacity preflight, restart deduplication, file/directory fsync fault injection, competing-process writer refusal, actual CLI priority 15, closed MTG and TERM lease release.

Nine existing tollbooth/node/broker regression checks also passed against a preserved November 14 source fixture with only this gate replacement. That dated fixture is a regression dependency, not a claim that every current repository module was rebuilt or audited.

The runtime SOURCE_MANIFEST records the reviewed bridge, launcher and behavioral-test hashes with three appended source-update records, preserving all 20 source entries, prior hashes/history and evidence flags. The unchanged provenance gate passed a complete bounded closure: 33 source files, 57 evidence gates and the preserved 248 historical test-execution metadata. This is a source check with no Git HEAD, native execution or OEM acceptance claim.

## Existing launcher owns one bounded attempt

The existing supervise_mesh_secure.sh path remains the launcher, with the same bind/port variables and private data/log locations. It reuses the bridge's pure bind validator before probing. Any actual HTTP response, including 429 or 503, proves only that a listener is present: the launcher holds without starting a competing process. Timeout or ambiguous availability also holds. Curl connection-error code 7 alone is insufficient; one bounded TCP probe must observe ECONNREFUSED before the launcher makes one foreground exec of the existing bridge. It resolves code relative to the versioned source layout while keeping data under the existing private home. No inner two-second relaunch loop remains; the outer canonical owner controls explicit recovery.

The former Python test which merely searched for a curl command string now exercises an actual HTTP503 listener and verifies that no competing runtime is launched. The Node checks also cover other HTTP statuses, an accepting non-HTTP socket, ambiguous curl7 with a real TCP listener, configuration refusal, failed-start settlement and a single surviving exec owner under MTG503.

## Existing state and activation

This is a reviewed source change, not an installed or activated phone endpoint. The coordinating native check did not establish an active instance of this legacy bridge; the existing federation peer remains held down. Do not launch another bridge or change a native source pin merely because this source was merged.

The ledger directory must already be owned/private (0700), and the existing bearer token must be an owned regular single-link private file. A stale/foreign writer lease is an explicit hold. Unsafe permissions, malformed/truncated history and exhausted capacity need owner-reviewed preservation and recovery; this code does not repair, prune, delete, chmod, rotate credentials or clear locks automatically.

A storage write/fence failure can leave preserved unacknowledged data. Retry the same event ID after explicit storage recovery; the bridge will not ACK until the existing record is fenced. No arbitrary request is automatically retried. An underlying filesystem that cannot fence the directory remains a hold.

Ledger rows remain the legacy unsigned recovery records. This change does not relabel them as owner-signed proof, hardware attestation, ACT-OMEGA enrollment, payment settlement, OEM firmware acceptance or a complete security audit. Overlay HTTP still depends on the existing private overlay's transport; no new TLS claim is made. The lease and file checks do not defend against a malicious actor with the same UID/root rolling back all state.

Native services, MTG source/pins, telemetry publisher, link watcher, ports, keys, boot state and device data were not changed by this source work.

The negative hardcoded-overlay health-route test now covers the whole canonical overlay range with a generic pattern; no particular device address is retained. This final privacy-only test/manifest follow-up reran the three Python checks and unchanged source-provenance gate. Node/ACT/runtime source remained unchanged, so prior results were retained.
