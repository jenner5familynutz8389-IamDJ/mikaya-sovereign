# Owner-local mobile evidence and verified AHAVA resume

**Source review and local tests; ACT admission remains HOLD.** This update builds on the existing MIKAYA node, native observation producer, signed ledger, verifier, thermal policy and AHAVA transport. It does not install anything on a phone or establish an ACT-operated connection.

## What changed

| Path | Behavior |
| --- | --- |
| `../live/federation-node.cjs` | Direct compute acceptance rechecks the current peer pin/capabilities and refuses ACT identities. ACT requests must use the existing broker v2 review/grant path. Ordinary CLI SIGTERM/SIGINT now closes its listener and releases only its own lease. |
| `../live/federation-broker.cjs` | Revalidates current owner policy, upstream capability, independent review and owner-grant lifetime immediately before forwarding. |
| `../../../ahava/core.js` and `sync.js` | A resumed pull reuses authenticated cached ciphertext, fetches missing chunks, then performs the original full-object verification. Importing the synchronizer is inert. |
| `local-evidence-gateway.cjs` | Adds an owner-signed, replay-resistant read interface on IPv4 loopback port **4188**. The optional combined launcher runs it with the existing node in the same process and under the same lease/admission budget. |

Existing 64 KiB AHAVA chunks remain in AHAVA's own protocol. The signed federation and mobile read interface retain the **8,192-byte request budget**. No AHAVA mesh token, private key, device ledger or settlement authority is shared with ACT. Push still uses its existing protocol; the bandwidth improvement applies to resumed **pulls**.

## Existing evidence, retained in place

The existing [`device_observation_producer.cjs`](../../../integrations/security-tollbooth/verified-events/device_observation_producer.cjs) obtains its fixed native F110 observations and appends a digest through the established signer. This change does not widen its probes or claim that its F110-specific profile runs on Motorola. The gateway can verify an existing independently signed ledger for either owned node; it does not create observations.

The existing [`ledger_event_collector.cjs`](../../../integrations/security-tollbooth/verified-events/ledger_event_collector.cjs) still performs bounded snapshots, pinned-verifier execution, signature verification, source freshness and persistent checkpoint rollback checks. Its vendored sources and pins are unchanged. The gateway calls `collect` without initialization. Missing state, a busy collector, invalid signatures, stale evidence or rollback produce HOLD.

Reads leave the canonical ledger, keys, peer pins and owner policy unchanged. The collector may update its **existing private verification checkpoint** and create/remove bounded temporary verification snapshots. “Read-only” refers to the source observations and allowed operations, not to absence of all local filesystem activity.

The returned fields are counts, digests and timestamps. They describe signed local observations, not independent hardware attestation, proof that an observed assertion is true, model throughput, payments or completed ACT work. No private filesystem path, source payload, key or token is returned.

## Port, identity and request contract

- The listener accepts only explicit `127.0.0.1`; wildcard binding, listener overloads and reuse of a closed listener are refused.
- `GET /healthz` returns a process-instance challenge and the fixed ACT HOLD state. It is not hardware health or connection evidence.
- `GET /v1/mobile/evidence` requires an Ed25519 signature from **this device's existing owner identity**. A separately pinned peer, including the other owned phone, does not gain access to this owner-local interface.
- Requests bind method, exact path, owner fingerprint, random nonce, boot challenge and a 60-second time window in a separate signature domain. Used nonces are bounded; a new instance changes the challenge so a restart does not reset request authority.
- Responses bind the request nonce, owner, instance and body digest. The client rechecks the exact evidence schema, source age and fixed false authorization flags at receipt.
- Browser Origin headers, foreign Host headers, request bodies, query-string variants and all other routes are refused. No CORS, arbitrary URL proxy, command route, payment route or ACT telemetry ingestion is provided.
- Requests use the existing security tollbooth, writer lease, connection/body timeouts and one-request admission budget. The client has an absolute three-second deadline and an 8,192-byte response cap.
- Owner policy is reloaded on every request and around verification. The production default uses the native MTG policy: unknown/unsafe thermal status remains HOLD. Charging is not treated as a safe thermal observation.

## Explicit integration with the existing node

`startOwnedRuntime` cohosts the original `fed.startServer` and the evidence gateway. They share one owner directory, one process, one writer lease and the native MTG admission budget. The compute listener and evidence listener both bind loopback. Existing MIKAYA/Motorola signatures and jobs are unchanged.

**Do not start a second process beside an active node using the same owner directory.** The existing writer lease correctly prevents that. A reviewed rollout replaces the existing process command with the combined launcher while retaining its identity, node directory, ledger and ports. Do not clear a lock or initialize a replacement identity to force startup. A crash/SIGKILL still leaves HOLD for deliberate recovery.

The supplied [`local-gateway.example.json`](local-gateway.example.json) contains placeholders, not live phone configuration. Its `collectorConfigFile` must point to an already initialized, owner-private collector configuration for this exact fingerprint with `max_age_ms:60000`. `nodePort` must match the owner's selected existing loopback node port. Keep the configuration mode0600 in a private directory.

After device access and the actual current runtime are verified, the reviewed commands are:

```sh
# Replace the existing node process only during a controlled owner-local rollout.
node engineering/federation/mobile-edge/local-evidence-gateway.cjs serve-with-node --config /ABSOLUTE/PRIVATE/mobile-gateway.json

# Run on that same phone. Its private key stays there; only the bounded result is printed.
node engineering/federation/mobile-edge/local-evidence-gateway.cjs read --config /ABSOLUTE/PRIVATE/mobile-gateway.json
```

The `serve` command provides an explicitly standalone evidence-only mode when no other process holds the node lease. It is not the deployment choice for simultaneous federation service. No startup script, supervisor, firmware setting, phone package or live configuration is changed by this source update.

## Charging, ADB and remote access

Each phone's `127.0.0.1` refers to that phone. This repository workspace's loopback is a different machine. Disconnecting a USB data link does not create wireless ADB or remote access.

Use an already paired Android wireless-debugging connection on a trusted network, or an owner-approved private remote channel. Android wireless debugging requires device-side pairing approval; see [Android's ADB documentation](https://developer.android.com/tools/adb#connect-to-a-device-over-wi-fi). Execute the owner-local read client on the phone through that authorized channel, retaining its local keys. Do not expose an ADB server, legacy TCP debugging port, application listener or mesh token to the public Internet. No ADB setting or forwarding rule is changed by this package.

At preparation time the connected remote service returned **zero paired devices and zero active sessions**. Consequently these are source/local-fixture results, with no new F110/Motorola/ACT device acceptance. Actual device pairing and runtime inspection remain necessary before rollout.

## Measured transfer result and limits

The deterministic synthetic AHAVA fixture has 131,109 ciphertext bytes in three chunks. An interrupted first attempt retains one authenticated 65,536-byte chunk. The successful retry fetches 65,573 bytes in two chunks: **65,536 ciphertext bytes avoided on retry**. A complete valid cache requires zero chunk GETs and still verifies the complete object. These numbers exclude JSON/base64/header overhead.

Corrupt/unsafe cache files are preserved and rejected, not overwritten. Signer revocation, GCM authentication failure, altered cached bytes and a wrong full-object digest prevent acceptance. Valid partial chunks may remain as bounded resumable content; a manifest is not accepted before full verification.

This establishes lower repeated ciphertext traffic for the tested retry workload. Phone-to-phone elapsed time, battery, temperature, CPU and real-link throughput have not been measured. No “zero-copy,” model-performance or ACT interoperability claim follows from the byte count.

## ACT reference and remaining bilateral requirements

See [`ACT_MOBILE_REFERENCE_20261118.md`](ACT_MOBILE_REFERENCE_20261118.md) for pinned current Android/gateway sources and the differences from the earlier handoff. Source-compatible data formats do not grant access. In particular, ACT's unsigned telemetry GET/query format is not a signed MIKAYA request, and source-defined ports are not independently verified running services.

Actual bilateral operation still requires ACT's independently verified public key and signed reply, independent hardware-review evidence, an agreed protocol, an owner-approved private encrypted route, a fresh scoped grant and signed deterministic results under that grant. The owner-local evidence port does not satisfy or replace these requirements. Live admission and payments require separate explicit authorization.

## Verification

```sh
node --test engineering/federation/live/tests/*.cjs
node --test engineering/federation/live/evidence-brief/tests/*.cjs
node --test engineering/federation/mobile-edge/tests/*.cjs tests/test_ahava_resume.cjs
```

Tests use synthetic identities/state, ephemeral loopback listeners and mocked AHAVA network responses. No ACT code, APK or runtime endpoint is executed. See [`VERIFICATION_20261118.md`](VERIFICATION_20261118.md) for exact observed results and baseline failures.
