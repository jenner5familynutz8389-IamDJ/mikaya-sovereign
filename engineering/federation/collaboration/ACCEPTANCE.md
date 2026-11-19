# Collaboration interface acceptance — 2026-11-19

**The bounded collaboration interface is implemented, installed on both physical Android phones and accepted in both directions. An ACT-Omega model connection has not been established.** The tested profile carries authenticated metadata, durable Toybox statements/receipts and explicitly published public artifacts. It preserves the existing federation and its separate compute admission requirements.

## Exact source and evidence

| Item | Recorded value |
| --- | --- |
| Prerequisite source | `1da7fbdd79e63f857b07af0738278156c19a9966`, PR 10 review head |
| Collaboration source manifest SHA-256 | `beedd7ee72105320af856c9a3d98f9db694621a05793cccd8370ac5da8c45ced` |
| Manifest coverage | 32 files: collaboration runtime, tests, fixtures, documentation and three unchanged legacy dependencies |
| Local runtime | Node `v24.22.3`, Linux x64 |
| F110 runtime | Android 15/API 35, arm64, Node `v26.13.1` |
| Motorola runtime | Android 14/API 34, arm64, Node `v26.3.1` |
| Physical acceptance interval | November 19, 2026, 19:11:02–19:11:44 UTC, as recorded by the respective devices |
| Machine-readable record | [ACCEPTANCE_20261119.public.json](evidence/ACCEPTANCE_20261119.public.json) |

These are operator-recorded test results. They are not manufacturer attestation, an independent security audit, financial proof or evidence that ACT accepted the interface. The public record retains test counts, log/capture digests, measurements and limits. Device routing, TLS private material, capability grants, owner state and private capture paths are excluded. Raw captures remain with the owner on the devices.

The manifest deliberately excludes this acceptance document and generated evidence to avoid circular hashes. An independently retained manifest digest verifies bytes, not a release authority. The installed wrapper verifies the covered source on each invocation.

## Executed tests

| Test set | Result | Boundary |
| --- | --- | --- |
| Existing federation/mobile-edge/AHAVA regressions | 181 passed, zero failed/skipped | Original sources remained unchanged |
| Preserved verified-events tests | 28 passed, zero failed/skipped | Existing verifier dependency checks retained |
| New collaboration suite, local | 147 passed, zero failed/skipped | TLS sockets, capabilities, journal, distribution, clock protocol and installer |
| Same new suite, F110 | 147 passed, zero failed/skipped | Actual Android/Termux runtime |
| Same new suite, Motorola | 147 passed, zero failed/skipped | Actual Android/Termux runtime |
| Independent Python capability fixture oracle | PASS | Custom chained-MAC wire fixture; not third-party macaroon/L402 interoperability |
| F110 → Motorola physical private-network exchange | PASS, 13 checks | Actual separate identities, certificates, storage and processes |
| Motorola → F110 physical private-network exchange | PASS, 13 checks | Actual reverse direction, same bounded profile |

The Android hardlink test encountered the platform's `EACCES` restriction when attempting to create a hardlink. The fixture explicitly verifies refusal, absent destination and unchanged original file/link count; it does not skip the test. Linux executes the application-level hardlink-denial case. Do not describe the Android result as exercising a hardlink that its kernel would not create.

### Physical acceptance performed in each direction

1. Verified all 32 covered source files before loading the installed modules.
2. Completed a nonce-bound signed peer-clock challenge over pinned mutual TLS.
3. Exchanged HTTP/2 requests with TLS 1.3 and original federation Ed25519 request/reply verification.
4. Recorded a durable Toybox statement and completed receipt.
5. Retried the identical immutable intent with a fresh nonce and obtained the same receipt without another business acceptance.
6. Rejected the exact attempt replay, an altered request signature and changed content under the same transaction ID.
7. Read the transaction receipt through the sender-scoped capability.
8. Exercised authenticated HTTP/1.1 with the same security contract.
9. Verified the original peer's signed public manifest and digest.
10. Received 65,536 verified bytes, closed and reopened the receiver, reused that chunk, fetched only the remaining 65,573 bytes and verified the complete 131,109-byte object.
11. Kept artifact activation, arbitrary execution, financial settlement and ACT compute disabled.
12. Ran 30 alternating HTTP/2 versus HTTP/1.1 paired screening samples on reused authenticated connections.
13. Confirmed original identity and peer-pin records were unchanged.

The fixture object SHA-256 was `ae651bb048a15256bcd2e33af6f83dc65aa6d0686ddc17237807470824f050f0` in both directions. The client verifies signed receipts and exposes the complete `signedResponse` for callers that retain an independently verifiable receipt. A test report's PASS field is not itself a signed device attestation.

## Defects found and resolved during acceptance

The first cross-phone attempts failed despite valid identity bindings, content digests and signatures. One captured response was 5,038 ms ahead of the requesting phone. The existing five-second future-time guard correctly refused it; the opposite direction also rejected an excessively future request. Same-device demos could not reveal this real clock difference.

The fix adds `POST /v1/session` for a signed challenge/response time sample. It is restricted to the same enrolled mTLS peer, binds a fresh 128-bit challenge and both original identities, and confers no business authority. Clients use the peer's sampled time plus monotonic elapsed time for outgoing attempt timestamps and response freshness. Samples require a round trip at most two seconds, expire after 30 seconds and refresh with response headroom. Owner clocks, token expiry, existing federation time windows and broker/hardware gates are unchanged. Both physical directions passed after this fix; the original failed captures are retained.

The durable readers also stopped allocating a full multi-megabyte maximum buffer for each small state file. They now allocate the previously validated size plus one byte, require the exact expected read length and retain the maximum-size, no-follow, nonblocking, inode, ownership, mode, link and final-change checks. This reduces needless allocation. It does not establish a universal mobile speedup.

## Authenticated transport measurements

Both directions ran concurrently on the same private network. These are 30-pair screening results including signature verification and durable receipt work, with one in-flight request per client. They are not isolated radio, thermal or battery experiments.

| Direction | H2 median / p95 | HTTP/1.1 median / p95 |
| --- | --- | --- |
| F110 → Motorola | 371.23 / 974.24 ms | 397.66 / 1,089.63 ms |
| Motorola → F110 | 536.07 / 1,386.20 ms | 615.85 / 1,376.25 ms |

H2 had a lower median in these captures. Tail latency varied and prior same-device before/after results were mixed. No general speed, energy or throughput claim is accepted. The implementation now provides an authenticated persistent transport and a reproducible comparison harness; a representative mobile workload and endurance study are still needed before selecting a performance SLO.

## Installed operational state

Each phone has the integrity-checking `mikaya-collaboration` command, its own collaboration state, separate TLS credentials and an independently issued capability root. The dedicated collaboration service was started once on explicit private port 4190. Its default-down supervision setting remains, so this release does not promise automatic reboot or crash recovery. The temporary enrollment certificates expire on November 26, 2026, around 18:08 UTC; renewal requires independently reviewed public bindings.

The existing owner-local evidence service remains on loopback port 4188. Its identity, ledger, verifier and producer were not replaced. The new live configuration has no legacy broker URL and permits only description, Toybox statements, receipt reads and published public manifest/chunk reads. The code's optional broker adapter preserves the original envelope and broker checks, but it was not enabled for this physical acceptance.

Use [OPERATIONS.md](OPERATIONS.md) for installation, inspection, grant issuance, request descriptors, source rollback and recovery. Do not remove a writer lease or erase state to clear a HOLD. The current stores are intentionally bounded: 2,048 transaction records, 2,048 audit events and 4,096 live nonces. A reviewed checkpoint/rotation procedure is required for unattended sustained operation.

## Remaining ACT acceptance and release gates

The MIKAYA collaboration port is usable for the tested profile. Connecting ACT's actual model additionally requires these concrete inputs and tests:

| Gate | Required completion evidence |
| --- | --- |
| ACT enrollment | Operator-confirmed original public identity, endpoint, TLS CA/SPKI and independently authenticated binding |
| Compatible peer adapter | Exact wire/profile version, canonical serialization, supported operation/resource limits and known-answer tests on ACT's implementation |
| Model contract | Named deployed model/version, typed request/result schemas, size/time limits and an approved model operation; no invented generic inference authority |
| Retained admission | Current manufacturer/hardware evidence where required, independent reviewer report and explicit owner grant; existing direct-compute refusal remains |
| Bilateral live result | A real approved model task, signed result, result validation, fresh replay/revocation tests and receipt reconciliation after interrupted delivery |
| Android lifecycle | Screen-off/Doze, network changes, force-stop, reboot, sustained load, certificate rotation and battery/thermal tests on both actual devices |
| Long-running operations | Reviewed audit/journal archival and checkpoint-preserving retention; alerting/export and operator recovery drills |

Private encrypted artifact key agreement, artifact activation, HTTP/3, an Android companion lifecycle service and financial settlement remain separately scoped work. The existing private AHAVA mesh key and paid M2M proof are unchanged. None of these pending gates is implied by a passing public-artifact transfer.

## Reproduce and integrate

Run the commands in [README.md](README.md), then install the manifest-pinned source using [OPERATIONS.md](OPERATIONS.md). Retain exact source/log digests and device/runtime versions in the next acceptance record. The public isolated `demo` generates its own identities and temporary certificates and terminates its listener after testing; it does not enroll a real ACT peer.

This change is stacked on `review/mobile-edge-gateway-hardening-20261118`. Keep PR 10 intact, review the new collaboration change separately, and retarget only after the prerequisite merges. No merge, automatic deployment or ACT admission is part of publication.
