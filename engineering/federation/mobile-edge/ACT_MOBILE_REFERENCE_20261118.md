# ACT Android/mobile reference — November 18, 2026

Read-only source inspection of public repository [`bospaladin34-crypto/Sovereign-Manifold-V30-A.P.H.U.S-`](https://github.com/bospaladin34-crypto/Sovereign-Manifold-V30-A.P.H.U.S-), branch `vesper_production`, pinned to commit [`e9804bf287753ced0595e60cb7931d5bb6953538`](https://github.com/bospaladin34-crypto/Sovereign-Manifold-V30-A.P.H.U.S-/commit/e9804bf287753ced0595e60cb7931d5bb6953538). The commit is dated November 18, 2026 14:37:30 UTC / 09:37:30 America/New_York. The earlier reviewed revision was `9257e712eede47fc77963fa5f10603e70b413f6c`.

No ACT runtime endpoint, APK, model, command dispatcher, MCP tools/call or device was executed. This is technical source attribution, not verified real-world identity, endorsement or permission to collaborate. No ACT code was copied into this update.

## Current topology and wire contracts

| Component and pinned source | Verified source behavior | MIKAYA implication |
| --- | --- | --- |
| [Android MainActivity / SovereignLiveBus](https://github.com/bospaladin34-crypto/Sovereign-Manifold-V30-A.P.H.U.S-/blob/e9804bf287753ced0595e60cb7931d5bb6953538/04_edge_silicon/pixel10_ndk_app/app/src/main/java/com/actomega/manifold/MainActivity.kt) | Active bus uses Android APIs for battery/RAM/sensors, GET telemetry query parameters, measured RTT and bearer selection. Pixel10 and Pixel8 have different roles. | Reuse the separation of observations and link state as a design reference. Do not copy ACT's private host addresses, sensor assumptions or identity. Existing MIKAYA signed native observations remain the evidence source. |
| [Deno server](https://github.com/bospaladin34-crypto/Sovereign-Manifold-V30-A.P.H.U.S-/blob/e9804bf287753ced0595e60cb7931d5bb6953538/02_gateway_deno/server.ts) | TCP/UDP use `DENO_TCP_PORT` or default **18098**. HTTP uses **8099**. Listeners bind `0.0.0.0`. | Earlier default 8098 documentation is stale for this gateway. MIKAYA's owner-local port4188 is a separate signed read contract, never an assumed ACT port. |
| Deno `/api/v1/telemetry` | Newly tries Rust host `127.0.0.1:8097` with a 1,200 ms timeout, accepts finite magnetometer components, returns merged source data and `Cache-Control:no-store`; failure returns `UNMEASURED/OFFLINE`. | Explicit offline evidence is useful. MIKAYA retains its signature, source-age and policy checks; it does not infer authenticated hardware from this status. |
| Deno `/health` and `/ws` | Still use an initialized/cached object containing preset values and initial `CONNECTED`. | The newer offline behavior is not uniform across all routes. A status string does not establish live measurements or connectivity. |
| [TelemetryStreamer.kt](https://github.com/bospaladin34-crypto/Sovereign-Manifold-V30-A.P.H.U.S-/blob/e9804bf287753ced0595e60cb7931d5bb6953538/04_edge_silicon/pixel10_ndk_app/app/src/main/java/com/actomega/manifold/TelemetryStreamer.kt) | Standalone bounded 256-entry DROP_OLDEST queue, persistent TCP, newline CSV `seq,timestamp_ms,bx,by,bz`, default 8098, UDP `ACTOMEGA_DISCOVERY`. | This differs from Deno's default 18098 and accepted discovery markers `ACTOMEGA_PROBE`/`SWARM_PROBE`. No active MainActivity reference to this class was found; it is not proof of the deployed path. |
| [SensorTransducer.kt](https://github.com/bospaladin34-crypto/Sovereign-Manifold-V30-A.P.H.U.S-/blob/e9804bf287753ced0595e60cb7931d5bb6953538/04_edge_silicon/pixel10_ndk_app/app/src/main/java/com/actomega/manifold/SensorTransducer.kt) | Uncalibrated magnetometer with calibrated fallback; requests 66,666 microsecond sampling and emits XYZ callbacks. | Requested cadence is not observed cadence or an authenticated sensor report. |

The implementation is under `04_edge_silicon/pixel10_ndk_app/app/src/main/java/com/actomega/manifold/`. The similarly named `04_edge_mobile` directory is not the active Kotlin source location. MainActivity has mirrored source copies; the inspected blob is `7204a5583ca7c59eda1afa0a9171d0d431406e8e`. The Deno server blob is `9e4689bf631d30869660d6f1ced86beb0ddb0be3`.

## Active Android telemetry

The bus selects `/api/v1/telemetry` for local bearers and `/api/v1/StateGraph` for configured ACT cloud hosts. Pixel10 query fields include `node`, `col`, magnetometer/norm, pressure, light, motion, battery temperature/voltage/percentage, RAM, sensor frequency, telemetry frequency, RTT and bearer. Pixel8 omits SensorManager and also sends literal throughput/cache values such as `kops=1140.0`, `p8_kops=1140.0` and `p8_free=89.11`. Those literal values are not benchmarks.

The latest change preserves the prior measured RTT for the next request and URL-encodes the bearer label. Its telemetry construction does not attach a MIKAYA-compatible signature or replay nonce. A GET carrying `node` and measurements can update the receiving host's telemetry; it must not be classified as harmless monitoring solely because its method is GET.

The Deno TCP parser still splits each individual 1,024-byte read without retaining partial lines across reads. CSV checks use `isNaN`, not complete finite/range validation. These are integration limitations, not evidence of exploitation or deployed failure. MIKAYA does not adopt this unauthenticated ingress or its automatic host fallback.

## Evidence boundary

The inspected [existing Gatekeeper job log](https://github.com/bospaladin34-crypto/Sovereign-Manifold-V30-A.P.H.U.S-/actions/runs/44327790628/job/134883650297) includes a `v50_brain_trainer` check error requiring the `standalone_qat_bin` feature at 14:46:36.440 UTC, followed by a successful full-manifest check. It also records seven static invariants passing and a source count of 1,010 Lean theorem definitions. These entries do not establish an Android instrumentation run, a successful brain-trainer check or a bilateral MIKAYA test. The latest commit's changed-file list contains no added test file.

The current source and CI metadata are development evidence. They do not establish installed APK acceptance, physical device ownership, Android sensor accuracy, a successful MIKAYA exchange, battery savings, faster transport or live model throughput. The MIKAYA tests in this change cover MIKAYA's own code and synthetic/local fixtures only.

Keep Android control, observation, compute authorization, AHAVA encrypted content and Lightning/L402 settlement separate. A source reference, star, follow, signed observation or successful HTTP status does not grant any of these permissions.
