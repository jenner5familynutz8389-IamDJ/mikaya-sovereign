# Executed interoperability validation — 2026-11-19

> **Historical baseline:** this report records the earlier source set
> `f45fdb7a4af0b2f303139eadc35d1d00d9bc3cbc619aceab98da8e9fa970b47a`,
> before the direct TLS service, signed receipt-ledger integration and owner
> service controller were added. Its 75-case results and owner-carried
> physical exchange are preserved as historical evidence. They are not the
> test count or transport description for the later implementation.
>
> Current deployment and execution evidence belongs in
> [LIVE_DEPLOYMENT_20261119.md](LIVE_DEPLOYMENT_20261119.md); operational commands
> are in [DIRECT_TRANSPORT.md](DIRECT_TRANSPORT.md). Statements below about
> listeners, publication and deployment describe this earlier baseline only.

## Verified result

The same isolated interoperability workset completed **75/75 tests on each of
three environments**: the workspace, the owner's F110 Pro, and the owner's
Motorola. Every run recorded zero failures, cancellations, skipped tests and
todo tests, process exit zero, a portable-runtime `MATCH`, and unchanged
before/after source hashes. These are three executions of the same 75 cases,
not 225 different test cases and not an ACT hardware execution.

The retrieved evidence was independently checked against the actual TAP
output, its recorded artifact hashes, and that baseline's source files. All
checks matched. This report adds documentation only; executable/test files
were frozen before these checks.

| Executing environment | Actual Node / platform / architecture | Result | Recorded runner duration | UTC run interval |
| --- | --- | --- | --- | --- |
| Workspace | 24.22.3 / Linux / x64 | 75 passed; 0 other outcomes | 5,203 ms | 17:25:18.050–17:25:23.253 |
| Owner F110 Pro | 26.13.1 / Android / arm64 | 75 passed; 0 other outcomes | 38,772 ms | 17:25:05.646–17:25:44.418 |
| Owner Motorola moto g power 5G — 2023 | 26.3.1 / Android / arm64 | 75 passed; 0 other outcomes | 26,081 ms | 17:25:08.389–17:25:34.470 |

Source: each environment's `acceptance.json` and `test-results.tap` in the
accompanying `workspace-acceptance`, `f110-acceptance` and
`motorola-acceptance` evidence directories. Durations are whole-run local
measurements, including collection and test execution. They are not network
throughput or native-worker acceleration benchmarks.

## Observed runtime and utility compatibility

The F110 reported Android 15 / SDK 35; the Motorola reported Android 14 /
SDK 34. Both reported little-endian arm64. Ed25519 and SHA-256 in-memory
self-checks succeeded in all three environments. These observations are
software evidence, with `hardwareAttested: false`.

| Environment / provider | Observed version | SHA-256 fixed stdin fixture | UTC epoch-zero date conversion | File-mode `stat` agrees with Node |
| --- | --- | --- | --- | --- |
| F110 BusyBox | 1.38.0 | true | true | true |
| F110 Toybox | 0.8.11-android | true | true | true |
| Motorola BusyBox | 1.38.0 | true | true | true |
| Motorola Toybox | 0.8.9-android | true | true | true |
| Workspace BusyBox and Toybox | unknown: not found in the fixed probe paths | unknown | unknown | unknown |

Both handsets' BusyBox listings included `sh`, `sha256sum`, `date`, `stat`,
`base64` and `timeout`. Both Toybox listings included the latter five but
**did not include the `sh` applet**. Availability of `base64` and `timeout`
was observed from the applet listing; this collector did not perform their
full semantic or failure-mode tests. BusyBox and Toybox are therefore not
treated as interchangeable shells or as universal substitutes for every
GNU utility option.

The collector found Android Toybox through the fixed `/system/bin/toybox`
path, including on the F110 where an earlier PATH lookup did not find it.
Root availability, boot slot, AVF, safe temporary storage and GPU renderer
remain explicitly unknown/not probed. Reported CPU features do not authorize
Pixel-specific compiler flags or establish that an ACT optimized binary ran.
Source: the three `runtime-profile.json` files and their
`runtime-comparison.json` records.

## Source and evidence integrity

All three runs recorded the same **21-file executed-source inventory**:
interop executable files, tests, fixtures and profiles, plus the existing
`federation-node.cjs`, `security-tollbooth.cjs` and
`act-backend-compat.cjs` contract dependencies. README/report documents are
intentionally excluded from this inventory.

```text
sourceSetSha256
f45fdb7a4af0b2f303139eadc35d1d00d9bc3cbc619aceab98da8e9fa970b47a
```

The digest is SHA-256 over the UTF-8 bytes of `JSON.stringify(files)`, where
`files` is the manifest's sorted array of path, byte length and SHA-256
records. For every environment:

- The recomputed before-run and after-run manifest digests match the value above.
- Every recorded artifact byte length and SHA-256 matches its retrieved file.
- Every recorded source byte length and SHA-256 matches the frozen workspace source.
- Independently reparsed raw TAP counters match `acceptance.json` exactly.
- `sourceStable` is true, `failureReasons` is empty, and termination reason/signal are null.

These checks establish byte consistency within the retained evidence. They
do not constitute hardware attestation or independent proof of an ACT run.

The workset is based on existing draft PR #10 commit
`1da7fbdd79e63f857b07af0738278156c19a9966`. The tracked-files diff against that
commit remained empty at report preparation; the additions are confined to
the new `engineering/federation/interop` workset. Existing production runtime,
owner identities, services, policy and ledgers were not replaced or enabled
by this workset.

## Commands and reproducibility

From the reviewed repository root, use this exact CLI form with a fresh,
absolute output path whose parent already exists:

```sh
node engineering/federation/interop/run-acceptance.cjs --output "$HOME/mikaya-interop-run-001"
```

This is a reproduction command; choose a new final directory name for every
run. The output directory must not already exist. It creates private evidence
and does not install dependencies or start a service. The workspace evidence
for this historical report is retained in the accompanying archive's
`evidence/workspace/` directory.

The actual outer invocation on each handset selected this same runner using
absolute source and output paths within the owner's private test workspace.
Its portable equivalent, run from the source root, is:

```sh
node engineering/federation/interop/run-acceptance.cjs --output "$HOME/mikaya-interop-acceptance-1"
```

The original device-specific output directories retain their recorded runs.
A repeat must use a different new output directory.

All three acceptance records contain this exact child-process argument list,
executed directly through the current `process.execPath` from the repository
root, without a shell:

```text
--test
--test-concurrency=1
--test-reporter=tap
engineering/federation/interop/tests/test_capability_macaroons.cjs
engineering/federation/interop/tests/test_device_handoff.cjs
engineering/federation/interop/tests/test_native_reference.cjs
engineering/federation/interop/tests/test_run_acceptance.cjs
engineering/federation/interop/tests/test_runtime_profile.cjs
engineering/federation/interop/tests/test_session_adapter.cjs
```

The runner imposes a 180-second test-process limit and an 8 MiB combined
stdout/stderr limit. It retains bounded failed results and rejects missing
TAP counters, skips, cancellations, todos, runtime-profile failures and source
drift. Node 22+, Python 3 and the required installed cryptographic backend
must be available. Although the Python reference supports either
`cryptography` or OpenSSL, the complete acceptance suite deliberately tests
the OpenSSL fallback and therefore requires installed OpenSSL 3 too.

## Existing-suite regression evidence

The separate fresh workspace regression run retained as `baseline-tests.tap`
records **209/209 passed**, zero failures/cancellations/skips/todos, and a
complete plan of 209 tests. Its TAP duration is 25,804.128077 ms. The file was
retained on 2026-11-19 before the three acceptance runs, and its counts were
independently reparsed during this report's preparation.

```text
baseline-tests.tap
bytes: 48886
sha256: 1247a725b047ba31cc1b9a8fb64c2050b52a1c64ea1bc12ef215aa13e6491321
```

This regression run is separate from each 75-test handset acceptance run.
The 209-case baseline was not automatically rerun on the handsets by the
one-command acceptance runner.

## Scope and remaining boundaries

The exercised implementation covers signed bounded request/result contracts,
Node-to-Python local process interoperability, first-party Macaroon V2
attenuation and verification, local replay/use/byte limits, explicit runtime
observations, and signed binding of the request, response and profile digest.
The native reference's replay state is in memory; the durable capability
replay boundary is for a single host and local filesystem.

Each acceptance record explicitly retains:

```text
actHardwareTested: false
actEndpointCalled: false
hardwareAttested: false
productionAdmission: false
paymentsAuthorized: false
firmwareOperations: false
distributedReplayProtectionProven: false
```

This does not establish an ACT deployment, third-party macaroon discharge
support, L402 settlement, transaction validation/mining, distributed replay
coordination, live admission, payment authority or a faster network transport.
The operating-system Toybox utility checks are separate from the historical
MIKAYA module named Toybox. ACT source profiles remain declared reference
profiles; an ACT operator must run and identify their own fresh evidence.

### Two-owner-device signed exchange

The separately invoked physical-handset exchange completed in both
directions. Each handset used its own newly created private test identity
and local macaroon root secret. Public packets were carried through the
owner-authorized DesktopCommander channel; the recorded transport is
`OWNER_CARRIED_PUBLIC_TEST_PACKET`. This was not a direct network transport
or an ACT connection, and no installed production identity was substituted.

| Requester → worker → verifying requester | Actual deterministic work | Verified UTC time |
| --- | --- | --- |
| F110 → Motorola → F110 | `compute.dot.v1`: `[1,2,3] · [4,5,6] = 32` | 2026-11-19T17:28:55.836Z |
| Motorola → F110 → Motorola | `compute.sha256.v1`: SHA-256 of 32 bytes, each `0xa5` | 2026-11-19T17:28:56.896Z |

The SHA-256 result was:

```text
fc8b64001c5fdd0f2f40fb67dae4a865a2c5bd17836676d6d5b58b7917e33717
```

The retrieved public proofs were independently reverified offline using
the recorded historical verification times, each counterpart's public test
identity, and the digest of its actual saved runtime profile. Request and
response signatures, exact deterministic results, signed evidence binding,
public identities, and the worker profile digest all matched. This archival
verification confirms the retained exchange; it does not make an expired
packet valid for a new request.

The operator also observed immediate replay refusal on both receiving
handsets. That check is separate from the successful returned receipts:
the receipt is not itself a signed replay-rejection record.

Bundle-relative public evidence locations:

- `evidence/handset-exchange/f110/physical-cross-device-proof.json`
- `evidence/handset-exchange/motorola/physical-cross-device-proof.json`

Each directory also contains `public-identity.json` and
`runtime-profile.json`. The proof-file SHA-256 values are:

```text
F110-returned proof:
7577bfb0f8cfe12575fd06d463c2df50f98cfff1351c5f3688568aefd0399402

Motorola-returned proof:
fe0503d1edf6eb92ce3e10c28e72d0d94197aec0dfefb71cfa4047cd3c8a6111
```

Private test keys and macaroon root secrets remained on the handset that
created them and are not part of these sharing artifacts. These two actual
exchanges are separate from the three 75-test local acceptance runs. Their
records retain `syntheticIdentities: true`, `hardwareAttested: false` and
`productionAdmission: false`.

## Delivery status

The workset and retained evidence are being provided as a downloadable
review/test bundle. No new public GitHub deployment or published test link is
claimed. The GitHub write connector returned 403, and automatic approval
review rejected the git push dry-run because explicit publication
authorization was absent. No further publishing attempt was made.
