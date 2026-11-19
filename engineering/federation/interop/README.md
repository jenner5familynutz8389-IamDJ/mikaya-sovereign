# MIKAYA and ACT interoperability acceptance workset

This workset includes executable compatibility tests and an explicitly paired
direct TLS service. It connects the existing MIKAYA signed JSON contract to a
separate Python reference process, implements a restricted Macaroon V2
capability boundary, exercises request/result/profile binding, and records
actual runtime and BusyBox/Toybox utility behavior. The direct service adds
mutual TLS, persistent sessions, owner lifecycle controls and separate signed
receipt ledgers.

## Guide and execution records

- [DIRECT_TRANSPORT.md](DIRECT_TRANSPORT.md): provisioning, explicit pairing
  policy, direct network exchange, service start/stop/kill/resume, benchmarks
  and operational limits.
- [LIVE_DEPLOYMENT_20261119.md](LIVE_DEPLOYMENT_20261119.md): current execution
  and deployment evidence; use the completed report for verified physical
  outcomes and source identity.
- [EXECUTED_VALIDATION_20261119.md](EXECUTED_VALIDATION_20261119.md): historical
  75-case baseline and owner-carried packet exchange before the direct service.
- This README: acceptance runner, runtime collector and portable contract.

## Hardware independence

The two systems can use different hardware, firmware and application runtimes.
The common boundary is the signed message contract and its checked evidence.
The ACT profiles included here are **source-declared reference profiles**, not
verified descriptions of a currently running ACT device and not a requirement
that an F110 or Motorola identify itself as a Pixel.

## One-command acceptance run

Requirements:

- Node.js 22 or newer.
- Python 3 available as `python3`, or an explicitly chosen interpreter in
  `MIKAYA_REFERENCE_PYTHON`.
- The Python reference uses its standard library plus either installed
  `cryptography` or installed OpenSSL with Ed25519 support. The complete test
  suite also **forces the OpenSSL fallback path**, so OpenSSL 3 must be
  available for this acceptance command even if `cryptography` is installed.
- A filesystem that enforces private directory/file permissions. Use native
  Android/Termux private storage or an appropriate local Linux filesystem.
  Do not assume shared Android/SD storage or a Windows volume enforces the
  same POSIX permission checks.

From the reviewed repository root:

```sh
node engineering/federation/interop/run-acceptance.cjs --output "$HOME/mikaya-interop-run-001"
```

The output path must be absolute, its parent must already exist, and its final
directory must not exist. Choose a fresh name for every run. The runner creates
that directory with mode `0700` and evidence files with mode `0600`; it refuses
an existing destination. It does not install dependencies.

The runner uses the current `process.execPath` with `--test`,
`--test-concurrency=1` and the TAP reporter. It passes the discovered
`interop/tests/*.cjs` filenames directly, without shell expansion. It does
**not** automatically execute the broader historical federation/mobile-edge
test suites on a handset.

The current suite includes temporary loopback TLS listeners and service
lifecycle tests. Their local execution is separate from the explicit
two-device `exercise` and persistent service deployment described in the
direct transport guide. The test harness cleans up its own temporary services.

The test process is limited to 180 seconds and 8 MiB of combined output. On
POSIX platforms, timeout/output-limit termination targets the runner's own
new child process group. Partial results are retained on failure. A short
pipe-cleanup allowance may follow termination.

### Generated evidence

| File | Meaning |
| --- | --- |
| `acceptance.json` | Overall result, actual TAP counts, runtime comparison, source stability, failure reasons and evidence-file hashes |
| `test-results.tap` | Raw output of tests executed during this run |
| `test-stderr.log` | Bounded test-process diagnostics |
| `runtime-profile.json` | Sanitized observations collected on the executing machine |
| `runtime-comparison.json` | Comparison with the portable Node/crypto requirements |
| `source-manifest.json` | Before-run SHA-256 inventory of executable/test/fixture/profile files and the three live contract dependencies |
| `source-manifest-after.json` | After-run inventory, used to detect source changes during execution |
| `acceptance-start.json` | Start record retained even if the later process does not complete |

The inventory includes the interop executable/test/fixture/profile files and
`live/federation-node.cjs`, `live/security-tollbooth.cjs`, and
`live/act-backend-compat.cjs`. Documentation and generated evidence/report
directories are excluded. A documentation edit therefore does not change the
tested executable source identity; an executable, test, fixture or profile
edit does.

Exit zero and `PASS` require all of the following:

- A complete TAP header, plan and unambiguous actual result counters.
- At least one executed test and every test passing.
- No failed, cancelled, skipped or todo tests.
- A successful test process with no timeout or output-limit termination.
- A `MATCH` against the portable Node/crypto requirements.
- Identical before/after source inventories.

Missing tools, missing counts, incomplete execution and source drift are
failures. The runner does not turn an unavailable dependency into a skipped
success. `acceptance.json` records the actual count; this README does not
substitute a historical count for a fresh run.

## Runtime and utility evidence

The collector can also run independently:

```sh
node engineering/federation/interop/runtime-profile.cjs collect --expected engineering/federation/interop/profiles/portable-node22.json
```

It records Node/OS/architecture facts, an in-memory Ed25519 and SHA-256
self-check, selected Android build/model properties, and reported CPU feature
names. CPU features are intersected across the CPU rows actually reported.
That is software observation, not a manufacturer attestation or proof that an
optimized native worker has executed correctly.

BusyBox and Android Toybox are checked separately. The collector looks in
fixed common installation paths, including Termux's BusyBox and
`/system/bin/toybox` even when that file is absent from Termux's `PATH`.
It records selected applet availability and actually checks:

- SHA-256 of a fixed fixture supplied on standard input.
- UTC conversion of epoch zero with the selected date syntax.
- `stat -c %a` agreement with Node's mode observation for the collector file.

An installed provider, an available applet and a successful semantic check
are separate facts. Missing/failed probes remain `unknown`; an observed
missing applet or incorrect result is recorded as false. Unsupported optional
utilities do not invalidate the Node-only protocol baseline, and their
limitations remain visible in the report.

Each utility/property command uses fixed arguments, no shell, a 750 ms timeout
and bounded output, within a 10-second aggregate probe budget. The report does
not include raw property dumps, raw stderr, serials, IP addresses, hostnames,
wallet data, accounts or private keys. Root availability, boot slot, AVF,
safe temporary storage and GPU renderer are explicitly `unknown/not_probed`.

The source profiles are:

| Profile | Use |
| --- | --- |
| `portable-node22.json` | Common Node 22+, Ed25519 and SHA-256 runtime baseline |
| `act-pixel8-source.json` | Comparison with the published Pixel 8 example markers |
| `act-pixel10-source.json` | Comparison with the published Tensor G5 worker markers and compile-time instruction requirements |
| `act-windows-host-source.json` | Comparison with the published Windows/Intel/NVIDIA reference-host markers |

Each profile records commit-pinned source URLs. A hardware-reference mismatch
on the F110/Motorola is expected when their actual hardware differs; it must
not cause identity rewriting or adoption of Pixel-specific native flags.
`MATCH` means only that the required checks in that selected profile matched.
Unknown optional checks never become measured successes.

## Implemented protocol and authorization scope

`native-reference.py` is a separate-process Python implementation of the
bounded canonical-JSON/Ed25519 request/result contract. It uses synthetic
identities and local stdin/stdout frames. Tests cover canonical bytes,
cross-language signatures, exact deterministic results, tampering, replay
within the reference process, expiry, and rejected capabilities. The Python
reference's replay state is in memory; its results do not prove durable
cross-restart or distributed replay protection.

`capability-macaroons.cjs` implements a restricted **first-party Macaroon V2**
wire-format and chained-HMAC boundary with independent upstream vectors.
Its caveats bind the isolated-test environment, verified holder, receiving
identity, profile digest, bounded operation, payload digest, expiry, use
count and byte budget. Unknown/unsupported caveats fail closed. Local durable
replay and budget reservations are for one host and its local filesystem;
they do not establish a multi-host/shared-storage reservation protocol.

This subset does not implement third-party discharge caveats, full L402
settlement, production admission, mining, wallet operations or a general
transaction-validation engine. The separate historical Bitcoin observation
module named **MIKAYA Toybox** is not the operating-system Toybox utility and
is not exercised by this runner as a live mempool or payment service.

`session-adapter.cjs` first verifies the real signed request and then derives
the macaroon verification context from that request. It preserves the existing
bounded `compute.dot.v1` and `compute.sha256.v1` result envelopes. A separate
signed evidence record binds the exact request, response and observed-profile
digest. A caller-supplied success flag is not accepted as this evidence.

`device-handoff.cjs` supports an explicitly invoked test exchange between two
owner-controlled computers using new private test-state directories. Its
public packets can be carried using the owner's chosen channel. This is
separate from the one-command local acceptance run. Private test keys and
root secrets remain with the device that created them; they are not sharing
artifacts.

`direct-transport.cjs` carries that bounded contract over mutually
authenticated TLS 1.3 with exact certificate pins and a signed TLS-exporter
binding. `service-control.cjs` manages its owner-local lifecycle and source
pins. `ledger-receipts.cjs` maintains separate signed receipt histories under
an explicitly supplied nonmonetary accounting policy. Consult the
[direct service guide](DIRECT_TRANSPORT.md) for their complete commands and
scope; the earlier handoff module's offline description does not describe
these newer network operations.

## TEST_SCOPE and sharing

Every acceptance result carries `TEST_SCOPE` identifying what that particular
local suite executed, including its local transport tests, with synthetic
identities. The result explicitly reports:

```text
actHardwareTested: false
actEndpointCalled: false
hardwareAttested: false
productionAdmission: false
paymentsAuthorized: false
firmwareOperations: false
distributedReplayProtectionProven: false
```

An ACT operator can review the pinned source and run the same acceptance
command in an ACT-controlled environment, then share the result and public
source/evidence hashes. Each operator's fresh execution must remain separately
identified. A MIKAYA phone run, workspace run, source example or green
repository badge must not be relabeled as an ACT hardware run.

Inspect diagnostics before sharing them publicly. The acceptance output
directory is private by default. Acceptance tests, an explicitly deployed
owner-pair service and an external ACT operator's execution are separate
records. Source hashes and software signatures make each recorded contract
and result inspectable; they do not replace independent operator identity
checks or hardware review. Publication and physical deployment status belong
in the current execution report rather than a blanket statement about what
the entire project has or has not performed.
