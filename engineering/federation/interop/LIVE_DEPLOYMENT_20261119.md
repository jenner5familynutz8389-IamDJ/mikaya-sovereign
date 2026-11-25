# Executed private interoperation deployment — November 19, 2026

The implementation is deployed on the owner's **F110 Pro and Motorola moto g power 5G — 2023**. The same final source completed **137/137 tests on each handset and in the workspace**, with zero failures, skips, cancellations or todos. After deployment, each handset sent real jobs to the other over mutually authenticated TLS 1.3, verified returned results and signatures, and observed rejection of replayed requests. Physical kill, disabled-resume, explicit clearance and restart checks passed on both devices.

The current link uses explicitly selected private LAN addresses on port 27443. These are the owner's two devices. The ACT owner's hardware has not executed this workset or accepted pairing; its published hardware examples remain source references.

## Review and evidence

- [Draft PR #11](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/pull/11) contains the implementation and this record. It is stacked on the existing PR #10 branch and remains unmerged.
- [Evidence index](evidence/20261119/README.md) explains the retained snapshots.
- [Complete public execution evidence](evidence/20261119/MIKAYA_EXECUTED_EVIDENCE_20261119.zip) contains raw TAP, manifests, runtime observations, signed public identities, physical exchange records, benchmarks, owner-control observations and separate receipt ledgers.
- [Independent archival verification](evidence/20261119/independent-verification.json) records recomputed hashes, cryptographic verification, exact result checks, reconciliation and evidence limits.
- [File inventory](evidence/20261119/evidence-manifest.json) records every archived file's byte length and SHA-256.

Public signed records are retained byte-for-byte. Endpoint addresses, private keys, macaroon root keys, credential material, replay-state files and private service configuration are excluded. Public test identities and certificates are included so their signatures can be checked.

## Final executed source and tests

The **27-file executed inventory**, covering executable code, tests, fixtures, profiles and three existing contract dependencies, is:

```text
76310862197a799269ea6aa9a2c8374538eb0ecabfa2ee74b91742e310c7ed31
```

The digest is SHA-256 of the UTF-8 bytes of `JSON.stringify(files)` in the recorded order. Before/after manifests agree, source bytes match the inventory, and `sourceStable` is true. Documentation and generated evidence are excluded.

| Execution environment | Observed runtime | Result | Whole-run duration | UTC interval |
| --- | --- | --- | --- | --- |
| Workspace | Node 24.22.3 / Linux / x64 | 137 passed; 0 other outcomes | 27,612 ms | 18:50:56.400–18:51:24.012 |
| F110 Pro | Node 26.13.1 / Android / arm64 | 137 passed; 0 other outcomes | 128,554 ms | 18:51:39.296–18:53:47.850 |
| Motorola | Node 26.3.1 / Android / arm64 | 137 passed; 0 other outcomes | 97,072 ms | 18:51:43.199–18:53:20.270 |

These are three executions of the same 137 cases. The acceptance suite uses isolated subprocesses, loopback TLS and temporary services. Physical cross-device traffic is additional execution, captured separately.

The service controller pins **10 runtime files**, whose digest is `b0cd09e2f84baf6e9b4eb33abf2de6f946e669c3853ceacd788a735daf8f5ef7`. This smaller inventory is deliberately different from the 27-file acceptance inventory.

The nine test files cover canonical serialization; Ed25519 identity/request/result verification; restricted Macaroon V2 encoding and attenuation; holder, audience, capability and profile binding; expiry and unknown-caveat refusal; persisted replay/use/byte limits; Node/Python agreement; the forced OpenSSL reference path; runtime/utility probes; mutual TLS pins and exporter binding; bounded framing; owner-policy changes; actual service lifecycle; signed receipt persistence, tampering, accounting and reconciliation.

The three newest tests use actual incomplete metadata files, retain emergency denial when ownership cannot be established, and deliberately delay real supervisor/worker metadata writes. The controller sees those incomplete states as `UNKNOWN`, never reports them as running, and reaches `READY` only after complete metadata and exact process identification.

## Actual physical network execution

Both directions completed `compute.dot.v1` and `compute.sha256.v1` after the final restart. Every exchange records TLS 1.3 with `TLS_AES_256_GCM_SHA384`, mutually validated and pinned certificates, Ed25519-signed request/results, signed runtime-profile evidence, an exporter-bound transport statement, and separate worker/holder ledger checkpoints. The dot-product result is 32. The fixed SHA-256 result is `fc8b64001c5fdd0f2f40fb67dae4a865a2c5bd17836676d6d5b58b7917e33717`.

Replaying the same captured request was refused in each exercise. Archival verification separately checked signatures, digests, exact results, peer/profile bindings and corresponding ledger entries. An offline verifier cannot reconstruct the original live TLS exporter; the transport statement is signed evidence about that live channel.

| Final physical observation | F110 | Motorola |
| --- | --- | --- |
| Explicit private LAN service | Running; exact supervisor/worker match; READY | Running; exact supervisor/worker match; READY |
| Source pins | Current | Current |
| Owner policy | Enabled for the pinned peer | Enabled for the pinned peer |
| Kill marker after explicit restart | Clear | Clear |
| Post-restart traffic/status record | 18:55:58.241 UTC | 18:58:06.095 UTC |

The original overlay route also carried verified bidirectional exchanges. During later control testing, the Motorola's overlay address disappeared from its current interfaces. A real bind attempt returned `EADDRNOTAVAIL`. Both phones retained reachable private LAN addresses, so their explicit bind and caller routes were changed to that LAN, preserving application identities, certificate pins and distribution policy. No wildcard or public listener was installed. A prior READY process record alone did not establish continuing reachability; fresh authenticated traffic established the final working route.

## Measured latency

Each condition executes the same fixed 32-byte SHA-256 job, including authorization, signed verification and durable accounting. Fresh and persistent-connection requests alternate order. For even counts, the implementation reports the upper middle order statistic as its median; raw samples are retained.

| Source and route | Requester → worker | Jobs per condition | Fresh TLS median | Reused TLS median | Recorded median reduction |
| --- | --- | --- | --- | --- | --- |
| Earlier 134-case source / overlay | Motorola → F110 | 20 | 491.640308 ms | 446.401308 ms | 9.2016% |
| Earlier 134-case source / overlay | F110 → Motorola | 20 | 815.432231 ms | 745.890538 ms | 8.5282% |
| Final 137-case source / private LAN | F110 → Motorola | 10 | 1,316.374538 ms | 1,304.758385 ms | 0.8824% |
| Final 137-case source / private LAN | Motorola → F110 | 10 | 1,548.825615 ms | 1,464.494538 ms | 5.4448% |

These small samples do not establish statistical significance, a large speedup or a causal comparison between routes. In the final Motorola → F110 capture, the persistent mean was **1,562.320631 ms**, versus **1,544.062838 ms** fresh, despite the lower persistent median. Device load, accumulated state and network conditions were not controlled between earlier and later captures. Raw bandwidth, bulk transfer, QUIC performance and native ACT worker acceleration were not measured by this workload.

## Separate ledgers and distribution

Each device maintains its own signed, hash-linked receipt ledger. Final snapshots contain **131 entries each: one genesis entry and 130 work receipts**. Reconciliation found **130 matching receipts and zero unmatched records**, counting shared work once.

The explicit fixture policy assigns 1,000 `NONMONETARY_COMPUTE_UNIT` per accepted bounded job and splits them 50/50 between the pinned identities: 65,000 units per identity after reconciliation. These units are test accounting, not currency, Bitcoin transactions or mining rewards. Receipt accounting does not itself grant execution or wallet authority; live job permission is enforced separately by owner policy and capability checks.

Exercise/benchmark files retain 128 unique successful work receipts. Full ledgers retain two additional earlier successful exchanges, accounting for 130 reconciled receipts. Independent verification checked 1,038 distinct signed envelopes. Signed response-minus-request timestamp differences ranged from −5,026 to +5,851 ms. Those values include clock disagreement and elapsed work/network time; they are not an attested clock-offset measurement.

## Hardware and firmware observations

| Read-only observation | F110 Pro | Motorola |
| --- | --- | --- |
| Android / SDK | 15 / 35 | 14 / 34 |
| Reported SoC | MT6835 | MT6855V/AZA |
| Reported board | e393_qc_f10_w_6835_v0 | devonn |
| Reported security patch | 2026-05-05 | 2026-02-01 |
| Verified-boot property | green | green |
| Vbmeta device-state property | locked | locked |
| Flash-lock property | 1 | 1 |
| Verity-mode property | enforcing | enforcing |

Fixed SHA-256, date and file-mode probes also ran against the installed BusyBox/Toybox providers. These observations describe the actual environments; neither phone was made to identify itself as a Pixel. ACT Pixel 8, Pixel 10 and Windows profiles cite public build examples and remain declared references.

Android properties are software observations. No manufacturer-rooted hardware-attestation certificate chain was obtained and verified. An IP address or board/model string does not prove human identity or wallet authority. The deployed keys bind this explicit pair and its signed software profiles.

## Owner controls installed and physically checked

On the provisioned phones:

```sh
mikaya-interop status
mikaya-interop check
mikaya-interop benchmark
mikaya-interop ledger
```

`check` performs real peer work and records new receipts. `benchmark` executes ten jobs per condition and also appends receipts. Both consume bounded journal capacity.

Emergency denial and explicit recovery:

```sh
mikaya-interop kill
mikaya-interop clear-kill
mikaya-interop start
```

Each phone's live check verified that kill closed the listening socket, resume preserved denial, start refused an active kill marker, clearing the marker left the service disabled, and a separate explicit start restored READY. Both were left enabled for their pinned counterpart.

The convenience command uses a shell launcher that executes Node by explicit path. On Motorola, a directly executed Node-shebang script made `process.execPath` identify the script instead of Node. That error was reproduced and corrected without weakening process matching.

Both phones have login resume hooks. F110 also has a hook for its existing Termux:Boot installation. **No Motorola boot hook was installed**. No cold reboot was executed on either device. Resume hooks respect disabled owner state and the kill marker. Android background execution, changing addresses and certificate expiry can affect availability; `check` tests current authenticated reachability.

## Failures that led to the final build

| Observed failure | Correction and executed evidence |
| --- | --- |
| Initial 124-case handset runs: 77 passed and 47 failed on each; Android denied hard-link creation with EACCES | Exclusive final-path receipt creation, durable append locks, file/directory fsync, retention of uncertain writes, and four added persistence regressions |
| Motorola then passed 119/128; procfs repeated the executable | Accept only that exact observed Android form with expected remaining arguments; mismatch regression added |
| One physical direction rejected valid signed results under legacy one-second timestamp ordering | Separate interop verifier preserves timestamps and requires an absolute signed timestamp difference ≤10 seconds, local freshness ≤60 seconds, exact signatures/digests and replay protection; five boundary regressions added |
| Motorola Node-shebang command misidentified service ownership | Explicit Node shell launcher, followed by actual wrapper/lifecycle checks |
| Motorola overlay address disappeared | Explicit private LAN rebind with existing pins, followed by actual bidirectional TLS jobs |
| Restart observer caught a partially written supervisor record | Unknown metadata grants no authority/readiness; three actual file/process regressions; full 137-case suite rerun in all three environments |

Earlier failed runs remain failures and are excluded from final pass counts. The archive includes hashed summaries of the initial physical failures. The historical 75-case owner-carried baseline remains separate in [EXECUTED_VALIDATION_20261119.md](EXECUTED_VALIDATION_20261119.md).

## Reproduction and ACT handoff

From the reviewed checkout, with Node 22+, Python 3 and OpenSSL 3:

```sh
node engineering/federation/interop/run-acceptance.cjs --output "$HOME/mikaya-interop-run-001"
```

Use a new absolute output directory for every run. This executes the acceptance workset on that machine and retains actual results. Compare its source manifest to the intended reviewed revision. See [DIRECT_TRANSPORT.md](DIRECT_TRANSPORT.md) for provisioning, explicit public-manifest pairing and direct exchange commands, and [LEDGER_RECEIPTS.md](LEDGER_RECEIPTS.md) for accounting/recovery semantics.

An ACT operator can review this PR and run the same command on their runtime. A successful ACT run, a fresh signed public manifest from that device and explicit bilateral pairing are still required before claiming ACT-side interoperability. Public hardware markers are compatibility hints, not preapproved identities.

Remaining production limits are concrete: seven-day certificates without automatic rotation; bounded replay/event journals; a 1,024-entry receipt ledger without automatic truncation; software checkpoints rather than hardware monotonic state; two fixed compute capabilities; first-party macaroon caveats without a third-party discharge exchange; and no executed Bitcoin/mining/mempool or L402 settlement workflow. This real two-device deployment does not establish ACT production admission or completion of a payment protocol.
