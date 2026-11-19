# Verification of mobile-edge source changes

Prepared November 18, 2026, America/New_York. Environment: isolated Linux workspace, **Node.js v24.22.1**. Target code remains Node.js 22+. No Android, ACT hardware, external ACT runtime, installed APK or wireless ADB test was performed.

Base: `jenner5familynutz8389-IamDJ/mikaya-sovereign` commit `81a0ff62c6e8f3a5963ae5b29b7d849346a6950a`. Review branch: `review/mobile-edge-gateway-hardening-20261118`.

## Actual executed results

| Command | Tests | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: | ---: |
| `node --test engineering/federation/live/tests/*.cjs engineering/federation/live/evidence-brief/tests/*.cjs engineering/federation/mobile-edge/tests/*.cjs tests/test_ahava_resume.cjs` | 130 | 130 | 0 | 0 |
| `node --test integrations/security-tollbooth/verified-events/tests/*.cjs` | 28 | 28 | 0 | 0 |

Total: **158 passed, zero failed, zero skipped**. These are local-fixture results, separate from historical phone acceptance counts. The AHAVA portion uses mocked transport with actual encryption/signature verification. Federation, broker and gateway tests use ephemeral loopback sockets; independent broker workers use separate child processes. Broker interface discovery is an explicit test-only loopback stub because this workspace denies `os.networkInterfaces`; production interface-discovery behavior was not bypassed.

Run-log SHA256 values (timings and ephemeral ports are run-specific):

- `mobile-federation-tests.log`: `f46deeca9c8b8ffdbd38373fe78c79a5fd9e6e364f554e769bc7fdd7f0f988fc`
- `existing-native-verifier-tests.log`: `8a87faf132461a3c646031bc72322b99ab430d88841f83dc3af7fa73f7c11de0`

`git diff --check` passed. No GitHub Actions or GitLab CI run was initiated by these local commands.

## Reproduced defects and corrections

1. **Direct ACT compute gate.** On an isolated checkout of the unmodified base, the new signed loopback regression returned HTTP200 where HTTP422 was required: one test, zero passed, one failed. The revised node returns422 before creating a job or completion journal entry. Pin/capability revocation and the owner kill switch are tested at shared acceptance; MIKAYA-to-Motorola and Motorola-to-MIKAYA signed results still pass.
2. **Authorization at forwarding time.** Current broker policy, owner capability, current peer pin/scope, reviewer signature and owner-grant expiry are rechecked immediately before forwarding. Tests reject changed/disabled policy, altered scope, revocation, expired grants and altered review signatures.
3. **Normal node shutdown.** The untouched base's node suite produced 12 passes and 1 failure: its restart test hit the stale writer lease left by ordinary SIGTERM. The revised CLI closes its listener on SIGTERM/SIGINT and releases only that process's lease. The existing replay-after-restart test now passes. Crash/SIGKILL recovery remains HOLD; stale locks are not automatically erased.
4. **Broker fixture topology.** The untouched broker suite produced 5 passes/3 failures in this environment due to interface-discovery permission errors. With only a known-loopback test stub, 6 passed/2 failed because positive tests incorrectly cohosted worker and broker in the same runtime. Corrected fixtures use separate worker processes; the production same-runtime ban remains and has explicit negative coverage. The updated broker suite passes 10/10.
5. **Resumed AHAVA pull.** A 131,109-byte encrypted object interrupted after one 65,536-byte chunk leaves a verified durable chunk. Retry fetches 65,573 bytes, avoiding 65,536 ciphertext bytes. Zero chunk GETs are needed for a complete valid cache. Tests retain trusted-signature, GCM, ciphertext/plaintext/full-object checks; unsafe/corrupt files are preserved and refused. A hostname beginning with a private-IP-looking prefix is rejected unless it is an actual permitted IPv4 address.

## Owner-local gateway coverage

Twelve tests cover signed read/response verification; unchanged independent node identities and canonical ledgers; unauthorized local/browser/foreign-host reads; method/path restrictions; instance-bound nonce replay; tampered and stale responses; refusal of a pinned other device as a local owner reader; owner kill switch; absent/unsafe native thermal status; tampered, stale, rolled-back or missing evidence; explicit loopback-only listeners; shared 8 KiB/busy/slow-body limits; an absolute 3-second client deadline; same-process cohosting with the original node; and refusal to clear existing leases or initialize a replacement owner.

The existing 28 native verifier/producer tests independently confirm the preserved pinned-verifier, durability and observation contracts. This update does not widen the fixed native probes or change their released source pins.

## Signed-release and deployment status

The existing `RELEASE-SOURCE-MANIFEST.json` and signature are retained verbatim as historical owner attestations. They **do not attest these new bytes**. Even at the base commit, the historical manifest's README digest already differed; this review additionally changes AHAVA core/sync. A signature-only success from the historical root verifier must not be reported as current-source acceptance. The separate review-source hash inventory is unsigned and supplies reproducibility, not owner authorization or a new release signature.

No private signing key was requested or used to renew a release. Owner-controlled release attestation, actual device rollout, original supervisor configuration, current private routes, ADB continuity, physical thermal behavior, model performance and bilateral ACT admission remain separate acceptance steps. No payment, Lightning/L402 settlement, firmware/slot operation or external network admission is enabled.

The connected remote service had no paired devices or active sessions during preparation. Local passing tests therefore do not mean the phones were updated. The combined launcher is an explicit replacement for an existing node process, not permission to start a duplicate runtime or remove a lease.
