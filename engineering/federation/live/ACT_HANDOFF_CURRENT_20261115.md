# Current ACT-OMEGA owner and device handoff

This is the current reproducible collaboration-source handoff, dated November 15, 2026. It supersedes the installation pointers in the older onboarding document; its historical observations remain historical. The handoff preserves the existing protocols and the human-principal wording. It creates no identity, enrollment, route, watcher, wallet or permission.

## Sources and completed local work

The base is GitLab project `iamdj1989-group/IamDJ1989-project`, immutable main commit `fccfdae5893ef8e8c57149e3228f533ae8a6061e`. Eight selected transport/invitation/grant/security sources and tests were retrieved directly at that ref and compared by SHA-256 and byte length. The existing `act-backend-compat.cjs` and its test were absent from that GitLab ref (HTTP 404). Their unchanged bytes were recovered directly from the approved GitHub main commit `1ed24c8fd79278e93b2d50123d82561f04fca8c1`, where the verifier is already published. This delivery restores those two existing files to the collaboration source; it does not invent another adapter.

The assembled handoff additionally includes the reviewed shared-gate integration for the existing legacy bridge. Only `security-tollbooth.cjs` differs from the eight captured GitLab base files: SHA-256 `f5b6bc0602c0f7623844eae40694bfb3ea9db24462fc42d05e722b661c183c29`. Its optional fifth per-server body-budget argument retains the existing federation node/broker default of 8192 bytes; the separate legacy bridge may explicitly choose its bounded 65536-byte limit. No ACT wire schema, owner grant or capability changes. The source manifest records both the original GitLab identity and this reviewed combined dependency, assembled for the same combined source delivery; the repository delivery receipt establishes its resulting remote commit. The 25 affected ACT tests were rerun once against these exact combined bytes and all passed.

`ACT_HANDOFF_SOURCE_MANIFEST_20261115.json` pins all ten selected executable/test files, including the reviewed combined gate. The selected package includes their dependencies; no npm install, phone key or network access is needed for its focused tests. In a normal project checkout or this source handoff, run from `engineering/federation/live`:

```sh
node --test tests/test_mesh_invite.cjs tests/test_owner_authorization.cjs tests/test_act_backend_compat.cjs
```

The completed combined-dependency local run passed **25 tests**, with no failures or skips. The earlier base-dependency run is retained separately. Tests create synthetic fixture identities only. They exercise signed invite/reply and expected pins, independent reviewer and owner scope, expiry, revocation, owner/broker scope agreement and deterministic signed-result validation. They do not establish an ACT device, legal identity, live route, hardware review, external computation or settlement. No device deployment or activation was performed by this source handoff.

## Existing ownership contract

Governance remains **human principal → owned device → delegated agents**. One human may own the F110 and Motorola. `MIKAYA`, `MOTOROLA` and `ACT-OMEGA` are existing protocol roles/labels; a label or signature does not verify a real-world human identity. This handoff adds no personal identifier, KYC system or new enrollment schema. Device software keys, hardware credentials, owner permission and payment settlement remain separate inputs. Existing grants delegate only the exact bounded compute capabilities and expire; there is no permission to run arbitrary agents or commands.

These existing entrypoints provide the contract:

| Existing source | Role | Required external input |
|---|---|---|
| `mesh-invite.cjs` `verifyInvite` / `verifyReply` | Verify a short-lived signed invitation and reciprocal proof of key possession. Results deliberately retain `enrolled:false`. | ACT's independently confirmed public key/fingerprint and a fresh signed reply; the existing owner's fresh invitation. |
| `owner-authorization.cjs` `verifySecurityReport` / `issueGrant` / `verifyGrant` | Require a pinned independent reviewer and a separately signed owner grant, exact peer/scope/report binding and expiry. Current peer revocation invalidates the grant. | Independently validated hardware challenge, chain and revocation evidence, reviewer key/report, and actual owner approval. |
| `federation-broker.cjs` `validateV2Policy` / `policyFromFile` | Recheck current enabled peer state, the owner/reviewer grant and exact capability agreement on the existing broker boundary. | Independently pinned ACT peer and Motorola worker, an owner-approved restricted HTTPS route and current valid grants. |
| `act-backend-compat.cjs` `verifyDeterministicReceipt` | Verify public signed request/reply, nonce/digests and recomputed deterministic result offline. It returns `executionAuthorized:false`. | A real signed request/result from the independent ACT worker and separately trusted public pins. |
| `federation-node.cjs` `revokePeer` / `verifyRequest` | Existing local revocation and durable request replay refusal. | Actual owner operation against the relevant local peer state; an archived proof does not exercise live replay state. |

No new private-state wrapper or readiness checker is required. Existing `loadNode`-based owner/broker APIs intentionally access the owner's local signing state; use them only inside that owner's controlled environment. Do not copy that state into this source package or into a peer's machine. The pure offline deterministic verifier uses public keys and supplied envelopes and does not open a network connection.

## Cross-owner sequence still required

1. **ACT public identity and version.** ACT supplies its own public Ed25519 key, an out-of-band verified fingerprint, and the actual running release/build digest and implemented protocol/capabilities. The last saved website/MCP/source version observations are dated November 9 and remain unverified as current. No fresh ACT service call was made in this handoff.
2. **Fresh proof of key possession.** Each operator uses the existing `mesh-invite.cjs` commands in their own controlled environment. A fresh invitation/reply must be verified with independent expected pins. Repository access and `enrolled:false` invite results do not create peer trust. No old invitation or owner grant is pre-generated here, since those expire.
3. **Independent hardware and owner admission.** Actual manufacturer-backed hardware evidence must be challenged and validated, including chain and revocation, by the independent reviewer. The existing signed review lasts at most 300 seconds. A separately approved owner grant lasts at most 120 seconds, cannot exceed the review and permits only `compute.dot.v1` and/or `compute.sha256.v1`. Payment, shell and firmware flags remain false. The issuer's existing exact approval requirement remains in force; no grant is issued here.
4. **Restricted live transport and one accepted job.** Both operators approve their route and current TLS/peer identities. The existing v2 broker policy and real live request/replay boundary must then pass, followed by a fresh signed deterministic result. The offline verifier's receipt is not live external job acceptance. For an optional broker relay, its upstream ACT, MIKAYA gateway and Motorola worker bindings must remain distinct protocol identities even when the two phones share one human owner.
5. **Revocation and paid work remain separate.** A current revoked peer must fail the existing request/grant checks; revocation must be tested at the eventual live boundary. Paid service needs an independent seller-local settlement implementation and agreed payment protocol before activation. The existing local caveated credential demonstration and an old chain payment do not settle a new invoice. No spending, wallet connection or settlement is performed here.

`ACT_HANDOFF_REQUIREMENTS_20261115.json` records these concrete missing inputs in machine-readable form. All admission remains **HOLD** until the relevant operators provide and accept them. This is a prepared source handoff, not a claim of completed external enrollment.

## Preserved transport and device limits

The current transport carries signed bounded JSON for `/v1/hello` and `/v1/task`; permitted compute is a small dot product or SHA-256 of a fixed 32-byte challenge. Off-host traffic requires validated HTTPS and separately approved routing. HTTP bodies are bounded to 8192 bytes; request signatures have a 60-second live window; current broker concurrency is one. The source does not provide general file transfer, compression/chunk negotiation, SD-to-SD networking, model transport or a measured high-speed transfer service.

The F110 telemetry publisher and private token remain separate from this peer contract. Cloud summary registration does not enroll ACT, verify a human owner, attest silicon, grant boot authority or authorize payments. This handoff changes no phone services, MTG policy, private key, SD contents, modem state, firmware or boot slot. No message is sent to ACT by preparing or publishing it.
