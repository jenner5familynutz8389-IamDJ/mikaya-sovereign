# ACT-Omega external source review and MIKAYA backend interface

Evidence observed November 9, 2026, directly from three public resources supplied by the owner. **This is a factual source review, not an independent audit of ACT hardware or model performance.**

## Public references and version reconciliation

| Reference | Observed, independently reproducible fact | Boundary of evidence |
|---|---|---|
| [GitHub source](https://github.com/bospaladin34-crypto/Sovereign-Manifold-V30-A.P.H.U.S-) | Public repository, default branch `vesper_production`, advertised MIT license. Observed HEAD `4f9f9e053207048483fa9140f8a47643f2050c8f`, commit date 2026-11-09 09:08:04Z, message advertising **v71.3.2**, including a claimed 950/950 Lean 4 theorem pass. | Commit messages and source trees document claims; they are **not independent reproduction** of theorem, throughput or device assertions. Verify exact commit before quoting a version as current. |
| [OSF project](https://osf.io/2xq5z/overview), [DOI](https://doi.org/10.17605/OSF.IO/2XQ5Z) | Public OSF project, created 2026-10-26, titled **A Topological Intermediate Representation, Lattice Vector Quantizer, and Cellular Sheaf Consensus Runtime for Edge-to-Workstation Heterogenous Computing {Aegis Cascade Topology}**. Its abstract describes BraidIR (Artin braid-group dependency modeling), lattice vector quantization, and a cellular sheaf consensus architecture. OSF lists Donevin Frownfelter as bibliographic contributor/admin. | An OSF **project** and DOI are traceable research records; neither establishes peer review, certified hardware execution, independent benchmarking, or validated formal proofs. |
| [ACT-Omega website](https://act-omega-net.dev/) | Public HTTPS endpoint responded HTTP 200 with successful TLS verification. Its HTML title advertised **ACT-Omega Net v70.0.0**, behind the GitHub release advertised as v71.3.2. Public [MCP endpoint](https://mcp.act-omega-net.dev/mcp) also returned HTTP 200 for a GET. | Reachability and marketing/version text are not authorization or proof of authenticated compute. `tools/call` was not executed against ACT's live service; prior source review found a Cloudflare worker returning canned `TOOL_CALLED_OK` responses for many calls. |

The public GitHub account's self-displayed operator name is **Donevin R. T. Z Frownfelter (OPERATOR-01)**, describing an ACT-Omega developer affiliated with **Vesper Tech UNLTD**. The OSF contributor name is consistent with this public claim. **The person's legal identity, ownership of deployed devices, institutional affiliation, and independent ability to sign runtime receipts have not been verified by MIKAYA.** These observations authorize no access and carry no endorsement.

### Integration fit

A restricted ACT backend can contribute **optional external compute**, **signed deterministic job results**, and possibly **separately scoped model routing**. MIKAYA retains the F110/Motorola device authority, private Ed25519 keys, thermal policy, immutable local evidence, wallet sovereignty, and final result verification. None of ACT's claimed throughput, 4K/8K memory scaling, 316/350 tooling or 950 Lean proofs should be imported as acceptance metrics until the code and measured receipts are independently reproduced on the claimed hardware.

1. **Discovery (public):** Confirm latest GitHub commit, OSF content version, running endpoint release, API implementation and TLS trust. The site currently says v70.0.0 while source advertises v71.3.2; treat running version as **unverified** until ACT supplies a signed attestation tied to a build digest.
2. **Identity:** Both independent operators exchange only public Ed25519 fingerprints through a second authenticated channel. Each independently signs fresh nonce-bound MIKAYA federation hello and limited invite/reply. Public social profiles, an OSF DOI and GitHub access are not machine attestation.
3. **Optional task:** Owner-approved capability, short-lived authorization, allowlisted mutual TLS endpoint, bounded `compute.dot.v1` or `compute.sha256.v1` payload, replay rejection and signed worker reply. `act-backend-compat.cjs` verifies public-key signatures, nonce, digests and recomputed deterministic result **offline**; it is not an ACT client and confers no network permissions.
4. **Operational proof:** ACT must document a real callable backend with a reproducible work trace and independent public-key signature. `TOOL_CALLED_OK`, an MCP tool catalog, an abstract, and a benchmark JSON file do **not** meet the required end-to-end proof.
5. **Payments/hardware:** Wallets, L402 macaroon validation, seller-verified Lightning settlement, OEM firmware, hardware credentials and any privileged remote device control remain outside the initial pilot. No remote shell, flashing, seed export or automatic payments.

### Review handoff and acceptance

ACT can inspect MIKAYA's [public draft PR #2](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/pull/2), clone and test source independently, and propose an adapter in a fork. ACT's private repositories and MIKAYA's private Android/AHAVA repositories remain mutually isolated. A real bilateral deploy requires owner-signed scope approval and reproducible physical device attestations **from both sides**.

Reproducibility: `node --test engineering/federation/live/tests/test_act_backend_compat.cjs`; `node --test engineering/federation/gitlab-20261107/tests/m2m.test.cjs`. No ACT service was mutated by this source review.
