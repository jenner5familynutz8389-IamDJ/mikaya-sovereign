# MIKAYA source routes and ACT-Omega review boundaries

**Pinned source inventory:** GitLab `iamdj1989-group/IamDJ1989-project`, `main` commit `fc40b1cd1950a01d01835895e4f4c05457077b36`. Inventory: 623 files across Android, AHAVA, federation, native runtime, OEM engineering, docs, tests, and evidence. Not all 623 are approved for public distribution; the remainder require file-by-file review and deduplication.

| Workstream | Destination | Current verified disposition |
| --- | --- | --- |
| Signed federation, reciprocal invite, backend compatibility, Toybox chain observation, public ledger and evidence dashboard | This public `mikaya-sovereign` GitHub review branch and [draft PR #2](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/pull/2) | Published source; 82/82 backend+federation tests plus 9/9 public evidence tests pass on F110. This is not ACT hardware admission. |
| AHAVA distribution, cross-project admission, Bitcoin proof and tests | Independent private AHAVA engineering review repo | Pinned GitLab import, private draft review PR. 62/62 Node and 2/2 Python source tests pass; wallet operations remain disabled. |
| Android 15, SELinux, boot diagnostics, SCS, OEM radio release checks | Independent private Android engineering review repo | Pinned source-only import, fail-closed release. No OEM modem firmware or verified flash. |
| OEM firmware compatibility and flashing procedures | OEM engineering/private-first review, later curated firmware-testing repo | HOLD pending manufacturer-approved images, board/revision mapping, signatures and physical device acceptance. |
| Documentation and evidence archives | Review the existing documentation/report repositories individually | Do not dump private case, device, health, family or wallet data to public repositories. |
| Remaining GitLab inventory and duplicate candidates | GitLab remains the authoritative original; migrate only after source-classification and dedup | All 623 original GitLab paths now have a recorded migration or owner-private canonical-retention disposition; do not claim public publication for the retained 233. |

## What ACT can do today

ACT can clone this review branch, test the signed federation source, independently check the public Toybox block, and submit a GitHub PR proposing a backend adapter. GitHub source-read access does **not** automatically grant access to private GitHub repositories, the live phones, Bluetooth mesh, tailnet, cloud resources, wallets or keys.

Production integration requires: out-of-band owner fingerprint exchange; ACT-owned separate signing keys; independently verified hardware proof; signed invite/reply; owner-approved, short-lived capability grant; restricted mutually authenticated network route; measured signed results; and separate payment verification if funds are ever involved.

Published Cloudflare/MCP discovery or a constant `TOOL_CALLED_OK` result is **not** accepted as backend execution. The private ACT side and public MIKAYA review are separate administrative domains. Nothing in this document authorizes automatic merge, remote shell, firmware modification, payments, or copying proprietary source to another owner.


## Verified source reconciliation snapshot (November 9, 2026)

The pinned GitLab main inventory at `fc40b1cd1950a01d01835895e4f4c05457077b36` contains **623 distinct original file paths**. Verified owner-review GitHub branches now carry **233** original Android/OEM/thermal sources, **146** original private AHAVA/research sources, and **11** original public federation/handoff sources, for **390 distinct migrated originals**. The other **233 originals** are deliberately retained at their canonical private GitLab source: **135** historical documents, **89** evidence artifacts, **5** inactive CI definitions and **4** GitLab root metadata files. Every path is assigned, but confidential retained contents are **not** individually cleared for public disclosure. The exact per-file Git object identity and disposition register is retained in the owner's private AHAVA review. ACT receives only curated public source and test contracts.

The complete file-by-file original-path/Git-blob reconciliation map is held **only in the private AHAVA development review**; ACT does not need access to it to inspect this repository's public, verified code. Exact duplicate GitLab blobs are identified without deleting any source. These figures describe source review coverage, not production deployment, commercial adoption, OEM firmware acceptance or payment.

Current ACT backend verification is independent: `node --test engineering/federation/live/tests/test_act_backend_compat.cjs` (10 tests). Historical source gate: `node --test engineering/federation/gitlab-20261107/tests/m2m.test.cjs` (12 tests). Hardware-enrollment, owner-signed authorization, real ACT endpoint execution and wallet settlement remain **held** until ACT and MIKAYA independently establish their identities and approve a limited connection.
