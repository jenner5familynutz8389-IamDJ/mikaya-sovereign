# MIKAYA source routes and ACT-Omega review boundaries

**Pinned source inventory:** GitLab `iamdj1989-group/IamDJ1989-project`, `main` commit `fc40b1cd1950a01d01835895e4f4c05457077b36`. Inventory: 623 files across Android, AHAVA, federation, native runtime, OEM engineering, docs, tests, and evidence. Not all 623 are approved for public distribution; the remainder require file-by-file review and deduplication.

| Workstream | Destination | Current verified disposition |
| --- | --- | --- |
| Signed federation, reciprocal invite, backend compatibility, Toybox chain observation, public ledger and evidence dashboard | This public `mikaya-sovereign` GitHub review branch and [draft PR #2](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/pull/2) | Published source; 82/82 backend+federation tests plus 9/9 public evidence tests pass on F110. This is not ACT hardware admission. |
| AHAVA distribution, cross-project admission, Bitcoin proof and tests | Independent private AHAVA engineering review repo | Pinned GitLab import, private draft review PR. 62/62 Node and 2/2 Python source tests pass; wallet operations remain disabled. |
| Android 15, SELinux, boot diagnostics, SCS, OEM radio release checks | Independent private Android engineering review repo | Pinned source-only import, fail-closed release. No OEM modem firmware or verified flash. |
| OEM firmware compatibility and flashing procedures | OEM engineering/private-first review, later curated firmware-testing repo | HOLD pending manufacturer-approved images, board/revision mapping, signatures and physical device acceptance. |
| Documentation and evidence archives | Review the existing documentation/report repositories individually | Do not dump private case, device, health, family or wallet data to public repositories. |
| Remaining GitLab inventory and duplicate candidates | GitLab remains the authoritative original; migrate only after source-classification and dedup | Not yet comprehensively migrated; do not claim complete 623-file coverage. |

## What ACT can do today

ACT can clone this review branch, test the signed federation source, independently check the public Toybox block, and submit a GitHub PR proposing a backend adapter. GitHub source-read access does **not** automatically grant access to private GitHub repositories, the live phones, Bluetooth mesh, tailnet, cloud resources, wallets or keys.

Production integration requires: out-of-band owner fingerprint exchange; ACT-owned separate signing keys; independently verified hardware proof; signed invite/reply; owner-approved, short-lived capability grant; restricted mutually authenticated network route; measured signed results; and separate payment verification if funds are ever involved.

Published Cloudflare/MCP discovery or a constant `TOOL_CALLED_OK` result is **not** accepted as backend execution. The private ACT side and public MIKAYA review are separate administrative domains. Nothing in this document authorizes automatic merge, remote shell, firmware modification, payments, or copying proprietary source to another owner.
