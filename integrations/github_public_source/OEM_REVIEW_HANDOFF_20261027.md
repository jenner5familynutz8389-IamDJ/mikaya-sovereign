# F110 OEM reviewer handoff — actual source and credential boundaries (2026-10-27)

**Purpose:** Make the owner-controlled MIKAYA-SOVEREIGN / AHAVA work inspectable by a manufacturer reviewer **using the reviewer's own GitHub or GitLab account**. This is evidence and source review, not manufacturer acceptance of a bootloader, firmware image, carrier fix or IP license.

## Exact source and branches

**Public curated GitHub**: https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign

- GitHub `main` reference checked: `fe18492950f5a539909ae9ec1b94c146cdde2fcb`.
- Repository contains just two branches at this review: `main`, `jenner5familynutz8389-IamDJ-patch-1` (behind `main` by 1 commit, not an independent firmware development branch).
- AHAVA signed/encrypted chunk transport: [`ahava/core.js`](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/blob/main/ahava/core.js), [`ahava/peer-server.js`](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/blob/main/ahava/peer-server.js), [`ahava/sync.js`](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/blob/main/ahava/sync.js).
- Signed correction history: [`integrity/correction-ledger.js`](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/blob/main/integrity/correction-ledger.js), [`integrity/signed-checkpoint.js`](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/blob/main/integrity/signed-checkpoint.js).
- Cortex source: [`cortex/qri_orchestrator.py`](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/blob/main/cortex/qri_orchestrator.py), [`cortex/self_debug.py`](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/blob/main/cortex/self_debug.py).
- [Public implementation backlog](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/blob/main/docs/IMPLEMENTATION_BACKLOG_2026-10-18.md), [security limitations](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/blob/main/docs/SECURITY.md), and [signed source manifest](https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/blob/main/RELEASE-SOURCE-MANIFEST.json).
- Commit history: https://github.com/jenner5familynutz8389-IamDJ/mikaya-sovereign/commits/main/ . These links can be read without credentials because this repo is public; a reviewer should authenticate to comment or fork using **their own** GitHub account.

**Private F110 engineering record (separate):** GitLab project `iamdj1989-group/IamDJ1989-project`. Source includes OEM carrier/IMS acceptance, exact Android 15 + vendor analysis, GKI source comparisons, signed build/rollback release gates, tests and multiple MRs. The GitLab P0 release work is not automatically available to GitHub visitors.

- Parent completion: private GitLab #19.
- GKI r2→r18 94-commit source review: draft MR !41.
- AOSP flags source-contract review: MR !38.
- This branch: `fix/public-source-manifest-verifier-20261027` proposes a fix to the public signed-file verifier and a TDD regression harness.

## Verified bug, corrective code and tests

Existing public `verify-release.js` checks Ed25519 signature authenticity and SHA-256 of the manifest **but does not check the source-file hashes listed within** `manifest.hashes`. This allows a modified listed file to pass while the manifest's signature remains intact.

- On an isolated synthetic Ed25519 fixture, **original verifier: 2/7 passed, 5/7 failed**, demonstrating unsigned file changes weren't rejected. Tests intentionally do not copy private owner signing keys.
- Corrected verifier: **8/8 passed** using Node.js `node --test` locally; covers valid signed fixture, tampered/missing signed file, symlinked file and parent directory, invalid signature, traversal and invalid digest.
- Files on this review branch: `integrations/github_public_source/verify-release.js`, `integrations/github_public_source/test-release-verification.cjs`.
- Test from checked-out branch: `node --test integrations/github_public_source/test-release-verification.cjs`. Once ported into the public repository, replace its root `verify-release.js` only after owner reviews the diff, then `node --test ...` and `node verify-release.js .` to confirm the **current public source bytes** still match the signed manifest.
- These are **local synthetic test results**, not GitLab hosted CI, on-device GKI/firmware or manufacturer acceptance. If the public manifest lists files later changed, re-signing must happen strictly with the owner's legitimate private key; do not share/export that key to manufacturer reviewers or agents.

## How manufacturer engineers review with their own credentials

1. **Public GitHub:** engineer signs in to their own GitHub account and opens the direct source/commit links above, using a fork and PR or issue for proposed changes. The owner's GitHub login or personal access token is never shared. No OEM reviewer account identity is confirmed at present.
2. **Private GitLab:** owner or project administrator verifies the engineer's *specific GitLab username* and, after explicit approval, invites that account at minimum **Reporter** permission for read-only code/MR inspection. If the reviewer must create their own branches/PRs, request a separately approved narrowly scoped Developer role or use forks. Do not make entire project public simply to share it.
3. Reviewer receives the exact MR, commit and evidence path links **after** authorized access. They sign in to their own account; all review comments and approvals are attributable to their identity. The manufacturer has **not** accepted any request or been sent credentials by this work.
4. Preserve owner IP, private signing keys, carrier IDs, unredacted forensic logs, mesh token/peer addresses, proprietary OEM firmware, and recovery secrets. Read-only access alone is not an IP assignment, license, OEM approval or firmware-signing authority.
5. If public GitHub write permission for the ChatGPT-connected integration is unavailable, use this **already tested private branch** as the provenance source; do not claim a GitHub PR was opened. On 2026-10-27 the GitHub connector returned `403 Resource not accessible by integration` on branch creation. GitHub's required permissions must be explicitly reviewed before trying again.

## Actual device release gates

- F110 Pro: MT6835 Android 15, running slot `_b`, AVB green locked, Google GKI `android13-5.15-2026-03_r2` lineage string; true running boot-image binary parity and signed rollback remain unverified.
- FOSSiBOT Factory S engineer email of 2026-09-23 supplies a firmware package link **without granting authority to flash a mismatched signed image or proving a fix**. Manufacturer and carrier still need to confirm signed-update mapping, IMS registration, working MO/MT SMS, inbound/outbound voice and OEM CTS/VTS/VINTF/rollback validation.
- Existing GitLab hosted CI failures from `ci_quota_exceeded` do not constitute run test failures or passes.
- Security: preserve locked boot, SELinux, OEM thermal limits, no NVRAM/IMEI alterations; do not touch production phone until safe OEM-approved update and recovery validated.
- New source lead [SWE-AF](https://github.com/Agent-Field/SWE-AF) is a potential workflow coordinator, **not** installed or granted MIKAYA access; test with sanitized fixture and no credentials before considering integration.

**Review disposition:** private source-verification fix proposed; public GitHub update awaiting permission and review; exact OEM carrier repair, firmware, and signing still HOLD.
