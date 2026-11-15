# X follow-up: sources 1 and 2

Reviewed 2026-11-15 UTC. These are source-grounded security findings and a conditional repair plan. Research captured public pages and inspected the listed local manifests; it did not install packages, run exploit repositories, scan deployed applications, connect to a database, or change services, phones, firmware, boot settings, or backups.

## 1. The Hacker News: PostgreSQL, CVE-2026-6460

**Verdict:** The central alert is confirmed by PostgreSQL's own November 12 release. The release fixes 52 security vulnerabilities, including an authenticated object-creator code-execution vulnerability. The warning that a server binary update alone can be insufficient is also vendor-confirmed: full protection requires rebuilt C-language extensions. Applicability to the user's actual database infrastructure remains unestablished by the inspected project evidence.

Social source: https://x.com/TheHackersNews/status/2121287163065319838, posted 2026-11-13 17:00:45 UTC; original supplied redirect https://share.google/SCeBtMjkcubhdFqL0. The resolved post and replies are preserved in `../POST_1.json`; replies are commentary rather than vendor advisories. Its linked article is https://thehackernews.com/2026/11/postgresql-patches-52-flaws-including.html, dated November 13.

### Confirmed behavior and conditions

The [PostgreSQL advisory](https://www.postgresql.org/support/security/CVE-2026-6460/) describes type confusion after changes such as `ALTER ... SET DATA TYPE`. Older composite values can remain in the system while the corresponding type layout changes, allowing a value to be interpreted using an incompatible layout. An object creator can execute arbitrary code as the operating-system account running PostgreSQL. The vendor assigns CVSS 8.8, network access, low complexity, low privileges required, and no user interaction. This is a database-authenticated escalation; the advisory does not say it gives an unauthenticated Internet visitor a PostgreSQL root shell.

| PostgreSQL major | Vendor fixed minor, published 2026-11-12 |
| --- | --- |
| 18 | 18.7 |
| 17 | 17.12 |
| 16 | 16.16 |
| 15 | 15.20 |
| 14 | 14.25, the final release of major 14 |

The [release announcement](https://www.postgresql.org/about/news/postgresql-187-1712-1616-1520-1425-and-19-rc-2-released-3442/) confirms 52 security fixes and over 140 bug fixes. The 52 should not be described as 52 unauthenticated server takeovers: the release covers different privileges, versions, components, code-execution flaws, information leaks, row-security bypasses, and client-tool issues. Direct counting of the announcement's security section yields 52 distinct CVE identifiers and 32 entries scored 8.8. PostgreSQL 19 RC 2 is also mentioned, but is a release candidate, not a reason to move a production system onto an unreleased major version.

The [18.7 release notes](https://www.postgresql.org/docs/18/release-18-7.html) explain the new composite-datum version checks and explicitly require rebuilding C-language extensions for full protection; some extensions also require source changes. The `composite_type_mismatch` parameter can disable the checks but carries security risks. Treat disabling it as weakening the fix, not as a security workaround.

The [PostgreSQL RPM maintainers' notice](https://yum.postgresql.org/news/extensions-require-minor-release/) explains the deployment trap: old extensions may still load with the patched server, so a successful startup does not prove that the extension paths have the new protections. Conversely, newly rebuilt extensions can fail on older servers because of new server functions. The RPM repository rebuilt extensions and added minimum minor-version dependencies. That repository behavior is specific to its packaging; a custom image, another Linux repository, or a managed service needs its own package/build evidence.

The "22-year-old" detail comes from the [researcher's primary write-up](https://mehmetince.net/part-3-6-how-i-ended-up-turning-a-22-year-old-postgresql-type-confusion-primitive-into-rce-cve-2026-6460/), dated November 9. He traces the mutable-row-type primitive to May 5, 2004, and his particular code-execution technique to a May 14, 2015 expanded-object change. This is stronger historical provenance than an X headline, while the advisory and release notes remain the authority for supported fixes. He describes a lowest-privileged login producing a crash and says he shared managed-service reports in August. This does not establish the present patch status of AWS, Azure, AlloyDB, Supabase, or any particular customer instance. The X reply claiming every read-only login can execute code via default temporary-table rights goes beyond the vendor's documented "object creator" prerequisite and the cited lowest-privilege crash claim.

### Repair plan if the product is present

1. Establish each actual PostgreSQL server major/minor, vendor build or backport status, owner, exposure, login/object-creation policy, native extensions, and separate administration/backup client versions. A package name on a workstation is not the remote server's version. For a managed service, obtain the provider's patch and extension-build evidence for the specific instance.
2. Plan a coordinated server and native-extension update to the fixed minor for the installed major, or a provider-confirmed equivalent. Follow that vendor's restart/failover procedure and verify that running processes use the new binaries. Update affected clients on the machines or job images that run `pg_dump`, `pg_restore`, `reindexdb`, `vacuumdb`, and related tools; a server update does not update a separate backup image.
3. Read the release notes for the actual major and any skipped minors. The announcement calls out conditional index repair: affected GIN indexes, `pg_trgm` GiST indexes using `gist_trgm_ops`, relevant TOAST/missing-chunk cases, and B-tree indexes on unconstrained `bpchar` columns. It also calls out invalid partitioned-table `NOT NULL NO INHERIT` constraints. These are conditional administrator repair tasks, not a blanket command to reindex everything immediately.
4. If PostgreSQL incremental backups are in use, the vendor recommends a fresh full backup after updating and using it as the basis of subsequent incremental backups. The 18.7 notes warn that existing incremental backup files should not be trusted and describe a defect whose existing WAL summaries can still affect later incremental backups. No backup was taken or modified in this review. Apply the actual deployment's recovery procedure and verify restore usability.
5. PostgreSQL 14.25 closes this release's issues but major 14 reached end of life on November 12; plan migration to a supported major. A same-major minor update generally does not require dump/restore, but the additional steps above still apply. A major upgrade is a separate operation.

**Project relevance:** The inspected `integrations/cursor-agent-sdk/package.json` lists `@grok/agent-sdk` and `zod`, with TypeScript tooling; it does not establish a PostgreSQL server or its version. The inspected Worldmonitor compose overlay names application, relay, Redis, Redis REST, and seeder services. The Worldmonitor Dockerfile copies application/static frontend files and installs nginx/supervisor; the research-runtime Dockerfile starts a Python supervisor. None of these inspected files identifies a deployed PostgreSQL server or its native extensions. External and inherited deployment configuration remains outside this evidence. Status: **upstream vulnerability confirmed; local applicability unknown, pending a real service/component inventory**.

## 2. Dark Web Informer: Next.js middleware, CVE-2025-29927

**Verdict:** The vulnerability and stated fixed versions are real, but this November 15, 2026 post recirculates a vulnerability publicly disclosed on March 21, 2025. It is not evidence of a newly discovered November 2026 flaw or of compromise of the user's project. The actual risk requires a vulnerable Next.js runtime and authorization that depends on its middleware.

Social source: https://x.com/DarkWebInformer/status/2121756237691756730, posted 2026-11-15 00:04:42 UTC; original supplied redirect https://share.google/bDOBrbI71CXfN3Il2. The resolved post and replies are preserved in `../POST_2.json`. Its linked repository is https://github.com/alinaclark672377250/CVE-2025-29927-POC.

### Vendor-confirmed behavior and ranges

The [Next.js repository advisory, GHSA-f82v-jwr5-mffw](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw), published March 21, 2025, confirms that authorization can be bypassed when its check occurs in middleware. The internal `x-middleware-subrequest` header can make the runtime treat middleware as already processed. This is an authorization-bypass finding, scored CVSS 9.1 with no privileges or user interaction required. It is not by itself proof of operating-system code execution.

| Affected range in the advisory | First fixed version for this CVE |
| --- | --- |
| 11.1.4 through 12.x below 12.3.5 | 12.3.5; advisory directs 11.x users to the workaround |
| 13.x below 13.5.9 | 13.5.9 |
| 14.x below 14.2.25 | 14.2.25 |
| 15.x below 15.2.3 | 15.2.3 |

Those are historical minimum fixes for this one CVE, not recommended current versions for all security issues in November 2026. An implementation should move to the latest appropriate maintained release and check its complete advisory set.

[Vercel's March 25, 2025 postmortem](https://vercel.com/blog/postmortem-on-next-js-middleware-bypass) provides useful deployment precision. Self-hosted applications using `next start` or `output: 'standalone'` were affected. Static exports have no server middleware runtime. Vercel was incidentally protected by decoupled routing, and the postmortem also says Netlify and Cloudflare Workers were never affected by this specific issue for the same architectural reason. These statements do not mean every deployment bearing those provider names is immune to every Next.js vulnerability. The GHSA states that Next.js deployments hosted on Vercel are automatically protected against this vulnerability.

The same postmortem advises against using middleware as the sole protection for application routes. Server handlers and the data-access layer need to enforce the authorization that protects their data and operations. Returning a login redirect in one normal request is not sufficient evidence that the underlying protected action is secured.

### Quality of the linked proof-of-concept source

GitHub's [repository metadata](https://api.github.com/repos/alinaclark672377250/CVE-2025-29927-POC) says this repository was created on November 13, 2026, at 21:53:14 UTC. The [README API response](https://api.github.com/repos/alinaclark672377250/CVE-2025-29927-POC/readme) was decoded and read as text. It calls this already-public CVE "hypothetical" and "placeholder", leaves the relevant software/version "TBD", gives generic rather than CVE-specific references, and shows sample responses dated March 23, 2025. These are concrete reasons to prefer the vendor advisory to its explanation and to treat a newly uploaded PoC as republication rather than proof of a newly discovered flaw. The README's request/response examples are claims, not a reproduction run performed in this review. Metadata and README review do not establish the entire repository's behavior, authorship, originality, safety, or maliciousness. No repository code or request examples were executed.

### Repair plan if the product is present

1. Identify the application's actual lockfile-resolved Next.js version, built artifact, hosting path, and middleware authorization behavior. A React component or a README mentioning Next.js does not establish a running Next.js application.
2. Upgrade and redeploy to an appropriate maintained release containing the fix. Confirm all serving instances and container images are updated, rather than only changing the source manifest.
3. If immediate patching is infeasible, the vendor workaround is to prevent external requests containing `x-middleware-subrequest` from reaching the application, using the controlled ingress/proxy. Cover every external path, including any direct-origin route around that proxy; do not rely only on a browser-side header filter.
4. Enforce authorization again in protected server actions, route/API handlers, and data access as appropriate. Under authorized staging tests, verify that anonymous and unauthorized users cannot obtain protected data or perform protected actions, including when the internal header arrives. No live target tests were run here.

**Project relevance:** The only package manifest found in the inspected repository is the evidence-review agent manifest above; it does not declare `next` or `next-auth`. `engineering/federation/live/evidence-brief/README.md:14` expressly describes copying a React component into a Vite/Next.js application and says the source is not a standalone deployed app. That mention cannot establish an affected Next.js deployment. The inspected Worldmonitor image uses an nginx/static-frontend plus application layout, without a Next.js dependency/version established by these files. Status: **historical upstream vulnerability confirmed; applicability to this project unestablished**.

## Evidence and limits

`FETCH_MANIFEST.json` records each requested/resolved URL, retrieval timestamp in UTC, response status, capture filename, and SHA-256 of successful raw HTTP bodies. Captures were retrieved between 04:02:34 and 04:04:12 UTC on 2026-11-15. The PostgreSQL news index returned 404; the exact release-announcement URL linked by the article succeeded. Extracted `.txt` files are reading derivatives; raw `.html`/`.json` capture hashes are the provenance reference. The separate social-post raw captures and redirect manifest remain in the parent folder.

`PROJECT_EVIDENCE_MANIFEST.json` records the inspected local paths and content hashes. The source root has no Git metadata, so a repository HEAD was not established. These were static, scoped reads, not a complete installed-component inventory or deployed-version attestation. This review does not certify vulnerability absence, current exploitation, compromise, provider patch status, or installed remediation. The repository's Android-specific CVE skill was inspected for relevance and was not applied: neither of these database/web-runtime advisories is evidence of an F110 firmware or modem CVE.


Public bundle note: raw HTTP captures and source manifests described above are retained separately; the companion X-source evidence index records their digests. No external tool was installed or run.
