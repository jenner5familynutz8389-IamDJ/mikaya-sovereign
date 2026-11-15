# REA source review — 15 November 2026

The [Nov13 post](https://x.com/akshay_pachaar/status/2121248029743497225) links through `https://t.co/boTstvieJC` to [morluto/rea](https://github.com/morluto/rea). GitHub's API reported **460,155 stars at 04:02:59 UTC on Nov15**. The claimed 450k total is consistent with this later snapshot; **450k gained in a month remains unverified**. GitHub records repository creation on April14, about seven months before the post, which does not itself establish or refute growth during the latest month.

The inspected [commit](https://github.com/morluto/rea/commit/2e1e6593f266b859d2f0fc858d51ed2f280b6849) is `2e1e6593f266b859d2f0fc858d51ed2f280b6849` (GitHub author/committer time Nov15 02:24:25Z). README and LICENSE were fetched at that commit and match the API document Git blobs. [REA's own code](https://github.com/morluto/rea/blob/2e1e6593f266b859d2f0fc858d51ed2f280b6849/LICENSE) is MIT; [README](https://github.com/morluto/rea/blob/2e1e6593f266b859d2f0fc858d51ed2f280b6849/README.md) expressly keeps third-party licenses and external commercial-engine terms separate. Thus “100% open-source” needs that qualification.

REA documents a local MCP/CLI interface for static artifact and application analysis plus separate runtime/device workflows. Native deep analysis depends on compatible decompilers. “Anything” is promotional breadth: target formats, host requirements and provider limits remain. No install or execution validated these documented capabilities.

The useful design detail is its structured Evidence: normalized facts, original provider reports, subject identity, sources, unknowns and parent links ([MCP contract, lines17–47](https://github.com/morluto/rea/blob/2e1e6593f266b859d2f0fc858d51ed2f280b6849/docs/reference/mcp-contracts.md#tool-results)). Partial inventories do not prove absence elsewhere (lines97–100). Bundle comparison is distinct from artifact-content comparison ([CLI Evidence contract](https://github.com/morluto/rea/blob/2e1e6593f266b859d2f0fc858d51ed2f280b6849/docs/getting-started/cli.md#import-export-and-compare-evidence)).

For MIKAYA, the existing signed artifact intake is a plausible future home for an external report adapter that binds target hash, exact REA/provider versions, report digest, source locations and unknowns. Reuse the current independent review/owner-grant chain and resource/thermal admission controls; those controls do not authorize arbitrary shell, device or firmware actions and are not a general analysis sandbox. Preserve original reports separately from the signed digest ledger. This review proposes that route only; it changes no source or runtime.

No evidence establishes copying or authorship priority. Generic interfaces, evidence records and bounded-resource mechanisms do not provide that proof. Full paraphrased findings, source URLs and limitations are in `REA_RESEARCH.json`; exact public captures and SHA256 digests are in `CAPTURES.json`.


Public bundle note: raw HTTP captures and source manifests described above are retained separately; the companion X-source evidence index records their digests. No external tool was installed or run.
