# MIKAYA–SOVEREIGN Evidence Brief (public derivative)

This adapts the user's original React expandable Technical Evidence Brief without publishing the IMEI, family identities, Bitcoin wallet address or other private registries from the source. The four original sections and claim terminology are retained. **Status is evidence-classified rather than inherited from an old `VERIFIED` label.** Existing source is not deleted or overwritten.

Files: `SovereignEvidenceBrief.tsx` (React 18/19 view), `sovereign-evidence-brief.css`, `evidence-brief.json` (date-scoped, owner-curated public snapshot), `evidence-policy.cjs` (minimum-disclosure and schema validator), `tests/test_evidence_brief.cjs`.

To run the validation, use Node.js 22+:

```bash
node --test tests/test_evidence_brief.cjs
node evidence-policy.cjs evidence-brief.json
```

To render, copy this folder into a React+TypeScript application (Vite/Next.js), import `SovereignEvidenceBrief` and render the component; it does not create a standalone deployed app and has no React dependency installed in the API-only source repo. Never feed unfiltered device-state or wallet JSON into the public view. Source claims like novel patentability, sovereign legal immunity or guaranteed adoption must be reviewed independently; the dashboard is not a lawyer's opinion or an attestation authority.

**Status evidence basis:** Two device federation/Toybox exchanges and 62/62 tests per phone occurred on Nov 8, 2026; a separate 10-test ledger suite passed on both phones; historical runit, BigSet and 10-layer claims were supplied as older logs/source and have not been promoted to modern live verified state; ACT hardware attestation, GitHub public branch push, Lightning settlement and production ACT admission remain blocked. This document makes no current-status claim beyond the dated evidence. See GitLab draft MR !97 and the repo's live federation source for provenance.
