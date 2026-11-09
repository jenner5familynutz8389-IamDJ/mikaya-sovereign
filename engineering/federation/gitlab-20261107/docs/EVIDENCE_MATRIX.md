# Evidence-backed integration boundary inventory (2026-11-07)

| Topic | Owner reference | Current finding | Required next action |
|:--|:--|:--|:--|
| Two-brain architecture | MIKAYA Drive architecture v2026.06; F110/Motorola private GitLab | Separate Motorola bridge and F110; only F110 remote channel currently reachable | Preserve separate physical identities; do not assume Motorola is connected |
| F110 verified boot | `getprop` on F110 2026-11-07 | `mt6835`, active slot `_b`, verified boot `green` | OEM modem/IMS issue separate from federation |
| Public ACT-Omega MCP | `https://mcp.act-omega-net.dev/mcp` | initialize version `68.0.0`, 21 advertised tools on 2026-11-07; no listed invoice/macaroon tools | ACT-Omega must supply a pin-able public Ed25519 key and actual signed node hello; reconcile v69 release |
| MIKAYA local demo | F110 `http://127.0.0.1:4179/api/status` | `LOCAL_SIMULATED_ONLY`, wallet disabled, nodes unconnected | Keep separate from live payment gate |
| MIKAYA LND | F110 loopback ports 8080, 10009, 8443 | Not listening at audit time; local `.lnd` directory exists but wallet state unknown | Owner-controlled, TLS-verified, restricted REST/gRPC configuration; never export admin credential |
| BTC historical settlement | `docs/evidence/MIKAYA_ETZORA_AHAVA_BITCOIN_MAINNET_20260806.md` & explorer crosscheck | 18,369 sats confirmed as historical Bitcoin mainnet transfer | Do not interpret as per-task BOLT11/L402 settlement |
| L402 original design | June 30 Outlook/Gmail source & July 24 bootstrap | invoice-generation design, macaroon helper, loopback contract; older source uses TLS `verify=False` and an admin macaroon | Require TLS verification and narrowly scoped invoice-only credentials |
| Original telemetry | `tools/mikaya_jitter_chain.py` | `mikaya.f110.jitter-evidence-chain.v1` | Preserve exact schema and send digest of sanitized payload only |
| Original owner policy | `engineering/ahava-v2/policy.cjs` | signed Ed25519 policy with fingerprint, object ID and thermal check | Policy is mandatory before task execution |
| Original transport | `engineering/ahava-v2/transport.cjs` | Ed25519 request signing, nonce replay guard, receipt verification | Extend for pinned third-party node, not auto-authorize new peer |
| Original accounting | `engineering/ahava-v2/accounting.cjs` | non-paying quotes | No automatic payout until independently approved |
| F110 canonical correction ledger | `~/sovereign_exec/integrity/correction-ledger.js` | hash-chain verified, sequence 18 after owner-authorized observation | Watcher can append subsequent public readiness **changes** only |
| F110 signed checkpoint ledger | `~/sovereign_exec/integrity/signed-checkpoint.js` | Ed25519-signed sequence 9 after owner-authorized checkpoint | Do not append fake signature or replace prior history |
| SD-card source copies | `/storage/6F1C-F4A3` | 4 apparently `.py` files contain binary data and do not parse as Python | inspect format separately before treating as executable code |
| GitLab collaboration | `iamdj1989-group/IamDJ1989-project` | Draft MR !94; branch `review/act-omega-m2m-l402-20261107` | Review in private; do not merge until security checks and peer evidence |
| Public GitHub collaboration | `jenner5familynutz8389-IamDJ/mikaya-sovereign` | GitHub app returns 403 for branch creation and issue write | Enable proper owner-authorized repo write access; no claim of publication |

No signed peer identity, Lightning settlement, production macaroon credential or remote task was proven by this inventory. Source and test artifacts cannot be treated as hardware/OEM acceptance or as proof of peer control.
