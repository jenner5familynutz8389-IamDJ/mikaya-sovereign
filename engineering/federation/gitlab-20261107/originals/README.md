# MIKAYA × ACT-Omega: M2M federation review implementation (2026-11-07)

**Scope:** This is a private-review, source-tested node handshake / first-party HMAC-chained capability gate **plus a deployed public MCP readiness observer**. It is NOT the real Lightning settlement verifier, NOT production L402 interoperability, NOT a connected ACT-Omega node, NOT a change to stock firmware, and NOT a command runner. It deliberately refuses remote execution and all wallet actions.

## Authority boundaries (existing MIKAYA design; preserved)

* **MIKAYA:** FOSSiBOT F110 Pro / Motorola two-brain architecture, Android 15 / MT6835 OEM governance, private AHAVA keys, Ed25519 peer allowlists, telemetry (schema `mikaya.f110.jitter-evidence-chain.v1`), MTG, event spine, and all current apps and websites.
* **ACT-Omega:** independent hardware/software compute network, models, wallets, code, identity, and owner governance.
* **Shared:** only out-of-band pinned public identities, one-time signed node hello, owner-approved telemetry digest, bounded task offer, seller-issued Lightning invoice, seller-confirmed settlement, scoped service credential, signed result digest receipt, and separately retained ledgers.
* **Prohibited:** exchanging firmware-signing keys, LND admin macaroons, wallet seeds, private SD-card data, ADB/root/Shizuku or arbitrary remote shell; auto-pay; auto-flash; claims that an old Bitcoin mainnet transfer settles a new Lightning invoice.

## Existing MIKAYA interfaces that remain authoritative

- `engineering/ahava-v2/policy.cjs`: Ed25519 owner distribution policies, approved peer fingerprint and thermal checks.
- `engineering/ahava-v2/transport.cjs`: authenticated request envelopes, nonce replay defenses and signed staging receipts.
- `engineering/ahava-v2/accounting.cjs`: pure, **non-paying** quotes; no AHAVA distribution/payout enabled by this build.
- `integrations/sovereign_agent/sovereign_agent_gate.py`: permission and receipt gate awaiting real trusted cryptographic settlement verifier.
- `tools/mikaya_jitter_chain.py`: original sensor/jitter/CLOCK/HAL/SELinux telemetry and manual L402 invoice challenge audit.
- `engineering/ahava-v2/bitcoin-proof.cjs`: historical chain-verified BTC transfer of 18,369 sats; NOT a new Lightning settlement.
- F110 device: `~/sovereign_exec/integrity/correction-ledger.js` and `signed-checkpoint.js` are the authoritative existing append-and-verify procedures.

## Contents

- `m2m-gate.cjs`: offline first-party caveated HMAC credential and Ed25519 hello contract, signed receipt, one-use durable replay refusal. **Not interoperable standard L402 macaroons.** `authorizeCredential` NEVER starts an arbitrary task.
- `tests/m2m.test.cjs`: 12 contract checks, including refusal and replay.
- `peer_watch.py`: restricts network requests to ACT-Omega's public MCP `GET /mcp` and JSON-RPC `tools/list` plus `http://127.0.0.1:4179/api/status`. Fails closed on Android thermal status other than 0/1 and on missing response. **Never uses `tools/call`.** No wallet files read.
- `tests/test_peer_watch.py`: 12 tests covering fail-closed identity, disallowed capabilities, thermal hold, duplicate suppression, corrupt journal refusal, and wallet-secret exclusion.
- `service/run`, `service/log/run`: Termux `runit` service skeleton with 900-second heartbeat and bounded rotating logs. Install only on owner-authorized F110.
- `docs/EVIDENCE_MATRIX.md`: actual provenance, closure gates and remaining tasks.

## Test locally

```sh
node --test engineering/federation/tests/m2m.test.cjs
python3 -m unittest discover -s engineering/federation/tests -p 'test_peer_watch.py' -v
```

No network or wallet is required for those tests. To perform one **actual public discovery** on the F110 without writing to ledger, use `python3 peer_watch.py status` first to see cached observations; `once` probes the public MCP and updates existing AHAVA integrity-corrections ledger only if the resulting readiness state differs from the cached state.

## Device deployment / ledgers

The owner-requested reconciliation was recorded directly on 2026-11-07 with existing audited writers:
- `integrity-corrections.jsonl`: prior sequence 17 → **18**, new observation subject `act-omega-m2m-peer-readiness-20261107` (no private credentials), verified valid hash chain.
- `signed-checkpoints.jsonl`: prior sequence 8 → **9**, created by device's existing AHAVA Ed25519 signing procedure and reverified; this is an authenticated *local checkpoint*, not proof of peer settlement or OEM acceptance.

The observer has its *own* mode-0600 status cache in `~/sovereign_exec/ledger/act-omega-readiness-state.json`; **all readiness changes** are appended using the existing correction-ledger CLI, with `policy.target=act-omega-federation-paid-execution` and `action=deny`. The service never modifies historical ledger rows, mesh observations, or private `.lnd` files. It only observes public MCP name/version/tool list and localhost simulated hub state. No real peer identity can be verified solely from an MCP GET response.

### F110 `runit` integration

The service source is already part of this branch. It is installed under `~/sovereign_exec/boot/act-omega-peer-readiness` and registered with the existing Termux service supervisor only after tests pass. Check without affecting other services:

```sh
sv status "$HOME/sovereign_exec/boot/act-omega-peer-readiness"
python3 "$HOME/sovereign_exec/integrations/federation/peer_watch.py" status
node "$HOME/sovereign_exec/integrity/correction-ledger.js" verify
node "$HOME/sovereign_exec/integrity/signed-checkpoint.js" verify
```

The first `once` run may append a new observational record distinct from the manually signed baseline. Subsequent identical observations do not create duplicates. `sv down` on only this service stops the watcher and does not alter the original AHAVA or F110 services.

## Remaining cross-owner handoff (blocked until his operator acts)

1. ACT-Omega confirms version provenance (v69 release versus v68 public MCP), supplies a **public signing identity** with out-of-band fingerprint, and signs a short-lived hello from an actual hardware node.
2. ACT-Omega configures a **seller-local Lightning receiving node/wallet** and authorized, restricted invoice issue/settlement-check service. MIKAYA connects its own separate node or wallet; neither supplies an admin macaroon to the peer.
3. Integrate a vetted **standard L402 macaroon verifier**, explicit BOLT11 invoice/payment hash matching, preimage proof, seller-side settlement verification, expiry, caveats, spend caps, and replay tracking. No faked settlement booleans.
4. Bind both parties' independently signed authorization policies to *one* bounded telemetry-digest job. Simulated demo is not evidence of payment.
5. ACT-Omega opens a reciprocal review PR in its own repository. MIKAYA's original source is reviewed privately in GitLab MR !94; public GitHub write access must be separately granted. Do not auto-merge across ownership boundaries.
6. Keep OEM firmware/IMS/RIL patching in its own validated engineering track; never make M2M a firmware authority.

**Status:** READY_TO_OBSERVE_PUBLIC_PEER, NOT_CONNECTED, NO_WALLET_SETTLEMENT, NO_REMOTE_EXECUTION, NO_OEM_FLASH.
