# MIKAYA Toybox: Bitcoin mainnet public observation bridge

**Actual tests Nov 8, 2026:** Both FOSSiBOT F110 Pro (Android 15, Node v26.12.1) and Motorola Moto G Power 5G 2023 (Android 14, Node v26.12.1) passed 62/62 federation+Toybox tests locally. Both independently queried mempool.space and blockstream.info for the same historical mainnet anchor, separately signed reports with their own device-owned Ed25519 identities, exchanged public-only copies, verified the other owner's signature and re-checked the chain. Joint agreement digest: `f8ed372a819c52fcbee1281f7ca80f9f90b5b57f87e0df439fa21e3530bff09c`.

Pinned historical chain anchor: transaction `8cd0125081b40e01df124fd66adc68638b552c0693bccceb15d4485bdb47c9c8`; block height `961297`; block hash `00000000000000000001dc4084eff84a44b5be05eca6f2c0fc231588afc085ae`; output index `1`, `18369` sats, fee `617` sats. Current tip and confirmations are rechecked against **two independently matching HTTPS explorers**; height-to-hash and best-chain status are required. Reorg, mismatched tips, missed confirmations, injected receipt fields or provider failures HOLD. This is a confirmed **historical** transaction, not a present unconfirmed mempool entry; it is not a Lightning invoice nor proof of ACT wallet ownership or authorized payment.

Use:
```bash
node --test engineering/federation/live/tests/test_toybox_bridge.cjs
node engineering/federation/live/toybox-mempool-bridge.cjs inspect
node engineering/federation/live/toybox-mempool-bridge.cjs once "$LOCAL_DEVICE_NODE_DIR" ./my-public-proof.json
node engineering/federation/live/toybox-mempool-bridge.cjs independent-verify peer-public-proof.json peer-pinned-public.pem expected-64-hex-fingerprint
```

ACT-Omega may pull this source and run the **same read-only mainnet check using its own sovereign identity**, then exchange signed public chain reports with MIKAYA. ACT maintains separate wallet, node, funds and credentials. This public source and unit tests omit the historical receiving address; they contain no wallet keys, session secrets, macaroons, phone IPs or ADB/firmware operations. The original private owner-side AHAVA output/address evidence remains separate in GitLab's `engineering/ahava-v2/bitcoin-proof.cjs`. Signed reports do NOT grant node enrollment, production compute, Lightning settlement or wallet authorization.

All ACT admission remains under `README_ACT_HANDOFF.md` and `owner-authorization.cjs`: signed join, out-of-band fingerprint pin, independent hardware attestation review, separate owner-approved short-lived scope grant, encrypted overlay route, local policy. ACT hardware proof/approval and cross-tailnet routing are **not** yet completed. GitHub publication requires repository-write authorization.
