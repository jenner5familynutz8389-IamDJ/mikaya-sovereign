# ACT-Omega independent mesh onboarding — public protocol

> Current source handoff (November 15, 2026): use [ACT_HANDOFF_CURRENT_20261115.md](ACT_HANDOFF_CURRENT_20261115.md) and its pinned manifest. The review-branch/PR pointers below describe the older setup; they do not describe current repository merge state or live ACT enrollment.

This procedure allows a second owner to **request** a scoped federation grant. It does not automatically create a VPN link, wallet, administrative access, hardware attestation or permission to execute arbitrary code.

## 1. Use the current source handoff and test it

Use the reviewed [current handoff](ACT_HANDOFF_CURRENT_20261115.md), its immutable source references and `ACT_HANDOFF_SOURCE_MANIFEST_20261115.json`. It identifies the current GitLab base and the unchanged verifier/test recovered from published GitHub source. Review the selected source before running it. Node.js 22+ is required. From the checkout or selected source bundle root:

```sh
cd engineering/federation/live
node --test tests/test_mesh_invite.cjs tests/test_owner_authorization.cjs tests/test_act_backend_compat.cjs
```

The recorded local run passed 25 focused tests using synthetic fixture keys. The selected source handoff does not include the separate Toybox observer and does not require it for enrollment-contract checks. Historical Bitcoin observations are not ACT identity, permission or payment evidence.

## 2. Establish an ACT-owned signing identity

ACT uses its own signing identity on an ACT-controlled computer. Reuse an existing reviewed ACT identity; the following `init` command is only for first setup into a new directory. **Do not reuse MIKAYA or Motorola key files.** Run inside the approved source directory:

```bash
cd engineering/federation/live
umask 077
node federation-node.cjs init "$HOME/act-omega-mesh-node" ACT-OMEGA act-compute-01
node federation-node.cjs health "$HOME/act-omega-mesh-node"
```

The new directory contains ACT's private key and must never be committed, emailed or copied to MIKAYA. Backups and security policies are the ACT owner's responsibility.

## 3. Verify the owner's signed invitation, then respond

MIKAYA sends ACT a short-lived signed JSON invitation privately. ACT must independently confirm MIKAYA's 64-character Ed25519 public-key fingerprint through an authenticated out-of-band channel — **do not trust the inviter fingerprint merely because it is inside the invitation or repository**.

```bash
node mesh-invite.cjs verify-invite ./mikaya-invite.json VERIFIED_MIKAYA_FINGERPRINT
node mesh-invite.cjs reply "$HOME/act-omega-mesh-node" ./mikaya-invite.json VERIFIED_MIKAYA_FINGERPRINT > ./act-public-reply.json
```

ACT privately returns only `act-public-reply.json`, the public signing key and independently verifiable hardware evidence. MIKAYA verifies ACT's public fingerprint out of band and checks:

```bash
node mesh-invite.cjs verify-reply ./mikaya-invite.json ./act-public-reply.json VERIFIED_MIKAYA_FINGERPRINT VERIFIED_ACT_FINGERPRINT
```

This validates software signatures, not hardware-root identity. It returns `enrolled:false` until further owner review.

## 4. Complete independent hardware and network authorization

Manufacturer-backed KeyMint/YubiKey certificate evidence must be challenged and reviewed against trusted roots, revocation and device-owner policy. A separately trusted reviewer must sign the result. The MIKAYA owner must independently approve a short-lived, capability-limited grant. The v2 broker enforces these two independent signatures; production ACT access is currently **HOLD**.

For remote routing, both owners choose and authorize a restricted encrypted overlay endpoint, such as a single-device Tailscale share, with TLS hostname and pinned peer identity. Neither a repository checkout nor a GitHub OAuth session authorizes network routing. Limit outbound and inbound capabilities to approved compute; never expose Android debugging, shell, modem/OTA endpoints, wallet software, raw logs or device storage.

## 5. Keep economic services independently owned

ACT builds and funds ACT's own wallet, on the owner-chosen Bitcoin network. A signed service quote is marked `UNPAID` and never authorizes execution. A real Lightning/L402 service requires seller-local invoice creation, independently verified settlement, amount/payee/network/expiry/caveat checks and anti-replay policy. There is **no** real settled payment or live ACT wallet bridge in this review build.

## 6. Request source improvements safely

Use the owner-approved repository contribution workflow for the relevant source revision: a PR on GitHub or an MR on GitLab. The current handoff distinguishes published source from the still-blocked GitHub update; a prepared bundle does not grant repository access. Source PRs require review, tests, minimized disclosures and owner approval; they do not enroll ACT's node or modify a running device. Do not place any device private-key, transaction signing secret, Google session, legal allegation, wallet address, personal identifier or internal network route in a public issue.

**Dated evidence:** The older device report records MIKAYA F110/Motorola mutual TLS and 72 federation/Toybox/ledger tests plus 9 public evidence-brief tests. Those are MIKAYA's phones, not an ACT node, and were not rerun for this source handoff. The current selected-source run passed 25 tests. External ACT hardware/owner admission and live bilateral acceptance remain HOLD; current GitHub update access is a separate delivery blocker, not a claim that prior public source is unpublished.
