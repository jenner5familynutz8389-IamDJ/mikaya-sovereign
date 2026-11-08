# ACT-Omega independent mesh onboarding — public protocol

This procedure allows a second owner to **request** a scoped federation grant. It does not automatically create a VPN link, wallet, administrative access, hardware attestation or permission to execute arbitrary code.

## 1. Install the reviewed source and test it

Clone the owner-approved MIKAYA GitHub review branch only after it has actually been pushed. Until then, GitLab draft MR !97 is the review source and GitHub source is **not yet published**. Review all source changes before running them. Node.js 22+ is required.

```bash
node --test engineering/federation/live/tests/*.cjs
node engineering/federation/live/toybox-mempool-bridge.cjs inspect
```

The Bitcoin Toybox observer is public, read-only and checks a **historical confirmed mainnet transaction**. It is not the ACT wallet's address, balance, Lightning payment or custody authorization.

## 2. Establish an ACT-owned signing identity

ACT creates a unique signing identity on an ACT-controlled computer. **Do not reuse MIKAYA or Motorola key files.** Run inside the approved source directory:

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

Manufacturer-backed KeyMint/YubiKey certificate evidence must be challenged and reviewed against trusted roots, revocation and device-owner policy. A separately trusted reviewer must sign the result. The MIKAYA owner must independently approve a short-lived, capability-limited grant. The v2 broker enforces these two signed grants; production ACT access is currently **HOLD**.

For remote routing, both owners choose and authorize a restricted encrypted overlay endpoint, such as a single-device Tailscale share, with TLS hostname and pinned peer identity. Neither a repository checkout nor a GitHub OAuth session authorizes network routing. Limit outbound and inbound capabilities to approved compute; never expose Android debugging, shell, modem/OTA endpoints, wallet software, raw logs or device storage.

## 5. Keep economic services independently owned

ACT builds and funds ACT's own wallet, on the owner-chosen Bitcoin network. A signed service quote is marked `UNPAID` and never authorizes execution. A real Lightning/L402 service requires seller-local invoice creation, independently verified settlement, amount/payee/network/expiry/caveat checks and anti-replay policy. There is **no** real settled payment or live ACT wallet bridge in this review build.

## 6. Request source improvements safely

ACT can fork the public GitHub repository and open a PR to the MIKAYA review branch once it has been published. Source PRs require review, tests, minimized disclosures and owner approval; they do not enroll ACT's node or modify a running device. Do not place any device private-key, transaction signing secret, Google session, legal allegation, wallet address, personal identifier or internal network route in a public issue.

**Current evidence:** MIKAYA F110 and Motorola authenticated each other over TLS and passed 72 federation/Toybox/ledger tests in a clean GitHub checkout, plus 9 public evidence-brief tests (81 total); neither is ACT's physical node. Hardware admission and GitHub write authorization remain pending.
