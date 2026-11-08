# MIKAYA–SOVEREIGN × ACT-Omega: proposed sovereign federation

Review-only public source. Independently owned Android/Linux nodes exchange bounded Ed25519-signed compute messages over authenticated TLS. Signing keys remain **on the owner’s own node**. An ACT peer may run this source with their own device identity and produce a signed reply to a short-lived invitation; neither step grants administrative access or shared wallet ownership.

The public source provides the local federation transport, independent one-hop test broker, ACT invitation and reply, independent attestation review, explicit owner-signed scoped grant, unsigned settlement-disabled service quote and **read-only Toybox Bitcoin mainnet anchor verification**.

## Verification
With Node.js 22+:
```bash
node --test engineering/federation/live/tests/*.cjs
node engineering/federation/live/toybox-mempool-bridge.cjs inspect
```
Physical MIKAYA F110 Pro (Android 15) and Motorola Moto G Power (Android 14) each passed 62/62 tests on Nov 8, 2026; each independently checked public blockchain observations, signed reports locally, and verified the other owner's public proof. These are **MIKAYA's two phones**, not ACT hardware.

ACT must independently pin MIKAYA's public fingerprint, verify the invitation, initialize a **separate** identity, and return a signed public reply. Independently checked KeyMint/YubiKey hardware attestation, pinned reviewer signature, separately approved time-limited owner grant, and authorized encrypted overlay network routing are required before production ACT enrollment. Default ACT admission is **HOLD**, not enabled. No wallet payment, Lightning/L402/x402 invoice settlement, hardware root certification, firmware modifications, mobile debugging control, or permission to execute arbitrary code is implemented by these source files.

See [Toybox public chain context](TOYBOX_PUBLIC_BRIDGE.md) and the source modules. The Toybox anchor is a **historical confirmed transaction**, not an unconfirmed mempool payment and not a proof of wallet ownership. ACT funds its own independent wallet and must never disclose seed phrases, macaroons or signing secrets.

Public source submitted for owner-reviewed GitHub PR; it does not contain private Termux state, private signing certificates, account tokens, identity backups or live mesh routing configuration.
