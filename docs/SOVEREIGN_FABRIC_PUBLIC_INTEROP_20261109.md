# MIKAYA sovereign fabric and ACT-Omega: public interoperability contract

The current design combines a double-helix topology (odd hardware/crypto/performance/WBAN layers and even sentinel/genesis/neural/network/discovery layers), bilateral approvals, four independent external shield functions and an event-spine record.

An owner-private source implementation is independently tested on the F110 using synthetic Ed25519 keypairs, concurrency-safe append, hash verification, replay/challenge mismatch tests, tampering tests and explicitly nonexecuting shield proposals. The original user-provided helix scripts remain private as historical source with SHA-256 provenance; this public document does not distribute raw logs, device identity, owner keys, phone OEM packages, wallet material or private correspondence.

ACT may implement a separate backend using its own keys, hardware and infrastructure. The ACT backend adapter must verify both signed request and signed response and recompute deterministic results; a static MCP TOOL_CALLED_OK response is not evidence of work. No production ACT enrollment, hardware attestation, owner trust grant, Lightning payment settlement or external repair execution is implied by this documentation.

An event spine with append-only hash chaining is tamper-evident, not physically immutable. It needs external independently signed checkpoints and a reviewed migration of historic distributed logs. A peer becoming visible in GitHub does not convey permissions to MIKAYA private repositories or live Android services.

Release status: source review only. Boot slot B and radio/IMS remediation are private Android/OEM engineering concerns, not authorized by this public protocol description. This document is part of one coordinated source and firmware evidence reconciliation, without automatically mutating the running devices.

## Verified source coverage after the November 9 merges

A read-only hash comparison identified 388 exact matches among 623 pinned GitLab originals across all three merged GitHub repositories. Another 235 originals require disposition: 220 private documentation/evidence, 5 Android items, and 10 root/CI items. These figures are a classification result, not authority to publish sensitive archives. The complete 623-file map remains private; no unmatched original public-federation sources were detected.
