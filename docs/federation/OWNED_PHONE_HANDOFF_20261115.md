# Owned-phone wireless request and F110 USB handoff

Delivery record: November 15, 2026 UTC. **State at capture: STAGED_NOT_ARMED.**

The native F110 submitted a real fixed-action request over its existing authenticated SSH route to the Motorola. The Motorola stored the request privately and returned a digest-matched acknowledgement. The F110 is the boot target, with final slot A; the Motorola is its control host and is never the reboot target.

This document is a sanitized contract and delivery summary. The follow-up review also includes [configurable receiver and sender source templates](../../engineering/federation/owned-phone-link/README.md). Neither this document nor those templates are the installed runtime source, a deployment bundle, an executable request, or a current device-health feed. Device node IDs, USB serial, private network endpoints, live request ID, raw receipt, credentials and keys remain in the owner's private device state.

## Existing implementation reused

The integration uses the installed slot-A backend, its source-pinned controller, USB wrapper, original postflight, canonical locks and private job state. It starts no new listener, permanent watcher, or automatic retry queue. It does not resume the suspended external federation/payment services.

The two installed entrypoints are:

- F110: `~/.local/bin/mikaya-request-f110-a` submits a bounded request and checks the acknowledgement.
- Motorola: `~/.local/bin/mikaya-owned-f110 status <request-id>` reads the stored receipt; `run <request-id> --arm-once` is the explicit local activation entrypoint.

These names describe existing private installations. Copying this document into a repository does not install or arm them. A source branch is not evidence of a successful phone reboot.

## Request contract

The envelope has exactly these fields; unknown fields are rejected:

| Field | Constraint |
|---|---|
| `schema` | `mikaya.owned-f110-handoff-request.v1` |
| `request_id` | Fresh 32-character lowercase hexadecimal identifier |
| `action` | Only `F110_RETURN_TO_A_AND_REBOOT` |
| `sender_node_id` | Must match the owner's privately configured F110 node |
| `controller_node_id` | Must match the owner's privately configured Motorola node |
| `target_usb_serial` | Must match the exact privately configured F110 USB serial |
| `issued_at` | Integer Unix timestamp; bounded future-clock tolerance |
| `expires_at` | Integer Unix timestamp; lifetime greater than zero and no more than one hour |

The request body is limited to 4 KiB. No shell command, source/destination path, callback, firmware image or arbitrary device selection is accepted. The existing strict SSH host-key route authenticates delivery; the receiver compares the complete request and its canonical SHA-256 acknowledgement.

An identical resubmission can return the stored receipt. Reusing the same identifier with changed contents is rejected. A consumed or armed request cannot be launched again automatically.

## Local execution and disconnect behavior

Receipt of a file does not execute it. The installed receiver stages the request as `STAGED_NOT_ARMED`. Explicit local activation first enforces the original data hold, source pins and an authorized USB Android connection to the exact F110 serial. Discovery results, subsequent ADB/fastboot commands and nested postflight reads remain target-bound.

Only after those conditions permit activation does the Motorola detach one local worker. Its stdin is closed, its log is private, and its request transitions are recorded atomically. It invokes the existing backend and controller locks. The local worker can continue if the F110's chat, SSH session or Android network disconnects during its reboot.

The original backend's bootloader checks still apply. The integration introduces no flash, wipe, unlock, AVB/SELinux change, modem/NV operation or automatic rollback. Selecting slot A is not a migration of B's modified system image. A returned A boot is not, by itself, acceptance of calling, IMS, SMS, account access or development-data compatibility.

The SSH-environment check on local activation is an accidental-invocation guard, not a new operating-system privilege boundary: an unrestricted owner account under the same UID already has native shell authority. This delivery does not demonstrate a new external federation signature protocol or hardware attestation.

## Captured delivery status and remaining gates

- Actual native F110-to-Motorola delivery and acknowledgement completed.
- The request was staged; it was not armed or consumed by this integration work.
- Original backend/controller pins and the existing A/userdata hold remained unchanged.
- No slot selection or reboot was executed by the delivery work.
- The Motorola's removable SD filesystem was mounted read-only underneath its FUSE view. Private internal storage therefore holds the request and acknowledgement.
- Direct bidirectional SD writing was not activated. Existing SD readback failures remain relevant; originals were retained.
- Current USB readiness and A/userdata compatibility must be established from dated native state before activation. This record does not supersede a later operation receipt.

## Source identity and review

These are the hashes of the private installed source reviewed for this delivery, not hashes of a public runtime export:

| Component | SHA-256 |
|---|---|
| Existing slot-A backend | `e65da89d002db93ec83fa5172a5d84e09fcc94cf252a746fc07b52f56eb8d2f5` |
| Installed owned-phone receiver/target adapter | `2ad4b45e70fc799c90c96ee30d5e8b33d4f4c151ca1339d68b0e0a69e24abfd4` |
| Installed F110 request sender | `22877284374fea7d18a71b06a4d7ecc06788ae653ea775f74ca471e4eafff936` |

The integration passed Python syntax compilation and independent source review. That review found and closed a nested-postflight target-binding gap. No new device test suite, simulated boot, hardware acceptance or remote CI pass is claimed here. The earlier MR106 delivery was documentation-only. This follow-up exports configurable source templates with private identities loaded from an owned private configuration file. Those templates are not byte-identical to the native copies and have not been deployed or armed. The installed runtime, its source pins, active state and deployment workflows are unchanged.

The existing human principal → owned device → delegated agent policy remains in force. Existing GitLab MR !103, GitLab MR !105 and GitHub PR #6 were read back as merged before preparing this separate documentation branch. Their merged source and ownership changes are preserved.
