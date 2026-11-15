# Owned-phone handoff source templates

These are configurable source templates derived from the reviewed private F110 sender and Motorola receiver. They expose the actual fixed-action request and target-binding logic for collaboration while keeping private node identities, USB serial and SSH source address outside the repository.

**These files are not byte-identical to the installed native copies, are not installed by this review, and are not armed.** Cloning this directory does not change either phone. The existing source-pinned slot-A backend is a prerequisite, not replaced or bundled here.

## Files and change scope

- `owned_handoff.py`: the receiver, private request receipt, target-bound ADB/fastboot runner, read-only nested-postflight adapter and detached local worker.
- `request_slot_a.py`: the native F110 sender using its existing strict-host-key SSH wrapper.
- `handoff_config.py`: the new bounded reader for private owner configuration.
- `private-config.example.json`: intentionally invalid placeholders; this is not a usable identity or request.
- `SOURCE_PROVENANCE.json`: native-source hashes, template hashes and static change scope.

Only the private identity constants and the exact SSH-source comparison are parameterized. Receiver validation, backend pin checks, original data hold, target serial checks, expiry, nonce/replay behavior, canonical locks, local arming and worker logic are retained. The sender's generated identity fields now come from the same strict configuration; its native-model check, existing SSH route and exact acknowledgement checks remain in place.

## Private configuration

Both programs require `~/.config/mikaya-owned-link-v1/identity.json`. There is no environment-variable path override, discovery fallback or wildcard identity.

1. Keep the containing directory owned by the native Termux UID and private, mode `0700`.
2. Create an owner-only regular configuration file, mode `0600` or read-only `0400`, with a single hard link. Do not overwrite an existing private configuration.
3. Use `private-config.example.json` as the field reference. Replace every placeholder using the owner's actual configured F110 node UUID, Motorola node UUID, exact F110 USB serial and exact F110 SSH-source IPv4 address.
4. Use the same identity contract on both phones. Node UUIDs must be canonical, nonzero and distinct. The source address must be one canonical unicast IPv4 address, not a CIDR, hostname, wildcard, loopback or broadcast address.
5. Keep this populated file private; do not commit it, include it in a plugin archive, paste it into a review or substitute a raw device receipt.

The loader refuses missing files, placeholders, unknown/duplicate JSON fields, symlinks in the configuration path, wrong ownership, broad permissions, hard links, oversized data, changed-during-read files, malformed UUIDs and serial wildcards/shell text. A configuration failure stops the program before any Android property read, SSH submission, backend import or hardware operation.

## Existing installation prerequisites

The templates deliberately retain the original private installation layout and existing backend SHA-256. They are not an installer or a general flashing tool. A later authorized deployment must review the complete private bundle and its wrapper paths together:

- The exact original backend and its controller/USB-wrapper/postflight source pins must match.
- The original canonical backend state, controller lock and `.data-portability-paused.json` hold must remain associated with that same installation. Do not point at a fresh copy to omit a hold or replay state.
- The `adb-f110-bound` wrapper must match the receiver's exact expected bytes and installed receiver path. Running a receiver from this checkout does not replace the existing installed adapter.
- Keep one deployment controlling the canonical state. This review does not update native launcher hashes, overwrite installed source, migrate an active request or clear a technical hold.

The only request action remains `F110_RETURN_TO_A_AND_REBOOT`. The F110 is the boot target; the Motorola is the controller and must never become the reboot target. Existing host-model and F110 target checks remain in the pinned backend/controller.

## Operational behavior retained

An authenticated request is stored as `STAGED_NOT_ARMED`. It has a 4-KiB budget, exact schema, one-hour maximum lifetime and immutable request digest. Receipt of a file does not execute it. Local Motorola `--arm-once` activation still requires all original technical gates and the exact authorized physical F110 USB connection before launching one detached worker.

Once properly launched, the local Motorola worker can continue while the F110/chat network is offline. It does not create a new listener, perpetual watcher, retry loop, arbitrary shell interface or automatic rollback. A consumed request cannot be silently replayed.

The exact SSH-source check is an accidental-invocation guard within an already-authorized owner SSH account, not a new operating-system privilege boundary or a demonstration of hardware attestation. Changing a human/device label does not confer OEM signing, payment or Android root authority.

## Dated delivery and unfinished hardware work

The private native sender/receiver previously delivered and acknowledged a real request, captured as `STAGED_NOT_ARMED`; their installed hashes remain in the provenance record. The source templates in this directory have not been deployed or used to repeat that delivery.

The owner workflow's latest update for this source preparation reported F110 wireless ADB working, USB functions `mtp,adb` prepared, and backup running. These are dated coordination observations, not hardware acceptance by this source review or a backup-completion claim. No slot change or arming is claimed here. A cable procedure was deferred by the owner; use current native receipts before any later activation.

The Motorola removable SD was previously mounted read-only underneath its FUSE view, so the acknowledged private request used internal staging. This source publication does not activate bidirectional SD writes, repair a filesystem, move B's system changes into A, preserve a Google session, or establish calling/IMS/SMS acceptance.

## Verification for this source export

All three Python files passed AST parsing and syntax compilation without importing them or executing device/network commands. A structural comparison confirms that every existing receiver function except the exact configured-source comparison in `submit` is unchanged; the sender changes only its identity-field construction and new fail-closed configuration loading. A focused independent read-only review is recorded in the publication receipt. No broad test suite, device procedure, pipeline pass or runtime-deployment claim is made.

The original private native source and its receipt remain separate. The repository copy is reviewable collaboration source, with the remaining deployment and hardware gates explicit.
