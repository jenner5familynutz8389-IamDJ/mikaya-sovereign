# F110 boot integrity and repair build — 16 November 2026

**The F110 currently boots B, locked and green. Repair candidates are built and checked, but have not been applied. A boot and IMS repair remain unproven.** This dated, sanitized summary updates the existing OEM engineering record. Its [machine-readable companion](F110_BOOT_INTEGRITY_EVIDENCE_20261116.json) distinguishes observed state, reference-image validation and remaining acceptance.

## Actual failure and shared storage

The recorded A activation and reboot commands were accepted. The retained previous-kernel log contains:

```text
verity-fec: 254:2: FEC: recursion too deep
verity: 254:2: metadata block 191350 is corrupted
Restarting system with command 'dm-verity device corrupted'
```

Android subsequently completed boot on B. In the checked kernel implementation, `254:2` is the data backing-device label; `191350` is the absolute hash-device block index, including hash_start. The failed boot's complete mapper table, slot-labelled command line and full kernel banner were not recovered. These lines alone do not identify the failed partition conclusively, establish the first corrupting write, or show an exploit or backdoor.

All seven captured A logical-partition sizes match the retained signed incremental update's OLD source; all seven B sizes match its NEW target. Their physical shared-super extents overlap, including the old A-system range. Old A therefore cannot be treated as a separately preserved complete OS backup after Virtual A/B merge. A stale old-A view over updated shared data is consistent with this failure. Conditional block mapping supports that explanation, while the missing failed mapper prevents a conclusive partition attribution.

All seven captured B verity configurations and the B vbmeta-chain digest match the OEM reference. The captured snapshot state is `none`, with linear B backing. COW-named reservations remain, but their names do not establish an active merge. These metadata matches are not a fresh byte-for-byte integrity check of every protected partition.

Retained OTA metadata signature verification passed under the current system OTA certificate. The signed target timestamp is June 2, 2026 at 12:33:40 UTC. The retained artifact contains metadata and **zero operation-data bytes**, so it is not a full repair payload or a reverse update. Available timestamps do not establish when the first corrupting write happened.

## Concrete native build results

The F110 built and re-read a **289,381,803-byte** static A component ZIP. All **21** component hashes matched the authenticated NEW target hashes. SHA-256: `faa5c4df53a43a030ca119fbd89496f6344935ac177d168f1f38600b784cb595`.

The components cover boot, init_boot, vendor_boot, dtbo, vbmeta chains and selected matching OEM firmware. The builder pins the MT6835/e393 UFS scatter entries and applies only the authenticated target's required zero padding. It excludes userdata, metadata, NV, preloader, GPT, shared super and debug images. Verified reference images do not establish that those replacements are necessary or have been installed.

The F110's native AOSP `lpdump -s 0` accepted the offline A metadata inspection image with exit code 0 and found all seven A data names. The image is **405,504 bytes**, SHA-256 `8d0d0b84ac780d9b17b9fd88d8356aa0624e0eb509abc6c1f941e64b76482289`. It retains the observed B data extents under A suffixes and preserves COW reservation names, ranges and attributes.

That artifact contains no dynamic partition data, uses OEM-reference geometry, and leaves noncandidate metadata slots zero/invalid. **It must never be flashed as a whole.** Native parser acceptance proves the candidate's parsability, not safe installation, complete protected-storage integrity or an A boot.

The included OEM boot-debug image is not an established trusted debug-root route on the current locked chain: its AVB public-key SHA-1 is `cdbb77177f731920bbe0a0f94f84d9038ae0617d`, while production root vbmeta delegates boot to `9d808b0995768d0677fccb1efcddb7cf9e153d99`, matching normal boot. Root, normal-boot and debug-boot AVB self-signature checks passed; the debug image still uses a key not delegated by production root. This small signature check does not verify every image payload byte or native partition readback. The debug image was not booted or flashed. The OEM DA container hash was verified natively, but its declared 256-byte signature tails are all zero; no DA acceptance, authentication or storage readback was observed. Container identity does not prove an accepted signed DA.

## Control restored; protected repair remains outstanding

The Motorola's native USB ADB connection again matched the expected F110 target and observed `_b`, locked/green verified boot and completed Android boot. The immediate USB transport failure was the F110 returning to host/source roles; correcting it to device/sink restored the control route. USB host authorization and native ADB command access are separate from protected partition write authority.

The existing Shizuku command path provides UID2000(shell), not kernel root. Actual read and read/write opens of `super` and `boot_a` were denied. No protected repair write or stock DA storage session is established. Container root, a USB permission grant and an OEM archive do not themselves supply that capability.

The remaining repair work is a validated data-retaining privileged/OEM service route; fresh geometry, all metadata copies and static-component readback; complete logical data/tree/FEC and boot-dependency verification; and an exact bounded apply transaction with readback. It must preserve userdata/FBE credentials, working B, the third metadata slot, NV, GPT and preloader. A compatible full signed repair OTA remains another possible route. Repeating the old slot flip alone does not rebuild a coherent A view.

Acceptance requires an actual native `_a` boot, locked/green verified boot, completed Android startup, stable owner unlock and access to development files. Carrier IMS, incoming/outgoing calls and SMS require separate functional acceptance. These results have not yet passed, and no OEM submission has been sent.

## Publication boundary

This summary follows the existing [public-source boundary](PUBLIC_GITHUB_SOURCE_BOUNDARY_20261115.md) and [security gates](../SECURITY.md). It publishes derived findings and reference hashes only. Raw device receipts, diagnostic dumps, device identifiers, network addresses, private paths, keys, account details, email and firmware/inspection images remain private. Source publication does not install the repair or change physical acceptance status.
