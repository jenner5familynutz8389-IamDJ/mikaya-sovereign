# Personal Android build-input contract correction — 2026-11-15

The Android 15 preflight now permits the recorded vendor API 33 input version as
well as the future vendor API 35 source route for its existing local compile-input
integrity check. The accepted release requirements already allowed matching,
lawfully usable vendor prebuilts; an Android platform version string alone did not
require rebuilding every vendor component for API 35. The old checksum gate
nevertheless rejected every vendor API 33 bundle. This correction removes that
contradiction without replacing the project architecture or vendor components.

`desired_vendor` still describes a future rebuilt vendor target. The exact board,
Android platform API 35, three product-file checksums, platform-tree markers and
manifest reference remain required. Only integer input vendor SDK 33 or 35 is
admitted. Other SDK values, malformed provenance, wrong board/platform, changed
files or missing platform markers cannot pass this gate. The shell driver now
asks for the matched product/vendor input root instead of describing proprietary
Android 15 vendor sources as the sole input path.

`source_compile_ready` retains its existing limited meaning: the small declared
input/checksum set and platform markers passed. It does not prove a complete or
authentic OEM checkout, correct lunch/product resolution, physical compatibility,
validated VINTF/KMI/policy, or a successful compilation. Those results require the
actual matching build inputs and relevant build/acceptance evidence. A matching
receipt is not an OEM signature. Full firmware readiness remains false, release
remains `HOLD`, and authenticity, compatibility, trust, hardware and carrier
acceptance remain separate. The blocker name changes from
`VENDOR15_SOURCE_AND_COMPATIBILITY_UNVERIFIED` to
`VENDOR_SOURCE_OR_PREBUILT_COMPATIBILITY_UNVERIFIED`; historical receipts retain
their original wording. No operational consumer of the old name was found in the
inspected source.

Both existing accepted trust paths remain options: the existing authenticated OEM
root/signing service, or manufacturer-documented owner-root support on this exact
variant. This change supplies neither signing authority nor enrollment support.
Personal use remains first; seller distribution stays deferred. The selected
modules remain ordinary vendor `cc_binary` executables; no APEX design or compiled
APEX has been introduced.

Nine focused contract tests cover API 33/35, malformed and unsupported SDKs,
board/platform mismatch, missing/changed inputs, missing platform markers and
release refusal. The API 33 regression failed before this correction and passed
afterwards. The existing 17 preflight tests also pass, and the shell driver parses.
Synthetic fixtures demonstrate gate behavior, not a real vendor compatibility
result. The earlier 16 unchanged source-staging/native-boundary checks were not
repeated.

The versioned handoff binds the corrected source bytes and exact inventory. It is
source only. No full Android checkout, target-files archive, signed firmware,
physical deployment or A/B-slot action is created or asserted by this correction.
