#!/usr/bin/env bash
# PRIVATE: Android 15/API35 source build gate. No flash, signing or device mutations.
set -euo pipefail
MODE="${1:-check}"
case "$MODE" in check|compile) ;; *) printf '%s\n' 'Usage: bash build_android15_base.sh check|compile' >&2; exit 64;; esac
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROFILE="$REPO/engineering/f110-android15/BUILD_PROFILE.json"
OBS="$REPO/engineering/f110-android15/F110_OBSERVED_REDACTED.json"
VALIDATOR="$REPO/tools/f110_android15_build_base.py"
PROVENANCE="$REPO/tools/f110_provenance_gate.py"
# Exact byte-level owner-source verification is required before check or compile.
# This cannot establish OEM image signing, and does not touch device partitions.
python3 "$PROVENANCE" --root "$REPO" >/dev/null
if [ "$MODE" = check ]; then
 python3 "$VALIDATOR" --profile "$PROFILE" --observations "$OBS" --aosp-root "${AOSP_ROOT:-/nonexistent-aosp15}" --oem-root "${OEM_ROOT:-/nonexistent-f110-bsp}"
 exit 0
fi
if [ "${MIKAYA_ALLOW_AOSP15_COMPILE:-}" != YES ]; then
 echo "HOLD: explicit MIKAYA_ALLOW_AOSP15_COMPILE=YES required" >&2;exit 2
fi
: "${AOSP_ROOT:?HOLD: provide verified Android 15 AOSP source root}"
: "${OEM_ROOT:?HOLD: provide reviewed F110 MT6835 matched product/vendor input root}"
: "${OEM_LUNCH_TARGET:?HOLD: provide actual OEM Android 15 lunch target}"
if [[ ! "$OEM_LUNCH_TARGET" =~ ^[A-Za-z0-9_-]+$ || "$OEM_LUNCH_TARGET" == *REPLACE* ]]; then
 echo "HOLD: nonverified lunch target" >&2;exit 2
fi
python3 "$VALIDATOR" --profile "$PROFILE" --observations "$OBS" \
 --aosp-root "$AOSP_ROOT" --oem-root "$OEM_ROOT" --require-compile-ready >/dev/null
if [ ! -f "$AOSP_ROOT/build/envsetup.sh" ]; then echo "HOLD: missing AOSP environment" >&2;exit 2;fi
# No phone-side full image staging: require ~200 GiB free at the build-host source filesystem.
FREE_KIB="$(df -Pk "$AOSP_ROOT" | awk 'NR==2{print $4}')"
if [ -z "$FREE_KIB" ] || [ "$FREE_KIB" -lt 209715200 ]; then
 echo "HOLD: insufficient build-host free storage (<200GiB)" >&2;exit 2
fi
JOBS="${MIKAYA_BUILD_JOBS:-2}"
if [[ ! "$JOBS" =~ ^[1-8]$ ]]; then echo "HOLD: build concurrency must be 1-8" >&2;exit 2;fi
GOAL="${MIKAYA_BUILD_GOAL:-droid}"
if [[ ! "$GOAL" =~ ^[A-Za-z0-9_-]+$ ]]; then echo "HOLD: unsupported build goal" >&2;exit 2;fi
# AOSP build output remains a private unsigned/unapproved candidate. No fastboot.
cd "$AOSP_ROOT"
# shellcheck disable=SC1091
source build/envsetup.sh
lunch "$OEM_LUNCH_TARGET"
m "-j$JOBS" "$GOAL"
echo "AOSP SOURCE COMPILE EXITED. Release, OEM AVB, modem and physical validation remain HOLD."
