#!/usr/bin/env python3
"""F110 Android 15/API35 source-base preflight. No flash, root or modem access."""
from __future__ import annotations
import argparse
import json
import hashlib
from pathlib import Path
import re
import subprocess
from typing import Callable

PLATFORM_RELEASE="15"
PLATFORM_SDK=35
TARGET_BOARD="e393_qc_f10_w_6835_v0"
TARGET_DEVICE="F110_Pro"
TARGET_SOC="mt6835"
AOSP_REF="android-15.0.0_r1"
# Android 15 supports android13-5.15 GKI; kernel branch does not select OS API.
GKI_FAMILY="android13-5.15"
# The recorded vendor33 baseline and future vendor35 source route remain options.
# Input checksums permit local compilation, never compatibility or release approval.
INPUT_VENDOR_SDKS=(33,35)
SAFE_PROPERTIES=(
 "ro.build.version.release","ro.build.version.sdk","ro.product.first_api_level",
 "ro.product.device","ro.product.board","ro.board.platform",
 "ro.vendor.build.version.release","ro.vendor.build.version.sdk",
 "ro.vendor.api_level","ro.vndk.version","ro.boot.verifiedbootstate",
)
AOSP_FILES=(
 "build/envsetup.sh","build/make/core/version_defaults.mk",
 "frameworks/base/Android.bp","system/core/Android.bp",
 ".repo/manifest.xml",
)
OEM_FILES=("BoardConfig.mk","device.mk","AndroidProducts.mk")

class BuildProfileError(ValueError):
 """An invalid or unsafe Android build profile."""

def _mapping(root, key):
 if not isinstance(root,dict) or not isinstance(root.get(key),dict):
  raise BuildProfileError("invalid or absent section: "+key)
 return root[key]

def validate_profile(profile:dict)->dict:
 if not isinstance(profile,dict) or profile.get("schema")!="mikaya.f110.android15-platform-baseline.v1":
  raise BuildProfileError("unsupported Android 15 profile schema")
 device=_mapping(profile,"device");platform=_mapping(profile,"android_platform")
 vendor=_mapping(profile,"observed_vendor");desired=_mapping(profile,"desired_vendor")
 kernel=_mapping(profile,"kernel");release=_mapping(profile,"release_policy")
 sources=_mapping(profile,"sources")
 if {k:device.get(k) for k in ("board","soc","product_device")}!={
  "board":TARGET_BOARD,"soc":TARGET_SOC,"product_device":TARGET_DEVICE
 }:
  raise BuildProfileError("F110 MT6835 exact board/device mismatch")
 if platform.get("release")!=PLATFORM_RELEASE or type(platform.get("sdk")) is not int or platform["sdk"]!=PLATFORM_SDK:
  raise BuildProfileError("system platform MUST be Android 15 / API 35; not Android 13")
 if platform.get("aosp_ref")!=AOSP_REF or platform.get("build_role")!="FRAMEWORK_BASE":
  raise BuildProfileError("Android 15 AOSP reference not pinned")
 if vendor.get("release")!="13" or type(vendor.get("sdk")) is not int or vendor["sdk"]!=33:
  raise BuildProfileError("observed vendor-API33 must remain honestly recorded")
 if type(vendor.get("vndk")) is not int or vendor["vndk"]!=33 or vendor.get("preserve_until_replaced") is not True:
  raise BuildProfileError("existing vendor VNDK/version cannot be silently replaced")
 if desired.get("release")!="15" or type(desired.get("sdk")) is not int or desired["sdk"]!=35:
  raise BuildProfileError("new vendor sources, if developed, must target Android 15")
 if desired.get("verified_bsp") is not False:
  raise BuildProfileError("verified Android 15 OEM BSP is not in this review")
 if kernel.get("observed_family")!=GKI_FAMILY or kernel.get("platform_identity") is not False:
  raise BuildProfileError("GKI lineage must not be used as OS platform version")
 if kernel.get("allow_android15_gki_previous_lineage") is not True:
  raise BuildProfileError("invalid Android 15 GKI compatibility policy")
 for key in ("flash_authorized","oem_signing_verified","signed_images_present"):
  if release.get(key) is not False:raise BuildProfileError("release authorization must remain false: "+key)
 for key in ("require_oem_board_sources","require_vintf_cts_vts"):
  if release.get(key) is not True:raise BuildProfileError("cannot bypass "+key)
 if sources.get("revision")!=AOSP_REF or sources.get("oem_product_target")!="OEM_SUPPLIED_NOT_VERIFIED":
  raise BuildProfileError("unverified OEM lunch target or Android platform revision")
 return {"platform_sdk":PLATFORM_SDK,"platform_release":PLATFORM_RELEASE,"board":TARGET_BOARD}

def snapshot_runtime(getprop:Callable[[str],str],uname:Callable[[],str])->dict:
 """Collect allowlisted non-identifying properties only; never enumerates IDs."""
 result={key:str(getprop(key)).strip() for key in SAFE_PROPERTIES}
 result["uname.release"]=str(uname()).strip()
 return result

def _kernel_matches(text):
 return bool(isinstance(text,str) and re.match(r"^5\.15\.\d+-android13-",text))

def evaluate(profile, observations, aosp_root=None, oem_root=None)->dict:
 validate_profile(profile)
 if not isinstance(observations,dict):raise BuildProfileError("observations must be a JSON object")
 checks={
  "platform_android15":observations.get("ro.build.version.release")=="15",
  "platform_api35":observations.get("ro.build.version.sdk")=="35",
  "first_api35":observations.get("ro.product.first_api_level")=="35",
  "f110_soc":observations.get("ro.board.platform")=="mt6835",
  "f110_board":observations.get("ro.product.board")==TARGET_BOARD,
  "f110_device":observations.get("ro.product.device")==TARGET_DEVICE,
  "observed_vendor_release13":observations.get("ro.vendor.build.version.release")=="13",
  "observed_vendor_sdk33":observations.get("ro.vendor.build.version.sdk")=="33",
  "observed_vendor_api33":observations.get("ro.vendor.api_level")=="33",
  "observed_vndk33":observations.get("ro.vndk.version")=="33",
 }
 blockers=[]
 oem_source_hashes_match=False
 checked_input_vendor_sdk=None
 for name,ok in checks.items():
  if not ok:blockers.append("BASELINE_MISMATCH_"+name.upper())
 kernel_ok=_kernel_matches(observations.get("uname.release"))
 if not kernel_ok:blockers.append("GKI_KERNEL_LINEAGE_UNVERIFIED")
 baseline_pass=all(checks.values())
 if aosp_root is None:blockers.append("AOSP_15_TREE_NOT_SUPPLIED")
 else:
  root=Path(aosp_root)
  if not root.is_dir():blockers.append("AOSP_15_TREE_MISSING")
  elif any(not (root/item).is_file() for item in AOSP_FILES):
   blockers.append("AOSP_15_TREE_INCOMPLETE")
  else:
   # Even presence of AOSP files is not a pinned/reviewed manifest checkout.
   manifest=(root/".repo/manifest.xml").read_text(errors="replace")
   if AOSP_REF not in manifest:blockers.append("AOSP_15_MANIFEST_TAG_UNVERIFIED")
 if oem_root is None:blockers.append("OEM_MT6835_BSP_NOT_SUPPLIED")
 else:
  root=Path(oem_root)
  if not root.is_dir():blockers.append("OEM_MT6835_BSP_MISSING")
  elif any(not (root/item).is_file() for item in OEM_FILES):
   blockers.append("OEM_MT6835_BSP_INCOMPLETE")
  else:
   receipt=root/"OEM_BUILD_PROVENANCE.json"
   if not receipt.is_file():blockers.append("OEM_BSP_SOURCE_HASH_MANIFEST_MISSING")
   else:
    try:
     record=json.loads(receipt.read_text())
     files=record.get("files")
     acceptable=(record.get("schema")=="mikaya.f110.oem-input-checksums.v1"
      and record.get("board")==TARGET_BOARD and type(record.get("platform_sdk")) is int
      and record.get("platform_sdk")==35 and type(record.get("vendor_sdk")) is int
      and record.get("vendor_sdk") in INPUT_VENDOR_SDKS and isinstance(files,dict)
      and set(files)==set(OEM_FILES))
     if acceptable:
      acceptable=all(isinstance(files[f],str) and len(files[f])==64
       and hashlib.sha256((root/f).read_bytes()).hexdigest()==files[f] for f in OEM_FILES)
     if not acceptable:blockers.append("OEM_BSP_SOURCE_HASH_MISMATCH")
     else:
      oem_source_hashes_match=True
      checked_input_vendor_sdk=record["vendor_sdk"]
    except (ValueError,OSError,TypeError,KeyError):
     blockers.append("OEM_BSP_SOURCE_HASH_MISMATCH")
    # File-integrity checks do not authenticate the real OEM or signing keys.
    blockers.append("OEM_MT6835_BSP_AUTHENTICITY_UNVERIFIED")
 blockers.extend((
  "VENDOR_SOURCE_OR_PREBUILT_COMPATIBILITY_UNVERIFIED",
  "OEM_AVB_SIGNING_AND_AB_ROLLBACK_NOT_VALIDATED",
  "VINTF_CTS_VTS_AND_RADIO_THERMAL_HARDWARE_NOT_VALIDATED",
 ))
 return {
  "schema":"mikaya.f110.android15-preflight.v1",
  "platform_release":"15","platform_sdk":35,
  "observed_vendor_release":observations.get("ro.vendor.build.version.release"),
  "observed_vendor_sdk":int(observations["ro.vendor.build.version.sdk"]) if observations.get("ro.vendor.build.version.sdk")=="33" else None,
  "observed_kernel_family":GKI_FAMILY,
  "checked_input_vendor_sdk":checked_input_vendor_sdk,
  "vendor_prebuilt_route_allowed":True,
  "vendor_api_upgrade_required_by_version_string_alone":False,
  "kernel_lineage_compatible":kernel_ok,
  "checks":checks,
  "baseline_pass":baseline_pass,
  "aosp_sources_ready":"AOSP_15_TREE_NOT_SUPPLIED" not in blockers and "AOSP_15_TREE_MISSING" not in blockers and "AOSP_15_TREE_INCOMPLETE" not in blockers and "AOSP_15_MANIFEST_TAG_UNVERIFIED" not in blockers,
  "source_compile_ready":(
   baseline_pass and kernel_ok and oem_source_hashes_match
   and not any(s.startswith("AOSP_15_") for s in blockers)),
  "full_oem_firmware_build_ready":False,
  "release_status":"HOLD",
  "blockers":blockers,
  "changes_to_running_device":False,
 }

def main(argv=None):
 p=argparse.ArgumentParser(description="F110 Android 15/API35 build preflight; read-only")
 p.add_argument("--profile",type=Path,default=Path(__file__).resolve().parents[1]/"engineering/f110-android15/BUILD_PROFILE.json")
 p.add_argument("--observations",type=Path,default=Path(__file__).resolve().parents[1]/"engineering/f110-android15/F110_OBSERVED_REDACTED.json")
 p.add_argument("--aosp-root",type=Path)
 p.add_argument("--oem-root",type=Path)
 p.add_argument("--output",type=Path)
 p.add_argument("--require-build-ready",action="store_true",help="fail closed when no OEM release acceptance")
 p.add_argument("--require-compile-ready",action="store_true",help="validate local source inputs before native AOSP compile; not OEM approval")
 args=p.parse_args(argv)
 try:
  data=evaluate(json.loads(args.profile.read_text()),json.loads(args.observations.read_text()),args.aosp_root,args.oem_root)
 except (BuildProfileError,OSError,json.JSONDecodeError) as exc:
  print(json.dumps({"status":"FAIL","reason":str(exc)}));return 2
 output=json.dumps(data,indent=2,sort_keys=True)+"\n"
 if args.output:
  args.output.parent.mkdir(parents=True,exist_ok=True)
  args.output.write_text(output)
 print(output,end="")
 return 0 if data["baseline_pass"] and not args.require_build_ready and (
  not args.require_compile_ready or data["source_compile_ready"]) else 2

if __name__=="__main__":raise SystemExit(main())
