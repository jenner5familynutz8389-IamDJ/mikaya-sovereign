"""Android 15 platform baseline: fail-closed and non-flashable until OEM acceptance."""
import copy,json,pathlib,tempfile,unittest
from tools.f110_android15_build_base import validate_profile,evaluate,BuildProfileError,snapshot_runtime
HERE=pathlib.Path(__file__).resolve().parent
PROFILE=json.loads((HERE/"BUILD_PROFILE.json").read_text())
OBSERVED=json.loads((HERE/"F110_OBSERVED_REDACTED.json").read_text())
class Android15BuildBaseTests(unittest.TestCase):
 def profile(self):return copy.deepcopy(PROFILE)
 def observed(self):return copy.deepcopy(OBSERVED)
 def test_platform_android15_api35(self):
  p=self.profile();self.assertEqual(validate_profile(p)["platform_sdk"],35)
  self.assertEqual(p["android_platform"]["release"],"15")
  self.assertEqual(p["android_platform"]["aosp_ref"],"android-15.0.0_r1")
 def test_platform_api33_rejected_even_when_vendor33(self):
  p=self.profile();p["android_platform"]["sdk"]=33
  with self.assertRaises(BuildProfileError):validate_profile(p)
 def test_platform_release13_rejected(self):
  p=self.profile();p["android_platform"]["release"]="13"
  with self.assertRaises(BuildProfileError):validate_profile(p)
 def test_real_android15_vendor13_are_separate(self):
  r=evaluate(self.profile(),self.observed());self.assertTrue(r["baseline_pass"])
  self.assertEqual(r["platform_sdk"],35);self.assertEqual(r["observed_vendor_sdk"],33)
  self.assertFalse(r["full_oem_firmware_build_ready"]);self.assertEqual(r["release_status"],"HOLD")
 def test_android13_system_fails(self):
  props=self.observed();props.update({"ro.build.version.release":"13","ro.build.version.sdk":"33"})
  self.assertFalse(evaluate(self.profile(),props)["baseline_pass"])
 def test_wrong_device_or_soc_rejected(self):
  for k,v in [("ro.board.platform","mt6855"),("ro.product.board","wrong"),("ro.product.device","motorola")]:
   with self.subTest(key=k):
    props=self.observed();props[k]=v
    self.assertFalse(evaluate(self.profile(),props)["baseline_pass"])
 def test_vendor33_not_silently_relabelled35(self):
  p=self.profile();p["observed_vendor"]["sdk"]=35
  with self.assertRaises(BuildProfileError):validate_profile(p)
 def test_android13_kernel_lineage_is_compatible_not_android_platform(self):
  r=evaluate(self.profile(),self.observed());self.assertTrue(r["kernel_lineage_compatible"])
  self.assertEqual(r["observed_kernel_family"],"android13-5.15")
  self.assertEqual(r["platform_sdk"],35)
 def test_unknown_kernel_lineage_holds(self):
  props=self.observed();props["uname.release"]="6.1.0-unknown"
  r=evaluate(self.profile(),props);self.assertFalse(r["kernel_lineage_compatible"])
  self.assertFalse(r["full_oem_firmware_build_ready"])
 def test_missing_runtime_property_holds(self):
  props=self.observed();del props["ro.build.version.sdk"]
  self.assertFalse(evaluate(self.profile(),props)["baseline_pass"])
 def test_flash_authorization_cannot_be_enabled_in_profile(self):
  p=self.profile();p["release_policy"]["flash_authorized"]=True
  with self.assertRaises(BuildProfileError):validate_profile(p)
 def test_missing_aosp_oem_trees_hold(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp)
   r=evaluate(self.profile(),self.observed(),aosp_root=root/"noaosp",oem_root=root/"nobsp")
   self.assertIn("AOSP_15_TREE_MISSING",r["blockers"]);self.assertIn("OEM_MT6835_BSP_MISSING",r["blockers"])
 def test_partial_aosp_tree_holds(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp);(root/"build").mkdir();(root/"build/envsetup.sh").write_text("#mock")
   r=evaluate(self.profile(),self.observed(),aosp_root=root)
   self.assertIn("AOSP_15_TREE_INCOMPLETE",r["blockers"])
 def test_vendor_source_or_prebuilt_requires_compatibility_acceptance(self):
  r=evaluate(self.profile(),self.observed())
  self.assertIn("VENDOR_SOURCE_OR_PREBUILT_COMPATIBILITY_UNVERIFIED",r["blockers"])
 def test_fota_mt6769_is_not_board(self):
  p=self.profile();p["device"]["soc"]="mt6769"
  with self.assertRaises(BuildProfileError):validate_profile(p)
 def test_snapshot_least_privilege(self):
  source={"ro.build.version.sdk":"35","ro.build.version.release":"15","persist.radio.secret":"secret"}
  result=snapshot_runtime(lambda k:source.get(k,""),lambda:"5.15.197-android13-8")
  self.assertNotIn("persist.radio.secret",result)
  self.assertEqual(result["uname.release"],"5.15.197-android13-8")
 def test_synthetic_complete_android15_inputs_permit_compile_not_firmware_release(self):
  import hashlib
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp);aosp=root/'aosp';oem=root/'oem'
   for name in ('build/envsetup.sh','build/make/core/version_defaults.mk','frameworks/base/Android.bp','system/core/Android.bp','.repo/manifest.xml'):
    f=aosp/name;f.parent.mkdir(parents=True,exist_ok=True)
    f.write_text('android-15.0.0_r1' if name=='.repo/manifest.xml' else 'synthetic_fixture')
   oem.mkdir()
   paths={}
   for name in ('BoardConfig.mk','device.mk','AndroidProducts.mk'):
    f=oem/name;f.write_text('synthetic_only_'+name)
    paths[name]=hashlib.sha256(f.read_bytes()).hexdigest()
   (oem/'OEM_BUILD_PROVENANCE.json').write_text(json.dumps({'schema':'mikaya.f110.oem-input-checksums.v1','board':'e393_qc_f10_w_6835_v0','platform_sdk':35,'vendor_sdk':35,'files':paths}))
   r=evaluate(self.profile(),self.observed(),aosp_root=aosp,oem_root=oem)
   self.assertTrue(r['source_compile_ready'])
   self.assertFalse(r['full_oem_firmware_build_ready'])
   self.assertEqual(r['release_status'],'HOLD')
   (oem/'device.mk').write_text('TAMPERED')
   after=evaluate(self.profile(),self.observed(),aosp_root=aosp,oem_root=oem)
   self.assertFalse(after['source_compile_ready'])
   self.assertIn('OEM_BSP_SOURCE_HASH_MISMATCH',after['blockers'])
if __name__=="__main__":unittest.main()
