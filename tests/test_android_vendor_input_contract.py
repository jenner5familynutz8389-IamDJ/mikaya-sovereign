"""Compile-input integrity never authenticates vendor compatibility or release trust."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.f110_android15_build_base import AOSP_FILES, OEM_FILES, evaluate

ROOT = Path(__file__).resolve().parents[1]
PROFILE = json.loads((ROOT/'engineering/f110-android15/BUILD_PROFILE.json').read_text())
OBSERVED = json.loads((ROOT/'engineering/f110-android15/F110_OBSERVED_REDACTED.json').read_text())


class VendorInputContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.aosp = self.root/'aosp'
        self.oem = self.root/'oem'
        for name in AOSP_FILES:
            path = self.aosp/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('android-15.0.0_r1' if name == '.repo/manifest.xml' else 'fixture_only')
        self.oem.mkdir()
        files = {}
        for name in OEM_FILES:
            path = self.oem/name
            path.write_text('fixture_only_'+name)
            files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.record = {'schema':'mikaya.f110.oem-input-checksums.v1',
                       'board':'e393_qc_f10_w_6835_v0',
                       'platform_sdk':35, 'vendor_sdk':33, 'files':files}
        self.receipt = self.oem/'OEM_BUILD_PROVENANCE.json'

    def result(self):
        self.receipt.write_text(json.dumps(self.record))
        return evaluate(copy.deepcopy(PROFILE), copy.deepcopy(OBSERVED), self.aosp, self.oem)

    def test_vendor33_bytes_can_pass_compile_input_integrity_only(self):
        result = self.result()
        self.assertTrue(result['source_compile_ready'])
        self.assertFalse(result['full_oem_firmware_build_ready'])
        self.assertEqual(result['release_status'], 'HOLD')
        self.assertEqual(result['checked_input_vendor_sdk'], 33)
        self.assertTrue(result['vendor_prebuilt_route_allowed'])
        self.assertFalse(result['vendor_api_upgrade_required_by_version_string_alone'])
        self.assertIn('VENDOR_SOURCE_OR_PREBUILT_COMPATIBILITY_UNVERIFIED', result['blockers'])
        self.assertIn('OEM_MT6835_BSP_AUTHENTICITY_UNVERIFIED', result['blockers'])
        self.assertIn('VINTF_CTS_VTS_AND_RADIO_THERMAL_HARDWARE_NOT_VALIDATED', result['blockers'])

    def test_vendor35_existing_compile_route_preserved(self):
        self.record['vendor_sdk'] = 35
        self.assertTrue(self.result()['source_compile_ready'])

    def test_unreviewed_vendor_versions_and_types_refused(self):
        for value in (32, 34, 36, '33', True, None):
            with self.subTest(value=value):
                self.record['vendor_sdk'] = value
                result = self.result()
                self.assertFalse(result['source_compile_ready'])
                self.assertIn('OEM_BSP_SOURCE_HASH_MISMATCH', result['blockers'])

    def test_wrong_board_refused(self):
        self.record['board'] = 'motorola'
        self.assertFalse(self.result()['source_compile_ready'])

    def test_wrong_platform_refused(self):
        self.record['platform_sdk'] = 33
        self.assertFalse(self.result()['source_compile_ready'])

    def test_missing_input_receipt_refused(self):
        result = evaluate(copy.deepcopy(PROFILE), copy.deepcopy(OBSERVED), self.aosp, self.oem)
        self.assertFalse(result['source_compile_ready'])
        self.assertIn('OEM_BSP_SOURCE_HASH_MANIFEST_MISSING', result['blockers'])

    def test_changed_input_refused(self):
        self.receipt.write_text(json.dumps(self.record))
        (self.oem/'device.mk').write_text('changed')
        result = evaluate(copy.deepcopy(PROFILE), copy.deepcopy(OBSERVED), self.aosp, self.oem)
        self.assertFalse(result['source_compile_ready'])

    def test_missing_platform_tree_refused(self):
        (self.aosp/'system/core/Android.bp').unlink()
        self.assertFalse(self.result()['source_compile_ready'])

    def test_source_compile_integrity_cannot_authorize_firmware_release(self):
        self.receipt.write_text(json.dumps(self.record))
        result = subprocess.run([sys.executable, str(ROOT/'tools/f110_android15_build_base.py'),
                                 '--aosp-root', str(self.aosp), '--oem-root', str(self.oem),
                                 '--require-build-ready'], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(json.loads(result.stdout)['full_oem_firmware_build_ready'])


if __name__ == '__main__':
    unittest.main()
