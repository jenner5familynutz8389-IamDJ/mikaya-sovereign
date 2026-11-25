import sys, pathlib, unittest, subprocess, json, tempfile
from unittest.mock import patch
sys.path.insert(0,sys.argv.pop(1))
import server
class NativeThermal(unittest.TestCase):
 def test_normal_does_not_authorize_optional_work(self):
  a=server.native_thermal_result(0, {'android_thermal_severity':0,'decision_for_optional_jobs':'ALLOW','factory_throttling_modified':False})
  self.assertEqual(a['mode'],'normal');self.assertEqual(a['native_optional_decision'],'ALLOW');self.assertFalse(a['optional_work_allowed'])
 def test_hot_holds(self):
  a=server.native_thermal_result(75,{'android_thermal_severity':3,'decision_for_optional_jobs':'HOLD','factory_throttling_modified':False})
  self.assertEqual(a['mode'],'hold');self.assertFalse(a['verified_healthy'])
 def test_unavailable_and_inconsistent_fail_closed(self):
  for rc,d in [(0,{}),(0,{'android_thermal_severity':3,'decision_for_optional_jobs':'ALLOW','factory_throttling_modified':False}),(75,{'android_thermal_severity':True,'decision_for_optional_jobs':'HOLD','factory_throttling_modified':False})]:
   a=server.native_thermal_result(rc,d);self.assertEqual(a['mode'],'unavailable');self.assertFalse(a['optional_work_allowed'])
unittest.main()
