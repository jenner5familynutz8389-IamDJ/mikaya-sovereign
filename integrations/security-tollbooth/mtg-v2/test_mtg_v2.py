"""Host-only lifecycle tests. Thermal values and shortened intervals are TEST FIXTURES."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SOURCE = Path(__file__).with_name("mtg_nice_policy_v2.py")
spec = importlib.util.spec_from_file_location("mtg_v2_test_subject", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

HARNESS = r'''
import importlib.util,json,os,pathlib,signal,sys,time
source,base,scenario,maximum=sys.argv[1:];base=pathlib.Path(base)
spec=importlib.util.spec_from_file_location("fixture_mtg",source);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
if scenario=="inherited15":os.nice(15)
calls=0
def fixture_reader(control,deadline):
 global calls
 calls+=1
 if calls==1:(base/"first-reading.marker").write_text("synthetic fixture only")
 if scenario=="blocked_probe" and calls>=3:
  script="import os,pathlib,sys,time;p=pathlib.Path(sys.argv[1]);t=p.with_suffix('.pending');t.write_text(str(os.getpid()));os.replace(t,p);time.sleep(30)"
  m._probe_command(control,[sys.executable,"-c",script,str(base/"probe.pid")],dict(os.environ),min(deadline,time.monotonic()+3))
  return None
 return json.loads((base/"thermal-fixture.json").read_text())
m.read_status=fixture_reader
if scenario=="spawn_return_signal":
 original=m.OwnedChild.__init__
 def raced(self,argv,**kw):
  original(self,argv,**kw)
  if not kw.get("capture",False):
   deadline=time.monotonic()+1
   while not (base/"job.pid").exists() and time.monotonic()<deadline:time.sleep(.005)
   os.kill(os.getpid(),signal.SIGTERM)
 m.OwnedChild.__init__=raced
interval=.3 if scenario=="startup_signal" else 2 if scenario=="startup_wall" else .04
result=m._run([sys.executable,str(base/"job.py"),str(base),scenario],_interval=interval,_max_wall=int(maximum))
print("FIXTURE_RESULT="+str(result),flush=True)
raise SystemExit(result)
'''
JOB = r'''
import os,pathlib,signal,sys,time
base=pathlib.Path(sys.argv[1]);scenario=sys.argv[2]
def record_pid(name):
 target=base/name;temporary=base/(name+".pending-"+str(os.getpid()))
 temporary.write_text(str(os.getpid()));os.replace(temporary,target)
if scenario=="ignore_term":signal.signal(signal.SIGTERM,signal.SIG_IGN)
record_pid("job.pid")
pid=os.fork()
if pid==0:
 record_pid("descendant.pid")
 while True:time.sleep(.05)
if scenario=="natural_descendant":
 deadline=time.monotonic()+1
 while not (base/"descendant.pid").exists() and time.monotonic()<deadline:time.sleep(.005)
 raise SystemExit(0)
while True:time.sleep(.05)
'''


def state(pid):
    try:
        raw=Path("/proc",str(pid),"stat").read_text()
        return raw[raw.rfind(")")+2:].split()[0]
    except FileNotFoundError:
        return None


def stopped_or_gone(pid):
    return state(pid) in (None, "Z", "X")

def read_pid(path):
    try:
        value=path.read_text()
        return int(value) if value.isascii() and value.isdecimal() else None
    except OSError:
        return None


class RealLifecycle(unittest.TestCase):
    def launch(self, scenario="normal", maximum=4, severity=0):
        temporary=tempfile.TemporaryDirectory(prefix="mikaya-mtg-v2-test-")
        self.addCleanup(temporary.cleanup)
        base=Path(temporary.name);(base/"thermal-fixture.json").write_text(json.dumps(severity));(base/"job.py").write_text(JOB)
        log=(base/"owner.log").open("wb");self.addCleanup(log.close)
        child=subprocess.Popen([sys.executable,"-c",HARNESS,str(SOURCE),str(base),scenario,str(maximum)],stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        def cleanup():
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
                try:child.wait(timeout=3)
                except subprocess.TimeoutExpired:child.kill();child.wait(timeout=2)
            # Emergency cleanup only exact unique fixture argv processes, never a saved free group.
            for name in ("job.pid","descendant.pid","probe.pid"):
                p=base/name
                if not p.exists():continue
                pid=read_pid(p)
                if pid is None:continue
                try:argv=Path("/proc",str(pid),"cmdline").read_bytes()
                except FileNotFoundError:continue
                if str(base).encode() not in argv:continue
                fd=os.pidfd_open(pid)
                try:signal.pidfd_send_signal(fd,signal.SIGKILL)
                finally:os.close(fd)
        self.addCleanup(cleanup)
        return child,base

    def wait_for(self, predicate, seconds=3):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.01)
        self.fail("fixture deadline: condition not reached")

    def assert_clean(self, base):
        for name in ("job.pid","descendant.pid","probe.pid"):
            p=base/name
            if p.exists():
                pid=read_pid(p);self.assertIsNotNone(pid);self.wait_for(lambda:stopped_or_gone(pid),2)

    def set_severity(self, base, severity):
        temporary=base/"thermal-fixture.pending"
        temporary.write_text(json.dumps(severity))
        os.replace(temporary,base/"thermal-fixture.json")

    def pause(self, base):
        self.set_severity(base,2)
        pid=int((base/"job.pid").read_text())
        self.wait_for(lambda:state(pid)=="T")

    def test_actual_nice_floor_from_zero_and_already_fifteen(self):
        for scenario in ("normal","inherited15"):
            with self.subTest(scenario=scenario):
                child,base=self.launch(scenario)
                self.wait_for(lambda:read_pid(base/"job.pid") is not None)
                pid=int((base/"job.pid").read_text())
                self.assertEqual(os.getpriority(os.PRIO_PROCESS,pid),15)
                self.assertEqual(os.getpgid(pid),pid);self.assertEqual(os.getsid(pid),pid)
                child.send_signal(signal.SIGTERM);self.assertEqual(child.wait(timeout=3),143);self.assert_clean(base)

    def test_term_int_hup_clean_paused_group(self):
        for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):
            with self.subTest(signal=sig):
                child,base=self.launch()
                self.wait_for(lambda:read_pid(base/"descendant.pid") is not None);self.pause(base)
                child.send_signal(sig);self.assertEqual(child.wait(timeout=3),128+sig);self.assert_clean(base)

    def test_unknown_thermal_pauses_and_two_safe_readings_resume_same_child(self):
        child,base=self.launch()
        self.wait_for(lambda:read_pid(base/"job.pid") is not None);pid=int((base/"job.pid").read_text())
        self.set_severity(base,None);self.wait_for(lambda:state(pid)=="T")
        self.set_severity(base,0)
        self.wait_for(lambda:state(pid) not in (None,"T","Z"))
        self.assertEqual(int((base/"job.pid").read_text()),pid)
        self.assertIn("RESUMED after two safe readings",(base/"owner.log").read_text())
        child.send_signal(signal.SIGTERM);self.assertEqual(child.wait(timeout=3),143);self.assert_clean(base)

    def test_startup_hold_does_not_start_optional_child(self):
        for severity in (2,None):
            with self.subTest(severity=severity):
                child,base=self.launch(severity=severity)
                self.assertEqual(child.wait(timeout=2),75);self.assertFalse((base/"job.pid").exists())

    def test_startup_signal_does_not_start_child(self):
        child,base=self.launch("startup_signal")
        self.wait_for(lambda:(base/"first-reading.marker").exists())
        child.send_signal(signal.SIGHUP)
        self.assertEqual(child.wait(timeout=2),129);self.assertFalse((base/"job.pid").exists())

    def test_spawn_return_signal_cannot_skip_assignment_cleanup(self):
        child,base=self.launch("spawn_return_signal")
        self.assertEqual(child.wait(timeout=4),143);self.assert_clean(base)

    def test_signal_during_blocked_probe_cleans_probe_and_job(self):
        child,base=self.launch("blocked_probe")
        self.wait_for(lambda:read_pid(base/"probe.pid") is not None)
        child.send_signal(signal.SIGHUP);self.assertEqual(child.wait(timeout=3),129);self.assert_clean(base)

    def test_wall_bound_stops_paused_job(self):
        child,base=self.launch(maximum=1)
        self.wait_for(lambda:read_pid(base/"job.pid") is not None);self.pause(base)
        self.assertEqual(child.wait(timeout=3),75);self.assert_clean(base)
        self.assertIn("WALL_HOLD",(base/"owner.log").read_text())

    def test_ignored_term_is_bounded_then_killed(self):
        child,base=self.launch("ignore_term")
        self.wait_for(lambda:read_pid(base/"descendant.pid") is not None);self.pause(base)
        started=time.monotonic();child.send_signal(signal.SIGTERM)
        self.assertEqual(child.wait(timeout=3),143);self.assertLess(time.monotonic()-started,2.5);self.assert_clean(base)

    def test_natural_leader_exit_cleans_same_group_descendant_before_reaping(self):
        child,base=self.launch("natural_descendant")
        self.assertEqual(child.wait(timeout=4),0);self.assert_clean(base)


    def test_wall_bound_includes_two_sample_startup_gap(self):
        child,base=self.launch("startup_wall",maximum=1)
        self.assertEqual(child.wait(timeout=2),75);self.assertFalse((base/"job.pid").exists())


class ProbeAndContract(unittest.TestCase):
    def test_sdk34_loader_copy_known_preload_only_other_sdk_unchanged(self):
        original={"LD_PRELOAD":m.STANDARD_PRELOAD,"LD_LIBRARY_PATH":"owner-path","PREFIX":m.PREFIX}
        new=m.probe_environment(34,original)
        self.assertNotIn("LD_PRELOAD",new);self.assertEqual(new["LD_LIBRARY_PATH"],"/system/lib64:"+m.PREFIX+"/lib")
        self.assertEqual(original["LD_LIBRARY_PATH"],"owner-path");self.assertEqual(original["LD_PRELOAD"],m.STANDARD_PRELOAD)
        self.assertEqual(m.probe_environment(35,original),original)
        self.assertEqual(m.probe_environment(34,{})["LD_LIBRARY_PATH"],"/system/lib64:"+m.PREFIX+"/lib")
        for preload in ("owner.so",m.STANDARD_PRELOAD+":owner.so"," "+m.STANDARD_PRELOAD,m.STANDARD_PRELOAD+" "+m.STANDARD_PRELOAD):
            self.assertIsNone(m.probe_environment(34,{"LD_PRELOAD":preload}))

    def test_wall_bound_is_finite_only_shorter_and_never_disabled(self):
        for raw,want in (("1",1),("21600",21600)):
            with mock.patch.dict(os.environ,{m.WALL_ENV:raw}):self.assertEqual(m.wall_bound(),want)
        for raw in ("0","21601","-1","inf","nan","1.5",""):
            with mock.patch.dict(os.environ,{m.WALL_ENV:raw}):
                with self.assertRaises(ValueError):m.wall_bound()

    def test_status_on_host_is_actual_unknown_not_a_synthetic_allow(self):
        result=subprocess.run([sys.executable,str(SOURCE),"status"],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,75);j=json.loads(result.stdout)
        self.assertEqual(set(j),{"name","android_thermal_severity","decision_for_optional_jobs","nice_increase","resume_requires","poll_interval_seconds","factory_throttling_modified","adb_required"})
        self.assertIsNone(j["android_thermal_severity"]);self.assertEqual(j["decision_for_optional_jobs"],"HOLD")
        self.assertEqual(j["poll_interval_seconds"],10);self.assertEqual(j["nice_increase"],15)

    def test_standalone_leaf_probe_handles_stdout_eof_before_exit(self):
        with m.Control(handlers=False) as control:
            raw=m._probe_command(control,[sys.executable,"-c","import os,time;print('actual-fixture-output',flush=True);os.close(1);time.sleep(.08)"],dict(os.environ),time.monotonic()+1)
        self.assertEqual(raw,b"actual-fixture-output\n")

    def test_ignored_sigchld_refuses_probe_before_spawn(self):
        old=signal.signal(signal.SIGCHLD,signal.SIG_IGN)
        try:
            with m.Control(handlers=False) as control,mock.patch.object(m,"OwnedChild",side_effect=AssertionError("must not spawn")):
                self.assertIsNone(m._probe_command(control,[sys.executable],{},time.monotonic()+1))
        finally:signal.signal(signal.SIGCHLD,old)

    def test_missing_wait_support_holds_without_job(self):
        with mock.patch.object(m,"wait_supported",return_value=False),contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(m.read_status());self.assertEqual(m._run([sys.executable]),75)

    def test_external_reap_loses_reservation_and_never_signals_reused_group(self):
        owned=m.OwnedChild([sys.executable,"-c","pass"],capture=True)
        end=time.monotonic()+1
        while owned.completed() is None and time.monotonic()<end:time.sleep(.005)
        os.waitpid(owned.process.pid,0)
        with self.assertRaises(m.CleanupHold):owned.completed()
        with mock.patch.object(os,"killpg",side_effect=AssertionError("must not signal unreserved group")):
            self.assertFalse(owned.close(grace=0))

    def test_leaf_probe_deadline_and_oversized_output_hold_and_reap(self):
        with tempfile.TemporaryDirectory(prefix="mikaya-mtg-probe-test-") as temporary:
            marker=Path(temporary)/"probe.pid"
            script="import os,pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text(str(os.getpid()));time.sleep(30)"
            with m.Control() as control:
                self.assertIsNone(m._probe_command(control,[sys.executable,"-c",script,str(marker)],dict(os.environ),time.monotonic()+.1))
            self.assertTrue(stopped_or_gone(int(marker.read_text())))
            with m.Control() as control:
                self.assertIsNone(m._probe_command(control,[sys.executable,"-c","print('x'*4097,flush=True)"],dict(os.environ),time.monotonic()+1))

    def test_status_cleanup_failure_retains_json_hold_contract(self):
        class FailedCleanup:
            stopped=0
            def __enter__(self):return self
            def __exit__(self,*_):raise m.CleanupHold("fixture cleanup failure")
        out=io.StringIO()
        with mock.patch.object(m,"Control",return_value=FailedCleanup()),mock.patch.object(m,"read_status",return_value=None),contextlib.redirect_stdout(out),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(m.main(["status"]),75)
        value=json.loads(out.getvalue())
        self.assertIsNone(value["android_thermal_severity"])
        self.assertEqual(value["decision_for_optional_jobs"],"HOLD")
        self.assertEqual(value["poll_interval_seconds"],10)


if __name__=="__main__":
    unittest.main(verbosity=2)
