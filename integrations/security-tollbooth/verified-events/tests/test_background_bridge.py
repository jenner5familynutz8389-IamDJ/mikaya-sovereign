"""Offline contract tests. Every token and home in this file is synthetic."""
import contextlib
import datetime as dt
import errno
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

import mikaya_background_bridge as bridge


SECRET = 'a' * 64  # Public test fixture; never reads a user's home or device.
BASE = dt.datetime(2026, 11, 14, 16, 0, tzinfo=dt.timezone.utc)


class Clock:
    def __init__(self):
        self.seconds = 0.0

    def monotonic(self):
        return self.seconds

    def sleep(self, seconds):
        self.seconds += seconds

    def utc(self):
        return BASE + dt.timedelta(seconds=self.seconds)


class Response:
    def __init__(self, value):
        self.raw = json.dumps(value).encode()
        self.headers = {'Content-Length': str(len(self.raw))}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def getcode(self):
        return 200

    def read(self, limit):
        return self.raw[:limit]


class Transport:
    def __init__(self, case, outcomes=(), state=None):
        self.case, self.outcomes = case, list(outcomes)
        self.state = state or case.dashboard.dashboard_state(None)
        self.posts, self.times, self.timeouts, self.gets = [], [], [], 0

    def __call__(self, request, timeout):
        self.timeouts.append(timeout)
        if request.get_method() != 'POST':
            self.gets += 1
            return Response(self.state)
        self.posts.append(request.data)
        self.times.append(self.case.clock.seconds)
        payload = json.loads(request.data)
        self.case.assertEqual(bridge.read_pending(self.case.home), payload['summary'])
        self.case.assertEqual(request.get_header('X-mikaya-device-token'), SECRET)
        self.case.assertEqual(request.full_url, bridge.ENDPOINT)
        if self.outcomes:
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, int):
                raise urllib.error.HTTPError(request.full_url, outcome, SECRET, {}, io.BytesIO(SECRET.encode()))
            if isinstance(outcome, Exception):
                raise outcome
            if outcome is not None:
                return Response(outcome)
        return Response({'accepted': True, 'duplicate': len(self.posts) > 1,
                         'received_at': self.case.clock.utc().isoformat().replace('+00:00', 'Z')})


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.directory = bridge.pub.state_directory(self.home, create=True)
        token = self.directory / 'device-token'
        token.write_text(SECRET)
        token.chmod(0o600)
        self.clock = Clock()
        self.events = []
        self.dashboard = bridge.load_pinned(bridge.ROOT / 'vendor/mikaya_unified.py', bridge.DASHBOARD_SHA)
        self.args = SimpleNamespace(source=bridge.ROOT / 'vendor/mikaya_unified.py',
                                    mtg_source=bridge.ROOT / 'vendor/mtg_nice_policy.py',
                                    endpoint=bridge.ENDPOINT, event_spine=None, event_format=None,
                                    interval=30, max_samples=1, max_wall=300, max_attempts=4)

    def summary(self, when=None):
        return bridge.pub.project_summary(self.dashboard.dashboard_state(None), 'unbound', bridge.DASHBOARD_SHA,
                                          clock=lambda: when or self.clock.utc())

    def execute(self, transport, thermal=lambda: 0):
        with patch.object(bridge, 'local_dashboard', lambda *_: contextlib.nullcontext(None)), \
                patch.object(bridge.random, 'uniform', return_value=0):
            return bridge.run(self.args, home=self.home, read_thermal=thermal, transport=transport,
                              monotonic=self.clock.monotonic, sleep=self.clock.sleep,
                              clock=self.clock.utc, emit=self.events.append, identity=False)

    def test_lost_ack_and_transient_http_retry_identical_durable_payload(self):
        for failure in (OSError('untrusted provider echo ' + SECRET), 409, 429, 503):
            with self.subTest(failure=type(failure).__name__ if isinstance(failure, Exception) else failure):
                transport = Transport(self, [failure])
                self.assertEqual(self.execute(transport), 0)
                self.assertEqual(len(transport.posts), 2)
                self.assertEqual(transport.posts[0], transport.posts[1])
                self.assertGreaterEqual(transport.times[1] - transport.times[0], 15)
                self.assertEqual(transport.gets, 1)
                self.assertIsNone(bridge.read_pending(self.home))
                self.assertNotIn(SECRET, json.dumps(self.events))
                self.assertNotIn(SECRET.encode(), transport.posts[0])
                self.assertTrue(all(0 < timeout <= 8 for timeout in transport.timeouts))

    def test_retry_budget_preserves_sample_for_a_later_process(self):
        self.args.max_attempts = 2
        offline = Transport(self, [OSError(SECRET), 429])
        self.assertEqual(self.execute(offline), 75)
        pending = bridge.read_pending(self.home)
        self.assertEqual(json.loads(offline.posts[0])['summary'], pending)
        recovered = Transport(self)
        self.assertEqual(self.execute(recovered), 0)
        self.assertEqual(recovered.posts[0], offline.posts[0])
        self.assertEqual(recovered.gets, 0)

    def test_auth_rejection_stops_without_retry_and_preserves_pending(self):
        transport = Transport(self, [401])
        self.assertEqual(self.execute(transport), 2)
        self.assertEqual(len(transport.posts), 1)
        self.assertIsNotNone(bridge.read_pending(self.home))
        self.assertNotIn(SECRET, json.dumps(self.events))

    def test_redirect_and_invalid_summary_stop_with_the_same_pending_sample(self):
        for status in (302, 400):
            with self.subTest(status=status):
                transport = Transport(self, [status])
                self.assertEqual(self.execute(transport), 2)
                self.assertEqual(len(transport.posts), 1)
                self.assertEqual(bridge.read_pending(self.home), json.loads(transport.posts[0])['summary'])
                self.assertEqual(self.events[-1]['event'], 'publish_hold')

    def test_prior_409_does_not_make_a_later_missing_token_retryable(self):
        class RemoveTokenAfter409(Transport):
            def __call__(inner, request, timeout):
                try:
                    return super().__call__(request, timeout)
                except urllib.error.HTTPError as error:
                    if error.code == 409:
                        (self.directory / 'device-token').unlink()
                    raise

        transport = RemoveTokenAfter409(self, [409])
        self.assertEqual(self.execute(transport), 2)
        self.assertEqual(len(transport.posts), 1)
        self.assertEqual(self.events[-1]['event'], 'publish_hold')
        self.assertIsNone(self.events[-1]['http_status'])
        self.assertIsNotNone(bridge.read_pending(self.home))

    def test_unverified_receipt_retries_same_sample(self):
        transport = Transport(self, [{'accepted': True, 'duplicate': False, 'received_at': SECRET}])
        self.assertEqual(self.execute(transport), 0)
        self.assertEqual(transport.posts[0], transport.posts[1])
        self.assertNotIn(SECRET, json.dumps(self.events))

    def test_expired_pending_is_resampled_and_labelled(self):
        old = self.summary(BASE - dt.timedelta(seconds=301))
        bridge.write_pending(self.home, old)
        transport = Transport(self)
        self.assertEqual(self.execute(transport), 0)
        new = json.loads(transport.posts[0])['summary']
        self.assertNotEqual(new['sample_id'], old['sample_id'])
        self.assertEqual(new['observed_at'], self.clock.utc().isoformat(timespec='milliseconds').replace('+00:00', 'Z'))
        self.assertIn({'event': 'pending_expired_resample', 'sample_id': old['sample_id']}, self.events)

    def test_exact_five_minute_pending_remains_the_same_sample(self):
        # Initial safe readings consume ten seconds: age is exactly 300 at first send.
        old = self.summary(BASE - dt.timedelta(seconds=290))
        bridge.write_pending(self.home, old)
        transport = Transport(self)
        self.assertEqual(self.execute(transport), 0)
        self.assertEqual(json.loads(transport.posts[0])['summary'], old)
        self.assertFalse(any(event['event'] == 'pending_expired_resample' for event in self.events))

    def test_private_atomic_outbox_and_strict_nine_field_allowlist(self):
        first, second = self.summary(), self.summary()
        bridge.write_pending(self.home, first)
        original = bridge.os.replace

        def inspect_replace(source, target):
            self.assertEqual(bridge.read_pending(self.home), first)
            self.assertEqual(os.stat(source).st_mode & 0o777, 0o600)
            self.assertEqual(set(json.loads(Path(source).read_bytes())), bridge.FIELDS)
            return original(source, target)

        with patch.object(bridge.os, 'replace', side_effect=inspect_replace):
            bridge.write_pending(self.home, second)
        pending = self.directory / 'pending-summary.json'
        self.assertEqual(pending.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(SECRET.encode(), pending.read_bytes())
        self.assertEqual(list(self.directory.glob('.pending-*.tmp')), [])
        with self.assertRaises(bridge.pub.PublisherError):
            bridge.write_pending(self.home, dict(second, token=SECRET))
        self.assertEqual(bridge.read_pending(self.home), second)

    def test_pending_wrong_mode_is_rejected(self):
        pending = self.directory / 'pending-summary.json'
        bridge.write_pending(self.home, self.summary())
        pending.chmod(0o644)
        with self.assertRaises(bridge.pub.PublisherError):
            bridge.read_pending(self.home)

    def test_pending_symlink_is_rejected(self):
        pending = self.directory / 'pending-summary.json'
        bridge.write_pending(self.home, self.summary())
        target = self.directory / 'target'
        pending.rename(target)
        pending.symlink_to(target)
        with self.assertRaises(bridge.pub.PublisherError):
            bridge.read_pending(self.home)

    def test_pending_hardlink_is_rejected_when_supported(self):
        pending = self.directory / 'pending-summary.json'
        bridge.write_pending(self.home, self.summary())
        linked = self.directory / 'linked'
        link = getattr(os, 'link', None)
        if link is None:
            self.skipTest('hardlinks unavailable: os.link is not provided by this Python platform')
        try:
            link(pending, linked)
        except NotImplementedError:
            self.skipTest('hardlinks unavailable: os.link is unsupported by this Python platform')
        except OSError as error:
            if error.errno in {errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS}:
                self.skipTest('hardlinks unavailable: filesystem/platform reports unsupported operation')
            raise
        self.assertEqual(pending.stat().st_nlink, 2)
        with self.assertRaises(bridge.pub.PublisherError):
            bridge.read_pending(self.home)

    def test_single_writer_lock_is_exclusive_and_private(self):
        with bridge.pub.publisher_lock(self.home):
            with self.assertRaisesRegex(bridge.pub.PublisherError, 'publisher_already_running'):
                with bridge.pub.publisher_lock(self.home):
                    self.fail('second writer acquired lock')
        self.assertEqual((self.directory / 'publisher.lock').stat().st_mode & 0o777, 0o600)
        with bridge.pub.publisher_lock(self.home):
            pass

    def test_thermal_initial_and_resume_need_two_safe_ten_second_readings(self):
        severity = [0]
        gate = bridge.ThermalGate(lambda: severity[0], self.clock.monotonic)
        self.assertFalse(gate.poll())
        self.clock.seconds = 9
        self.assertFalse(gate.poll(force=True))
        self.clock.seconds = 10
        self.assertTrue(gate.poll(force=True))
        for unsafe in (None, True, 2, 6, -1, '0'):
            severity[0] = unsafe
            self.assertFalse(gate.poll(force=True))
            severity[0] = 1
            self.assertFalse(gate.poll(force=True))
            self.clock.sleep(9)
            self.assertFalse(gate.poll(force=True))
            self.clock.sleep(1)
            self.assertTrue(gate.poll(force=True))

    def test_thermal_hold_consumes_wall_budget_without_collection_or_upload(self):
        self.args.max_wall = 25
        transport = Transport(self)
        with self.assertRaises(bridge.WallLimit):
            self.execute(transport, thermal=lambda: None)
        self.assertEqual(self.clock.seconds, 25)
        self.assertEqual(transport.gets, 0)
        self.assertEqual(transport.posts, [])
        self.assertIsNone(bridge.read_pending(self.home))

    def test_installed_mtg_policy_change_invalidates_the_review(self):
        installed = self.home / 'mtg_policy.py'
        shutil.copyfile(self.args.mtg_source, installed)
        reader = bridge.thermal_reader(installed)
        status = reader()
        self.assertTrue(status is None or type(status) is int and 0 <= status <= 6)
        with installed.open('a') as stream:
            stream.write('\n# Owner policy changed\n')
        with self.assertRaisesRegex(ValueError, 'reviewed_source_pin_failed'):
            reader()

    def test_modified_dashboard_source_and_changed_endpoint_are_refused(self):
        changed = self.home / 'dashboard.py'
        shutil.copyfile(self.args.source, changed)
        with changed.open('a') as stream:
            stream.write('\n# Unreviewed change\n')
        self.args.source = changed
        transport = Transport(self)
        with self.assertRaisesRegex(ValueError, 'reviewed_source_pin_failed'):
            self.execute(transport)
        self.assertEqual(transport.posts, [])
        self.args.source = bridge.ROOT / 'vendor/mikaya_unified.py'
        self.args.endpoint = 'https://other.example.com/api/runtime/publish'
        with self.assertRaisesRegex(bridge.pub.PublisherError, 'invalid_bounded_bridge_configuration'):
            self.execute(transport)

    def test_subprocess_interface_only_allows_fixed_getprop_queries(self):
        gate = SimpleNamespace(poll=lambda **_: True)
        runner = bridge.device_runner(gate)
        with patch.object(bridge.subprocess, 'run') as command:
            self.assertNotEqual(runner(['sh', '-c', 'arbitrary']).returncode, 0)
            self.assertNotEqual(runner(['git', 'status']).returncode, 0)
            command.assert_not_called()
            runner(['getprop', 'ro.product.model'], timeout=3)
            command.assert_called_once_with(['getprop', 'ro.product.model'], capture_output=True,
                                            text=True, check=False, timeout=3)

    def test_main_lowers_priority_to_at_least_plus_fifteen(self):
        with patch.object(bridge.os, 'getpriority', return_value=0), \
                patch.object(bridge.os, 'nice') as nice, \
                patch.object(bridge, 'run', return_value=0), \
                patch.object(bridge, 'hard_wall', lambda *_: contextlib.nullcontext()):
            self.assertEqual(bridge.main(['--source', str(self.args.source)]), 0)
            nice.assert_called_once_with(15)

    def test_sample_count_and_success_cadence_are_bounded(self):
        self.args.max_samples = 2
        transport = Transport(self)
        self.assertEqual(self.execute(transport), 0)
        self.assertEqual(len(transport.posts), 2)
        self.assertGreaterEqual(transport.times[1] - transport.times[0], self.args.interval)
        self.assertNotEqual(json.loads(transport.posts[0])['summary']['sample_id'],
                            json.loads(transport.posts[1])['summary']['sample_id'])

    def test_default_source_is_not_configured_and_mismatching_existing_data_holds(self):
        transport = Transport(self)
        self.assertEqual(self.execute(transport), 0)
        summary = json.loads(transport.posts[0])['summary']
        self.assertEqual(summary['event_spine_status'], 'not_configured')
        state = self.dashboard.dashboard_state(None)
        state['l402']['event_spine']['source_status'] = 'read_only_local_file'
        mismatch = Transport(self, state=state)
        self.assertEqual(self.execute(mismatch), 2)
        self.assertEqual(mismatch.posts, [])

    def test_event_path_requires_explicit_reviewed_format(self):
        self.args.event_spine = self.home / 'events.jsonl'
        with self.assertRaisesRegex(bridge.pub.PublisherError, 'reviewed_event_path_and_format_required'):
            self.execute(Transport(self))

    def test_explicit_reviewed_jsonl_source_roundtrips_only_redacted_counts(self):
        events = self.home / 'reviewed-events.jsonl'
        events.write_text('\n'.join(json.dumps(event) for event in (
            {'type': 'L402_LIVE_GATE', 'data': {'action': '402_REJECT', 'private': SECRET}},
            {'type': 'INTERNAL_WATCHER', 'data': {'private': SECRET}},
            {'type': 'UNRECOGNIZED', 'data': {'private': SECRET}},
        )) + '\n')
        self.args.event_spine = events
        self.args.event_format = bridge.EVENT_FORMAT
        transport = Transport(self, state=self.dashboard.dashboard_state(events))
        self.assertEqual(self.execute(transport), 0)
        summary = json.loads(transport.posts[0])['summary']
        self.assertEqual(summary['event_spine_status'], 'read_only_local_file')
        self.assertEqual(summary['recognized_event_count'], 2)
        self.assertEqual(summary['l402_challenge_count'], 1)
        self.assertNotIn(SECRET.encode(), transport.posts[0])
        self.assertNotIn(SECRET, json.dumps(self.events))

    def test_owned_dashboard_cleanup_and_preexisting_listener_ownership(self):
        gate = SimpleNamespace(fresh=lambda: True)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with bridge.local_dashboard(self.dashboard, None, gate, ('127.0.0.1', 0)) as owned:
            address = owned.server_address
            url = 'http://127.0.0.1:%d/api/status' % address[1]
            with opener.open(url, timeout=1) as response:
                self.assertEqual(json.load(response)['l402']['event_spine']['source_status'], 'not_configured')
            with bridge.local_dashboard(self.dashboard, None, gate, address) as preexisting:
                self.assertIsNone(preexisting)
            # Leaving the second context must preserve the first listener.
            with opener.open(url, timeout=1) as response:
                self.assertEqual(response.getcode(), 200)
        with socket.socket() as client:
            client.settimeout(1)
            self.assertNotEqual(client.connect_ex(address), 0)

    def test_hard_wall_interrupts_a_blocking_operation(self):
        started = time.monotonic()
        with self.assertRaises(bridge.WallLimit):
            with bridge.hard_wall(0.05):
                time.sleep(1)
        self.assertLess(time.monotonic() - started, 0.5)

    def test_runit_template_is_down_and_finish_stops_only_its_own_permanent_failure(self):
        template = bridge.ROOT / 'runit-template'
        self.assertTrue((template / 'down').is_file())
        supervise = self.home / 'supervise'
        supervise.mkdir()
        control = supervise / 'control'
        control.write_text('')
        for status in (0, 75):
            result = subprocess.run(['/bin/sh', str(template / 'finish'), str(status)],
                                    cwd=self.home, capture_output=True, timeout=2)
            self.assertEqual(result.returncode, 0)
            self.assertFalse((self.home / 'down').exists())
            self.assertEqual(control.read_text(), '')
        result = subprocess.run(['/bin/sh', str(template / 'finish'), '2'],
                                cwd=self.home, capture_output=True, timeout=2)
        self.assertEqual(result.returncode, 0)
        self.assertTrue((self.home / 'down').is_file())
        self.assertEqual(control.read_text(), 'd')

    def test_private_log_appends_and_refuses_unsafe_files(self):
        with bridge.private_log(self.home):
            print('safe receipt one')
            print('safe hold', file=bridge.sys.stderr)
        with bridge.private_log(self.home):
            print('safe receipt two')
        path = self.directory / 'bridge.log'
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.read_text(), 'safe receipt one\nsafe hold\nsafe receipt two\n')
        path.chmod(0o644)
        with self.assertRaisesRegex(bridge.pub.PublisherError, 'unsafe_private_log'):
            with bridge.private_log(self.home):
                self.fail('unsafe file accepted')
        path.chmod(0o600)
        target = self.directory / 'old.log'
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises(OSError):
            with bridge.private_log(self.home):
                self.fail('log symlink followed')
        path.unlink()
        os.mkfifo(path, 0o600)
        with self.assertRaises(OSError):
            with bridge.private_log(self.home):
                self.fail('log FIFO opened')

    def test_runit_template_has_explicit_native_getprop_path_and_private_logging(self):
        script = (bridge.ROOT / 'runit-template/run').read_text()
        self.assertIn('PATH=/data/data/com.termux/files/usr/bin:/system/bin:/system/xbin', script)
        self.assertIn('export PATH', script)
        self.assertIn('--private-log', script)


if __name__ == '__main__':
    unittest.main()
