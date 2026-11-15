"""Offline tests; all identities, state directories and credentials are fixtures."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import mikaya_background_bridge as bridge
import verified_ledger_hook as hook
import test_background_bridge as baseline


def save(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


class HookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        node = shutil.which('node')
        fixture = r'''
const fs=require('node:fs'),path=require('node:path');
const {fed,ledger}=require(process.argv[1]+'/ledger_event_collector.cjs').loadVerifier();
const root=process.argv[2],nodeDir=path.join(root,'fixture-node'),ledgerDir=path.join(root,'ledger');
const n=fed.initNode(nodeDir,'MIKAYA','fixture-f110'),now=Date.now();
ledger.initializeLedger({nodeDir,ledgerDir,nowMs:now-1});
ledger.appendDigest({nodeDir,ledgerDir,kind:'DEVICE_HEALTH_OBSERVED',payloadSha256:fed.sha('fixture observation'),nowMs:now});
console.log(JSON.stringify({fingerprint:n.fingerprint,nodeDir,ledgerDir}));
'''
        fixture_data = json.loads(subprocess.run([node, '-e', fixture, str(hook.ROOT), str(self.root)],
                                                capture_output=True, check=True).stdout)
        self.producer = {'schema': 'mikaya.device-observation-config.v1', 'node_dir': fixture_data['nodeDir'],
                         'ledger_dir': fixture_data['ledgerDir'], 'receipt_dir': str(self.root / 'receipts'),
                         'expected_fingerprint': fixture_data['fingerprint']}
        self.collector = {'schema': 'mikaya.verified-ledger-config.v1', 'ledger_dir': fixture_data['ledgerDir'],
                          'public_key_path': str(Path(fixture_data['nodeDir']) / 'identity-public.pem'),
                          'expected_fingerprint': fixture_data['fingerprint'], 'state_dir': str(self.root / 'projection'),
                          'max_age_ms': 300000}
        save(self.root / 'producer.json', self.producer)
        save(self.root / 'collector.json', self.collector)
        self.config = {'schema': 'mikaya.verified-event-integration.v1', 'node_path': str(Path(node).resolve()),
                       'producer_config_path': str(self.root / 'producer.json'),
                       'collector_config_path': str(self.root / 'collector.json')}
        self.config_path = self.root / 'integration.json'
        save(self.config_path, self.config)
        subprocess.run([node, str(hook.ROOT / 'ledger_event_collector.cjs'), '--config',
                        str(self.root / 'collector.json'), '--initialize-new'], capture_output=True, check=True)
        self.calls = []

    def runner(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[-3] == 'device_observation_producer.cjs':
            return subprocess.CompletedProcess(argv, 0, b'{"status":"DEVICE_OBSERVATION_SIGNED"}', b'')
        return subprocess.run(argv, **kwargs)

    def test_real_verified_projection_fixes_original_collector_gap_without_payment_counts(self):
        dashboard = bridge.load_pinned(bridge.ROOT / 'vendor/mikaya_unified.py', bridge.DASHBOARD_SHA)
        raw_row = self.root / 'raw.jsonl'
        raw_row.write_bytes((Path(self.collector['ledger_dir']) / '000001.json').read_bytes())
        self.assertEqual(dashboard.scan_event_spine(raw_row)['recognized_event_count'], 0)
        with hook.Session(self.config_path, runner=self.runner) as session:
            result = session.prepare()
            with session.read_path() as immutable:
                self.assertEqual(immutable.stat().st_mode & 0o777, 0o400)
                observed = dashboard.scan_event_spine(immutable)
                self.assertEqual(observed['recognized_event_count'], 1)
                self.assertEqual(observed['mint_gate_trigger_count'], 0)
                self.assertEqual(observed['mint_gate_success_with_matching_txid'], 0)
                self.assertEqual(observed['l402_challenge_count'], 0)
                self.assertFalse(observed['l402_payment_settled'])
                self.assertEqual(result['recognized_event_count'], 1)
                old = immutable
            session.prepare()
            self.assertFalse(old.exists())
        self.assertFalse(session.directory)

    def test_producer_failure_prevents_collector_and_readable_projection(self):
        def stopped(argv, **kwargs):
            self.calls.append(argv)
            return subprocess.CompletedProcess(argv, 2, b'', b'HOLD')
        with hook.Session(self.config_path, runner=stopped) as session:
            with self.assertRaises(ValueError):
                session.prepare()
            with self.assertRaises(ValueError):
                with session.read_path():
                    pass
        self.assertEqual(len(self.calls), 1)

    def test_config_change_and_receipt_hash_mismatch_hold(self):
        with hook.Session(self.config_path, runner=self.runner) as session:
            self.config_path.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'configuration_changed'):
                session.prepare()
        save(self.config_path, self.config)
        def altered(argv, **kwargs):
            response = self.runner(argv, **kwargs)
            if argv[-3] == 'ledger_event_collector.cjs':
                value = json.loads(response.stdout)
                value['projection_sha256'] = '0' * 64
                response.stdout = json.dumps(value).encode()
            return response
        with hook.Session(self.config_path, runner=altered) as session:
            with self.assertRaisesRegex(ValueError, 'changed_before_consumption'):
                session.prepare()

    def test_mismatched_owner_configs_and_unreviewed_sources_hold(self):
        altered = {**self.producer, 'expected_fingerprint': 'a' * 64}
        save(self.root / 'producer.json', altered)
        with self.assertRaisesRegex(ValueError, 'identity_mismatch'):
            hook.Session(self.config_path)
        save(self.root / 'producer.json', self.producer)
        with hook.Session(self.config_path, runner=self.runner) as session, patch.object(hook, 'SOURCE_PINS', {}):
            with self.assertRaisesRegex(ValueError, 'unreviewed_source'):
                session.prepare()

    def test_bound_pending_prefix_restores_without_producing_and_expires_honestly(self):
        now = [int(__import__('time').time() * 1000)]
        with hook.Session(self.config_path, runner=self.runner, now_ms=lambda: now[0]) as session:
            session.prepare(append_observation=False)
            self.assertEqual(len(self.calls), 1)
            self.assertEqual(self.calls[0][-3], 'ledger_event_collector.cjs')
            binding = session.pending_binding()
            summary = {'event_spine_status': 'read_only_local_file', 'recognized_event_count': 1, 'l402_challenge_count': 0}
            self.assertTrue(session.validate_binding(summary, binding, prefix=True))
            now[0] += 400000
            self.assertFalse(session.validate_binding(summary, binding))
            with self.assertRaisesRegex(ValueError, 'stale'):
                with session.read_path():
                    pass

    def test_execute_loader_rechecks_captured_bytes_after_python_pin_check(self):
        copied = self.root / 'package'
        copied.mkdir()
        for name in hook.SOURCE_PINS:
            target = copied / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(hook.ROOT / name, target)
        marker = self.root / 'must-not-execute'
        def raced(argv, **kwargs):
            if argv[-3] == 'ledger_event_collector.cjs':
                with (copied / 'ledger_event_collector.cjs').open('a') as stream:
                    stream.write('\nrequire("node:fs").writeFileSync(' + json.dumps(str(marker)) + ',"bad");\n')
            return self.runner(argv, **kwargs)
        with hook.Session(self.config_path, runner=raced) as session, patch.object(hook, 'ROOT', copied):
            with self.assertRaisesRegex(ValueError, 'command_hold'):
                session.prepare()
        self.assertFalse(marker.exists())


class BridgeHookTests(unittest.TestCase):
    # Reuse fixture setup/helpers without inheriting and re-running the old28tests.
    setUp = baseline.BridgeTests.setUp
    summary = baseline.BridgeTests.summary

    def run_hooked(self, outcomes=(), thermal=lambda: 0, fail=False, samples=2, pending=None, envelope=True, get_failures=0):
        owner = self
        class Events:
            calls = 0
            modes = []
            path = owner.home / 'events.jsonl'
            def __init__(self, _):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *_):
                pass
            def prepare(self, *, append_observation=True):
                Events.calls += 1
                Events.modes.append(append_observation)
                if fail:
                    raise ValueError('fixture hold')
                self.path.write_text('{"type":"INTERNAL_WATCHER","ts":"2026-11-14T16:00:00Z","data":{}}\n')
            def assert_fresh(self):
                pass
            def pending_binding(self):
                return {'fixture': 'verified-binding'}
            def validate_binding(self, summary, evidence, *, prefix=False):
                if evidence != self.pending_binding():
                    raise ValueError('fixture mismatch')
                return True
            @contextlib.contextmanager
            def read_path(self):
                yield self.path
        class DynamicTransport(baseline.Transport):
            remaining_get_failures = get_failures
            def __call__(self, request, timeout):
                if request.get_method() != 'POST':
                    if self.remaining_get_failures:
                        self.remaining_get_failures -= 1
                        raise bridge.pub.PublisherError('request_failed_or_invalid_response')
                    self.state = owner.dashboard.dashboard_state(Events.path)
                return super().__call__(request, timeout)
        lifecycle = []
        @contextlib.contextmanager
        def server(*_):
            lifecycle.append('start')
            try:
                yield None
            finally:
                lifecycle.append('stop')
        original = bridge.load_pinned
        def loader(path, digest):
            return SimpleNamespace(Session=Events) if Path(path).name == 'verified_ledger_hook.py' else original(path, digest)
        self.args.verified_ledger_config = Path('/synthetic/config.json')
        self.args.interval, self.args.max_samples = 60, samples
        if pending:
            bridge.write_pending(self.home, pending, {'fixture': 'verified-binding'} if envelope else None)
        transport = DynamicTransport(self, outcomes)
        with patch.object(bridge, 'load_pinned', loader), patch.object(bridge, 'local_dashboard', server):
            try:
                result = bridge.run(self.args, home=self.home, read_thermal=thermal, transport=transport,
                                    monotonic=self.clock.monotonic, sleep=self.clock.sleep,
                                    clock=self.clock.utc, emit=self.events.append, identity=False)
            except bridge.pub.PublisherError:
                result = 2
        self.prepare_modes = Events.modes
        return result, Events.calls, transport, lifecycle

    def test_retry_reuses_one_observation_and_keeps_one_server_for_two_cycles(self):
        result, calls, transport, lifecycle = self.run_hooked([503])
        self.assertEqual(result, 0)
        self.assertEqual(calls, 2)
        self.assertEqual(lifecycle, ['start', 'stop'])
        self.assertEqual(transport.posts[0], transport.posts[1])
        self.assertGreaterEqual(transport.times[-1] - transport.times[-2], 60)
        for raw in transport.posts:
            summary = json.loads(raw)['summary']
            self.assertEqual(summary['recognized_event_count'], 1)
            self.assertEqual(summary['l402_challenge_count'], 0)

    def test_thermal_hold_precedes_producer_and_invalid_source_precedes_publication(self):
        with self.assertRaises(bridge.WallLimit):
            self.run_hooked(thermal=lambda: 2)
        result, calls, transport, lifecycle = self.run_hooked(fail=True)
        self.assertEqual(result, 2)
        self.assertEqual(calls, 1)
        self.assertEqual(transport.posts, [])
        self.assertEqual(lifecycle, [])

    def test_permanent_publication_failure_stops_without_second_observation(self):
        result, calls, transport, lifecycle = self.run_hooked([401])
        self.assertEqual(result, 2)
        self.assertEqual(calls, 1)
        self.assertEqual(len(transport.posts), 1)
        self.assertEqual(lifecycle, ['start', 'stop'])

    def test_restart_reuses_valid_pending_uuid_and_restores_without_producer(self):
        pending = self.summary()
        pending.update(event_spine_status='read_only_local_file', recognized_event_count=1)
        result, calls, transport, _ = self.run_hooked(samples=1, pending=pending)
        self.assertEqual(result, 0)
        self.assertEqual(self.prepare_modes, [False])
        self.assertEqual(json.loads(transport.posts[0])['summary'], pending)

    def test_unbound_legacy_pending_requires_baseline_drain_and_is_preserved(self):
        pending = self.summary()
        result, calls, transport, lifecycle = self.run_hooked(samples=1, pending=pending, envelope=False)
        self.assertEqual(result, 2)
        self.assertEqual(calls, 0)
        self.assertEqual(transport.posts, [])
        self.assertEqual(lifecycle, [])
        self.assertEqual(bridge.read_pending(self.home), pending)

    def test_expired_pending_after_thermal_pause_gets_new_observation_and_uuid(self):
        self.args.max_wall = 600
        thermal = lambda: 2 if 20 < self.clock.seconds < 350 else 0
        result, calls, transport, lifecycle = self.run_hooked([503], thermal=thermal, samples=1)
        self.assertEqual(result, 0)
        self.assertEqual(self.prepare_modes, [True, True])
        self.assertNotEqual(json.loads(transport.posts[0])['summary']['sample_id'],
                            json.loads(transport.posts[-1])['summary']['sample_id'])
        self.assertEqual(lifecycle, ['start', 'stop'])

    def test_retryable_read_replacing_expired_pending_reuses_one_prepared_observation(self):
        import datetime as dt
        pending = self.summary(when=self.clock.utc() - dt.timedelta(seconds=400))
        pending.update(event_spine_status='read_only_local_file', recognized_event_count=1)
        result, calls, transport, lifecycle = self.run_hooked(samples=1, pending=pending, get_failures=1)
        self.assertEqual(result, 0)
        self.assertEqual(self.prepare_modes, [True])
        self.assertEqual(len(transport.posts), 1)
        self.assertNotEqual(json.loads(transport.posts[0])['summary']['sample_id'], pending['sample_id'])


if __name__ == '__main__':
    unittest.main()
