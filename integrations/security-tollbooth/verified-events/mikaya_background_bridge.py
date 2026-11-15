#!/usr/bin/env python3
"""Bounded one-way latest-status bridge; no service, pairing, or command interface."""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import errno
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import random
import re
import signal
import stat
import subprocess
import sys
import threading
import time
import types
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent
PUBLISHER_SHA = '9777e4f8e7d6edc587dd858dbe6350924290ddbf7cf7dd5a37676738b18b7647'
DASHBOARD_SHA = '47ed2335f8b3741b590d76c7a2a91c416fbe93d8f215620b018576529f4cd66c'
MTG_SHA = '6d41877fa3e288cf17cfab8b7b323090a001eacc0770108404aa3e7c18cad933'
VERIFIED_EVENT_HOOK_SHA = '329c44c717f7080c1cd024322d7238f5952a9ca7c66bdfd3a08a0e3eb775f3fc'
ENDPOINT = 'https://api-v2.appdeploy.ai/app/mikaya-runtime-vv96kk/api/runtime/publish'
EVENT_FORMAT = 'mikaya-event-spine-jsonl-v1'
FIELDS = {'schema', 'sample_id', 'observed_at', 'source_revision', 'source_sha256',
          'dashboard_reachable', 'event_spine_status', 'recognized_event_count', 'l402_challenge_count'}
EVENT_FIELDS = ('event_spine_status', 'recognized_event_count', 'l402_challenge_count')


def pinned_bytes(path, digest):
    """Execute only the exact reviewed bytes, never a later path replacement."""
    try:
        info = Path(path).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 131072:
            raise ValueError()
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as stream:
            actual = os.fstat(stream.fileno())
            raw = stream.read(131073)
        if ((actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino) or
                len(raw) > 131072 or hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError()
        return raw
    except (OSError, ValueError):
        raise ValueError('reviewed_source_pin_failed') from None


def load_pinned(path, digest):
    module = types.ModuleType('_mikaya_reviewed_' + digest[:12])
    module.__file__ = str(Path(path).resolve())
    exec(compile(pinned_bytes(path, digest), str(path), 'exec'), module.__dict__)
    return module


pub = load_pinned(ROOT / 'vendor/mikaya_runtime_publish.py', PUBLISHER_SHA)


class WallLimit(RuntimeError):
    pass


class Budget:
    def __init__(self, seconds, monotonic=time.monotonic, sleep=time.sleep):
        self.now, self.sleep = monotonic, sleep
        self.end = monotonic() + seconds

    def remaining(self):
        left = self.end - self.now()
        if left <= 0:
            raise WallLimit()
        return left

    def pause(self, seconds):
        self.sleep(min(seconds, self.remaining()))
        self.remaining()


@contextlib.contextmanager
def hard_wall(seconds):
    # Main-thread Unix/Termux alarm bounds DNS, slow reads, thermal waits and cleanup.
    def expired(*_):
        raise WallLimit()
    old = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def thermal_reader(path):
    module = load_pinned(path, MTG_SHA)

    def read():
        # An owner policy update invalidates this review; never keep an old policy silently.
        pinned_bytes(path, MTG_SHA)
        return module.read_status()
    return read


class ThermalGate:
    def __init__(self, read, now=time.monotonic):
        self.read, self.now = read, now
        self.first_safe = self.last = None
        self.ready = False
        self.severity = None

    def poll(self, force=False):
        now = self.now()
        if force or self.last is None or now - self.last >= 10:
            self.severity = self.read()
            self.last = now
            if type(self.severity) is not int or self.severity not in (0, 1):
                self.first_safe, self.ready = None, False
            elif self.first_safe is None:
                self.first_safe, self.ready = now, False
            elif now - self.first_safe >= 10:
                self.ready = True
        return self.ready

    def fresh(self):
        return self.ready and self.last is not None and self.now() - self.last <= 10


def device_runner(gate):
    def run(args, **kwargs):
        if args == ['mikaya-nice', 'status']:
            state = {'decision_for_optional_jobs': 'ALLOW' if gate.poll(force=True) else 'HOLD'}
            return subprocess.CompletedProcess(args, 0, json.dumps(state), '')
        if args in (['getprop', 'ro.product.model'], ['getprop', 'ro.board.platform'],
                    ['getprop', 'ro.build.version.release']):
            return subprocess.run(args, capture_output=True, text=True, check=False, **kwargs)
        # source_provenance's optional git lookup is deliberately unbound, without subprocesses.
        return subprocess.CompletedProcess(args, 1, '', '')
    return run


@contextlib.contextmanager
def event_path(source):
    # The verified source retains its immutable path while a reader consumes it.
    with source.read_path() if hasattr(source, 'read_path') else contextlib.nullcontext(source) as path:
        yield path


@contextlib.contextmanager
def local_dashboard(module, event_spine, gate, address=('127.0.0.1', 8787)):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in ('/', '/api/status'):
                self.send_error(404)
                return
            if not gate.fresh():
                self.send_error(503)
                return
            try:
                with event_path(event_spine) as current:
                    raw = (module.HTML if self.path == '/' else
                           json.dumps(module.dashboard_state(current))).encode('utf-8')
            except ValueError:
                self.send_error(503)
                return
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8' if self.path == '/' else 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; style-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_):
            pass

    try:
        server = ThreadingHTTPServer(address, Handler)
    except OSError as error:
        if error.errno != errno.EADDRINUSE:
            raise
        yield None  # A preexisting listener is never stopped or replaced.
        return
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.1}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=0.5)


def validate_summary(summary):
    try:
        if not isinstance(summary, dict) or set(summary) != FIELDS:
            raise ValueError()
        sid = uuid.UUID(summary['sample_id'])
        observed = dt.datetime.fromisoformat(summary['observed_at'].replace('Z', '+00:00'))
        canonical_time = observed.astimezone(dt.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        if (str(sid) != summary['sample_id'] or sid.version != 4 or observed.utcoffset() is None or
                canonical_time != summary['observed_at'] or summary['schema'] != 'mikaya.runtime-summary.v1' or
                summary['dashboard_reachable'] is not True or summary['source_sha256'] != DASHBOARD_SHA or
                not re.fullmatch(r'(?:[a-f0-9]{40}|unbound)', summary['source_revision']) or
                summary['event_spine_status'] not in ('not_configured', 'not_accessible', 'read_only_local_file') or
                any(type(summary[k]) is not int or not 0 <= summary[k] <= 1000000000 for k in EVENT_FIELDS[1:])):
            raise ValueError()
        return observed
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise pub.PublisherError('invalid_pending_summary') from None


def fsync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_pending(home, summary, evidence=None):
    validate_summary(summary)
    directory = pub.state_directory(home)
    target = directory / 'pending-summary.json'
    temporary = directory / ('.pending-' + str(uuid.uuid4()) + '.tmp')
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            record = summary if evidence is None else {'schema': 'mikaya.verified-pending-summary.v1',
                                                       'summary': summary, 'evidence': evidence}
            stream.write(json.dumps(record, separators=(',', ':')).encode('utf-8'))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        fsync_directory(directory)
    finally:
        temporary.unlink(missing_ok=True)


def read_pending_record(home):
    path = pub.state_directory(home) / 'pending-summary.json'
    if not path.exists() and not path.is_symlink():
        return None
    try:
        record = json.loads(pub.read_private_file(path, 8192).decode('utf-8'))
    except (ValueError, UnicodeError):
        raise pub.PublisherError('invalid_pending_summary') from None
    if (isinstance(record, dict) and set(record) == {'schema', 'summary', 'evidence'} and
            record['schema'] == 'mikaya.verified-pending-summary.v1'):
        validate_summary(record['summary'])
        return record
    validate_summary(record)
    return {'summary': record, 'evidence': None}


def read_pending(home):
    record = read_pending_record(home)
    return record['summary'] if record else None


def clear_pending(home):
    directory = pub.state_directory(home)
    (directory / 'pending-summary.json').unlink()
    fsync_directory(directory)


@contextlib.contextmanager
def private_log(home=None):
    directory = pub.state_directory(Path.home() if home is None else home)
    fd = os.open(directory / 'bridge.log', os.O_WRONLY | os.O_APPEND | os.O_CREAT |
                 getattr(os, 'O_NOFOLLOW', 0) | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600):
            raise pub.PublisherError('unsafe_private_log')
        with os.fdopen(fd, 'a', buffering=1, closefd=False) as stream, \
                contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            yield
    finally:
        os.close(fd)


class BoundedTransport:
    def __init__(self, budget, transport=None):
        self.budget, self.status = budget, None
        self.send = transport or pub.build_transport().open

    def __call__(self, request, timeout):
        self.status = None
        try:
            return self.send(request, timeout=min(timeout, self.budget.remaining()))
        except urllib.error.HTTPError as error:
            self.status = error.code
            raise


def send_pending(endpoint, summary, home, transport):
    token = pub.read_device_token(home)
    payload = json.dumps({'action': 'publish', 'summary': summary}, separators=(',', ':')).encode('utf-8')
    request = urllib.request.Request(endpoint, data=payload, method='POST', headers={
        'Content-Type': 'application/json', 'Accept': 'application/json', 'X-Mikaya-Device-Token': token})
    reply = pub.request_json(request, pub.MAX_RESPONSE_BYTES, transport)
    try:
        received = dt.datetime.fromisoformat(reply['received_at'].replace('Z', '+00:00'))
        if (reply.get('accepted') is not True or type(reply.get('duplicate')) is not bool or
                len(reply['received_at']) > 40 or received.utcoffset() is None):
            raise ValueError()
    except (ValueError, TypeError, KeyError, AttributeError):
        raise pub.PublisherError('device_receipt_unverified') from None
    return {'accepted': True, 'duplicate': reply['duplicate'], 'sample_id': summary['sample_id'],
            'observed_at': summary['observed_at'], 'received_at': reply['received_at']}


def run(args, *, home=None, read_thermal=None, transport=None, monotonic=time.monotonic,
        sleep=time.sleep, clock=lambda: dt.datetime.now(dt.timezone.utc), emit=None, identity=True):
    home = Path.home() if home is None else Path(home)
    emit = emit or (lambda item: print(json.dumps(item, separators=(',', ':')), flush=True))
    endpoint = pub.validate_endpoint(args.endpoint)
    if (endpoint != ENDPOINT or not 1 <= args.max_samples <= 120 or not 30 <= args.interval <= 3600 or
            not 15 <= args.max_wall <= 7200 or not 1 <= args.max_attempts <= 6):
        raise pub.PublisherError('invalid_bounded_bridge_configuration')
    if bool(args.event_spine) != bool(args.event_format) or (args.event_format and args.event_format != EVENT_FORMAT):
        raise pub.PublisherError('reviewed_event_path_and_format_required')
    if args.event_spine and not Path(args.event_spine).is_absolute():
        raise pub.PublisherError('absolute_reviewed_event_path_required')
    verified_config = getattr(args, 'verified_ledger_config', None)
    if verified_config and (args.event_spine or args.event_format):
        raise pub.PublisherError('choose_one_reviewed_event_source')
    dashboard = load_pinned(args.source, DASHBOARD_SHA)
    gate = ThermalGate(read_thermal or thermal_reader(args.mtg_source), monotonic)
    budget = Budget(args.max_wall, monotonic, sleep)
    bounded = BoundedTransport(budget, transport)
    runner = device_runner(gate)
    completed, attempts, next_attempt = 0, 0, monotonic()
    with pub.publisher_lock(home), contextlib.ExitStack() as stack:
        verified_events = (stack.enter_context(load_pinned(ROOT / 'verified_ledger_hook.py',
                           VERIFIED_EVENT_HOOK_SHA).Session(verified_config)) if verified_config else None)
        selected_events = verified_events or args.event_spine
        observation_prepared = False
        discarded_pending_id = None
        server_started = False
        while completed < args.max_samples:
            budget.remaining()
            if not gate.poll() or monotonic() < next_attempt:
                budget.pause(min(10, max(0.01, next_attempt - monotonic())) if gate.ready else 10)
                continue
            pinned_bytes(args.source, DASHBOARD_SHA)
            if identity:
                pub.require_device(runner)
                identity = False
            pending = read_pending_record(home)
            summary = pending['summary'] if pending else None
            discarded = False
            if pending and verified_events is not None:
                if pending['evidence'] is None:
                    raise pub.PublisherError('legacy_pending_requires_baseline_drain')
                try:
                    if not verified_events.validate_binding(summary, pending['evidence']):
                        summary, discarded = None, True
                except ValueError:
                    raise pub.PublisherError('pending_evidence_binding_hold') from None
            elif pending and pending['evidence'] is not None:
                raise pub.PublisherError('verified_pending_requires_config')
            if summary:
                age = (clock() - validate_summary(summary)).total_seconds()
                if age > 300 or age < -300:
                    emit({'event': 'pending_expired_resample' if age > 300 else 'pending_clock_skew_resample',
                          'sample_id': summary['sample_id']})
                    summary = None
                    discarded = True
            if verified_events is not None:
                try:
                    if discarded and discarded_pending_id != pending['summary']['sample_id']:
                        observation_prepared = False
                        discarded_pending_id = pending['summary']['sample_id']
                    if not observation_prepared:
                        verified_events.prepare(append_observation=summary is None)
                        observation_prepared = True
                    if summary is not None:
                        if not verified_events.validate_binding(summary, pending['evidence'], prefix=True):
                            raise ValueError('pending_evidence_expired')
                    verified_events.assert_fresh()
                except Exception:
                    raise pub.PublisherError('verified_event_source_hold') from None
            if not server_started:
                owned = stack.enter_context(local_dashboard(dashboard, selected_events, gate))
                emit({'event': 'dashboard_owned' if owned else 'dashboard_preexisting'})
                server_started = True
            bounded.status = None
            try:
                if summary is None:
                    revision, digest = pub.source_provenance(args.source, runner=runner)
                    state = pub.request_json(urllib.request.Request(pub.LOCAL_STATUS, headers={'Accept': 'application/json'}),
                                             pub.MAX_DASHBOARD_BYTES, bounded)
                    summary = pub.project_summary(state, revision, digest, clock=clock)
                    with event_path(selected_events) as current:
                        expected = pub.project_summary(dashboard.dashboard_state(current), revision, digest, clock=clock)
                    if any(summary[k] != expected[k] for k in EVENT_FIELDS):
                        raise pub.PublisherError('dashboard_event_source_not_reviewed')
                    write_pending(home, summary, verified_events.pending_binding() if verified_events else None)
                if not gate.poll(force=True):
                    continue
                if verified_events is not None:
                    verified_events.assert_fresh()
                receipt = send_pending(endpoint, summary, home, bounded)
            except pub.PublisherError as error:
                attempts += 1
                status = bounded.status
                retryable = (status in (409, 429) or (status is not None and 500 <= status <= 599) or
                             (status is None and str(error) in ('request_failed_or_invalid_response',
                              'invalid_json_response', 'device_receipt_unverified')))
                event = ('retry_pending' if summary is not None else 'retry_attempt') if retryable else 'publish_hold'
                emit({'event': event, 'http_status': status,
                      'reason': 'retryable_http_' + str(status) if retryable and status else str(error),
                      'attempt': attempts})
                if not retryable:
                    return 2
                if attempts >= args.max_attempts:
                    return 75
                next_attempt = monotonic() + min(60, 15 * 2 ** (attempts - 1)) + random.uniform(0, 3)
                continue
            clear_pending(home)
            completed, attempts = completed + 1, 0
            observation_prepared = False
            discarded_pending_id = None
            emit({'event': 'publish_accepted', **receipt})
            next_attempt = monotonic() + args.interval
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True, help='Reviewed dashboard source; required SHA256 is fixed')
    parser.add_argument('--mtg-source', type=Path, default=Path.home() / '.local/share/mikaya/mtg_policy.py')
    parser.add_argument('--endpoint', default=ENDPOINT)
    parser.add_argument('--event-spine', type=Path)
    parser.add_argument('--event-format', choices=[EVENT_FORMAT])
    parser.add_argument('--verified-ledger-config', type=Path,
                        help='Reviewed private fixed-observation/verified-ledger integration config')
    parser.add_argument('--interval', type=int, default=60)
    parser.add_argument('--max-samples', type=int, default=10)
    parser.add_argument('--max-wall', type=int, default=1800)
    parser.add_argument('--max-attempts', type=int, default=4)
    parser.add_argument('--private-log', action='store_true', help='Append safe diagnostics to private state/bridge.log')
    args = parser.parse_args(argv)
    stack = contextlib.ExitStack()
    try:
        # Reserve one second of the advertised wall budget for owned-server cleanup.
        stack.enter_context(hard_wall(max(0.01, args.max_wall - 1)))
        if args.private_log:
            stack.enter_context(private_log())
        os.nice(max(0, 15 - os.getpriority(os.PRIO_PROCESS, 0)))
        return run(args)
    except WallLimit:
        print('MIKAYA_BRIDGE_HOLD: wall_limit', file=sys.stderr)
        return 75
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        reason = str(error) if isinstance(error, pub.PublisherError) else 'local_configuration_or_source_unavailable'
        print('MIKAYA_BRIDGE_HOLD: ' + reason, file=sys.stderr)
        return 2
    finally:
        stack.close()


if __name__ == '__main__':
    raise SystemExit(main())
