#!/usr/bin/env python3
"""Foreground F110 -> MIKAYA Runtime redacted status publisher. Standard library only.

Pair locally, register only the printed token_hash in the owner workspace, then publish.
This neither starts a service nor operates ADB, wallets, firmware or radios.
The source digest identifies a reviewed local file, not process attestation.
"""
from __future__ import annotations
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

KNOWN_SOURCE_SHA256 = '47ed2335f8b3741b590d76c7a2a91c416fbe93d8f215620b018576529f4cd66c'
LOCAL_STATUS = 'http://127.0.0.1:8787/api/status'
MAX_DASHBOARD_BYTES = 65536
MAX_RESPONSE_BYTES = 8192
HEX64 = re.compile(r'^[a-f0-9]{64}$')

class PublisherError(ValueError):
    """A safe diagnostic code; never include secrets or raw provider responses."""

def command(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, check=False, **kwargs)

def require_device(runner=command):
    expected = {'ro.product.model': 'F110 Pro', 'ro.board.platform': 'mt6835',
                'ro.build.version.release': '15'}
    try:
        for name, value in expected.items():
            result = runner(['getprop', name], timeout=3)
            if result.returncode or result.stdout.strip() != value:
                raise PublisherError('f110_identity_required')
        result = runner(['mikaya-nice', 'status'], timeout=5)
        state = json.loads(result.stdout[:65536])
        if result.returncode or not isinstance(state, dict) or state.get('decision_for_optional_jobs') != 'ALLOW':
            raise PublisherError('thermal_hold_or_unknown')
    except (OSError, subprocess.SubprocessError, ValueError, TypeError) as error:
        if isinstance(error, PublisherError): raise
        raise PublisherError('device_or_thermal_status_unavailable') from None

def state_directory(home, create=False):
    current = Path(home)
    for part in ('.local', 'state', 'mikaya-runtime'):
        current = current / part
        if create:
            try: current.mkdir(mode=0o700)
            except FileExistsError: pass
        try: info = current.lstat()
        except OSError: raise PublisherError('pair_on_f110_first') from None
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise PublisherError('unsafe_state_directory')
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise PublisherError('state_directory_must_be_private')
    return current

def read_private_file(path, limit, *, mode=0o600):
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode): raise PublisherError('unsafe_private_file')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if ((info.st_dev, info.st_ino) != (before.st_dev, before.st_ino) or
                info.st_uid != os.getuid() or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != mode or info.st_size > limit):
                raise PublisherError('unsafe_private_file')
            raw = stream.read(limit + 1)
            if len(raw) > limit: raise PublisherError('private_file_too_large')
            return raw
    except OSError: raise PublisherError('private_file_unavailable') from None

def read_device_token(home):
    path = state_directory(home) / 'device-token'
    try: token = read_private_file(path, 64).decode('ascii')
    except UnicodeError: raise PublisherError('invalid_device_token') from None
    if not HEX64.fullmatch(token): raise PublisherError('invalid_device_token')
    return token

def pair_device(*, home=None, runner=command):
    require_device(runner)
    home = Path.home() if home is None else Path(home)
    path = state_directory(home, create=True) / 'device-token'
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    except FileExistsError:
        pass
    except OSError: raise PublisherError('token_creation_failed') from None
    else:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(secrets.token_hex(32).encode('ascii'))
            stream.flush(); os.fsync(stream.fileno())
    token = read_device_token(home)
    return {'status': 'ready_for_owner_registration',
            'token_hash': hashlib.sha256(token.encode('ascii')).hexdigest()}

@contextlib.contextmanager
def publisher_lock(home):
    path = state_directory(home) / 'publisher.lock'
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            os.close(fd); raise PublisherError('unsafe_publisher_lock')
    except OSError: raise PublisherError('publisher_lock_unavailable') from None
    try:
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise PublisherError('publisher_already_running') from None
        yield
    finally: os.close(fd)

def validate_endpoint(value):
    # The owner deliberately supplies the exact published HTTPS endpoint.
    # Dedicated tokens are private to this runtime; redirects are never followed.
    if not isinstance(value, str) or len(value) > 512 or '?' in value or '#' in value:
        raise PublisherError('invalid_runtime_endpoint')
    try:
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname or ''
        if (parsed.scheme != 'https' or parsed.username is not None or parsed.password is not None or
            parsed.port not in (None, 443) or not parsed.path.endswith('/api/runtime/publish') or
            not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}', host) or
            host.endswith(('.localhost', '.local', '.internal')) or
            '%' in parsed.path or '..' in parsed.path or '//' in parsed.path):
            raise PublisherError('invalid_runtime_endpoint')
    except ValueError:
        raise PublisherError('invalid_runtime_endpoint') from None
    return 'https://' + host + parsed.path

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs): return None

def build_transport():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

def request_json(req, limit, transport=None):
    send = transport or build_transport().open
    try:
        with send(req, timeout=8) as response:
            code = response.getcode()
            if 300 <= code < 400: raise PublisherError('redirect_refused')
            if code != 200: raise PublisherError('http_request_rejected')
            length = response.headers.get('Content-Length')
            if length is not None and int(length) > limit: raise PublisherError('response_too_large')
            raw = response.read(limit + 1)
            if len(raw) > limit: raise PublisherError('response_too_large')
        result = json.loads(raw.decode('utf-8'))
        if not isinstance(result, dict): raise PublisherError('invalid_json_response')
        return result
    except urllib.error.HTTPError as error:
        raise PublisherError('redirect_refused' if 300 <= error.code < 400 else 'http_request_rejected') from None
    except (OSError, ValueError, UnicodeError) as error:
        if isinstance(error, PublisherError): raise
        raise PublisherError('request_failed_or_invalid_response') from None

def source_provenance(source, *, runner=command, expected_sha256=KNOWN_SOURCE_SHA256):
    source = Path(source)
    try:
        info = source.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 131072:
            raise PublisherError('unsafe_dashboard_source')
        fd = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as stream:
            actual = os.fstat(stream.fileno())
            if (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino):
                raise PublisherError('dashboard_source_changed')
            raw = stream.read(131073)
        digest = hashlib.sha256(raw).hexdigest()
        if len(raw) > 131072 or digest != expected_sha256:
            raise PublisherError('dashboard_source_hash_mismatch')
    except OSError: raise PublisherError('dashboard_source_unavailable') from None
    revision = 'unbound'
    try:
        top = runner(['git', '-C', str(source.parent), 'rev-parse', '--show-toplevel'], timeout=3)
        if top.returncode: return revision, digest
        root = Path(top.stdout.strip()).resolve()
        relative = source.resolve().relative_to(root).as_posix()
        head = runner(['git', '-C', str(root), 'rev-parse', 'HEAD'], timeout=3)
        blob = runner(['git', '-C', str(root), 'show', 'HEAD:' + relative], timeout=3)
        if (head.returncode == blob.returncode == 0 and re.fullmatch(r'[a-f0-9]{40}', head.stdout.strip()) and
            hashlib.sha256(blob.stdout.encode('utf-8')).hexdigest() == digest):
            revision = head.stdout.strip()
    except (OSError, subprocess.SubprocessError, ValueError, UnicodeError): pass
    return revision, digest

def project_summary(state, revision, source_hash, *, clock=None):
    try:
        event = state['l402']['event_spine']
        if state['schema'] != 'mikaya.unified-dashboard.v1' or event['source_status'] not in (
            'not_configured', 'not_accessible', 'read_only_local_file'):
            raise PublisherError('unsupported_dashboard_status')
        for name in ('recognized_event_count', 'l402_challenge_count'):
            if type(event[name]) is not int or not 0 <= event[name] <= 1000000000:
                raise PublisherError('invalid_dashboard_counts')
        now = clock() if clock else dt.datetime.now(dt.timezone.utc)
        if now.tzinfo is None or now.utcoffset() is None: raise PublisherError('utc_clock_required')
        if not re.fullmatch(r'(?:[a-f0-9]{40}|unbound)', revision) or not HEX64.fullmatch(source_hash):
            raise PublisherError('invalid_source_provenance')
        return {'schema': 'mikaya.runtime-summary.v1', 'sample_id': str(uuid.uuid4()),
                'observed_at': now.astimezone(dt.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                'source_revision': revision, 'source_sha256': source_hash, 'dashboard_reachable': True,
                'event_spine_status': event['source_status'],
                'recognized_event_count': event['recognized_event_count'],
                'l402_challenge_count': event['l402_challenge_count']}
    except (KeyError, TypeError, AttributeError): raise PublisherError('invalid_dashboard_status') from None

def publish_once(endpoint, source, *, home=None, runner=command, transport=None, clock=None,
                 expected_sha256=KNOWN_SOURCE_SHA256, _session_locked=False):
    endpoint = validate_endpoint(endpoint)
    require_device(runner)
    home = Path.home() if home is None else Path(home)
    with contextlib.nullcontext() if _session_locked else publisher_lock(home):
        revision, digest = source_provenance(source, runner=runner, expected_sha256=expected_sha256)
        token = read_device_token(home)
        state = request_json(urllib.request.Request(LOCAL_STATUS, headers={'Accept': 'application/json'}),
                             MAX_DASHBOARD_BYTES, transport)
        summary = project_summary(state, revision, digest, clock=clock)
        payload = json.dumps({'action': 'publish', 'summary': summary}, separators=(',', ':')).encode('utf-8')
        req = urllib.request.Request(endpoint, data=payload, method='POST', headers={
            'Content-Type': 'application/json', 'Accept': 'application/json',
            'X-Mikaya-Device-Token': token})
        reply = request_json(req, MAX_RESPONSE_BYTES, transport)
        if (reply.get('accepted') is not True or type(reply.get('duplicate')) is not bool or
            not isinstance(reply.get('received_at'), str) or len(reply['received_at']) > 40):
            raise PublisherError('device_receipt_unverified')
        try:
            received = dt.datetime.fromisoformat(reply['received_at'].replace('Z', '+00:00'))
            if received.utcoffset() is None: raise ValueError()
        except ValueError: raise PublisherError('device_receipt_unverified') from None
        return {'accepted': True, 'duplicate': reply['duplicate'], 'sample_id': summary['sample_id'],
                'observed_at': summary['observed_at'], 'received_at': reply['received_at']}

def main(argv=None, *, home=None, runner=command, transport=None, clock=None, sleep=time.sleep):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--pair', action='store_true')
    modes.add_argument('--once', action='store_true')
    modes.add_argument('--watch', action='store_true')
    parser.add_argument('--endpoint')
    parser.add_argument('--source', type=Path, help='Existing reviewed tools/mikaya_unified.py')
    parser.add_argument('--config', type=Path, help='Private mode-0600 endpoint/source_file JSON')
    parser.add_argument('--interval', type=int, default=60)
    parser.add_argument('--max-samples', type=int, default=10)
    args = parser.parse_args(argv)
    home = Path.home() if home is None else Path(home)
    try:
        if args.watch and (not 30 <= args.interval <= 3600 or not 1 <= args.max_samples <= 120 or
                           args.interval * args.max_samples > 7200):
            raise PublisherError('watch_must_be_bounded_30s_to_2h')
        if args.pair:
            print(json.dumps(pair_device(home=home, runner=runner))); return 0
        config = {}
        config_path = args.config or home / '.local/state/mikaya-runtime/config.json'
        if config_path.exists() or config_path.is_symlink():
            config = json.loads(read_private_file(config_path, 8192).decode('utf-8'))
            if not isinstance(config, dict) or set(config) - {'endpoint', 'source_file'}:
                raise PublisherError('invalid_configuration')
        endpoint = args.endpoint or config.get('endpoint')
        source = args.source or config.get('source_file')
        if not endpoint or not source: raise PublisherError('endpoint_and_reviewed_source_required')
        count = args.max_samples if args.watch else 1
        require_device(runner)
        with publisher_lock(home):
            for index in range(count):
                result = publish_once(endpoint, source, home=home, runner=runner, transport=transport,
                                      clock=clock, _session_locked=True)
                print(json.dumps(result), flush=True)
                if index + 1 < count: sleep(args.interval)
        return 0
    except (PublisherError, OSError, ValueError) as error:
        message = str(error) if isinstance(error, PublisherError) else 'local_configuration_unavailable'
        print('MIKAYA_PUBLISH_HOLD: ' + message, file=sys.stderr); return 2

if __name__ == '__main__': raise SystemExit(main())
