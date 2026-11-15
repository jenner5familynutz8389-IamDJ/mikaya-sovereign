"""One synchronous evidence cycle, invoked only by the existing gated publisher.

No credentials, raw identity export, service lifecycle or network interface.
The bridge owns publication and lifetime. Source/identity/state failures HOLD.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent
SOURCE_PINS = {'device_observation_producer.cjs': '6e48e74d0a1a448cd260e4d5383399668642000a7d8c39eb9f308fc45b4446d6', 'ledger_event_collector.cjs': '40994a07f4e116cf63a15d9ad2d4c4ae5efb4cffc714c6b87420f51481b7c6a8', 'vendor/sovereign-event-ledger.cjs': '56c894c87d6d7d4bb57d90e520b80f968a72a683469defc0b5e7d36c49f13c65', 'vendor/federation-node.cjs': '33ea94880c74c7392535ff443b467a7df79117f2bf42993956a5add4ee7f1827'}
MAX_PROJECTION = 8 * 1024 * 1024
NODE_LOADER = r'''
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),Module=require('node:module');
try {
 const [root,entry,pinsText,config]=process.argv.slice(1),pins=JSON.parse(pinsText),cache=new Map();
 const allowed=new Set(['node:fs','node:path','node:crypto','node:child_process','node:util','node:module','node:http','node:https','node:url']);
 function load(name,main=false){
  if(cache.has(name))return cache.get(name).exports;
  if(!Object.hasOwn(pins,name))throw Error('unreviewed_source');
  const file=path.join(root,name),fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  let raw;
  try {const before=fs.fstatSync(fd,{bigint:true});if(!before.isFile()||before.nlink!==1n||before.size>131072n)throw Error('unsafe_source');
   raw=Buffer.alloc(Number(before.size)+1);let size=0;while(size<raw.length){const n=fs.readSync(fd,raw,size,raw.length-size,null);if(!n)break;size+=n;}
   const after=fs.fstatSync(fd,{bigint:true});if(size!==Number(before.size)||before.ino!==after.ino||before.size!==after.size||before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs)throw Error('source_changed');raw=raw.subarray(0,size);
  } finally {fs.closeSync(fd);}
  if(crypto.createHash('sha256').update(raw).digest('hex')!==pins[name])throw Error('source_pin');
  const mod=new Module(file);mod.filename=file;cache.set(name,mod);
  mod.require=specifier=>{if(allowed.has(specifier))return require(specifier);if(specifier==='./ledger_event_collector.cjs')return load('ledger_event_collector.cjs');throw Error('unreviewed_dependency');};
  if(main){process.mainModule=mod;process.argv=[process.execPath,file,'--config',config];}
  mod._compile(raw.toString('utf8'),file);return mod.exports;
 }
 load(entry,true);
} catch {console.error('{"status":"HOLD","reason":"source_execution_refused"}');process.exitCode=2;}
'''


def private_bytes(path, limit, *, private=True):
    path = Path(path)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit or
            before.st_uid != os.getuid() or (private and before.st_mode & 0o077)):
        raise ValueError('unsafe_local_file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError('local_file_changed')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
    if len(raw) > limit or identity(opened) != identity(after):
        raise ValueError('local_file_changed')
    return raw


def private_json(path):
    raw = private_bytes(path, 8192)
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


class Session:
    def __init__(self, config_path, *, runner=subprocess.run, now_ms=lambda: int(time.time() * 1000)):
        self.runner, self.lock = runner, threading.RLock()
        self.now_ms, self.metadata, self.events = now_ms, None, None
        self.current, self.directory = None, None
        self.config_path = Path(config_path)
        self.config, digest = private_json(self.config_path)
        if (set(self.config) != {'schema', 'node_path', 'producer_config_path', 'collector_config_path'} or
                self.config['schema'] != 'mikaya.verified-event-integration.v1'):
            raise ValueError('invalid_event_integration_config')
        for key in ('node_path', 'producer_config_path', 'collector_config_path'):
            p = Path(self.config[key])
            if not p.is_absolute() or str(p.resolve()) != str(p):
                raise ValueError('canonical_absolute_config_path_required')
        self.producer, producer_digest = private_json(self.config['producer_config_path'])
        self.collector, collector_digest = private_json(self.config['collector_config_path'])
        if (self.producer.get('ledger_dir') != self.collector.get('ledger_dir') or
                self.producer.get('expected_fingerprint') != self.collector.get('expected_fingerprint')):
            raise ValueError('producer_collector_identity_mismatch')
        self.config_pins = {self.config_path: digest,
                            Path(self.config['producer_config_path']): producer_digest,
                            Path(self.config['collector_config_path']): collector_digest}
        self.config_digest = hashlib.sha256(json.dumps(sorted(str(p) + ':' + d for p, d in self.config_pins.items())).encode()).hexdigest()
        self.state = Path(self.collector['state_dir'])
        info = self.state.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or
                self.state.resolve() != self.state):
            raise ValueError('unsafe_projection_state')

    def __enter__(self):
        self.directory = Path(tempfile.mkdtemp(prefix='.publish-cycle-', dir=self.state))
        return self

    def __exit__(self, *_):
        with self.lock:
            if self.current is not None:
                self.current.unlink()
            if self.directory is not None:
                self.directory.rmdir()
            self.current = self.directory = None

    def _check_pins(self):
        if not SOURCE_PINS:
            raise ValueError('unreviewed_source_release')
        for name, digest in SOURCE_PINS.items():
            raw = private_bytes(ROOT / name, 131072, private=False)
            if hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError('event_source_pin_failed')
        for path, digest in self.config_pins.items():
            if hashlib.sha256(private_bytes(path, 8192)).hexdigest() != digest:
                raise ValueError('event_configuration_changed')

    def _command(self, script, config):
        result = self.runner([self.config['node_path'], '-e', NODE_LOADER, str(ROOT), script,
                              json.dumps(SOURCE_PINS), config],
                             stdin=subprocess.DEVNULL, capture_output=True, timeout=8, check=False)
        if result.returncode != 0 or len(result.stdout) > 8192 or len(result.stderr) > 8192:
            raise ValueError('verified_event_command_hold')
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            raise ValueError('invalid_verified_event_receipt')
        return value

    def prepare(self, *, append_observation=True):
        if self.directory is None:
            raise ValueError('event_session_not_entered')
        self._check_pins()
        if append_observation:
            producer = self._command('device_observation_producer.cjs', self.config['producer_config_path'])
            if producer.get('status') != 'DEVICE_OBSERVATION_SIGNED':
                raise ValueError('observation_not_appended')
        receipt = self._command('ledger_event_collector.cjs', self.config['collector_config_path'])
        expected = self.state / 'projection.jsonl'
        if (receipt.get('status') != 'VERIFIED_LOCAL_PROJECTION' or
                receipt.get('projection_path') != str(expected) or
                receipt.get('payment_authorized') is not False or
                receipt.get('hardware_attested') is not False):
            raise ValueError('projection_receipt_invalid')
        raw = private_bytes(expected, MAX_PROJECTION)
        if hashlib.sha256(raw).hexdigest() != receipt.get('projection_sha256'):
            raise ValueError('projection_changed_before_consumption')
        lines = raw.decode('utf-8').splitlines()
        metadata, events = json.loads(lines[0]), [json.loads(line) for line in lines[1:]]
        fd, name = tempfile.mkstemp(prefix='events-', suffix='.jsonl', dir=self.directory)
        prepared = Path(name)
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o400)
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            with self.lock:
                previous, self.current = self.current, prepared
                self.metadata, self.events = metadata, events
                if previous is not None:
                    previous.unlink()
        except BaseException:
            prepared.unlink(missing_ok=True)
            raise
        return {'recognized_event_count': receipt['recognized_event_count'],
                'source_latest_at_ms': receipt['source_latest_at_ms']}

    @contextlib.contextmanager
    def read_path(self):
        with self.lock:
            if self.current is None:
                raise ValueError('verified_event_source_not_prepared')
            self.assert_fresh()
            yield self.current

    def assert_fresh(self):
        if self.metadata is None:
            raise ValueError('verified_event_source_not_prepared')
        age = self.now_ms() - self.metadata['latestObservationAtMs']
        if age < -30000 or age > self.collector['max_age_ms']:
            raise ValueError('verified_event_source_stale')

    def pending_binding(self):
        with self.lock:
            self.assert_fresh()
            return {'config_sha256': self.config_digest, 'genesis_sha256': self.metadata['genesisHash'],
                    'head_index': self.metadata['headIndex'], 'head_sha256': self.metadata['headHash'],
                    'source_latest_at_ms': self.metadata['latestObservationAtMs']}

    def validate_binding(self, summary, evidence, *, prefix=False):
        keys = {'config_sha256', 'genesis_sha256', 'head_index', 'head_sha256', 'source_latest_at_ms'}
        if (not isinstance(evidence, dict) or set(evidence) != keys or evidence['config_sha256'] != self.config_digest or
                type(evidence['head_index']) is not int or not 1 <= evidence['head_index'] <= 4095 or
                type(evidence['source_latest_at_ms']) is not int or
                any(not isinstance(evidence[k], str) or len(evidence[k]) != 64 or
                    any(c not in '0123456789abcdef' for c in evidence[k]) for k in ('config_sha256', 'genesis_sha256', 'head_sha256')) or
                summary.get('event_spine_status') != 'read_only_local_file' or
                summary.get('recognized_event_count') != evidence['head_index'] or summary.get('l402_challenge_count') != 0):
            raise ValueError('pending_evidence_binding_invalid')
        if prefix:
            self.assert_fresh()
            index = evidence['head_index']
            if (evidence['genesis_sha256'] != self.metadata['genesisHash'] or index > len(self.events) or
                    self.events[index-1]['data']['entry_sha256'] != evidence['head_sha256']):
                raise ValueError('pending_evidence_prefix_mismatch')
            import datetime as dt
            timestamp = int(dt.datetime.fromisoformat(self.events[index-1]['ts'].replace('Z', '+00:00')).timestamp() * 1000)
            if timestamp != evidence['source_latest_at_ms']:
                raise ValueError('pending_evidence_timestamp_mismatch')
        return self.now_ms() - evidence['source_latest_at_ms'] <= self.collector['max_age_ms'] and evidence['source_latest_at_ms'] <= self.now_ms() + 30000
