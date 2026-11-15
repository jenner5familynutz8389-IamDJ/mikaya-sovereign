#!/data/data/com.termux/files/usr/bin/python
"""Configurable source template; private configuration required, not deployed or armed."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import types

from handoff_config import ConfigError, load_config

HOME = Path.home()
try:
    CONFIG = load_config()
except ConfigError as error:
    print(json.dumps({'state': 'HOLD', 'reason': str(error), 'automatic_replay': False}),
          flush=True)
    raise SystemExit(2)
F110 = CONFIG['sender_node_id']
MOTO = CONFIG['controller_node_id']
SERIAL = CONFIG['target_usb_serial']
SSH_SOURCE = CONFIG['ssh_source_address']
PREFIX = '/data/data/com.termux/files/usr'
BACKEND_SHA = 'e65da89d002db93ec83fa5172a5d84e09fcc94cf252a746fc07b52f56eb8d2f5'
BACKEND_PATH = HOME / '.local/share/mikaya/f110-a-backend-e65da89d002d/backend.py'
HANDOFF = HOME / 'sovereign_exec/motorola-host-handoff-87672eb'
STATE = HOME / '.local/state/mikaya-owned-link-v1'
BACKEND_STATE = HOME / '.local/state/mikaya-f110-a-backend'
BOUND_ADB = HOME / '.local/share/mikaya/owned-phone-link-v1/adb-f110-bound'
BOUND_ADB_BYTES = (f'#!{PREFIX}/bin/sh\nexec {PREFIX}/bin/python '
                   f'{HOME}/.local/share/mikaya/owned-phone-link-v1/owned_handoff.py '
                   '_adb-bound "$@"\n').encode()

class Hold(Exception):
    pass

def require(ok, why):
    if not ok:
        raise Hold(why)

def backend_module():
    raw = BACKEND_PATH.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == BACKEND_SHA, 'Original backend source pin differs')
    m = types.ModuleType('existing_f110_backend')
    m.__file__ = str(BACKEND_PATH)
    exec(compile(raw, str(BACKEND_PATH), 'exec'), m.__dict__)
    m.probe_motorola_host()
    m.validate_pins(HANDOFF)
    return m

def validate_request(r, fresh=True):
    fields = {'schema', 'request_id', 'action', 'sender_node_id', 'controller_node_id',
              'target_usb_serial', 'issued_at', 'expires_at'}
    require(type(r) is dict and set(r) == fields, 'Exact fixed-action request schema required')
    require(r['schema'] == 'mikaya.owned-f110-handoff-request.v1', 'Unknown request schema')
    require(type(r['request_id']) is str and re.fullmatch('[a-f0-9]{32}', r['request_id']), 'Bad request ID')
    require(r['action'] == 'F110_RETURN_TO_A_AND_REBOOT', 'Action is not allowed')
    require(r['sender_node_id'] == F110 and r['controller_node_id'] == MOTO
            and r['target_usb_serial'] == SERIAL, 'Wrong device or controller identity')
    require(type(r['issued_at']) is int and type(r['expires_at']) is int
            and 0 < r['expires_at'] - r['issued_at'] <= 3600, 'Invalid request lifetime')
    if fresh:
        require(r['issued_at'] - 30 <= time.time() <= r['expires_at'], 'Request is stale or future-dated')
    return r

def request_digest(r):
    return hashlib.sha256(json.dumps(r, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def job_path(rid):
    require(re.fullmatch('[a-f0-9]{32}', rid or '') is not None, 'Bad request ID')
    return STATE / (rid + '.json')

def read_job(m, rid):
    j = json.loads(m.read_regular(job_path(rid)))
    validate_request(j['request'], fresh=False)
    require(j['request']['request_id'] == rid and j['request_sha256'] == request_digest(j['request']),
            'Saved request digest mismatch')
    return j

def fixed_runner(argv, **kwargs):
    args = [str(x) for x in argv]
    tool = Path(args[0]).name
    if tool in {'usb-adb', 'termux-fastboot'}:
        discovery = args[1:] in (['devices'], ['devices', '-l'])
        if not discovery:
            require('-s' in args and args.index('-s') + 1 < len(args)
                    and args[args.index('-s') + 1] == SERIAL,
                    'Hardware command is not bound to the exact F110 serial')
        result = subprocess.run(args, **kwargs)
        if discovery and result.returncode == 0:
            rows = [line.split() for line in result.stdout.splitlines()
                    if line.strip() and not line.startswith('List of devices attached')]
            if rows:
                require(len(rows) == 1 and rows[0][0] == SERIAL, 'Wrong USB device discovered')
        return result
    if tool in {'bash', 'sh'}:
        env = kwargs.get('env') or {}
        require(env.get('ANDROID_SERIAL') == SERIAL, 'Postflight is not bound to F110')
        require(len(args) == 6 and args[1] == str(HANDOFF/'motorola_f110_adb_postflight.sh')
                and args[2] == '--phase' and args[3] in {'pre','post'}
                and args[4] == '--expect-slot' and args[5] in {'_a','_b'},
                'Only the unchanged pinned postflight shell is allowed')
        require(not BOUND_ADB.is_symlink() and BOUND_ADB.read_bytes() == BOUND_ADB_BYTES,
                'Serial-bound postflight adapter differs')
        kwargs['env'] = dict(env, ADB_BIN=str(BOUND_ADB))
    return subprocess.run(args, **kwargs)

def local_only():
    # Accident guard only. An unrestricted shell under this same owner UID already
    # has direct access to the original backend; this is not an OS privilege boundary.
    require(not os.environ.get('SSH_CONNECTION'), 'Arming is a local Motorola owner operation')

def adb_bound_proxy():
    backend_module()
    args = sys.argv[2:]
    allowed_properties = {'ro.product.model','ro.product.board','ro.boot.slot_suffix',
        'ro.boot.verifiedbootstate','ro.boot.vbmeta.device_state','ro.build.version.release',
        'ro.build.fingerprint','gsm.version.baseband','ro.build.version.security_patch'}
    require(args in (['devices'],['devices','-l']) or
            (len(args) == 5 and args[:4] == ['-s',SERIAL,'shell','getprop']
             and args[4] in allowed_properties), 'Postflight adapter is read-only and fixed-target')
    result = fixed_runner([str(HANDOFF/'usb-adb'),*args], capture_output=True,
                          text=True, timeout=8, shell=False)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.returncode

def private_lock(m, wait=False):
    m.private_directory(STATE)
    fd = os.open(STATE / 'request.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    st = os.fstat(fd)
    require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o077,
            'Unsafe request lock')
    deadline = time.monotonic() + (5 if wait else 0)
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if time.monotonic() >= deadline:
                os.close(fd)
                raise Hold('Another request transition is active; no job queued') from None
            time.sleep(0.05)
    return fd

def submit(m):
    require(os.environ.get('SSH_CONNECTION', '').split(' ')[0] == SSH_SOURCE,
            'Request must arrive through the existing authenticated F110 SSH route')
    raw = sys.stdin.buffer.read(4097)
    require(len(raw) <= 4096, 'Request exceeds size budget')
    r = validate_request(json.loads(raw))
    fd = private_lock(m)
    try:
        path = job_path(r['request_id'])
        if path.exists():
            j = read_job(m, r['request_id'])
            require(j['request_sha256'] == request_digest(r), 'Request ID reuse with different data')
            return j
        j = {'schema': 'mikaya.owned-f110-request-receipt.v1', 'request': r,
             'request_sha256': request_digest(r), 'state': 'STAGED_NOT_ARMED',
             'accepted_at': int(time.time()), 'authenticated_transport': 'existing_strict_host_key_SSH',
             'hardware_commands_executed': False, 'automatic_replay': False,
             'data_hold_cleared': False, 'system_partition_migration': False}
        m.BackendStore(STATE).atomic(path, j)
        return j
    finally:
        os.close(fd)

def arm_and_launch(m, rid, armed):
    local_only()
    require(armed, 'Explicit --arm-once is required; request files never trigger execution')
    fd = private_lock(m)
    try:
        j = read_job(m, rid)
        require(j['state'] == 'STAGED_NOT_ARMED', 'Request was already armed or consumed; no replay')
        validate_request(j['request'])
        b = m.Backend(HANDOFF, BACKEND_STATE, runner=fixed_runner)
        p = b.prepare()
        require(not p['data_hold_present'], 'Original A/userdata hold remains in force')
        result = fixed_runner([str(HANDOFF/'usb-adb'), 'devices', '-l'],
                              capture_output=True, text=True, timeout=12, shell=False)
        rows = [line.split() for line in result.stdout.splitlines()
                if line.strip() and not line.startswith('List of devices attached')]
        require(result.returncode == 0 and len(rows) == 1 and rows[0][0] == SERIAL
                and rows[0][1] == 'device' and any(x.startswith('usb:') for x in rows[0][2:]),
                'Exact F110 authorized USB Android connection is not ready')
        logfile = STATE / (rid + '.log')
        logfd = os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        j.update(state='LAUNCH_REQUESTED', armed_at=int(time.time()))
        m.BackendStore(STATE).atomic(job_path(rid), j)
        try:
            child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '_worker', rid],
                                     stdin=subprocess.DEVNULL, stdout=logfd, stderr=subprocess.STDOUT,
                                     start_new_session=True, close_fds=True)
            # Worker owns its following state transition; do not overwrite it after spawn.
        except BaseException:
            j.update(state='LAUNCH_FAILED_RECONCILE_REQUIRED')
            m.BackendStore(STATE).atomic(job_path(rid), j)
            raise
        finally:
            os.close(logfd)
        return {'state': 'MOTOROLA_LOCAL_WORKER_LAUNCHED', 'request_id': rid,
                'pid': child.pid, 'target_usb_serial': SERIAL, 'log': str(logfile),
                'chat_connection_required_during_reboot': False}
    finally:
        os.close(fd)

def worker(m, rid):
    local_only()
    fd = private_lock(m, wait=True)
    try:
        j = read_job(m, rid)
        require(j['state'] == 'LAUNCH_REQUESTED', 'No unused local arming record')
        validate_request(j['request'])
        j.update(state='RUNNING', worker_pid=os.getpid(), consumed_at=int(time.time()))
        j.pop('hardware_commands_executed', None)
        j['hardware_execution_attempted'] = True
        m.BackendStore(STATE).atomic(job_path(rid), j)
    finally:
        os.close(fd)
    try:
        result = m.Backend(HANDOFF, BACKEND_STATE, runner=fixed_runner).run_a()
        j.update(state='BACKEND_RETURNED', backend_result=result)
    except BaseException as error:
        j.update(state='BACKEND_HOLD_OR_RECONCILE_REQUIRED', error_type=type(error).__name__,
                 error_summary=str(error)[:300])
    j['finished_at'] = int(time.time())
    m.BackendStore(STATE).atomic(job_path(rid), j)
    return j

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['submit', 'status', 'run', '_worker'])
    p.add_argument('request_id', nargs='?')
    p.add_argument('--arm-once', action='store_true')
    a = p.parse_args()
    try:
        m = backend_module()
        if a.action == 'submit':
            result = submit(m)
        elif a.action == 'status':
            result = read_job(m, a.request_id)
        elif a.action == 'run':
            result = arm_and_launch(m, a.request_id, a.arm_once)
        else:
            result = worker(m, a.request_id)
        print(json.dumps(result, indent=2), flush=True)
        return 0
    except Exception as e:
        print(json.dumps({'state':'HOLD','reason':str(e)[:300],
                          'automatic_replay':False,'boot_target':'F110 only'}), flush=True)
        return 2

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '_adb-bound':
        try:
            raise SystemExit(adb_bound_proxy())
        except Exception as error:
            print('HOLD_BOUND_POSTFLIGHT: '+str(error)[:200], file=sys.stderr)
            raise SystemExit(2)
    raise SystemExit(main())
