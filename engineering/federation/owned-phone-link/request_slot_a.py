#!/data/data/com.termux/files/usr/bin/python
"""Configurable sender template; requires private configuration before any device read."""
from pathlib import Path
import hashlib
import json
import os
import stat
import subprocess
import time
import uuid

from handoff_config import ConfigError, load_config

HOME = Path.home()
try:
    CONFIG = load_config()
except ConfigError as error:
    print(json.dumps({'status': 'HOLD', 'reason': str(error), 'automatic_replay': False}),
          flush=True)
    raise SystemExit(2)
def write_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(value, out, indent=2)
        out.write('\n'); out.flush(); os.fsync(out.fileno())

def main():
    model = subprocess.run(['/system/bin/getprop','ro.product.model'], capture_output=True,
                           text=True, timeout=5, check=True).stdout.strip()
    if model not in {'F110 Pro','F110_Pro'}:
        raise RuntimeError('Sender must be the native F110, not Motorola or a Linux guest')
    directory = HOME/'.local/state/mikaya-owned-link-v1'
    if any(p.is_symlink() for p in [directory,*directory.parents]):
        raise RuntimeError('Symlink state path refused')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = directory.stat()
    if st.st_uid != os.getuid() or st.st_mode & 0o077 or not stat.S_ISDIR(st.st_mode):
        raise RuntimeError('Owned private request state required')
    rid = uuid.uuid4().hex; issued = int(time.time())
    request = {'schema':'mikaya.owned-f110-handoff-request.v1','request_id':rid,
        'action':'F110_RETURN_TO_A_AND_REBOOT',
        'sender_node_id':CONFIG['sender_node_id'],
        'controller_node_id':CONFIG['controller_node_id'],
        'target_usb_serial':CONFIG['target_usb_serial'],'issued_at':issued,'expires_at':issued+3600}
    write_new(directory/(rid+'.request.json'), request)
    encoded=json.dumps(request,sort_keys=True,separators=(',',':'))
    remote='/data/data/com.termux/files/home/.local/bin/mikaya-owned-f110 submit'
    result=subprocess.run([str(HOME/'.local/bin/mikaya-motorola-ssh'),remote],
        input=encoded, capture_output=True, text=True, timeout=20)
    write_new(directory/(rid+'.transport.json'),
        {'exit':result.returncode,'stdout':result.stdout[:12000],'stderr':result.stderr[:2000]})
    if result.returncode != 0:
        raise RuntimeError('Request transport did not acknowledge; retain request ID '+rid)
    receipt=json.loads(result.stdout)
    if (receipt.get('request') != request or receipt.get('state') != 'STAGED_NOT_ARMED'
            or receipt.get('request_sha256') != hashlib.sha256(encoded.encode()).hexdigest()):
        raise RuntimeError('Motorola request receipt differs')
    write_new(directory/(rid+'.motorola.json'),receipt)
    print(json.dumps({'status':'OWNED_WIRELESS_HANDOFF_REQUEST_DELIVERED',
        'request_id':rid,'motorola_state':receipt['state'],
        'request_sha256':receipt['request_sha256'],
        'local_receipt':str(directory/(rid+'.motorola.json')),
        'motorola_receipt':'/data/data/com.termux/files/home/.local/state/mikaya-owned-link-v1/'+rid+'.json',
        'hardware_commands_executed':False,'automatic_replay':False},indent=2),flush=True)

if __name__=='__main__':
    main()
