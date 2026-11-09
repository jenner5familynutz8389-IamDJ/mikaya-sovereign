#!/usr/bin/env python3
"""MIKAYA x ACT-Omega: bounded public MCP readiness observer.

The observer is deliberately NOT a federation joiner, Lightning client, L402
verifier, code executor, wallet daemon, or firmware tool. It calls only the
public MCP `initialize` discovery page (GET) and `tools/list` (POST) and the
local federation demo status. An unverified peer stays denied.

On every distinct observed state change it appends a non-secret OBSERVATION to
MIKAYA's existing, verified `integrity/correction-ledger.js` ledger. Historical
signed checkpoint and other ledger formats are never rewritten. If the
append fails, the observer refuses to advance its status cache.
"""
from __future__ import annotations
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from urllib import request

SCHEMA = 'mikaya.act-omega.peer-readiness.v1'
PEER = 'https://mcp.act-omega-net.dev/mcp'
LOCAL = 'http://127.0.0.1:4179/api/status'
ROOT = Path.home() / 'sovereign_exec'
STATE_FILE = ROOT / 'ledger/act-omega-readiness-state.json'
CORRECTION_CLI = ROOT / 'integrity/correction-ledger.js'
TOOL_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_.\-/]{0,79}$')
PAY_RE = re.compile(r'(l402|lightning|invoice|payment|wallet|macaroon|settle)', re.I)

class WatchError(ValueError):
    pass

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',', ':'),ensure_ascii=False,allow_nan=False)

def sha256(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def thermal_native():
    """Read Android native thermal state; UNKNOWN never permits optional work."""
    try:
        lib = ctypes.CDLL('/system/lib64/libandroid.so')
        lib.AThermal_acquireManager.restype = ctypes.c_void_p
        lib.AThermal_getCurrentThermalStatus.argtypes = [ctypes.c_void_p]
        lib.AThermal_getCurrentThermalStatus.restype = ctypes.c_int
        lib.AThermal_releaseManager.argtypes = [ctypes.c_void_p]
        lib.AThermal_releaseManager.restype = None
        mgr = lib.AThermal_acquireManager()
        if not mgr:
            return None
        try:
            value = lib.AThermal_getCurrentThermalStatus(mgr)
        finally:
            lib.AThermal_releaseManager(mgr)
        return value if isinstance(value,int) and 0 <= value <= 6 else None
    except (OSError,AttributeError,TypeError,ValueError):
        return None

def fetch_live(name):
    """Strict allowlist; never calls MCP tools/call or arbitrary URLs."""
    if name == 'peer_initialize':
        url, method, body = PEER, 'GET', None
    elif name == 'peer_tools':
        url, method = PEER, 'POST'
        body = b'{"jsonrpc":"2.0","id":42,"method":"tools/list","params":{}}'
    elif name == 'local_status':
        url, method, body = LOCAL, 'GET', None
    else:
        raise WatchError('unknown fetch label')
    headers={'Accept':'application/json','User-Agent':'MIKAYA-M2M-Readiness/1'}
    if body is not None:
        headers['Content-Type']='application/json'
    req = request.Request(url, data=body, headers=headers, method=method)
    try:
        with request.urlopen(req,timeout=10) as resp:
            if resp.status != 200:
                raise WatchError('unexpected public HTTP status')
            content = resp.read(131073)
            if len(content)>131072:
                raise WatchError('oversized discovery response')
            value = json.loads(content)
            if not isinstance(value,dict):
                raise WatchError('discovery response must be JSON object')
            return value
    except (OSError,ValueError,WatchError) as exc:
        return {'_error':type(exc).__name__}

def observe(fetch, thermal_status, time_utc):
    """Produce sanitized, safety-explicit snapshot; never interpret public MCP as identity."""
    out={
        'schema':SCHEMA,'observed_at':time_utc,
        'thermal':{'status':thermal_status if type(thermal_status) is int and 0<=thermal_status<=6 else None,
                   'source':'android_ndk_thermal_api' if type(thermal_status) is int and 0<=thermal_status<=6 else 'UNKNOWN',
                   'optional_discovery_allowed':thermal_status in (0,1) and type(thermal_status) is int},
        'act_omega_public_mcp':{'reachable':False,'server_name':'UNKNOWN','version':'UNKNOWN',
                                'advertised_tools':0,'payment_tool_names_advertised':[]},
        'local_federation':{'running':False,'mode':'UNKNOWN','nodes_connected':False,'wallet_enabled':False},
        'authorization':{'peer_identity_verified':False,'settlement_verified':False,
                         'macaroon_verified':False,'owner_policy_approved':False,
                         'paid_job_permitted':False,'firmware_access_permitted':False},
        'state':'THERMAL_HOLD' if thermal_status not in (0,1) or type(thermal_status) is not int else 'PUBLIC_MCP_UNAVAILABLE'
    }
    if out['state']=='THERMAL_HOLD':
        return out
    peer=fetch('peer_initialize')
    if isinstance(peer,dict) and isinstance(peer.get('result'),dict):
        info=peer['result'].get('serverInfo')
        if isinstance(info,dict) and info.get('name')=='ACT-Omega-Sovereign-Manifold-MCP':
            ver=info.get('version')
            out['act_omega_public_mcp'].update(reachable=True,server_name=info['name'],
                  version=ver[:24] if isinstance(ver,str) and re.fullmatch(r'[A-Za-z0-9._-]{1,24}',ver) else 'UNKNOWN')
            tools=fetch('peer_tools')
            raw=tools.get('result',{}).get('tools') if isinstance(tools,dict) else None
            if isinstance(raw,list) and len(raw)<=256:
                names=[x['name'] for x in raw if isinstance(x,dict) and isinstance(x.get('name'),str) and TOOL_RE.fullmatch(x['name'])]
                out['act_omega_public_mcp']['advertised_tools']=len(names)
                out['act_omega_public_mcp']['payment_tool_names_advertised']=[n for n in names if PAY_RE.search(n)][:12]
            out['state']='AWAITING_PEER_IDENTITY'
    local=fetch('local_status')
    if isinstance(local,dict):
        mode=local.get('mode')
        if mode == 'LOCAL_SIMULATED_ONLY':
            out['local_federation']={'running':True,'mode':mode,
                                   'nodes_connected':False,'wallet_enabled':False}
        # Never accept remotely supplied booleans as authority or proof.
    return out

def semantic_snapshot(snapshot):
    if not isinstance(snapshot,dict) or snapshot.get('schema')!=SCHEMA:
        raise WatchError('invalid observation')
    auth=snapshot.get('authorization')
    if not isinstance(auth,dict) or any(v is not False for v in auth.values()):
        raise WatchError('unverified authorization must remain denied')
    return {k:v for k,v in snapshot.items() if k!='observed_at'}

def record_change(status_file, snapshot, append):
    """No cache update on failed ledger append; fcntl protects simultaneous polls."""
    target=Path(status_file)
    if target.is_symlink() or target.parent.is_symlink():
        raise WatchError('symlink status path refused')
    target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    lock=target.with_name(target.name+'.lock')
    if lock.is_symlink():
        raise WatchError('symlink lock path refused')
    fd=os.open(lock,os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'r+') as lk:
        if not stat.S_ISREG(os.fstat(lk.fileno()).st_mode):
            raise WatchError('non-regular lock path')
        fcntl.flock(lk.fileno(),fcntl.LOCK_EX)
        observed=semantic_snapshot(snapshot)
        current_hash=sha256(canonical(observed))
        old=None
        if target.exists():
            try:
                old=json.loads(target.read_text(encoding='utf-8'))
                if not isinstance(old,dict) or old.get('schema')!=SCHEMA or not isinstance(old.get('semantic_sha256'),str):
                    raise ValueError('invalid cache schema')
                if sha256(canonical(semantic_snapshot(old['snapshot'])))!=old['semantic_sha256']:
                    raise ValueError('cache digest mismatch')
            except (ValueError,KeyError,OSError,TypeError) as exc:
                raise WatchError('readiness cache integrity mismatch') from exc
        if old and old['semantic_sha256']==current_hash:
            return {'changed':False,'semantic_sha256':current_hash,'state':snapshot['state']}
        event={'kind':'observation','subject':'act-omega-peer-readiness-change',
               'evidence':{'schema':'mikaya.act-omega.peer-observation-event.v1',
                           'observed_at':snapshot.get('observed_at'),
                           'semantic_sha256':current_hash,
                           'public_service':observed['act_omega_public_mcp'],
                           'f110_local_federation':observed['local_federation'],
                           'status':observed['state'],'authentication_verified':False,
                           'payment_settlement_verified':False},
               'fallback':'HOLD_UNTIL_OWNER_PINNED_PEER_IDENTITY_AND_VERIFIED_L402_SETTLEMENT',
               'policy':{'target':'act-omega-federation-paid-execution','action':'deny'}}
        append(event)
        state={'schema':SCHEMA,'semantic_sha256':current_hash,'snapshot':snapshot}
        path=None
        try:
            with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=target.parent,
                                             prefix='.act-omega-readiness-',delete=False) as f:
                path=Path(f.name)
                os.fchmod(f.fileno(),0o600)
                f.write(canonical(state)+'\n');f.flush();os.fsync(f.fileno())
            os.replace(path,target)
        finally:
            if path is not None and path.exists():path.unlink()
        return {'changed':True,'semantic_sha256':current_hash,'state':snapshot['state']}

def append_existing_ledger(event):
    """Use MIKAYA's existing append/verify CLI and retain its SHA256 chain."""
    if not CORRECTION_CLI.is_file() or CORRECTION_CLI.is_symlink():
        raise WatchError('canonical AHAVA correction appender unavailable')
    p=subprocess.run(['node',str(CORRECTION_CLI),'append',canonical(event)],
                     capture_output=True,text=True,timeout=25)
    if p.returncode:
        raise WatchError('canonical ledger append refused')
    r=subprocess.run(['node',str(CORRECTION_CLI),'verify'],capture_output=True,text=True,timeout=25)
    if r.returncode or json.loads(r.stdout).get('ok') is not True:
        raise WatchError('post-append ledger verification refused')

def run_once():
    s=observe(fetch_live,thermal_native(),datetime.now(timezone.utc).isoformat())
    result=record_change(STATE_FILE,s,append_existing_ledger)
    return {'schema':SCHEMA,'state':s['state'],'changed':result['changed'],
            'public_mcp_version':s['act_omega_public_mcp']['version'],
            'paid_job_permitted':False,'settlement_verified':False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['once','watch','status'])
    parser.add_argument('--interval',type=int,default=900)
    args=parser.parse_args()
    if args.command=='status':
        if STATE_FILE.is_file() and not STATE_FILE.is_symlink():
            old=json.loads(STATE_FILE.read_text(encoding='utf-8'))
            if sha256(canonical(semantic_snapshot(old['snapshot'])))!=old.get('semantic_sha256'):
                raise WatchError('corrupt readiness status')
            print(json.dumps(old,indent=2))
        else:
            print(json.dumps({'schema':SCHEMA,'status':'NOT_OBSERVED'}))
        return
    if args.interval<300 or args.interval>86400:
        raise WatchError('interval must be between 300 and 86400 seconds')
    while True:
        try:
            print(json.dumps(run_once()),flush=True)
        except (WatchError,ValueError,OSError,subprocess.SubprocessError) as exc:
            # Errors are not silently converted into authorization.
            print(json.dumps({'state':'OBSERVER_ERROR','error_type':type(exc).__name__,
                              'paid_job_permitted':False}),flush=True)
            if args.command=='once':raise
        if args.command=='once':return
        time.sleep(args.interval)

if __name__=='__main__':
    main()
