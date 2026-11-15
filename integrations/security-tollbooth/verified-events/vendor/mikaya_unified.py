#!/usr/bin/env python3
"""MIKAYA integrated local dashboard and parallel host-only source gates.
No wallet access, payout, ADB, OEM firmware change or remote service controls.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import datetime as dt
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

TXID = '8cd0125081b40e01df124fd66adc68638b552c0693bccceb15d4485bdb47c9c8'
ADDRESS = 'bc1qfcpd4vyynx8u2q45tpcrqh8zzhwhe2z7gd0rsj'
ROOT = Path(__file__).resolve().parents[1]
BANNED = re.compile(r'\b(?:adb|fastboot|sudo|su|apt-get|apt|pkg|reboot|shutdown|flash|wallet|lncli|keysend|curl|wget)\b|rm\s+-[a-z]*r|git\s+(?:push|commit)|pip\s+install', re.I)
EVENT_TYPES = {'MINT_GATE_LIVE_TRIGGER','MINT_GATE_SUCCESS','L402_LIVE_GATE','INTERNAL_WATCHER'}

def mainnet_receipt():
    return {'chain':'bitcoin-mainnet','txid':TXID,'output_index':1,'receiving_address':ADDRESS,
        'sats':18369,'reported_cashapp_usd':'11.79','block_height':961297,
        'block_time_utc':'2026-08-06T13:33:53Z','status':'confirmed',
        'independent_explorers':['mempool.space','blockstream.info'],
        'payment_instruction':False,'lightning_settlement_verified':False}

def scan_event_spine(path: Path, max_bytes=8*1024*1024):
    out = {'source_status':'not_accessible','recognized_event_count':0,
        'mint_gate_trigger_count':0,'mint_gate_success_with_matching_txid':0,
        'l402_challenge_count':0,'l402_payment_settled':False,'invalid_line_count':0,
        'last_recognized_at':None}
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size>max_bytes:
            return out
        with path.open('rb') as f:
            lines=f.readlines()
    except (OSError,ValueError):return out
    out['source_status']='read_only_local_file'
    for line in lines:
        if len(line)>65536:out['invalid_line_count']+=1;continue
        try: ev=json.loads(line)
        except (json.JSONDecodeError,UnicodeDecodeError):out['invalid_line_count']+=1;continue
        if not isinstance(ev,dict) or ev.get('type') not in EVENT_TYPES:continue
        typ=ev['type'];data=ev.get('data') if isinstance(ev.get('data'),dict) else {}
        out['recognized_event_count']+=1
        if isinstance(ev.get('ts'),str) and re.fullmatch(r'[0-9TZ:+.\-]{15,55}',ev['ts']):
            out['last_recognized_at']=ev['ts']
        if typ=='MINT_GATE_LIVE_TRIGGER':out['mint_gate_trigger_count']+=1
        elif typ=='MINT_GATE_SUCCESS':
            receipt=data.get('tx_receipt','')
            if isinstance(receipt,dict): got=receipt.get('txid')
            elif isinstance(receipt,str):
                try:got=json.loads(receipt).get('txid')
                except (ValueError,AttributeError):got=None
            else:got=None
            if got==TXID or data.get('txid')==TXID:out['mint_gate_success_with_matching_txid']+=1
        elif typ=='L402_LIVE_GATE' and data.get('action')=='402_REJECT':out['l402_challenge_count']+=1
    return out

def dashboard_state(event_spine:Path|None,revision='unbound'):
    event=scan_event_spine(event_spine) if event_spine else {'source_status':'not_configured',
        'recognized_event_count':0,'l402_payment_settled':False,'l402_challenge_count':0,
        'mint_gate_success_with_matching_txid':0}
    return {'schema':'mikaya.unified-dashboard.v1','revision':revision,
        'bitcoin':mainnet_receipt(), 'etzora_vault':{'mode':'read_only_evidence_index',
            'ledger_observed':event['source_status']=='read_only_local_file','protected_vault_written':False},
        'ahava':{'source_module':'engineering/ahava-v2',
            'requires_signed_owner_policy':True,'automatic_disbursement':False,
            'evidence_object':'engineering/ahava-v2/bitcoin-proof.cjs'},
        'l402':{'event_spine':event,'payment_preimage_verified':False,
            'macaroon_verified_from_original':False},
        'watchers':{'canonical_active_count':1,'canonical':'MIKAYA Unified F110 Watch',
            'archive_path':'docs/watch/archive/MIKAYA_F110_AUTOMATIONS_SNAPSHOT_20261026.json',
            'device_background_services_mutated':False},
        'manus':{'previous_dashboard_url':'https://sh-sm5re8hf.manus.space/',
            'last_known_dashboard':'unverified_404','authenticated_site_inspected':False},
        'release':{'android_firmware_signed':False,'apk_installed':False,
            'cloud_deployed':False,'device_oem_acceptance':False}}

def _fallback_bitcoin_evidence(timeout):
    """Portable, read-only two-explorer verification when Node adapter unavailable."""
    import urllib.request
    urls=['https://mempool.space/api/tx/'+TXID,'https://blockstream.info/api/tx/'+TXID]
    observations=[]
    for url in urls:
        request=urllib.request.Request(url,headers={'User-Agent':'MIKAYA-Mainnet-ReadOnly/1.0'})
        with urllib.request.urlopen(request,timeout=timeout/2) as response:
            item=json.loads(response.read(512*1024))
        status=item.get('status',{})
        outputs=item.get('vout',[])
        if (item.get('txid')!=TXID or status.get('confirmed') is not True or
            not isinstance(outputs,list) or len(outputs)<2 or
            outputs[1].get('scriptpubkey_address')!=ADDRESS or outputs[1].get('value')!=18369 or
            status.get('block_height')!=961297 or not isinstance(status.get('block_hash'),str) or
            len(status['block_hash'])!=64 or status.get('block_time')!=1786023233):
            raise RuntimeError('Explorer transaction output or block mismatch')
        observations.append((item['txid'],status['block_hash'],status['block_height'],
                             status['block_time'],item.get('fee'),outputs[1]['value']))
    if observations[0]!=observations[1]:raise RuntimeError('Independent explorers disagree')
    return {'evidence':{'schema':'mikaya.bitcoin-mainnet-evidence.v1','network':'bitcoin-mainnet',
      'transaction':{'txid':TXID,'receiving_address':ADDRESS,'output_index':1,
      'received_sats':18369,'confirmed':True,'block_height':961297,
      'block_hash':observations[0][1],'block_time':'2026-08-06T13:33:53.000Z',
      'miner_fee_sats':observations[0][4]},
      'settlement':{'bitcoin_mainnet':'confirmed','lightning_invoice':'not_asserted',
       'l402_payment_authorization':'not_asserted'}},'source':'portable_two_explorer_fallback'}

def verify_bitcoin_live(output: Path | None = None,timeout=28):
    """Use installed AHAVA node verifier or portable strict mainnet verifier."""
    if not is_host_job_execution_allowed():
        raise RuntimeError('MTG thermal status prevents optional live verification')
    module=ROOT/'tools/ahava-mainnet-proof.cjs'
    if module.is_file():
        process=subprocess.run(['node',str(module)],cwd=ROOT,text=True,capture_output=True,
                                timeout=timeout,check=False)
        if process.returncode!=0:raise RuntimeError('Bitcoin independent explorer check failed')
        data=json.loads(process.stdout)
    else:
        data=_fallback_bitcoin_evidence(timeout)
    receipt=data.get('evidence',{}).get('transaction',{})
    if (receipt.get('txid')!=TXID or receipt.get('received_sats')!=18369 or
        receipt.get('receiving_address')!=ADDRESS or receipt.get('confirmed') is not True or
        receipt.get('block_height')!=961297):
        raise RuntimeError('Bitcoin receipt mismatch: refusing to accept')
    if output:
        output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        if output.exists() or output.is_symlink():
            raise FileExistsError('evidence immutable: select unused destination')
        with os.fdopen(os.open(str(output),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as f:
            json.dump(data,f,indent=2)
            f.write('\n')
    return data

def select_jobs(plan,profile):
    jobs=plan.get('jobs')
    if not isinstance(jobs,dict) or not jobs:raise ValueError('empty CI source plan')
    if profile=='all':return sorted(jobs)
    if profile=='smoke':
        selected=plan.get('smoke_jobs') or list(jobs)
        if any(n not in jobs for n in selected):raise ValueError('missing smoke job')
        return list(selected)
    raise ValueError('unsupported job profile')

def read_thermal_allowed():
    try:
        r=subprocess.run(['mikaya-nice','status'],capture_output=True,text=True,timeout=5,check=False)
        return r.returncode==0 and '"decision_for_optional_jobs": "ALLOW"' in r.stdout
    except (OSError,subprocess.SubprocessError):return False

def is_host_job_execution_allowed():
    if os.environ.get('ANDROID_ROOT') or os.environ.get('PREFIX','').startswith('/data/data/com.termux/'):
        return read_thermal_allowed()
    return True

def _execute_job(job_name,job,output,revision,timeout):
    scripts=job.get('script',[])
    result={'revision':revision,'job':job_name,'status':'DENIED','exit_code':2}
    if not scripts or not all(isinstance(s,str) and s.strip() and not BANNED.search(s) for s in scripts):
        return result
    if not is_host_job_execution_allowed():return {**result,'status':'THERMAL_HOLD','exit_code':75}
    log=output/(job_name+'.log')
    env={**os.environ,'CI_COMMIT_SHA':revision,'CI':'true','PYTHONDONTWRITEBYTECODE':'1'}
    started=time.monotonic()
    try:
        with log.open('wb') as f:
            p=subprocess.Popen(['/bin/sh','-eu','-c','\n'.join(scripts)],cwd=ROOT,
                                env=env,stdout=f,stderr=subprocess.STDOUT,
                                start_new_session=True)
            try:rc=p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                import signal
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                p.wait();rc=124
    except OSError:rc=127
    return {**result,'status':'PASS' if rc==0 else 'FAIL','exit_code':rc,
            'elapsed_seconds':round(time.monotonic()-started,3),'log':log.name if log.exists() else None}

def run_parallel_jobs(plan,output,selected,revision,workers=4,timeout=180):
    if not (1<=workers<=8) or not (1<=timeout<=3600):raise ValueError('unbounded execution')
    output.mkdir(parents=True,exist_ok=True,mode=0o700)
    if any(n not in plan['jobs'] for n in selected):raise ValueError('unknown job')
    results={}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures={pool.submit(_execute_job,n,plan['jobs'][n],output,revision,timeout):n for n in selected}
        for f in concurrent.futures.as_completed(futures):
            results[futures[f]]=f.result()
    status='PASS' if results and all(r['status']=='PASS' for r in results.values()) else 'FAIL'
    report={'schema':'mikaya.unified-parallel-pipeline.v1','revision':revision,'status':status,
            'synchronized':bool(results) and all(r['revision']==revision for r in results.values()),
            'jobs':{k:results[k] for k in sorted(results)},'job_count':len(results),
            'no_wallet_transfers':True,'oem_release_approved':False}
    (output/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    return report

HTML='''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MIKAYA • Unified Evidence</title><style>body{font:16px system-ui;background:#111a24;color:#e5edf7;padding:24px;max-width:1000px;margin:auto}pre{background:#182634;white-space:pre-wrap;overflow-wrap:anywhere;padding:20px;border-radius:12px}h1{font-size:28px}.sub{color:#9dc3cf}a{color:#97d2fa}</style><h1>MIKAYA Sovereign • Etzora / AHAVA</h1><p class="sub">Read-only Bitcoin, L402, vault, engineering CI and unified watch status. No wallet keys or automatic payouts.</p><pre id="report">Loading local data...</pre><script>fetch('/api/status',{cache:'no-store'}).then(x=>x.json()).then(x=>document.getElementById('report').textContent=JSON.stringify(x,null,2)).catch(()=>document.getElementById('report').textContent='status unavailable');</script></html>'''

def serve(event_spine,revision,port):
    if not 1024<=port<=65535:raise ValueError('port out of range')
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in ('/','/api/status'):
                self.send_error(404);return
            raw=(HTML if self.path=='/' else json.dumps(dashboard_state(event_spine,revision),indent=2)).encode()
            self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8' if self.path=='/' else 'application/json; charset=utf-8')
            self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; style-src 'unsafe-inline'")
            self.end_headers();self.wfile.write(raw)
        def log_message(self,*_):pass
    host='127.0.0.1'
    server=ThreadingHTTPServer((host,port),Handler)
    print(f'MIKAYA dashboard local: http://127.0.0.1:{port}/',flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()

def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    sub=ap.add_subparsers(dest='command',required=True)
    for name in ('status','serve'):
        s=sub.add_parser(name);s.add_argument('--event-spine',type=Path,default=None);s.add_argument('--revision',default='unbound')
        if name=='serve':s.add_argument('--port',type=int,default=8787)
    v=sub.add_parser('verify-bitcoin');v.add_argument('--output',type=Path,default=None)
    p=sub.add_parser('pipeline');p.add_argument('--plan',type=Path,default=ROOT/'.ci/f110-host-jobs.json');p.add_argument('--profile',choices=['smoke','all'],default='all');p.add_argument('--workers',type=int,default=4);p.add_argument('--timeout',type=int,default=180);p.add_argument('--output',type=Path,default=ROOT/'.mikaya_reports');p.add_argument('--revision',default=os.environ.get('CI_COMMIT_SHA','local'))
    a=ap.parse_args(argv)
    if a.command=='status':print(json.dumps(dashboard_state(a.event_spine,a.revision),indent=2));return 0
    if a.command=='serve':serve(a.event_spine,a.revision,a.port);return 0
    if a.command=='verify-bitcoin':
        try: receipt=verify_bitcoin_live(a.output)
        except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
            print('MIKAYA_BITCOIN_HOLD: '+str(exc),file=sys.stderr);return 2
        print(json.dumps(receipt,indent=2));return 0
    if a.command=='pipeline':
        if (os.environ.get('ANDROID_ROOT') or os.environ.get('PREFIX','').startswith('/data/data/com.termux/')) and a.profile=='all':
            print('MIKAYA_HOST_ONLY: full multi-job CI is not permitted on Android',file=sys.stderr);return 75
        if not is_host_job_execution_allowed():print('MIKAYA_THERMAL_HOLD: run independent host pipeline when device cools',file=sys.stderr);return 75
        plan=json.loads(a.plan.read_text());result=run_parallel_jobs(plan,a.output,select_jobs(plan,a.profile),a.revision,a.workers,a.timeout)
        print(json.dumps(result,indent=2));return 0 if result['status']=='PASS' else 1
    return 2
if __name__=='__main__':raise SystemExit(main())
