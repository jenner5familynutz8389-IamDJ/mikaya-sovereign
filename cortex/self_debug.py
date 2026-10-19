#!/usr/bin/env python3
"""Read-only Sovereign self-debug observer: never restarts a service or accesses private keys."""
import argparse,datetime as dt,fcntl,hashlib,json,os,subprocess,time
from pathlib import Path
ROOT=Path.home()/"sovereign_exec"
LED=ROOT/"ledger"
LOCK=LED/"self-debug.lock"
STATE=LED/"self-debug-state.json"
EVENTS=LED/"self-debug-events.jsonl"
DOMAIN=b"SOVEREIGN-SELF-DEBUG-V1\x00"
INTERVAL=38
def canon(obj):
 return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def sha(value):
 return hashlib.sha256(value).hexdigest()
def read(path):
 try:
  data=json.loads(path.read_text())
  return data if isinstance(data,dict) else {}
 except (OSError,ValueError):return {}
def seconds(path):
 try:return round(max(0,time.time()-path.stat().st_mtime),2)
 except OSError:return None
def procs():
 try:
  p=subprocess.run(["ps","-A","-o","pid,args"],text=True,capture_output=True,timeout=3)
  if p.returncode:return None
  return [line.strip().split(None,1)[1].split() for line in p.stdout.splitlines()[1:] if len(line.strip().split(None,1))==2]
 except (OSError,subprocess.TimeoutExpired):return None
def count(cmds,rel,kind):
 if cmds is None:return None
 target=str(ROOT/rel)
 return sum(1 for args in cmds if args and Path(args[0]).name in (kind,kind+"3") and target in args[1:])
def inspect():
 role="F110" if (ROOT/"start_fossibot_mesh.sh").exists() else "Motorola"
 roles=[("thermal","cortex/resource_governor.py","python"),("shadow","cortex/shadow_governance.py","python"),("qri","cortex/qri_orchestrator.py","python"),("jitter","cortex/jitter_monitor.py","python")]
 if role=="F110":roles += [("ahava-peer","ahava/peer-server.js","node"),("mesh-bridge","boot/mesh_bridge_secure.js","node")]
 else:roles += [("ahava-sync","ahava/sync.js","node"),("mesh-client","motorola_mesh_client_secure.js","node")]
 observed=procs();processes={};findings=[]
 for name,rel,kind in roles:
  n=count(observed,rel,kind)
  processes[name]={"instances":n,"source":"app_visible_ps" if n is not None else "restricted"}
  if n==0:findings.append({"code":"missing_process","service":name})
  elif n is not None and n>1:findings.append({"code":"duplicate_process","service":name})
 t=read(LED/"thermal-governor-state.json")
 shadow=read(LED/"shadow-state.json")
 qri=read(LED/"qri-automation-state.json")
 age={key:seconds(LED/file) for key,file in (("thermal","thermal-governor-state.json"),("shadow","shadow-governance-runtime.log"),("qri","qri-automation-state.json"))}
 for name,v in age.items():
  if v is None or v>190:findings.append({"code":"stale_status","service":name})
 if t.get("mode") in ("severe","critical"):findings.append({"code":"thermal_pressure","service":"android"})
 for name,data in shadow.items():
  if isinstance(data,dict) and data.get("healthy") is False:findings.append({"code":"shadow_not_healthy","service":name})
 return {"schema":"sovereign.debug.observation.v1","at":dt.datetime.now(dt.timezone.utc).isoformat(),"node":role,"thermalMode":t.get("mode","unavailable"),"thermalTrusted":t.get("confidence")=="observed","workQueue":qri.get("currentReview"),"optionalWorkAllowed":bool(t.get("nextOptionalLaunchAllowed",False)) and not findings,"agesSeconds":age,"processes":processes,"findings":findings,"status":"needs_review" if findings else "observing","action":"diagnose_only_shadow_governance_retains_failover"}
def append(obs):
 prev="0"*64;n=0
 if EVENTS.is_file() and EVENTS.stat().st_size:
  with EVENTS.open("rb") as f:
   f.seek(max(0,EVENTS.stat().st_size-65536));lines=f.read().splitlines()
  if not lines:raise ValueError("empty audit tail")
  last=json.loads(lines[-1]);unsigned={k:v for k,v in last.items() if k!="hash"}
  if last.get("hash")!=sha(DOMAIN+canon(unsigned)):raise ValueError("self-debug tail hash mismatch")
  prev=last["hash"];n=int(last["seq"])
 body={"seq":n+1,"prevHash":prev,"observation":obs}
 event={**body,"hash":sha(DOMAIN+canon(body))}
 with EVENTS.open("a") as f:
  os.chmod(EVENTS,0o600);f.write(canon(event).decode()+"\n");f.flush();os.fsync(f.fileno())
 tmp=STATE.with_name(STATE.name+".tmp."+str(os.getpid()))
 with tmp.open("x") as f:
  os.chmod(tmp,0o600);f.write(canon({**obs,"audit":{"seq":n+1,"tip":event["hash"]}}).decode()+"\n");f.flush();os.fsync(f.fileno())
 os.replace(tmp,STATE)
 return {"node":obs["node"],"seq":n+1,"status":obs["status"],"thermalMode":obs["thermalMode"],"findings":obs["findings"]}
def selftest():
 assert count([["node","/home/u/sovereign_exec/ahava/sync.js"]],"ahava/sync.js","node")==0
 assert count(None,"any","node") is None
 sample={"seq":1,"prevHash":"0"*64,"observation":{"test":True}}
 h=sha(DOMAIN+canon(sample))
 assert len(h)==64 and h==sha(DOMAIN+canon(sample))
 assert len(inspect().get("processes",{}))==6
 print(json.dumps({"selfTest":"PASS","checks":4}))
def main():
 p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True)
 g.add_argument("--self-test",action="store_true");g.add_argument("--once",action="store_true");g.add_argument("--loop",action="store_true");o=p.parse_args()
 if o.self_test:selftest();return
 LED.mkdir(parents=True,exist_ok=True)
 with LOCK.open("a+") as f:
  try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:print("observer already active");return
  while True:
   try:print(json.dumps(append(inspect())),flush=True)
   except (OSError,ValueError,KeyError) as e:
    print("observer_error "+type(e).__name__+": "+str(e),flush=True)
    if o.once:raise
   if not o.loop:return
   time.sleep(INTERVAL)
if __name__=="__main__":main()
