#!/usr/bin/env python3
"""One-at-a-time safe rolling restart of the Sovereign shadow observer."""
import os,subprocess,signal,time,pathlib,json,sys
root=pathlib.Path.home()/"sovereign_exec"
target=(root/"cortex"/"shadow_governance.py").resolve()
log=root/"ledger"/"shadow-governance-runtime.log"
def processes():
    p=subprocess.run(["ps","-A","-o","pid,args"],capture_output=True,text=True,timeout=4,check=True)
    result=[]
    for line in p.stdout.splitlines()[1:]:
        a=line.strip().split()
        if len(a)<4:continue
        try:pid=int(a[0])
        except ValueError:continue
        argv=a[1:]
        exe=argv[0].rsplit("/",1)[-1]
        if not exe.startswith("python"):continue
        if str(target) in argv[1:] and "--loop" in argv:
            result.append(pid)
    return result
before=processes()
if len(before)>1: raise SystemExit("ABORT: multiple shadow processes; manual review needed")
if len(before)==1:
    os.kill(before[0],signal.SIGTERM)
    for _ in range(30):
        if not processes():break
        time.sleep(.1)
    if processes():raise SystemExit("ABORT: existing shadow didn't exit, no duplicate started")
with log.open("ab") as out:
    child=subprocess.Popen([sys.executable,"-u",str(target),"--loop","--active"],cwd=root,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
time.sleep(1.5)
pids=processes()
if len(pids)!=1 or child.pid not in pids:
    raise SystemExit("FAIL: shadow not uniquely running; pids="+repr(pids))
print(json.dumps({"result":"active","previous":before,"pid":child.pid,"instanceCount":len(pids),"loopSeconds":38}))
