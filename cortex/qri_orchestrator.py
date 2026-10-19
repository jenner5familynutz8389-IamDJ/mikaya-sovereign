#!/usr/bin/env python3
"""Sovereign QRI ordered review, thermal gate, and completion handoff.
Unprivileged, read-only observations. Never executes queued shell commands,
changes Android policies, restarts services, edits history or moves Git refs.
The existing thermal governor and shadow watcher retain service authority.
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

BASE=Path.home()/"sovereign_exec"
LEDGER=BASE/"ledger"
CORTEX=BASE/"cortex"
DOCS=BASE/"docs"
SIGNED_QUEUE=CORTEX/"QRI_WORK_QUEUE.json"
GOV=LEDGER/"thermal-governor-state.json"
LOCK=LEDGER/"qri-automation.lock"
EVENTS=LEDGER/"qri-automation-events.jsonl"
STATE=LEDGER/"qri-automation-state.json"
HANDOFF=DOCS/"QRI_LATEST_HANDOFF.json"
HANDOFF_MD=DOCS/"QRI_LATEST_HANDOFF.md"
REVIEW_SECONDS=38
MAX_SENSOR_AGE=150
GENESIS="0"*64

def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def read_json(p,default=None):
    try: return json.loads(Path(p).read_text())
    except (OSError,ValueError): return default if default is not None else {}

def atomic(path,data):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+".new."+str(os.getpid()))
    with tmp.open("x",encoding="utf-8") as h:
        h.write(data)
        h.flush()
        os.fsync(h.fileno())
    os.replace(tmp,path)

def age_seconds(stamp):
    try:
        when=dt.datetime.fromisoformat(str(stamp).replace("Z","+00:00"))
        return (dt.datetime.now(dt.timezone.utc)-when).total_seconds()
    except (ValueError,TypeError,AttributeError): return 1e30

def signed_document(path):
    """Authenticate against THIS device's existing public key; never read private key."""
    path=Path(path)
    if not path.is_file() or not Path(str(path)+".sig.json").is_file():
        return False
    public=BASE/"ahava/identity/node-ed25519-public.pem"
    if not public.is_file(): return False
    js=('const f=require("fs"),c=require("crypto");'
        'const p=process.argv[1],s=JSON.parse(f.readFileSync(p+".sig.json")),b=f.readFileSync(p);'
        'const trusted=f.readFileSync(process.argv[2],"utf8");'
        'if(s.publicKeyPem!==trusted||s.sha256!==c.createHash("sha256").update(b).digest("hex")'
        '||!c.verify(null,b,trusted,Buffer.from(s.signatureBase64,"base64")))process.exit(3);')
    try:
        r=subprocess.run(["node","-e",js,str(path),str(public)],capture_output=True,
                         text=True,timeout=4)
        return r.returncode==0
    except (OSError,subprocess.TimeoutExpired): return False

def last_event():
    if not EVENTS.is_file() or EVENTS.stat().st_size==0: return GENESIS
    with EVENTS.open("rb") as f:
        f.seek(max(0,EVENTS.stat().st_size-16384))
        lines=f.read().splitlines()
    if not lines: return GENESIS
    row=json.loads(lines[-1])
    candidate={k:v for k,v in row.items() if k!="hash"}
    if row.get("hash")!=sha(canonical(candidate)):
        raise RuntimeError("QRI append-only audit tail invalid; fail closed")
    return row["hash"]

def ledger_append(payload):
    prior=last_event()
    event={"schema":"sovereign.qri-automation-event.v1","at":utc(),"prevHash":prior,
           "payload":payload}
    event["hash"]=sha(canonical(event))
    with EVENTS.open("a",encoding="utf-8") as h:
        h.write(canonical(event).decode()+"\n")
        h.flush()
        os.fsync(h.fileno())
    return event["hash"]

def git_snapshot():
    repo=Path("/storage/emulated/0/Documents/MIKAYA-SOVEREIGN-GITSYNC")
    if not (repo/".git").exists(): return {"state":"checkout_not_found"}
    def git(*args):
        try:
            r=subprocess.run(["git","-c","safe.directory="+str(repo),"-C",str(repo),*args],
                            capture_output=True,text=True,timeout=4)
            return r.stdout.strip() if r.returncode==0 else None
        except (OSError,subprocess.TimeoutExpired): return None
    local=git("rev-parse","HEAD")
    upstream=git("rev-parse","refs/remotes/origin/main")
    ahead=git("rev-list","--count","refs/remotes/origin/main..HEAD") if upstream else None
    return {"state":"local_ahead" if ahead is not None and int(ahead)>0 else
                   "local_matches_tracking" if local and local==upstream else "review_required",
            "localHead":local,"originTrackingHead":upstream,
            "commitsNotPublishedByThisCheck":int(ahead) if ahead is not None else None,
            "remoteLiveVerified":False}

def governor_snapshot():
    g=read_json(GOV)
    fresh=age_seconds(g.get("at")) <= MAX_SENSOR_AGE
    allowed=(fresh and g.get("mode")=="normal"
             and g.get("confidence")=="observed"
             and g.get("nextOptionalLaunchAllowed") is True)
    return {"mode":g.get("mode","unknown") if fresh else "stale",
            "fresh":fresh,"thermalSensorAvailable":bool(fresh and g.get("confidence")=="observed"),
            "optionalJobsPermitted":bool(allowed),"source":g.get("androidThermalSource","unavailable"),
            "reviewIntervalSeconds":REVIEW_SECONDS}

def jobs_snapshot(queue, governor, git, report_ok):
    raw=queue.get("jobs",[])
    known={x.get("id"):x for x in raw if isinstance(x,dict)}
    results=[]
    def add(key,state,why,where,manual=None):
        results.append({"id":key,"state":state,"reason":why,"evidencePath":where,
                        "manualStep":manual})
    add("MOTO-USERSPACE-EVENTS",
        "VERIFIED_TO_2900" if report_ok else "CHECKPOINT_NEEDS_REVIEW",
        "Both original device audits compared 2900 sequential records with identical canonical SHA-256; report separately signed on each phone" if report_ok else "Missing or untrusted signed checkpoint",
        "docs/MOTOROLA_EVENT_AUDIT_CHECKPOINT_2900.json")
    thermal_ok=(CORTEX/"resource_governor.py").is_file() and (CORTEX/"shadow_governance.py").is_file()
    add("THERMAL-AND-SHADOW",
        "PARTIAL_THERMAL_GATED" if thermal_ok else "NEEDS_IMPLEMENTATION",
        "Current supervisor/governor installed; real Android thermal values unavailable or not normal, so optional load remains deferred" if thermal_ok else "Expected sources missing",
        "ledger/thermal-governor-state.json",
        "Provide supported OEM Android thermal sensor/OnThermalStatusChanged integration; run real reboot and recovery tests safely")
    add("MOTO-PRIVILEGED-EVENTS","BLOCKED_OEM_ACCESS",
        "Termux sandbox cannot collect complete Android framework, GPU, modem, MTK sensor or kernel events",
        "docs/MOTOROLA_EVENT_AUDIT_CHECKPOINT_2900.json",
        "Supply manufacturer-authorized build access and sensor/SELinux integration for each device")
    backup=read_json(DOCS/"INDEPENDENT_BACKUP_RESTORE_TEST_2026-10-18.json")
    add("SD-RECOVERY",
        "PARTIAL_EXTERNAL_UNTRUSTED" if backup.get("status")=="passed" else "REVIEW_REQUIRED",
        "Internal 11-manifest restore passed on earlier test; external microSD recovery still has damaged FOSSiBOT copies and Motorola media was read-only",
        "docs/INDEPENDENT_BACKUP_RESTORE_TEST_2026-10-18.json",
        "When cool, inspect media and authorize non-destructive card diagnostics; do not erase or rewrite bad evidence")
    add("GITHUB-MULTIREPO-PUBLISH",
        "PENDING_PUSH" if git["state"]=="local_ahead" else "PUBLICATION_CHECK_REQUIRED",
        "Local commits ahead of previously fetched origin/main; no credentials or forced publish attempted" if git["state"]=="local_ahead" else "Review live GitHub permissions and repository routing",
        "/storage/emulated/0/Documents/MIKAYA-SOVEREIGN-GITSYNC",
        "Use authorized GitSync Push Origin for signed curated commit and confirm exact remote SHA")
    # Existing signed QRI items always take priority; do not promote speculative tasks.
    if set(known)!={"MOTO-USERSPACE-EVENTS","THERMAL-AND-SHADOW",
                    "MOTO-PRIVILEGED-EVENTS","SD-RECOVERY","GITHUB-MULTIREPO-PUBLISH"}:
        add("QUEUE-SCHEMA-REVIEW","BLOCKED_SIGNATURE_OR_SCHEMA_REVIEW",
            "Unexpected signed queue job list; do not run unrecognized jobs",
            "cortex/QRI_WORK_QUEUE.json")
    for name,reason in [
        ("DEBUG-TELEMETRY","Automatic diagnosis with bounded, reversible repairs not yet acceptance-tested"),
        ("MACAROON-FORGE","Device-scope, issuer, replay, rotation and revocation tests outstanding"),
        ("COLD-REBOOT-VALIDATION","No verified physical restart test of both phones"),
        ("OEM-KERNEL-INTEGRATION","Full source and device-specific OEM signing inputs not verified"),
        ("AI-GOVERNANCE-71-SOURCES","NotebookLM source provenance/access not verified"),
        ("COMPENSATION-MODEL","Simulated only; no real Bitcoin settlement or dividend verified"),
        ("UNKNOWN-GIT-OBJECT","SHA 21c6c0c912b9d8300f0242061925de6b396f0508 not located")]:
        add(name,"WAITING_FOR_IMPLEMENTATION_OR_INPUT",reason,
            "docs/IMPLEMENTATION_BACKLOG_2026-10-18.md")
    return results

def snapshot():
    if not signed_document(SIGNED_QUEUE):
        raise RuntimeError("Signed QRI policy not verified: no work permitted")
    q=read_json(SIGNED_QUEUE)
    g=governor_snapshot()
    gs=git_snapshot()
    report=DOCS/"MOTOROLA_EVENT_AUDIT_CHECKPOINT_2900.json"
    report_ok=signed_document(report)
    if report_ok:
        v=read_json(report).get("verification",{})
        report_ok=(v.get("recordsMatched")==2900
                    and v.get("canonicalSha256")=="55c2914fd8c6aaec7ffa4b068b749f259455e2d3a6d902c72f336e5a09a2db7f"
                    and v.get("receiverAndReplicaMatched") is True)
    jobs=jobs_snapshot(q,g,gs,report_ok)
    active=next((j for j in jobs if j["state"].startswith("PARTIAL")),None)
    manual=[{"task":j["id"],"action":j["manualStep"]} for j in jobs if j.get("manualStep")]
    all_software_complete=all(j["state"].startswith("VERIFIED") for j in jobs)
    return {"schema":"sovereign.qri-handoff.v1","observedAt":utc(),
            "node":"FOSSiBOT" if (BASE/"start_fossibot_mesh.sh").exists() else "Motorola",
            "signedPolicyVerified":True,"motorolaCheckpointVerified":report_ok,
            "thermal":g,"git":gs,"jobs":jobs,
            "currentReview":active["id"] if active else "NONE",
            "optionalWorkLaunched":False,
            "safetyReason":"No optional work runs while status is unknown/severe or when prerequisites are unverified",
            "physicalOrAccountActions":manual,"allSoftwareCompleted":all_software_complete}

def markdown(state):
    lines=["# Sovereign QRI — live handoff","",
           "Reviewed: "+state["observedAt"],
           "Node: "+state["node"],
           "Thermal mode: "+state["thermal"]["mode"],
           "Optional work permitted: "+str(state["thermal"]["optionalJobsPermitted"]),
           "Current review: "+state["currentReview"],"",
           "| Task | State | Evidence |","|---|---|---|"]
    for j in state["jobs"]:
        lines.append("| "+j["id"]+" | "+j["state"]+" | "+j["evidencePath"]+" |")
    lines+=["","## Owner / physical actions"]
    for item in state["physicalOrAccountActions"]:
        lines.append("- "+item["task"]+": "+item["action"])
    lines+=["","## Operational safety",
            "All original event logs and past correction chains remain unchanged.",
            "The 38-second review is diagnostic; it does not launch firmware changes or unverified optional work.",
            "Completion will be reported only after signed acceptance evidence exists.",
            ""]
    return "\n".join(lines)

def execute_once(force_log=False):
    state=snapshot()
    old=read_json(STATE)
    signature=sha(canonical({"jobs":state["jobs"],"thermal":state["thermal"],
                             "git":state["git"],"motorolaCheckpointVerified":state["motorolaCheckpointVerified"]}))
    old_at=age_seconds(old.get("observedAt"))
    if force_log or signature!=old.get("statusDigest") or old_at>=600:
        tip=ledger_append({"node":state["node"],"snapshotDigest":signature,
                           "thermalMode":state["thermal"]["mode"],"currentReview":state["currentReview"],
                           "optionalWorkLaunched":False,
                           "verifiedMotorolaCheckpoint":state["motorolaCheckpointVerified"],
                           "counts":{s:sum(1 for j in state["jobs"] if j["state"]==s)
                                     for s in set(j["state"] for j in state["jobs"])}})
    else: tip=last_event()
    state["statusDigest"]=signature
    state["auditTip"]=tip
    atomic(STATE,json.dumps(state,sort_keys=True,separators=(",",":"))+"\n")
    atomic(HANDOFF,json.dumps(state,indent=2,sort_keys=True)+"\n")
    if force_log or signature!=old.get("statusDigest"):
        atomic(HANDOFF_MD,markdown(state))
    return {"node":state["node"],"checkpoint":state["motorolaCheckpointVerified"],
            "thermal":state["thermal"]["mode"],"active":state["currentReview"],
            "eventHash":tip,"jobs":len(state["jobs"]),
            "allSoftwareCompleted":state["allSoftwareCompleted"]}

def self_test():
    # Test a little of the ordered, fail-closed logic without touching live files.
    fake={"mode":"unknown","optionalJobsPermitted":False}
    snapshot_git={"state":"local_ahead"}
    mock_jobs=jobs_snapshot({"jobs":[{"id":x} for x in [
        "MOTO-USERSPACE-EVENTS","THERMAL-AND-SHADOW",
        "MOTO-PRIVILEGED-EVENTS","SD-RECOVERY","GITHUB-MULTIREPO-PUBLISH"]]},
        fake,snapshot_git,True)
    assert mock_jobs[0]["id"]=="MOTO-USERSPACE-EVENTS"
    assert mock_jobs[0]["state"]=="VERIFIED_TO_2900"
    assert mock_jobs[1]["id"]=="THERMAL-AND-SHADOW"
    assert next(x for x in mock_jobs if x["id"]=="GITHUB-MULTIREPO-PUBLISH")["state"]=="PENDING_PUSH"
    assert not any(x["state"]=="COMPLETED_ALL" for x in mock_jobs)
    print(json.dumps({"passed":5,"checks":"ordered_queue, no_optional_unknown, verified_checkpoint, git_gate, manual_gates"}))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--once",action="store_true")
    ap.add_argument("--loop",action="store_true")
    ap.add_argument("--self-test",action="store_true")
    args=ap.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.once and not args.loop:
        raise SystemExit("Pass --once or --loop explicitly")
    LEDGER.mkdir(parents=True,exist_ok=True)
    DOCS.mkdir(parents=True,exist_ok=True)
    with LOCK.open("a+") as fd:
        try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({"alreadyRunning":True}))
            return
        while True:
            try: print(json.dumps(execute_once()),flush=True)
            except Exception as e:
                print(json.dumps({"error":type(e).__name__,"reason":str(e)[:160],
                                  "safe":"No optional jobs started"}),flush=True)
                if args.once: raise
            if not args.loop: break
            time.sleep(REVIEW_SECONDS)

if __name__=="__main__": main()
