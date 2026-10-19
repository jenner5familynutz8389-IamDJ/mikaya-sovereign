#!/usr/bin/env python3
"""Generate a bounded, non-executable-source fabric recovery snapshot.
Private keys, telemetry ledgers, wallet data and Android firmware are excluded.
The result must be put in AHAVA for signed encrypted distribution.
"""
import hashlib,io,json,os,pathlib,subprocess,tarfile,datetime,sys
root=pathlib.Path.home()/"sovereign_exec"
role="F110" if (root/"start_fossibot_mesh.sh").exists() else "Motorola"
outdir=root/"integrity"/"fabric-snapshots"
outdir.mkdir(parents=True,exist_ok=True,mode=0o700)
stamp="20261019"
name=f"MIKAYA-FABRIC-{role}-{stamp}-v1.tar.gz"
out=outdir/name
shared=[
 "cortex/resource_governor.py","cortex/shadow_governance.py",
 "cortex/qri_orchestrator.py","cortex/jitter_monitor.py",
 "cortex/policy.json","cortex/QRI_WORK_QUEUE.json",
 "cortex/QRI_WORK_QUEUE.json.sig.json",
 "cortex/patch_shadow_review_interval.py",
 "cortex/restart_shadow_once.py",
 "ahava/core.js","ahava/sync.js","ahava/backup-loop.py",
 "start_sovereign_secure.sh"
]
specific=(["boot/mesh_bridge_secure.js","start_fossibot_mesh.sh"] if role=="F110"
          else ["motorola_mesh_client_secure.js","start_motorola_mesh.sh"])
items={}
for rel in shared+specific:
 p=root/rel
 if not p.is_file():raise SystemExit("Required audited source missing: "+rel)
 if p.is_symlink():raise SystemExit("No links allowed: "+rel)
 b=p.read_bytes()
 if len(b)>1024*1024:raise SystemExit("Unexpected large source file: "+rel)
 items[rel]=b
gitrepo=pathlib.Path("/storage/emulated/0/Documents/MIKAYA-SOVEREIGN-GITSYNC")
commit=subprocess.run(["git","-C",str(gitrepo),"rev-parse","HEAD"],capture_output=True,text=True,timeout=8,check=True).stdout.strip()
manifest={"schema":"sovereign.fabric-snapshot.v1","nodeRole":role,
 "sourceCommit":commit,"fileCount":len(items),
 "files":{p:{"sha256":hashlib.sha256(b).hexdigest(),"size":len(b)} for p,b in sorted(items.items())},
 "exclusions":["private device signing keys","wallet data","raw telemetry","user identifiers","OEM firmware"],
 "operatorNote":"Use AHAVA-signed ciphertext as recovery medium. Do not run files from archives until separately reviewed. Android thermal framework remains authoritative."}
items["FABRIC-SNAPSHOT-MANIFEST.json"]=(json.dumps(manifest,sort_keys=True,indent=2)+"\n").encode()
items["RECOVERY-INSTRUCTIONS.txt"]=(
 "MIKAYA-SOVEREIGN fabric snapshot (versioned and read-only)\n"
 "Contains user-space source and a signed QRI work-queue configuration.\n"
 "Confirm source hashes, AHAVA signed manifest and peer identity before extracting.\n"
 "Never extract over running Termux files; restore to a separate testing folder.\n"
 "Do not flash to Android partitions or assume OEM firmware-signing rights.\n"
 "Live thermal sensor restrictions and microSD integrity exceptions remain open.\n"
).encode()
if out.exists():raise SystemExit("Existing snapshot left untouched: "+str(out))
with tarfile.open(out,"x:gz") as tar:
 for rel,b in sorted(items.items()):
  i=tarfile.TarInfo(rel);i.size=len(b);i.mode=0o600;i.uid=0;i.gid=0;i.mtime=0
  tar.addfile(i,io.BytesIO(b))
data=out.read_bytes()
if len(data)>2*1024*1024:raise SystemExit("Snapshot exceeds size guard")
with tarfile.open(out,"r:gz") as t:
 for rel,b in items.items():
  buf=t.extractfile(rel).read()
  if buf!=b:raise SystemExit("Tar roundtrip mismatch "+rel)
report={"node":role,"path":str(out),"size":len(data),
        "sha256":hashlib.sha256(data).hexdigest(),
        "sourceCommit":commit,"files":len(items),
        "roundtripVerified":True}
(out.with_suffix(out.suffix+".index.json")).write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
print(json.dumps(report))
