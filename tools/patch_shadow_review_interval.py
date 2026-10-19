#!/usr/bin/env python3
"""Idempotent deployment prep for Sovereign shadow governor.
Only adjust its periodic interval; preserve source hash and prior version.
"""
from pathlib import Path
import hashlib, py_compile, subprocess, sys, shutil
root=Path.home()/"sovereign_exec"
source=root/"cortex"/"shadow_governance.py"
original=source.read_bytes()
old=b"time.sleep(15)"
new=b"time.sleep(38)"
if old in original and original.count(old)!=1: raise SystemExit("ABORT ambiguous shadow loop")
if old in original:
    tagged=hashlib.sha256(original).hexdigest()[:12]
    back=source.with_name("shadow_governance.py.backup.before-38s."+tagged)
    if back.exists() and back.read_bytes()!=original:raise SystemExit("ABORT backup collision")
    if not back.exists():back.write_bytes(original)
    modified=original.replace(old,new)
    source.write_bytes(modified)
elif new in original:
    modified=original
else:raise SystemExit("ABORT unknown version of shadow implementation")
py_compile.compile(str(source),doraise=True)
p=subprocess.run([sys.executable,str(source),"--selftest"],capture_output=True,text=True,timeout=8)
if p.returncode!=0 or "SELFTEST_PASS" not in p.stdout:raise SystemExit("SELFTEST FAIL: "+p.stderr[-250:])
print("SHADOW_READY interval_seconds=38 sha256="+hashlib.sha256(modified).hexdigest()+" "+p.stdout.strip())
