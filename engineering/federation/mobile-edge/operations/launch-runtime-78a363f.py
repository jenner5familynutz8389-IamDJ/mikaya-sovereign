#!/usr/bin/env python3
"""Verify reviewed source and existing native execution support before Node starts."""
import fcntl, hashlib, json, os, pathlib, stat, sys

if sys.flags.optimize:
    raise RuntimeError('optimized_python_refused')
H=pathlib.Path('/data/data/com.termux/files/home')
P=pathlib.Path('/data/data/com.termux/files/usr')
R=H/'.local/share/mikaya/mobile-evidence-78a363fd516634cd'
MANIFEST_SHA='feb22bd2697ae77c1324d2e61858bcd863454df97bc27a556617ca931c13ca5d'
COMMIT='78a363fd516634cd12331810dbde6a938b157e1b'

def private_read(p,limit=131072):
    assert p.is_absolute() and p.resolve(strict=True)==p
    s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1
    assert not s.st_mode&0o077 and s.st_size<=limit
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        start=os.fstat(f.fileno());b=f.read(limit+1);end=os.fstat(f.fileno())
    identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    assert len(b)<=limit and identity(s)==identity(start)==identity(end)==identity(p.lstat())
    return b

def main():
    assert os.getuid() in (10229,10882) and len(sys.argv) in (3,4)
    mode=sys.argv[1];assert mode in ('serve','read','observe')
    assert len(sys.argv)==(4 if mode=='observe' else 3)
    manifest_raw=private_read(R/'RUNTIME-SOURCE.json',8192)
    assert hashlib.sha256(manifest_raw).hexdigest()==MANIFEST_SHA
    manifest=json.loads(manifest_raw);assert manifest['sourceCommit']==COMMIT
    for name,digest in manifest['files'].items():
        assert hashlib.sha256(private_read(R/name)).hexdigest()==digest
    config=pathlib.Path(sys.argv[2]);g=json.loads(private_read(config,8192))
    assert g['schema']=='mikaya.mobile-edge.local-gateway.v1' and g['port']==4188
    profile=g['nativeMtg'];required={'command','commandSha256','policyFile','policySha256'}
    assert set(profile) in (required,required|{'termuxExecSha256'})
    for path_field,hash_field in [('command','commandSha256'),('policyFile','policySha256')]:
        assert hashlib.sha256(private_read(pathlib.Path(profile[path_field]))).hexdigest()==profile[hash_field]
    env={'HOME':str(H),'PREFIX':str(P),'PATH':str(P/'bin'),'LANG':'C.UTF-8'}
    if 'termuxExecSha256' in profile:
        library=P/'lib/libtermux-exec.so'
        assert hashlib.sha256(private_read(library,262144)).hexdigest()==profile['termuxExecSha256']
        env['LD_PRELOAD']=str(library)
    node=str(P/'bin/node')
    if mode=='observe':
        observation=pathlib.Path(sys.argv[3]);private_read(observation,8192)
        args=[node,str(R/'engineering/federation/mobile-edge/observe-and-read.cjs'),
              '--gateway-config',str(config),'--observation-config',str(observation)]
        if os.getuid()==10229:
            # Hold the existing publisher coordination boundary through this exec.
            lock=H/'.local/state/mikaya-runtime/publisher.lock';private_read(lock,8192)
            fd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW);before=lock.lstat();opened=os.fstat(fd)
            assert (before.st_dev,before.st_ino)==(opened.st_dev,opened.st_ino)
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);os.set_inheritable(fd,True)
    else:
        args=[node,str(R/'engineering/federation/mobile-edge/local-evidence-gateway.cjs'),
              mode,'--config',str(config)]
    current=os.getpriority(os.PRIO_PROCESS,0)
    if current<15:os.nice(15-current)
    os.umask(0o077);os.execve(node,args,env)

if __name__=='__main__':
    try:
        main()
    except Exception:
        print('MIKAYA_OWNER_LOCAL_RUNTIME_HOLD',file=sys.stderr)
        raise SystemExit(2)
