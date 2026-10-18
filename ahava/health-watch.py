#!/data/data/com.termux/files/usr/bin/python
"""Monitor the AHAVA application health endpoint; preserve existing state."""
import datetime,fcntl,json,os,subprocess,time,urllib.request
from pathlib import Path
home=Path.home()
root=home/'sovereign_exec'
role='F110' if (root/'start_fossibot_mesh.sh').exists() else 'Motorola'
log=root/'ledger'/'ahava-health-watch.log'
lock=root/'ledger'/'ahava-health-watch.lock'
root.joinpath('ledger').mkdir(parents=True,exist_ok=True)
def record(message):
 with log.open('a') as handle:
  handle.write(datetime.datetime.now(datetime.timezone.utc).isoformat()+' '+message+'\n')
def ready():
 if role=='F110':
  try:
   with urllib.request.urlopen('http://127.0.0.1:43824/health',timeout=3) as f:
    return json.load(f).get('service')=='ahava-peer'
  except Exception:return False
 p=root/'ahava'/'sync-state.json'
 try:
  state=json.loads(p.read_text())
  t=state.get('lastAttempt') or state.get('lastSuccess')
  age=(datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromisoformat(t.replace('Z','+00:00'))).total_seconds()
  return age<185
 except Exception:return False
def secure_bridge_ready():
 try:
  with urllib.request.urlopen('http://127.0.0.1:43823/health',timeout=3) as f:
   obj=json.load(f)
  return obj.get('status')=='ok'
 except Exception:return False
def start_bridge():
 env=os.environ.copy()
 with (root/'ledger'/'secure-bridge-runtime.log').open('ab') as out:
  child=subprocess.Popen(['node',str(root/'boot'/'mesh_bridge_secure.js')],cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
 record('secure_bridge_relaunch_requested pid='+str(child.pid))
def start():
 env=os.environ.copy()
 env['AHAVA_NODE']=role
 if role=='F110':
  env.update(AHAVA_BIND='127.0.0.1',AHAVA_PORT='43824')
  target=root/'ahava'/'peer-server.js'
 else:
  env['AHAVA_PEER_URL']='http://127.0.0.1:43824'
  target=root/'ahava'/'sync.js'
 with (root/'ledger'/'ahava-runtime.log').open('ab') as out:
  child=subprocess.Popen(['node',str(target)],cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
 record('relaunch_requested role='+role+' pid='+str(child.pid))
def main():
 with lock.open('a+') as fd:
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:
   record('watch_already_running');return
  record('watch_started role='+role)
  next_retry=0
  bridge_retry=0
  while True:
   good=ready()
   if good: next_retry=0
   elif time.monotonic()>=next_retry:
    start()
    next_retry=time.monotonic()+90
   if role=='F110' and not secure_bridge_ready() and time.monotonic()>=bridge_retry:
    start_bridge()
    bridge_retry=time.monotonic()+90
   time.sleep(15)
if __name__=='__main__':main()
