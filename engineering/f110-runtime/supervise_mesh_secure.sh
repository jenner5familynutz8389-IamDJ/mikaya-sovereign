#!/data/data/com.termux/files/usr/bin/sh
# One bounded launch attempt; an outer owner may decide when explicit recovery is safe.
umask 077
CODE_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P) || exit 2
BASE="$HOME/sovereign_exec"
BIND="$MESH_BRIDGE_BIND"
PORT="$MESH_BRIDGE_PORT"
[ -n "$BIND" ] || BIND='127.0.0.1'
[ -n "$PORT" ] || PORT='43823'
BRIDGE="$CODE_DIR/boot/mesh_bridge_secure.js"
cd "$BASE" || exit 2

record() {
  printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" >> "$BASE/ledger/receiver-supervisor.log" || exit 2
}
# Reuse the bridge's pure bind validator, before any request or writer acquisition.
if ! node -e 'require(process.argv[1]).validateBindConfig(process.argv[2],Number(process.argv[3]))' "$BRIDGE" "$BIND" "$PORT" >/dev/null 2>&1; then
  record "HOLD invalid or unavailable bridge configuration"
  exit 2
fi

# -f may report an HTTP error; the status still proves a listener is present.
# Disable proxy inheritance for this explicitly private loopback/overlay probe.
probe_code=$(curl -fsS --connect-timeout 1 --max-time 2 --noproxy '*' --proto '=http' \
  --output /dev/null --write-out '%{http_code}' "http://$BIND:$PORT/health" 2>/dev/null)
probe_exit=$?
case "$probe_code" in
  [1-5][0-9][0-9])
    record "HOLD existing HTTP listener observed; no competing bridge launched"
    exit 2
    ;;
esac
if [ "$probe_exit" -ne 7 ]; then
  record "HOLD listener availability unresolved; no bridge launched"
  exit 2
fi

# Curl7 is not itself proof of ECONNREFUSED (it can mean an unreachable route).
# A single bounded TCP probe must observe that exact error before starting.
if ! node -e '
const socket=require("node:net").connect({host:process.argv[1],port:Number(process.argv[2])});
const settle=code=>{socket.destroy();process.exit(code);};
socket.setTimeout(1000,()=>settle(2));
socket.once("connect",()=>settle(2));
socket.once("error",error=>settle(error.code==="ECONNREFUSED"?0:2));
' "$BIND" "$PORT" >/dev/null 2>&1; then
  record "HOLD TCP listener absence unproven; no bridge launched"
  exit 2
fi
record "listener connection refused; making one foreground bridge start attempt"
# Source-relative code preserves dependency layout in a versioned package. Data stays private.
# exec leaves a single owner; there is no inner two-second restart/log-flood loop.
exec node "$BRIDGE" >> "$BASE/ledger/secure-bridge-runtime.log" 2>&1
