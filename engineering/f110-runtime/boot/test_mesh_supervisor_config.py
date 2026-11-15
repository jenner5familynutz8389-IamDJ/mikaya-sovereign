import unittest
import http.server
import os
import subprocess
import tempfile
import threading
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
class BridgeSupervisorTests(unittest.TestCase):
    def test_matches_default_listener_host(self):
        s=(ROOT/"supervise_mesh_secure.sh").read_text()
        self.assertIn("MESH_BRIDGE_BIND",s)
        self.assertIn("127.0.0.1",s)
    def test_does_not_poll_hardcoded_overlay_health_routes(self):
        s=(ROOT/"supervise_mesh_secure.sh").read_text()
        self.assertNotRegex(s,r"100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}/health")
    def test_existing_thermal_hold_listener_does_not_launch_competing_bridge(self):
        class HeldListener(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(503)
                self.end_headers()
            def log_message(self, *_args):
                pass
        server = http.server.HTTPServer(("127.0.0.1", 0), HeldListener)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="mikaya-mesh-supervisor-test-") as home:
                base = Path(home) / "sovereign_exec"
                (base / "ledger").mkdir(parents=True, mode=0o700)
                env = dict(os.environ, HOME=home, MESH_BRIDGE_BIND="127.0.0.1",
                           MESH_BRIDGE_PORT=str(server.server_address[1]))
                result = subprocess.run(["sh", str(ROOT / "supervise_mesh_secure.sh")],
                                        env=env, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertFalse((base / "ledger" / "secure-bridge-runtime.log").exists())
                self.assertIn("existing HTTP listener", (base / "ledger" / "receiver-supervisor.log").read_text())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
if __name__=="__main__": unittest.main(verbosity=2)
