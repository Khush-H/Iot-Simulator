from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import json

def start_missing_auth_control(device, port):
    class ControlHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length).decode("utf-8")

            try:
                payload = json.loads(data)
            except:
                payload = {}

            # Directly modify device state WITHOUT authentication
            for key, value in payload.items():
                setattr(device, key, value)

            print(f"[VULNERABILITY] Unauthenticated control access on {device.device_id}: {payload}")

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

    def run_server():
        server = HTTPServer(("0.0.0.0", port), ControlHandler)
        print(f"[VULNERABILITY] Unauthenticated CONTROL endpoint running on port {port} for {device.device_id}")
        server.serve_forever()

    t = threading.Thread(target=run_server, daemon=True)
    t.start()


def missing_auth_vulnerability():
    # assign a unique port per device
    base_port = 9000  

    def apply(device):
        port_offset = abs(hash(device.device_id)) % 100
        start_missing_auth_control(device, base_port + port_offset)

    return apply
