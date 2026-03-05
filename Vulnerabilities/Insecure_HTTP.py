from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import json

class InsecureHTTPRequestHandler(BaseHTTPRequestHandler):

    # Existing GET (keep it)
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()

        response = f"""
        [INSECURE HTTP ENDPOINT]
        device_id: {self.server.device_id}
        firmware_version: {self.server.firmware_version}
        open_ports: {self.server.open_ports}
        sensitive_data: firmware_debug_mode=True
        """
        self.wfile.write(response.encode("utf-8"))

    # NEW → Add insecure POST support (allows remote manipulation)
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length).decode("utf-8")
            payload = json.loads(data)
        except:
            payload = {}

        # Modify device state WITHOUT ANY AUTHENTICATION
        for key, value in payload.items():
            setattr(self.server.device, key, value)

        print(f"[VULNERABILITY] Insecure HTTP POST on {self.server.device_id}: {payload}")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"POST accepted (insecure HTTP vulnerability triggered)")

    def log_message(self, format, *args):
        return  # silence logs


def start_insecure_http_server(device, port):
    server = HTTPServer(("0.0.0.0", port), InsecureHTTPRequestHandler)
    server.device = device                 # so POST can modify device
    server.device_id = device.device_id
    server.firmware_version = device.firmware_version
    server.open_ports = device.open_ports

    print(f"[VULNERABILITY] Insecure HTTP endpoint running on port {port} for {device.device_id}")

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()


def insecure_http_vulnerability(device):
    base_port = 8500
    port = base_port + abs(hash(device.device_id)) % 100  
    start_insecure_http_server(device, port)