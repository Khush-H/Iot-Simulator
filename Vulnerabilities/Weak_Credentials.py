import json
import random
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

def weak_credentials_vulnerability():
    def vuln(device):

        # Assign a random port per device (9001–9099)
        port = random.randint(9001, 9099)

        # Save login info to device attributes
        device.default_username = "admin"
        device.default_password = "1234"
        device.login_port = port

        print(f"[VULNERABILITY] Weak credentials login portal for {device.device_id} running on port {port}")
        
        class WeakCredsHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return  # disable default logging

            def do_POST(self):
                length = int(self.headers['Content-Length'])
                data = self.rfile.read(length).decode()
                try:
                    creds = json.loads(data)
                    username = creds.get("username")
                    password = creds.get("password")
                except:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Bad request")
                    return

                if username == device.default_username and password == device.default_password:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Login successful (weak credential vulnerability exploited)")
                else:
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b"Invalid credentials")

        def start_server():
            server = HTTPServer(("0.0.0.0", port), WeakCredsHandler)
            server.serve_forever()

        threading.Thread(target=start_server, daemon=True).start()

    return vuln
