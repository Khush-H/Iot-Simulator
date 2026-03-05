import socket
import threading

def open_ports_vulnerability(ports=[21, 22, 80, 8080]):
    def apply(device):
        device.open_ports = ports  # adds port info to telemetry

        # Optionally open the fake ports on OS level
        for p in ports:
            t = threading.Thread(target=start_fake_port, args=(p,))
            t.daemon = True
            t.start()

    return apply


def start_fake_port(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", port))
        s.listen(1)
        print(f"[VULNERABILITY] Fake open port {port} active")
        while True:
            conn, _ = s.accept()
            conn.close()
    except OSError:
        print(f"[ERROR] Port {port} already in use, skipping.")
