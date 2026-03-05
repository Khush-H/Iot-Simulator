import time
from abc import ABC, abstractmethod
import json
from datetime import datetime

class BaseDevice(ABC):
    def __init__(self, device_id, mqtt_client, vulnerabilities=None):
        self.device_id = device_id
        self.mqtt_client = mqtt_client
        self.vulnerabilities = vulnerabilities or []
        self.open_ports = []  # keep the open ports list here
        self.default_username = None
        self.default_password = None

        # Firmware fields (needed for outdated firmware vuln)
        self.firmware_version = "1.0.0"
        self.latest_firmware_version = "1.0.0"
        self.is_firmware_outdated = False

        # Apply vulns
        self.apply_vulnerabilities()

    def apply_vulnerabilities(self):
        for vuln in self.vulnerabilities:
            vuln(self)

    @abstractmethod
    def generate_data(self):
        pass

    def run(self, interval=5):
        while True:
            data = self.generate_data()

            # Include open ports vulnerability in telemetry
            if self.open_ports:
                data["open_ports"] = self.open_ports
                # LOW-RISK VULNERABILITY: Excessive telemetry / information leakage
                data["device_id"] = self.device_id
                data["firmware_version"] = self.firmware_version
                data["latest_firmware_version"] = self.latest_firmware_version
                data["firmware_outdated"] = self.is_firmware_outdated
                data["debug_mode"] = False


            self.mqtt_client.publish(f"devices/{self.device_id}/telemetry", data)
            self.pretty_log("Telemetry Published", data)

            time.sleep(interval)

    def pretty_log(self, label, payload):
        timestamp = datetime.now().strftime("%H:%M:%S")

        print("\n" + "=" * 60)
        print(f"[{timestamp}]  {self.device_id}  →  {label}")
        print("-" * 60)
        print(json.dumps(payload, indent=4))
        print("=" * 60 + "\n")
