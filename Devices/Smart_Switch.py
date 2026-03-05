import random
from Devices.Base_Device import BaseDevice

class SmartSwitch(BaseDevice):
    def __init__(self, device_id, mqtt_client, vulnerabilities=[]):
        super().__init__(device_id, mqtt_client, vulnerabilities)
        self.state = random.choice(["ON", "OFF"])

    def generate_data(self):
        payload = {
            "device_id": self.device_id,
            "type": "smart_switch",
            "state": self.state,
        }

        # ✅ ONLY add firmware info if outdated_firmware vulnerability is applied
        if self.is_firmware_outdated or self.firmware_version != "1.0.0":
            payload["firmware_version"] = self.firmware_version
            payload["latest_firmware_version"] = self.latest_firmware_version
            payload["firmware_outdated"] = self.is_firmware_outdated

        # ✅ ONLY add weak credentials if they exist
        if self.default_username and self.default_password:
            payload["weak_credentials"] = {
                "username": self.default_username,
                "password": self.default_password,
                "login_port": getattr(self, "login_port", None)
            }

        # ✅ ONLY add open ports if they exist
        if getattr(self, "open_ports", []):
            payload["open_ports"] = self.open_ports

        return payload