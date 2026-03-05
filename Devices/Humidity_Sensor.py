import random
from Devices.Base_Device import BaseDevice

class HumiditySensor(BaseDevice):
    def __init__(self, device_id, mqtt_client, vulnerabilities=[]):
        super().__init__(device_id, mqtt_client, vulnerabilities)
        self.current_humidity = random.uniform(40.0, 55.0)

    def generate_data(self):
        # Slow drift
        self.current_humidity += random.uniform(-1.0, 1.0)

        # Clamp to realistic indoor humidity
        self.current_humidity = max(30.0, min(70.0, self.current_humidity))

        payload = {
            "device_id": self.device_id,
            "type": "humidity_sensor",
            "humidity": round(self.current_humidity, 1),
            "unit": "%",
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