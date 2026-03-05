import random
from Devices.Base_Device import BaseDevice

class TemperatureSensor(BaseDevice):
    def __init__(self, device_id, mqtt_client, vulnerabilities=[]):
        super().__init__(device_id, mqtt_client, vulnerabilities)
        # Start at a realistic indoor temperature
        self.current_temperature = random.uniform(21.0, 25.0)

    def generate_data(self):
        # Small gradual drift
        self.current_temperature += random.uniform(-0.2, 0.2)

        # Clamp to realistic indoor range
        self.current_temperature = max(18.0, min(30.0, self.current_temperature))

        payload = {
            "device_id": self.device_id,
            "type": "temperature_sensor",
            "temperature": round(self.current_temperature, 2),
            "unit": "C",
            "firmware_version": self.firmware_version,
            "latest_firmware_version": self.latest_firmware_version,
            "firmware_outdated": self.is_firmware_outdated,
        }

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
