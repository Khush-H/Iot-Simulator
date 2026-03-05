import random
from Devices.Base_Device import BaseDevice

class CameraDevice(BaseDevice):
    def __init__(self, device_id, mqtt_client, vulnerabilities=[]):
        super().__init__(device_id, mqtt_client, vulnerabilities)
        self.light_level = random.randint(150, 400)

    def generate_data(self):
        # Simulate gradual ambient light change
        self.light_level += random.randint(-15, 15)
        self.light_level = max(50, min(800, self.light_level))

        # Motion is event-based, not constant
        motion_detected = random.random() < 0.15  # 15% chance

        payload = {
            "device_id": self.device_id,
            "type": "camera",
            "camera_status": "online",
            "motion_detected": motion_detected,
            "light_level_lux": self.light_level,
            "resolution": "1920x1080",
            "frame_rate_fps": 30,
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