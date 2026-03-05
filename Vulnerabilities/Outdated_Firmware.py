def outdated_firmware_vulnerability(device):
    device.firmware_version = "0.8.0"
    device.latest_firmware_version = "1.2.0"
    device.is_firmware_outdated = True
    print(f"[VULNERABILITY] {device.device_id} running OUTDATED firmware "
          f"(current=0.8.0, latest=1.2.0)")
