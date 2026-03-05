import threading
from Utils.Mqtt_Client import MQTTClientWrapper
from Vulnerabilities.Open_Ports import open_ports_vulnerability
from Vulnerabilities.Insecure_HTTP import insecure_http_vulnerability
from Vulnerabilities.Outdated_Firmware import outdated_firmware_vulnerability
from Vulnerabilities.Missing_Auth_Control import missing_auth_vulnerability
from Vulnerabilities.Weak_Credentials import weak_credentials_vulnerability

# Import all devices
from Devices.Temperature_Sensor import TemperatureSensor
from Devices.Humidity_Sensor import HumiditySensor
from Devices.Smart_Switch import SmartSwitch
from Devices.Smart_Door_Lock import DoorLock
from Devices.Camera_Device import CameraDevice

def print_banner(title):
    print("\n" + "=" * 60)
    print(f"{title}".center(60))
    print("=" * 60 + "\n")

def start_device(device):
    device.run(interval=5)   # send telemetry every 3 seconds

if __name__ == "__main__":

    print("Starting IoT Simulation...")

    # Shared MQTT client with WEAK CREDENTIALS vulnerability enabled
    mqtt_client = MQTTClientWrapper(
        client_id="iot_simulator",
        use_weak_credentials=True,
        use_unencrypted_traffic=True,
        broker="localhost"
    )


    devices = [
        TemperatureSensor("SunroomTempSensor", mqtt_client,
            vulnerabilities=[open_ports_vulnerability(), insecure_http_vulnerability, outdated_firmware_vulnerability, missing_auth_vulnerability(), weak_credentials_vulnerability()]),
        HumiditySensor("SunroomHumSensor", mqtt_client,
            vulnerabilities=[open_ports_vulnerability(), insecure_http_vulnerability, outdated_firmware_vulnerability, missing_auth_vulnerability(), weak_credentials_vulnerability()]),       
        SmartSwitch("SmartSwitch", mqtt_client,
            vulnerabilities=[open_ports_vulnerability(), insecure_http_vulnerability, outdated_firmware_vulnerability, missing_auth_vulnerability(), weak_credentials_vulnerability()]),        
        DoorLock("MainDoorLock", mqtt_client,
            vulnerabilities=[open_ports_vulnerability(), insecure_http_vulnerability, outdated_firmware_vulnerability, missing_auth_vulnerability(), weak_credentials_vulnerability()]),        
        CameraDevice("MainEntranceCamera", mqtt_client,
            vulnerabilities=[open_ports_vulnerability(), insecure_http_vulnerability, outdated_firmware_vulnerability, missing_auth_vulnerability(), weak_credentials_vulnerability()]),
            
        # Clean devices (no vulnerabilities)
        TemperatureSensor("StudyTempSensor",mqtt_client,vulnerabilities=[]),
        HumiditySensor("StudyHumSensor", mqtt_client, vulnerabilities=[]),

        # Selectively vulnerable devices
        CameraDevice("GardenCamera", mqtt_client, 
            vulnerabilities=[weak_credentials_vulnerability(), open_ports_vulnerability()]),
        DoorLock("BackDoorLock", mqtt_client,
            vulnerabilities=[insecure_http_vulnerability]),
        CameraDevice("UpstairsHallwayCamera", mqtt_client,
            vulnerabilities=[missing_auth_vulnerability(),outdated_firmware_vulnerability]),
    ]

    print_banner("APPLYING DEVICE VULNERABILITIES")

    for device in devices:
        print(f"→ Setting up {device.device_id}")
        for vuln in device.vulnerabilities:
            print(f"   • Applying: {vuln.__name__}")
        device.apply_vulnerabilities()
        print("")  # spacing

    print_banner("STARTING ALL DEVICES")

    # Launch each device in a separate thread
    threads = []
    for device in devices:
        t = threading.Thread(target=start_device, args=(device,))
        t.daemon = True
        t.start()
        threads.append(t)
        print(f"[STARTED] {device.device_id}")

    print_banner("ALL DEVICES ARE NOW RUNNING AND PUBLISHING TELEMETRY")


    # Keep the main program alive
    while True:
        pass
