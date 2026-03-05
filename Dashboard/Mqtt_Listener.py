# Dashboard/mqtt_listener.py
import json
import time
import paho.mqtt.client as mqtt

# Global state
latest_device_data = {}
security_events_tracker = {}
_socketio = None

# MQTT Configuration
MQTT_BROKER_HOST = "localhost"
MQTT_BROKER_PORT = 1883
MQTT_TOPICS = [("devices/+/telemetry", 0)]


def set_socketio(socketio_instance):
    """Set the SocketIO instance for emitting events"""
    global _socketio
    _socketio = socketio_instance


# ==============================================================================
# CENTRALIZED VULNERABILITY DETECTION SYSTEM
# ==============================================================================

class VulnerabilityChecker:
    """Base class for all vulnerability checkers"""
    
    def __init__(self, vuln_type, description):
        self.vuln_type = vuln_type
        self.description = description
    
    def check(self, device_id, data, msg):
        """
        Check for vulnerability. Return vulnerability dict if found, None otherwise.
        
        Args:
            device_id: Device identifier
            data: Parsed payload data
            msg: Raw MQTT message object
            
        Returns:
            dict or None: Vulnerability details if found
        """
        raise NotImplementedError("Subclasses must implement check()")


class WeakCredentialsChecker(VulnerabilityChecker):
    """Detects weak or default passwords"""
    
    def __init__(self):
        super().__init__(
            vuln_type="weak_credentials",
            description="Weak or default password detected"
        )
        self.weak_passwords = ["1234", "admin", "admin123", "password", "12345678", "qwerty"]
    
    def check(self, device_id, data, msg):
        # Check if password is in weak_credentials object or top-level
        password = None
        if "weak_credentials" in data and isinstance(data["weak_credentials"], dict):
            password = data["weak_credentials"].get("password")
        elif "password" in data:
            password = data["password"]
        
        if password and password in self.weak_passwords:
            return {
                "severity": "high",
                "message": f"Weak password detected: {password}",
                "details": {"password": password},
                "remediation": "Use strong passwords with at least 12 characters including numbers and symbols"
            }
        return None


class OutdatedFirmwareChecker(VulnerabilityChecker):
    """Detects outdated firmware versions"""
    
    def __init__(self):
        super().__init__(
            vuln_type="outdated_firmware",
            description="Device firmware is outdated"
        )
    
    def check(self, device_id, data, msg):
        if data.get("firmware_outdated") is True:
            current = data.get("firmware_version", "unknown")
            latest = data.get("latest_firmware_version", "unknown")
            return {
                "severity": "medium",
                "message": f"Firmware {current} is outdated (latest: {latest})",
                "details": {
                    "current_version": current,
                    "latest_version": latest
                },
                "remediation": f"Update firmware to version {latest}"
            }
        return None


class UnencryptedTrafficChecker(VulnerabilityChecker):
    """Detects unencrypted MQTT traffic"""
    
    def __init__(self):
        super().__init__(
            vuln_type="unencrypted_traffic",
            description="Unencrypted communication detected"
        )
        # Whitelist of devices that are allowed to use unencrypted MQTT
        # (e.g., secure/trusted devices on internal network)
        self.secure_devices = ["StudyTempSensor", "StudyHumSensor"]
    
    def check(self, device_id, data, msg):
        # Skip check for whitelisted secure devices
        if device_id in self.secure_devices:
            return None
            
        # Check if traffic is encrypted (placeholder logic)
        if not self._is_encrypted(msg):
            return {
                "severity": "high",
                "message": "Unencrypted MQTT traffic detected",
                "details": {"protocol": "MQTT", "port": MQTT_BROKER_PORT},
                "remediation": "Enable TLS/SSL encryption for MQTT communications"
            }
        return None
    
    def _is_encrypted(self, msg):
        """Check if MQTT message is encrypted"""
        # Placeholder: In production, check if using MQTTS (port 8883)
        return False


class ExposedPortsChecker(VulnerabilityChecker):
    """Detects dangerous open ports"""
    
    def __init__(self):
        super().__init__(
            vuln_type="exposed_ports",
            description="Dangerous network ports are exposed"
        )
        self.dangerous_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            3389: "RDP",
            5900: "VNC"
        }
    
    def check(self, device_id, data, msg):
        if "open_ports" in data:
            open_ports = data.get("open_ports", [])
            exposed = [p for p in open_ports if p in self.dangerous_ports]
            
            if exposed:
                port_names = [f"{p} ({self.dangerous_ports[p]})" for p in exposed]
                return {
                    "severity": "critical",
                    "message": f"Dangerous open ports detected: {exposed}",
                    "details": {
                        "open_ports": exposed,
                        "port_services": port_names
                    },
                    "remediation": "Close unnecessary ports or restrict access with firewall rules"
                }
        return None


class DefaultUsernameChecker(VulnerabilityChecker):
    """Detects default usernames"""
    
    def __init__(self):
        super().__init__(
            vuln_type="default_username",
            description="Default username in use"
        )
        self.default_usernames = ["admin", "root", "user", "administrator"]
    
    def check(self, device_id, data, msg):
        username = None
        if "weak_credentials" in data and isinstance(data["weak_credentials"], dict):
            username = data["weak_credentials"].get("username")
        elif "username" in data:
            username = data["username"]
        
        if username and username.lower() in self.default_usernames:
            return {
                "severity": "medium",
                "message": f"Default username detected: {username}",
                "details": {"username": username},
                "remediation": "Change default username to a unique identifier"
            }
        return None


class InformationLeakageChecker(VulnerabilityChecker):
    """Detects excessive telemetry that exposes internal metadata"""
    
    def __init__(self):
        super().__init__(
            vuln_type="information_leakage",
            description="Excessive telemetry exposes internal device metadata"
        )
        self.sensitive_fields = ["firmware_version", "username", "login_port", "open_ports", "debug_mode"]
        # Exclude secure devices from this check
        self.secure_devices = ["StudyTempSensor", "StudyHumSensor"]
    
    def check(self, device_id, data, msg):
        # Skip check for whitelisted secure devices
        if device_id in self.secure_devices:
            return None
            
        # Check if telemetry contains too much sensitive metadata
        exposed_fields = [field for field in self.sensitive_fields if field in data]
        
        if len(exposed_fields) >= 3:  # If 3+ sensitive fields are exposed
            return {
                "severity": "low",
                "message": "Excessive telemetry exposes internal device metadata",
                "details": {
                    "exposed_fields": exposed_fields,
                    "count": len(exposed_fields)
                },
                "remediation": "Limit telemetry to essential operational data only"
            }
        return None


# ==============================================================================
# VULNERABILITY REGISTRY
# ==============================================================================

# Register all vulnerability checkers
VULNERABILITY_CHECKERS = [
    WeakCredentialsChecker(),
    OutdatedFirmwareChecker(),
    UnencryptedTrafficChecker(),
    ExposedPortsChecker(),
    DefaultUsernameChecker(),
    InformationLeakageChecker(),
]


def evaluate_vulnerabilities(device_id, data, msg):
    """
    Centralized vulnerability evaluation pipeline.
    
    Runs all registered vulnerability checkers against device data.
    
    Args:
        device_id: Device identifier
        data: Parsed payload data
        msg: Raw MQTT message object
        
    Returns:
        list: List of detected vulnerabilities
    """
    vulnerabilities = []
    
    for checker in VULNERABILITY_CHECKERS:
        try:
            result = checker.check(device_id, data, msg)
            if result:
                # Add metadata to vulnerability
                vulnerability = {
                    "type": checker.vuln_type,
                    "device_id": device_id,
                    "timestamp": time.time(),
                    **result  # Unpack severity, message, details, remediation
                }
                vulnerabilities.append(vulnerability)
        except Exception as e:
            print(f"❌ Error in {checker.__class__.__name__}: {e}")
    
    if vulnerabilities:
        print(f"✓ Found {len(vulnerabilities)} vulnerabilities for {device_id}")
    
    return vulnerabilities


def emit_security_events(device_id, vulnerabilities):
    """
    Emit security events to frontend, with deduplication.
    
    Args:
        device_id: Device identifier
        vulnerabilities: List of vulnerability dicts
    """
    global security_events_tracker, _socketio
    
    if _socketio is None:
        return
    
    # Initialize tracker for this device
    if device_id not in security_events_tracker:
        security_events_tracker[device_id] = set()
    
    events_sent = security_events_tracker[device_id]
    
    # Send all events continuously (set to True for real-time display)
    send_continuously = True
    
    for vuln in vulnerabilities:
        event_key = f"{vuln['type']}_{device_id}"
        
        # Send event continuously or only once
        if send_continuously or event_key not in events_sent:
            _socketio.emit("security_event", vuln)
            events_sent.add(event_key)
            print(f"🔔 Sent {vuln['type']} alert for {device_id}")


# ==============================================================================
# MQTT EVENT HANDLERS
# ==============================================================================

def on_connect(client, userdata, flags, rc, properties=None):
    """Handle MQTT connection"""
    print(f"MQTT connected with result code: {rc}")
    for topic, qos in MQTT_TOPICS:
        client.subscribe(topic, qos)
        print(f"Subscribed to {topic}")


def on_message(client, userdata, msg, properties=None):
    """
    Handle incoming MQTT messages.
    
    Pipeline:
    1. Parse message
    2. Update device state
    3. Evaluate vulnerabilities
    4. Emit events to frontend
    """
    global latest_device_data
    
    if _socketio is None:
        return
    
    # Parse message
    topic = msg.topic
    payload_bytes = msg.payload
    payload_text = payload_bytes.decode("utf-8", errors="ignore")
    
    # Extract device_id from topic (format: devices/{device_id}/telemetry)
    parts = topic.split("/")
    device_id = parts[1] if len(parts) > 1 else "unknown"
    
    # Parse JSON payload
    try:
        data = json.loads(payload_text)
    except json.JSONDecodeError:
        data = {"raw": payload_text}
    
    # Update device state
    latest_device_data[device_id] = data
    
    # CENTRALIZED VULNERABILITY PIPELINE
    vulnerabilities = evaluate_vulnerabilities(device_id, data, msg)
    
    # Emit security events
    if vulnerabilities:
        emit_security_events(device_id, vulnerabilities)
    
    # Emit telemetry data to frontend
    telemetry_event = {
        "device_id": device_id,
        "topic": topic,
        "payload": data,
        "timestamp": time.time(),
    }
    _socketio.emit("telemetry", telemetry_event)


def start_mqtt_listener():
    """
    Start MQTT listener (blocking loop).
    Should be run in a separate thread.
    """
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    
    client.connect(MQTT_BROKER_HOST, MQTT_BROKER_PORT, keepalive=60)
    print(f"Connecting to MQTT broker at {MQTT_BROKER_HOST}:{MQTT_BROKER_PORT}")
    
    client.loop_forever()