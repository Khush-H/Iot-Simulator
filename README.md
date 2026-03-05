# 🛡️ Simulated IoT Ecosystem with Real-Time Vulnerability Testing & Threat Monitoring Dashboard

A Final Year Project by **Khush Naran Hirani (TP073863)**  
BSc Computer Science (Cybersecurity) — Asia Pacific University of Technology and Innovation

---

## 📖 Overview

This project simulates a realistic IoT environment to enable **controlled, ethical vulnerability testing** and **real-time threat monitoring** — without the need for physical hardware.

It replicates common IoT device behaviours (sensors, cameras, smart locks) and exposes security flaws based on the **OWASP IoT Top 10**, while providing a live web dashboard to visualise threats and telemetry.

---

## ✨ Features

- 🔌 **IoT Device Simulation** — Python-based virtual devices (temperature sensors, smart locks, IP cameras) communicating via MQTT and REST APIs
- 🐛 **Vulnerability Injection** — Simulate real-world flaws: weak credentials, unencrypted traffic, outdated firmware, open ports, and missing authentication
- 📊 **Real-Time Dashboard** — Flask + Dash web interface displaying live alerts, telemetry streams, device status, and attack logs
- 🔍 **Packet Analysis Support** — Compatible with Wireshark for inspecting plaintext MQTT payloads and intercepted credentials
- 🧪 **Safe & Ethical** — Fully offline, simulation-only environment; no real hardware or production networks required

---

## 🛠️ Tech Stack

| Tool | Purpose |
|---|---|
| Python 3 | Core simulation logic and backend |
| Eclipse Mosquitto | MQTT broker |
| Flask | Web server / REST API backend |
| Dash (Plotly) | Real-time dashboard frontend |
| Wireshark / tcpdump | Packet-level traffic analysis |
| paho-mqtt | Python MQTT client library |

---

## 📁 Project Structure

```
├── Run_Devices.py        # Entry point — starts all simulated IoT devices
├── Base_Device.py        # Base class for all device types
├── devices/
│   ├── sensor.py         # Temperature sensor simulation
│   ├── camera.py         # IP camera simulation
│   └── lock.py           # Smart lock simulation
├── vulnerabilities/
│   ├── weak_credentials.py
│   ├── unencrypted_traffic.py
│   ├── outdated_firmware.py
│   ├── open_ports.py
│   └── missing_auth.py
├── mqtt/
│   ├── MQTT_Client.py    # Publishes device telemetry to broker
│   └── MQTT_Listener.py  # Subscribes and logs incoming messages
├── dashboard/
│   ├── App.py            # Flask + Dash application
│   └── templates/
│       └── index.html    # Dashboard UI
└── requirements.txt
```

---

## ⚙️ Installation & Setup

### Prerequisites

- Python 3.8+
- [Eclipse Mosquitto](https://mosquitto.org/download/) installed and running
- pip

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Start the Mosquitto MQTT Broker

```bash
mosquitto
```

> On Windows, you may need to run this from the Mosquitto install directory or add it to PATH.

### 4. Run the IoT Device Simulation

```bash
python Run_Devices.py
```

### 5. Launch the Dashboard

```bash
python dashboard/App.py
```

Then open your browser and go to: **http://localhost:5000**

---

## 🔍 Simulated Vulnerabilities (OWASP IoT Top 10)

| ID | Vulnerability | Description |
|---|---|---|
| V1 | Weak Credentials | Devices configured with default/weak passwords |
| V2 | Unencrypted Traffic | MQTT payloads sent in plaintext (visible in Wireshark) |
| V3 | Outdated Firmware | Devices flagged as running outdated firmware versions |
| V4 | Open Ports | Unnecessary network ports left exposed |
| V5 | Missing Authentication | REST endpoints accessible without credentials |

---

## 📊 Dashboard Tabs

- **Main Dashboard** — Live overview of all device statuses and active alerts
- **Security Events** — Log of detected vulnerabilities and threat activity
- **Active Devices** — Real-time list of connected simulated devices
- **Device History** — Past vulnerabilities and payloads per device

---

## 🧪 Testing

Functional testing was performed using a black-box methodology. To verify vulnerability detection:

1. Run `Run_Devices.py` with a vulnerable device configuration
2. Observe alerts appear on the dashboard in real time
3. (Optional) Open **Wireshark** and filter by `mqtt` to inspect plaintext payloads

---

## ⚠️ Disclaimer

This project is strictly for **educational and research purposes**. All simulations are conducted in a controlled, offline environment. Do **not** use this tool against real networks or physical devices without explicit authorisation.

---

## 👤 Author

**Khush Naran Hirani**  
TP073863 | APD3F2505CS(CYB)  
Supervisor: Assoc. Prof. Dr. Jalil Md Desa  
Asia Pacific University of Technology and Innovation
