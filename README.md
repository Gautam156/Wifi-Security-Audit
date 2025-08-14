# Wi-Fi Security Audit Model

## 📌 Overview
The **Wi-Fi Security Audit Model** is a Python-based penetration testing and auditing tool designed to evaluate the security posture of wireless networks.  
It simulates real-world attack scenarios (dictionary-based WPA/WPA2 cracking) and performs **comprehensive network scanning, device fingerprinting, vulnerability assessment, and communication mapping**, generating a structured **HTML report** for administrators.

> ⚠️ **Ethical Use Only** — This project is intended for **educational and authorized penetration testing** purposes. Testing should only be done on networks you own or have explicit permission to audit.

---

## 🚀 Features
- **WPA/WPA2 Dictionary Attack** to identify weak passphrases.
- **Automated Network Connection** after successful key recovery.
- **Device Discovery** – IP & MAC address identification, vendor lookup.
- **OS Detection** using port and service fingerprinting.
- **Port Scanning & Service Enumeration** on all connected devices.
- **Vulnerability Assessment** against known CVEs.
- **Inter-Device Communication Mapping** for lateral movement analysis.
- **Automated HTML Report Generation** with findings and recommendations.

---

## 🛠️ Tools & Technologies Used
- **Python 3.x**
- **Nmap** – Device discovery, port scanning, OS detection.
- **Scapy** – Packet sniffing and network scanning.
- **tcpdump** – Communication analysis.
- **python-nmap** – Nmap integration with Python.
- **NetworkX + Matplotlib** – Communication graph visualization.
- **HTML/CSS** – Report formatting.
- **Tkinter** (optional) – GUI extension.

---

## 📂 Project Workflow
1. **Dictionary Attack** – Capture WPA/WPA2 handshake and crack it using a wordlist.
2. **Network Access** – Connect to the target Wi-Fi network.
3. **Device Discovery** – Identify all connected devices.
4. **Device Fingerprinting** – Detect OS and classify device type.
5. **Port & Service Scanning** – Identify open ports and services.
6. **Vulnerability Assessment** – Map services to known CVEs.
7. **Communication Mapping** – Visualize device interactions.
8. **Report Generation** – Save findings as an HTML report.

---

## ⚙️ Installation & Usage
### Prerequisites
- Python 3.10+
- Wireless adapter supporting **monitor mode** & **packet injection**
- Linux environment (Kali Linux recommended)
- Required Python libraries:
  ```bash
  pip install python-nmap scapy networkx matplotlib jinja2
