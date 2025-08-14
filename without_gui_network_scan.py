import socket
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup

# Common TCP ports and vulnerability info
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    995: "POP3S", 1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt"
}

vulnerable_ports_info = {
    21: ("FTP", "High", "Plaintext credentials, vulnerable to MITM."),
    22: ("SSH", "Medium", "Secure, but brute-force attacks possible."),
    23: ("Telnet", "High", "Insecure protocol, transmits data unencrypted."),
    25: ("SMTP", "Medium", "Can be used for spam or relay if misconfigured."),
    53: ("DNS", "Medium", "May be abused for DNS amplification attacks."),
    80: ("HTTP", "Medium", "Web-based attacks, lacks encryption."),
    110: ("POP3", "High", "Plaintext login, insecure."),
    139: ("NetBIOS", "High", "File sharing vulnerabilities in Windows."),
    143: ("IMAP", "Medium", "Insecure access to email."),
    445: ("SMB", "High", "Exploited by ransomware like WannaCry."),
    3306: ("MySQL", "High", "Database exposure risk."),
    3389: ("RDP", "High", "Targeted for remote access exploits."),
    5900: ("VNC", "High", "Remote desktop service with weak auth."),
    8080: ("HTTP-Alt", "Medium", "Alternative HTTP, also web vulnerabilities."),
}

# ========== GET LOCAL IP ADDRESS ==========
def get_ip_address():
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception as e:
        return f"Error: {e}"

# ========== SCAN FOR CONNECTED DEVICES ==========
def scan_connected_devices():
    print("\nScanning for connected devices...\n")
    ip = get_ip_address()
    if ip.startswith("Error"):
        print("Unable to determine IP address.")
        return []

    ip_parts = ip.split('.')
    ip_parts[-1] = '1/24'
    target_ip = '.'.join(ip_parts)

    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            hostname = "Unknown"
        devices.append({'ip': received.psrc, 'mac': received.hwsrc, 'hostname': hostname})

    return devices

# ========== MAC VENDOR LOOKUP ==========
def add_vendor_info(devices):
    mac_lookup = MacLookup()
    try:
        mac_lookup.update()
    except Exception:
        pass  # Skip if offline

    for device in devices:
        try:
            device["vendor"] = mac_lookup.lookup(device["mac"])
        except Exception:
            device["vendor"] = "Unknown"

# ========== NMAP OS DETECTION ==========
def detect_os(ip, mac=None, open_ports=None):
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-O -T4")

        if ip in nm.all_hosts():
            os_match = nm[ip].get('osmatch')
            if os_match and len(os_match) > 0:
                return os_match[0]['name']

        guessed_os = "Unknown OS"
        ports = open_ports if open_ports else []

        if 445 in ports or 139 in ports or 135 in ports:
            guessed_os = "Likely Windows"
        elif 22 in ports:
            guessed_os = "Likely Linux/Unix"
        elif 80 in ports and 443 in ports and not 22 in ports:
            guessed_os = "Likely Router/Web Appliance"
        elif 9100 in ports:
            guessed_os = "Likely Printer"
        elif 5555 in ports:
            guessed_os = "Likely Android (ADB)"
        elif mac:
            if mac.startswith("00:1A:79") or mac.startswith("B8:27:EB"):
                guessed_os = "Likely Raspberry Pi (Linux)"
            elif mac.startswith("B4:8C:9D"):
                guessed_os = "Likely Windows"

        return guessed_os

    except Exception as e:
        return f"Error detecting OS: {e}"

# ========== PORT SCAN ==========
def scan_ports(ip, ports=COMMON_PORTS):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                open_ports.append((port, service))
            sock.close()
        except Exception:
            continue
    return open_ports

# ========== DEVICE TYPE CLASSIFICATION ==========
def classify_device_type(device):
    os = device.get("os", "").lower()
    ports = [port for port, _ in device.get("ports", [])]
    mac = device.get("mac", "").upper()
    known_vendors = device.get("vendor", "").lower()

    if "android" in os or 5555 in ports:
        return "Smartphone / Android"
    elif "iphone" in os or "ios" in os:
        return "Smartphone / iOS"
    elif "windows" in os or 3389 in ports or 135 in ports:
        return "Windows PC"
    elif "linux" in os or 22 in ports:
        if "raspberry" in known_vendors or mac.startswith("B8:27:EB"):
            return "Raspberry Pi"
        return "Linux Device"
    elif 9100 in ports or "printer" in known_vendors:
        return "Printer"
    elif 80 in ports and 443 in ports and not 22 in ports:
        return "Router / Web Appliance"
    elif 23 in ports:
        return "Legacy Device (Telnet)"
    elif 139 in ports or 445 in ports:
        return "File Server / NAS"
    else:
        return "Unknown Device"

# ========== REPORT GENERATION ==========
def generate_report(devices, filename="connected_devices_full_report.txt"):
    with open(filename, "w") as f:
        f.write("Connected Devices with Vendor, OS, and Port Info:\n")
        f.write("===============================================================\n")
        for device in devices:
            f.write(f"IP Address : {device['ip']}\n")
            f.write(f"MAC Address: {device['mac']}\n")
            f.write(f"Hostname   : {device['hostname']}\n")
            f.write(f"Vendor     : {device.get('vendor', 'Unknown')}\n")
            f.write(f"Device Type: {device.get('type', 'Unknown')}\n")
            f.write(f"OS         : {device.get('os', 'Unknown')}\n")
            f.write("Open Ports :\n")
            if "ports" in device and device["ports"]:
                for port, service in device["ports"]:
                    f.write(f"  - {port} ({service})\n")
                    svc, risk, desc = vulnerable_ports_info.get(port, ("Unknown", "Low", "No major known risk."))
                    f.write(f"    - Risk Level: {risk} - {desc}\n")
            else:
                f.write("  - No common open ports found.\n")
            f.write("---------------------------------------------------------------\n")
    print(f"\nReport saved to '{filename}'.")

# ========== MAIN ==========
if __name__ == "__main__":
    devices = scan_connected_devices()
    if not devices:
        print("No devices found.")
        exit()

    add_vendor_info(devices)

    for device in devices:
        print(f"Scanning ports for {device['ip']}...")
        device["ports"] = scan_ports(device["ip"])

        print(f"Detecting OS for {device['ip']}...")
        device["os"] = detect_os(device['ip'], device["mac"], [port for port, _ in device["ports"]])

        print(f"Classifying device type for {device['ip']}...")
        device["type"] = classify_device_type(device)

    generate_report(devices)
