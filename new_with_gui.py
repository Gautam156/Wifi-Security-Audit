import socket
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
import matplotlib.pyplot as plt
import networkx as nx

# (Re-use your existing dictionaries: COMMON_PORTS, vulnerable_ports_info)
# [Paste your dictionaries here or keep them in a separate config section]

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
        pass

    for device in devices:
        try:
            device["vendor"] = mac_lookup.lookup(device["mac"])
        except Exception:
            device["vendor"] = "Unknown"

# ========== PORT SCAN ==========
def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = ports.get(port, "Unknown")
                open_ports.append((port, service))
            sock.close()
        except Exception:
            continue
    return open_ports

# ========== OS DETECTION ==========
def detect_os(ip, mac=None, open_ports=None):
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-O -T4")
        if ip in nm.all_hosts():
            os_match = nm[ip].get('osmatch')
            if os_match:
                return os_match[0]['name']
    except Exception:
        pass

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
    return guessed_os

# ========== DEVICE TYPE CLASSIFICATION ==========
def classify_device_type(device):
    os = device.get("os", "").lower()
    ports = [port for port, _ in device.get("ports", [])]
    mac = device.get("mac", "").upper()
    vendor = device.get("vendor", "").lower()

    if "android" in os or 5555 in ports:
        return "Android Phone"
    elif "iphone" in os or "ios" in os:
        return "iPhone"
    elif "windows" in os or 3389 in ports:
        return "Windows PC"
    elif "linux" in os or 22 in ports:
        if "raspberry" in vendor or mac.startswith("B8:27:EB"):
            return "Raspberry Pi"
        return "Linux PC"
    elif 9100 in ports or "printer" in vendor:
        return "Printer"
    elif 80 in ports and 443 in ports:
        return "Router"
    return "Unknown"

# ========== COMMUNICATION MAP ==========
def draw_network_map(devices):
    G = nx.Graph()
    local_ip = get_ip_address()
    G.add_node("You", color='green')

    for device in devices:
        label = f"{device['ip']}\n{device['type']}"
        G.add_node(label, color='skyblue')
        G.add_edge("You", label)

    pos = nx.spring_layout(G)
    colors = [G.nodes[n].get('color', 'gray') for n in G.nodes()]
    nx.draw(G, pos, with_labels=True, node_color=colors, font_size=8, node_size=1500)
    plt.title("Network Communication Map")
    plt.show()

# ========== MAIN ==========
if __name__ == "__main__":
    from collections import OrderedDict

    COMMON_PORTS = OrderedDict({
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
        110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
        3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt"
    })

    devices = scan_connected_devices()
    if not devices:
        print("No devices found.")
        exit()

    add_vendor_info(devices)

    for device in devices:
        print(f"\n→ {device['ip']} ({device['hostname']})")
        device["ports"] = scan_ports(device['ip'], COMMON_PORTS)
        device["os"] = detect_os(device['ip'], device['mac'], [p[0] for p in device["ports"]])
        device["type"] = classify_device_type(device)

    draw_network_map(devices)
