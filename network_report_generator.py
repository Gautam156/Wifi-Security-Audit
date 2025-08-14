import socket
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
import networkx as nx
import matplotlib.pyplot as plt
import base64
import io

# ========== Port and Vulnerability Info ==========
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    995: "POP3S", 1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt"
}

# ========== Get Local IP ==========
def get_ip_address():
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        return ip
    except:
        return None

# ========== Scan Devices ==========
def scan_connected_devices():
    ip = get_ip_address()
    if not ip:
        return []

    ip_parts = ip.split('.')
    ip_parts[-1] = '1/24'
    target_ip = '.'.join(ip_parts)

    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for _, received in result:
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except:
            hostname = "Unknown"
        devices.append({'ip': received.psrc, 'mac': received.hwsrc, 'hostname': hostname})
    return devices

# ========== MAC Vendor ==========
def add_vendor_info(devices):
    lookup = MacLookup()
    try:
        lookup.update()
    except:
        pass
    for d in devices:
        try:
            d['vendor'] = lookup.lookup(d['mac'])
        except:
            d['vendor'] = "Unknown"

# ========== Port Scan ==========
def scan_ports(ip):
    open_ports = []
    for port in COMMON_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append((port, COMMON_PORTS[port]))
            sock.close()
        except:
            continue
    return open_ports

# ========== OS Detection ==========
def detect_os(ip, mac, ports):
    if 445 in ports or 139 in ports or 135 in ports:
        return "Likely Windows"
    elif 22 in ports:
        return "Likely Linux/Unix"
    elif 80 in ports and 443 in ports and not 22 in ports:
        return "Likely Router/Web Appliance"
    elif 9100 in ports:
        return "Likely Printer"
    elif 5555 in ports:
        return "Likely Android (ADB)"
    elif mac.startswith("B8:27:EB"):
        return "Likely Raspberry Pi"
    return "Unknown OS"

# ========== Device Type ==========
def classify_device_type(device):
    ports = [p[0] for p in device["ports"]]
    os = device["os"].lower()
    vendor = device["vendor"].lower()
    mac = device["mac"].upper()

    if "android" in os or 5555 in ports:
        return "Smartphone / Android"
    elif "windows" in os or 3389 in ports:
        return "Windows PC"
    elif "linux" in os or 22 in ports:
        if "raspberry" in vendor or mac.startswith("B8:27:EB"):
            return "Raspberry Pi"
        return "Linux Device"
    elif 9100 in ports or "printer" in vendor:
        return "Printer"
    elif 80 in ports and 443 in ports:
        return "Router / Web Appliance"
    else:
        return "Unknown Device"

# ========== Graph Image Generation ==========
def generate_network_graph_image(devices):
    G = nx.Graph()
    G.add_node("Router", type="Router")
    for device in devices:
        G.add_node(device['ip'], label=device['hostname'], type=device['type'])
        G.add_edge("Router", device['ip'])

    pos = nx.spring_layout(G)
    fig, ax = plt.subplots(figsize=(8, 6))
    nx.draw(G, pos, with_labels=True, node_size=2500, node_color='skyblue', font_size=9, ax=ax)
    plt.title("Network Communication Map")

    buf = io.BytesIO()
    plt.savefig(buf, format="png")
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode()

# ========== HTML Report ==========
def generate_html_report(devices, filename="network_report.html"):
    graph_image = generate_network_graph_image(devices)
    html = """
    <html><head><title>Network Report</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ccc; padding: 8px; }
        th { background-color: #f2f2f2; }
        img { max-width: 100%; height: auto; }
    </style></head><body>
    <h1>Network Scan Report</h1>
    <table>
    <tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Vendor</th><th>Type</th><th>OS</th><th>Open Ports</th></tr>
    """

    for d in devices:
        ports = "<br>".join(f"{p} ({s})" for p, s in d["ports"]) or "None"
        html += f"<tr><td>{d['ip']}</td><td>{d['mac']}</td><td>{d['hostname']}</td><td>{d['vendor']}</td><td>{d['type']}</td><td>{d['os']}</td><td>{ports}</td></tr>"

    html += f"""
    </table>
    <h2>Device Communication Map</h2>
    <img src="data:image/png;base64,{graph_image}" />
    </body></html>
    """

    with open(filename, "w") as f:
        f.write(html)
    print(f"[+] HTML report saved as '{filename}'")

# ========== Main ==========
if __name__ == "__main__":
    print("[*] Scanning network...")
    devices = scan_connected_devices()
    if not devices:
        print("[-] No devices found.")
        exit()

    add_vendor_info(devices)

    for device in devices:
        device["ports"] = scan_ports(device["ip"])
        device["os"] = detect_os(device["ip"], device["mac"], [p[0] for p in device["ports"]])
        device["type"] = classify_device_type(device)

    generate_html_report(devices)
