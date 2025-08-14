import pywifi
from pywifi import const
import socket
import subprocess
import platform
import time
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup


def lookup_mac_vendors(input_file="connected_devices.txt", output_file="connected_devices_with_vendors.txt"):
    mac_lookup = MacLookup()
    try:
        mac_lookup.update()
    except Exception:
        pass

    with open(input_file, "r") as infile, open(output_file, "w") as outfile:
        for line in infile:
            if line.count(":") == 5:
                parts = line.strip().split()
                if len(parts) >= 2:
                    mac = parts[1]
                    try:
                        vendor = mac_lookup.lookup(mac)
                    except Exception:
                        vendor = "Unknown Vendor"
                    line = line.strip() + f"\tVendor: {vendor}\n"
            outfile.write(line)

    print(f"Vendor info added to '{output_file}'")


def get_ip_address():
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception as e:
        return f"Error: {e}"


def get_connected_wifi_info():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
    status_map = {
        const.IFACE_DISCONNECTED: "Disconnected",
        const.IFACE_SCANNING: "Scanning",
        const.IFACE_INACTIVE: "Inactive",
        const.IFACE_CONNECTING: "Connecting",
        const.IFACE_CONNECTED: "Connected"
    }

    if iface.status() != const.IFACE_CONNECTED:
        return "Not connected to any Wi-Fi network."

    iface.scan()
    time.sleep(3)
    scan_results = iface.scan_results()

    ssid = None
    bssid = None
    signal = None
    freq = None

    current_profile = iface.network_profiles()[0] if iface.network_profiles() else None
    if current_profile:
        for network in scan_results:
            if network.ssid == current_profile.ssid:
                ssid = network.ssid
                bssid = network.bssid
                signal = network.signal
                freq = network.freq
                break

    ip = get_ip_address()

    info = f"""
========== Connected Wi-Fi Info ==========
Interface Name : {iface.name()}
Status         : {status_map.get(iface.status(), 'Unknown')}
SSID           : {ssid or 'N/A'}
BSSID          : {bssid or 'N/A'}
Signal Strength: {signal or 'N/A'} dBm
Frequency      : {freq or 'N/A'} MHz
IP Address     : {ip}
==========================================
"""
    return info


def get_windows_link_speed():
    try:
        result = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], encoding='utf-8')
        for line in result.split('\n'):
            if "Receive rate (Mbps)" in line:
                return line.strip()
    except Exception:
        return None


def scan_connected_devices():
    print("\nScanning for connected devices...\n")
    ip = get_ip_address()
    if ip.startswith("Error"):
        print("Unable to determine IP address.")
        return

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

    print("Connected Devices:")
    print("IP Address\tMAC Address\t\tHostname")
    print("-------------------------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t{device['mac']}\t{device['hostname']}")
    print("-------------------------------------------------------\n")

    with open("connected_devices.txt", "w") as file:
        file.write("Connected Devices:\n")
        file.write("IP Address\tMAC Address\t\tHostname\n")
        file.write("-------------------------------------------------------\n")
        for device in devices:
            file.write(f"{device['ip']}\t{device['mac']}\t{device['hostname']}\n")
        file.write("-------------------------------------------------------\n")

    print("Connected devices saved to 'connected_devices.txt'")


if __name__ == "__main__":
    info = get_connected_wifi_info()
    print(info)

    if platform.system() == "Windows":
        link_speed = get_windows_link_speed()
        if link_speed:
            print(f"Link Speed     : {link_speed}")

    scan_connected_devices()
    lookup_mac_vendors()  # ✅ THIS WAS MISSING!
