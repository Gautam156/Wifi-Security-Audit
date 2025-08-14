import time
import pywifi
from pywifi import const
import socket
import subprocess
import platform
from scapy.all import ARP, Ether, srp
import tkinter as tk
from tkinter import ttk, messagebox
import os
import nmap
from mac_vendor_lookup import MacLookup

# Function to get IP address
def get_ip_address():
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception as e:
        return f"Error: {e}"

# Get connected Wi-Fi info
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

# Function to scan for connected devices
def scan_connected_devices():
    ip = get_ip_address()
    if ip.startswith("Error"):
        return "Unable to determine IP address."

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

    devices_info = "\n".join([f"{device['ip']} {device['mac']} {device['hostname']}" for device in devices])
    return devices_info

# Function to detect OS
def detect_os(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, '22-80')  # scan ports 22 to 80
        if 'osmatch' in nm[ip]:
            return nm[ip]['osmatch'][0]['name']
        else:
            return "OS Detection Failed"
    except Exception as e:
        return str(e)

# Tkinter GUI setup
class NetworkScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Scanner")
        self.geometry("600x600")

        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True)

        # Create tabs
        self.create_wifi_info_tab()
        self.create_devices_tab()
        self.create_os_info_tab()

    def create_wifi_info_tab(self):
        self.wifi_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.wifi_tab, text="Wi-Fi Info")

        self.wifi_text = tk.Text(self.wifi_tab, wrap=tk.WORD, height=15)
        self.wifi_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.wifi_button = tk.Button(self.wifi_tab, text="Refresh", command=self.refresh_wifi_info)
        self.wifi_button.pack(padx=10, pady=10)

        self.refresh_wifi_info()

    def refresh_wifi_info(self):
        wifi_info = get_connected_wifi_info()
        self.wifi_text.delete(1.0, tk.END)
        self.wifi_text.insert(tk.END, wifi_info)

    def create_devices_tab(self):
        self.devices_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.devices_tab, text="Connected Devices")

        self.devices_text = tk.Text(self.devices_tab, wrap=tk.WORD, height=15)
        self.devices_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.devices_button = tk.Button(self.devices_tab, text="Refresh", command=self.refresh_devices_info)
        self.devices_button.pack(padx=10, pady=10)

        self.refresh_devices_info()

    def refresh_devices_info(self):
        devices_info = scan_connected_devices()
        self.devices_text.delete(1.0, tk.END)
        self.devices_text.insert(tk.END, devices_info)

    def create_os_info_tab(self):
        self.os_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.os_tab, text="OS Info")

        self.os_text = tk.Text(self.os_tab, wrap=tk.WORD, height=15)
        self.os_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.os_button = tk.Button(self.os_tab, text="Refresh", command=self.refresh_os_info)
        self.os_button.pack(padx=10, pady=10)

        self.refresh_os_info()

    def refresh_os_info(self):
        ip = get_ip_address()
        os_info = detect_os(ip)
        self.os_text.delete(1.0, tk.END)
        self.os_text.insert(tk.END, f"OS of {ip}: {os_info}")

if __name__ == "__main__":
    app = NetworkScannerApp()
    app.mainloop()
