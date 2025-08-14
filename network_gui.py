import tkinter as tk
from tkinter import scrolledtext, messagebox
from network_scan import main_scan

def run_scan():
    output_text.delete("1.0", tk.END)
    try:
        main_scan()
        with open("connected_devices_with_vendors.txt", "r") as file:
            content = file.read()
        output_text.insert(tk.END, content)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Setup GUI
root = tk.Tk()
root.title("Network Scanner")
root.geometry("800x600")

title_label = tk.Label(root, text="Wi-Fi Network Scanner", font=("Arial", 20, "bold"))
title_label.pack(pady=10)

scan_button = tk.Button(root, text="Start Scan", font=("Arial", 14), command=run_scan)
scan_button.pack(pady=5)

output_text = scrolledtext.ScrolledText(root, width=100, height=30)
output_text.pack(padx=10, pady=10)

root.mainloop()
