import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP
import threading

running = False

def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto

        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        elif proto == 1:
            protocol = "ICMP"
        else:
            protocol = "OTHER"

        tree.insert("", "end", values=(protocol, src, dst))


def start_sniffing():
    global running
    running = True
    thread = threading.Thread(target=sniffer_loop)
    thread.daemon = True
    thread.start()


def stop_sniffing():
    global running
    running = False


def sniffer_loop():
    while running:
        sniff(prn=packet_callback, count=1)


# GUI Window
root = tk.Tk()
root.title("Network Sniffer GUI")
root.geometry("700x400")

columns = ("Protocol", "Source", "Destination")
tree = ttk.Treeview(root, columns=columns, show='headings')
tree.heading("Protocol", text="Protocol")
tree.heading("Source", text="Source IP")
tree.heading("Destination", text="Destination IP")
tree.pack(fill="both", expand=True)

frame = tk.Frame(root)
frame.pack()

start_btn = tk.Button(frame, text="Start Sniffing", command=start_sniffing)
start_btn.grid(row=0, column=0, padx=10, pady=10)

stop_btn = tk.Button(frame, text="Stop", command=stop_sniffing)
stop_btn.grid(row=0, column=1, padx=10, pady=10)

root.mainloop()
