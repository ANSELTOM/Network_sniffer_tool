import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP
import threading
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

running = False

# Protocol counters
tcp_count = 0
udp_count = 0
icmp_count = 0
other_count = 0

# Chart data
time_axis = []
packet_axis = []

def update_chart():
    global packet_axis, time_axis

    time_axis.append(len(time_axis) + 1)
    packet_axis.append(tcp_count + udp_count + icmp_count + other_count)

    ax.clear()
    ax.plot(time_axis, packet_axis, linewidth=2)
    ax.set_title("Real-Time Traffic Chart")
    ax.set_xlabel("Time")
    ax.set_ylabel("Packets")

    canvas.draw()


def packet_callback(packet):
    global tcp_count, udp_count, icmp_count, other_count

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto

        if proto == 6:
            protocol = "TCP"
            color = "cyan"
            tcp_count += 1
        elif proto == 17:
            protocol = "UDP"
            color = "yellow"
            udp_count += 1
        elif proto == 1:
            protocol = "ICMP"
            color = "lightgreen"
            icmp_count += 1
        else:
            protocol = "OTHER"
            color = "pink"
            other_count += 1

        # Insert colored row
        tree.insert("", "end", values=(protocol, src, dst), tags=(color,))

        # Update counters
        tcp_label.config(text=f"TCP: {tcp_count}")
        udp_label.config(text=f"UDP: {udp_count}")
        icmp_label.config(text=f"ICMP: {icmp_count}")
        other_label.config(text=f"OTHER: {other_count}")

        update_chart()


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
root.title("Advanced Network Sniffer")
root.geometry("900x600")

# Protocol counters area
counter_frame = tk.Frame(root)
counter_frame.pack(pady=5)

tcp_label = tk.Label(counter_frame, text="TCP: 0", font=("Arial", 12), fg="cyan")
tcp_label.grid(row=0, column=0, padx=10)

udp_label = tk.Label(counter_frame, text="UDP: 0", font=("Arial", 12), fg="yellow")
udp_label.grid(row=0, column=1, padx=10)

icmp_label = tk.Label(counter_frame, text="ICMP: 0", font=("Arial", 12), fg="lightgreen")
icmp_label.grid(row=0, column=2, padx=10)

other_label = tk.Label(counter_frame, text="OTHER: 0", font=("Arial", 12), fg="pink")
other_label.grid(row=0, column=3, padx=10)

# Packet table
columns = ("Protocol", "Source", "Destination")
tree = ttk.Treeview(root, columns=columns, show='headings')
tree.heading("Protocol", text="Protocol")
tree.heading("Source", text="Source IP")
tree.heading("Destination", text="Destination IP")
tree.pack(fill="both", expand=True)

# Color tags
tree.tag_configure("cyan", background="#b3ffff")
tree.tag_configure("yellow", background="#ffffb3")
tree.tag_configure("lightgreen", background="#ccffcc")
tree.tag_configure("pink", background="#ffccff")

# Start/Stop buttons
btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)

start_btn = tk.Button(btn_frame, text="Start Sniffing", command=start_sniffing, width=15)
start_btn.grid(row=0, column=0, padx=10)

stop_btn = tk.Button(btn_frame, text="Stop", command=stop_sniffing, width=15)
stop_btn.grid(row=0, column=1, padx=10)

# Matplotlib real-time chart
fig = Figure(figsize=(5, 3), dpi=100)
ax = fig.add_subplot(111)

canvas = FigureCanvasTkAgg(fig, master=root)
canvas.draw()
canvas.get_tk_widget().pack(fill="x")

root.mainloop()
