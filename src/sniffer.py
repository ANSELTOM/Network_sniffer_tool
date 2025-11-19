from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP
from datetime import datetime
import argparse

packets = []

def process_packet(packet):
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

        print(f"[+] {src} → {dst}  [{protocol}]")

        packets.append(packet)

def save_pcap(filename):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    full_name = f"{filename}_{timestamp}.pcap"
    wrpcap(full_name, packets)
    print(f"\n[✔] Saved to {full_name}\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--filter", default="", help="BPF filter like tcp, udp, icmp, port 80")
    parser.add_argument("--pcap", default="capture", help="Output PCAP file name")
    parser.add_argument("--count", type=int, default=0, help="Number of packets (0 = infinite)")
    args = parser.parse_args()

    print("\n--- Simple Network Sniffer ---")
    print(f"Filter: {args.filter}")
    print("-------------------------------\n")

    sniff(filter=args.filter, prn=process_packet, count=args.count)
    save_pcap(args.pcap)

if __name__ == "__main__":
    main()
