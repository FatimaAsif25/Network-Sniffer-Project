import csv
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = "Other"
        src_port = dst_port = ""

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        with open("packets.csv", "a", newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                ip_layer.src,
                ip_layer.dst,
                protocol,
                src_port,
                dst_port
            ])

def start_sniffing():
    with open("packets.csv", "w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Src Port", "Dst Port"])

    print("[*] Logging packets to packets.csv ... Press Ctrl+C to stop.")
    sniff(filter="ip", prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffing()
