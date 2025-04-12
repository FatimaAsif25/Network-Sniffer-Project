from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] IP Packet: {ip_layer.src} -> {ip_layer.dst}")

        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"    Protocol: TCP | Src Port: {tcp_layer.sport} -> Dst Port: {tcp_layer.dport}")

        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"    Protocol: UDP | Src Port: {udp_layer.sport} -> Dst Port: {udp_layer.dport}")

        else:
            print("    Protocol: Other (Not TCP/UDP)")
def start_sniffing():
    print("[*] Starting packet sniffing... Press Ctrl+C to stop.\n")
    sniff(filter="ip", prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffing()
