pip install scapy

from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        if TCP in packet:
            proto_name = "TCP"
        elif UDP in packet:
            proto_name = "UDP"
        elif ICMP in packet:
            proto_name = "ICMP"
        else:
            proto_name = str(proto)

        print(f"\n[+] Packet Captured")
        print(f"    Protocol: {proto_name}")
        print(f"    Source IP: {ip_src}")
        print(f"    Destination IP: {ip_dst}")
        if packet.haslayer(Raw):
            print(f"    Payload: {bytes(packet[Raw])[:32]}...")  # Print partial payload
        else:
            print("    No Payload")

# Start sniffing
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)
