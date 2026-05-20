from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to process packets
def packet_callback(packet):

    print("\n==============================")

    # Check if packet contains IP layer
    if packet.haslayer(IP):

        ip_layer = packet[IP]

        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")

        # Detect Protocol
        if packet.haslayer(TCP):
            print("Protocol       : TCP")

        elif packet.haslayer(UDP):
            print("Protocol       : UDP")

        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        else:
            print("Protocol       : Other")

        # Display Payload
        payload = bytes(packet.payload)

        print(f"Payload         : {payload[:50]}")

# Start sniffing
print("Starting Network Sniffer...")

sniff(prn=packet_callback, store=False)