from scapy.all import sniff, IP, TCP, UDP, Raw

# Callback function to process each packet
def analyze_packet(packet):
    print("\n--- Packet Captured ---")

    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"From: {ip_layer.src} --> To: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        # Check for TCP packets
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP Segment: {tcp_layer.sport} --> {tcp_layer.dport}")

            # Check if it contains raw payload (e.g., HTTP data)
            if Raw in packet:
                data = packet[Raw].load
                try:
                    print("Raw Data:")
                    print(data.decode('utf-8'))
                except UnicodeDecodeError:
                    print("Non-decodable raw data.")

        # Check for UDP packets
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"UDP Datagram: {udp_layer.sport} --> {udp_layer.dport}")

# Start sniffing (Ctrl+C to stop)
print("Sniffing packets... (Press Ctrl+C to stop)")
sniff(filter="ip", prn=analyze_packet, count=10)  # Captures 10 IP packets
