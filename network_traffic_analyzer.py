from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    """
    if packet.haslayer(IP):
        print(f"Source: {packet[IP].src}")
        print(f"Destination: {packet[IP].dst}")
        if packet.haslayer(TCP):
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        print("\n")

if __name__ == "__main__":
    print("Starting Network Traffic Analyzer...")
    # Capture 10 packets (can be modified to run indefinitely with count=0)
    sniff(prn=packet_callback, count=10)

