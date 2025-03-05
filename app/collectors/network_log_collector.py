from scapy.all import sniff, wrpcap
import os
from datetime import datetime

# Create logs directory if not exists
if not os.path.exists("logs/network_logs"):

    os.makedirs("logs/network_logs")  # Create the directory if it does not exist


# Function to capture network packets
def capture_network_packets(packet_count=10):
    log_filename = f"logs/network_logs/network_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    print("Capturing packets...")

    packets = sniff(timeout=20)  # Capture packets for 60 seconds
    wrpcap(log_filename, packets)  # Save packets in PCAP format

    print(f"Network log saved: {log_filename} with {len(packets)} packets captured.")

    # Log alerts for significant packets (e.g., TCP SYN packets)
    for packet in packets:
        if packet.haslayer('TCP') and packet['TCP'].flags == 0x02:  # SYN flag
            print(f"Alert: SYN packet detected from {packet[1].src} to {packet[1].dst}")

# Run network packet capture
if __name__ == "__main__":
    capture_network_packets(10)  # Capture 100 packets

    print("Network packet capture complete.")
