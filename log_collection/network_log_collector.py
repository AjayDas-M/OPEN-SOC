from scapy.all import sniff, wrpcap
import os
from datetime import datetime

# Create logs directory if not exists
if not os.path.exists("logs/network_logs"):
    os.makedirs("logs/network_logs")

# Function to capture network packets
def capture_network_packets(packet_count=10):
    log_filename = f"logs/network_logs/network_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    print(f"Capturing {packet_count} packets...")

    packets = sniff(count=packet_count)  # Capture packets
    wrpcap(log_filename, packets)  # Save packets in PCAP format

    print(f"Network log saved: {log_filename}")

# Run network packet capture
if __name__ == "__main__":
    capture_network_packets(10)  # Capture 10 packets

    print("Network packet capture complete.")