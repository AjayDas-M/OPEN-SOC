import os
import subprocess
import json
import scapy.all as scapy
import requests
import psutil
from datetime import datetime

# Configuration (can be stored in a config.yaml or as constants)
LOG_OUTPUT_DIR = "./logs"
NETWORK_LOG_FILE = os.path.join(LOG_OUTPUT_DIR, "network_logs.pcap")
SYSTEM_LOG_FILE = os.path.join(LOG_OUTPUT_DIR, "system_logs.json")
EXTERNAL_LOG_FILE = os.path.join(LOG_OUTPUT_DIR, "external_logs.json")

# Ensure output directory exists
os.makedirs(LOG_OUTPUT_DIR, exist_ok=True)

# 1. Collect System Logs
def collect_system_logs():
    logs = []
    for proc in psutil.process_iter(attrs=['pid', 'name', 'username']):
        logs.append(proc.info)

    with open(SYSTEM_LOG_FILE, "w") as f:
        json.dump({"timestamp": str(datetime.now()), "logs": logs}, f, indent=4)

    print(f"System logs collected in {SYSTEM_LOG_FILE}")

# 2. Collect Network Logs
'''def collect_network_logs():
    def packet_handler(packet):
        scapy.wrpcap(NETWORK_LOG_FILE, packet, append=True)

    print(f"Capturing network packets... Logs will be saved to {NETWORK_LOG_FILE}")
    scapy.sniff(prn=packet_handler, count=50)  # Capture 50 packets for testing'''

# 3. Collect Firewall Logs (Example API Integration)
def collect_firewall_logs():
    api_url = "http://example-firewall-api.com/logs"
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            logs = response.json()
            with open(EXTERNAL_LOG_FILE, "w") as f:
                json.dump({"timestamp": str(datetime.now()), "logs": logs}, f, indent=4)
            print(f"Firewall logs collected in {EXTERNAL_LOG_FILE}")
        else:
            print(f"Failed to fetch firewall logs: {response.status_code}")
    except Exception as e:
        print(f"Error fetching firewall logs: {e}")

# 4. Collect External Logs
def collect_external_logs():
    external_api = "https://jsonplaceholder.typicode.com/posts"  # Example API
    try:
        response = requests.get(external_api)
        if response.status_code == 200:
            logs = response.json()
            with open(EXTERNAL_LOG_FILE, "w") as f:
                json.dump({"timestamp": str(datetime.now()), "logs": logs}, f, indent=4)
            print(f"External logs collected in {EXTERNAL_LOG_FILE}")
        else:
            print(f"Failed to fetch external logs: {response.status_code}")
    except Exception as e:
        print(f"Error fetching external logs: {e}")




if __name__ == "__main__":
    print("Starting log collection...")
    collect_system_logs()
   # collect_network_logs()
    collect_firewall_logs()
    collect_external_logs()
    print("Log collection completed.")

