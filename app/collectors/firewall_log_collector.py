import os
import json
from datetime import datetime

# Location of firewall logs (depends on system)
LOG_FILE_PATH = "/var/log/iptables.log"  # Change to /var/log/syslog if necessary

# Create logs directory if not exists
if not os.path.exists("logs/firewall_logs"):
    os.makedirs("logs/firewall_logs")

# Function to extract firewall logs
def collect_firewall_logs():
    log_filename = f"logs/firewall_logs/firewall_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    try:
        with open(LOG_FILE_PATH, "r") as file:
            logs = file.readlines()

        # Filter only IPTables logs
        firewall_logs = [log.strip() for log in logs if "IPTables-" in log]

        # Save to JSON file
        with open(log_filename, "w") as json_file:
            json.dump(firewall_logs, json_file, indent=4)

        print(f"Firewall log saved: {log_filename}")

    except Exception as e:
        print(f"Error reading firewall logs: {e}")

# Run the firewall log collection
if __name__ == "__main__":
    collect_firewall_logs()

    print("Firewall log collection complete.")