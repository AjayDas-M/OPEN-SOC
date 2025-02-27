import psutil
import json
import os
from datetime import datetime

# Create logs directory if not exists
if not os.path.exists("logs/system_logs"):
    os.makedirs("logs/system_logs")

# Function to collect system logs
def collect_system_logs():
    log_data = {
        "hostname": os.uname().nodename,
        "timestamp": str(datetime.now()),
        "cpu_usage": psutil.cpu_percent(interval=1),
        "memory_usage": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage('/').percent,
        "running_processes": [proc.info for proc in psutil.process_iter(['pid', 'name'])]
    }

    # Save log to file
    log_filename = f"logs/system_logs/system_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(log_filename, "w") as file:
        json.dump(log_data, file, indent=4)

    print(f"System log saved: {log_filename}")

# Run the log collection
if __name__ == "__main__":
    collect_system_logs()
