import platform
import socket
import requests
import json
import subprocess
import time
import sys
import os
import ctypes
import urllib.parse
from datetime import datetime  # Import datetime for timestamps


# Get system name
system_name = socket.gethostname()

# Ensure the script runs with Admin/Root privileges
def request_admin():
    system_type = platform.system()

    if system_type == "Windows":
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[*] Requesting Admin Privileges...")
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{os.path.abspath(__file__)}"', None, 1)
                sys.exit(0)
        except Exception as e:
            print(f"[!] Failed to get admin privileges: {e}")
            sys.exit(1)
    elif system_type in ["Linux", "Darwin"]:  # Linux/macOS
        if os.geteuid() != 0:
            print("[*] Please run the script with sudo for elevated privileges.")
            sys.exit(1)

# Function to collect multiple types of logs with timestamps
def collect_logs():
    system_type = platform.system()
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Timestamp format

    commands = {
        "Windows": {
            "system_logs": "wevtutil qe System /f:text /c:100",
            "security_logs": "wevtutil qe Security /f:text /c:100",
            "application_logs": "wevtutil qe Application /f:text /c:100",
            "access_logs": 'type "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log"',
            "crash_logs": 'wevtutil qe System /q:"*[System[(Level=2)]]" /f:text /c:100',
            "network_logs": "netstat -an",
            "audit_logs": "auditpol /get /category:*",
            "kernel_logs": 'wevtutil qe System /q:"*[System[(ProviderName=\'Kernel-General\')]]" /f:text /c:100',
            "firewall_logs": "netsh advfirewall monitor show current",
            "user_activity_logs": 'wevtutil qe "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /f:text /c:50',
        },
        "Linux": {
            "system_logs": "journalctl -n 100",
            "security_logs": "tail -n 100 /var/log/auth.log",
            "application_logs": "tail -n 100 /var/log/syslog",
            "access_logs": "tail -n 100 /var/log/nginx/access.log",
            "crash_logs": "journalctl -p err -n 100",
            "network_logs": "ss -tulnp",
            "audit_logs": "tail -n 100 /var/log/audit/audit.log",
            "database_logs": "tail -n 100 /var/log/mysql/error.log",
            "kernel_logs": "dmesg -T | tail -n 100",
            "firewall_logs": "sudo iptables -L -v -n",
            "user_activity_logs": "last -n 100",
        },
        "Darwin": {
            "system_logs": "log show --info --last 1d",
            "security_logs": "log show --predicate 'eventMessage CONTAINS \"auth\"' --last 1d",
            "application_logs": "log show --predicate 'processImagePath CONTAINS \"/Applications\"' --last 1d",
            "access_logs": "tail -n 100 /var/log/apache2/access_log",
            "crash_logs": "log show --predicate 'eventType == crashReport' --last 1d",
            "network_logs": "netstat -an",
            "audit_logs": "tail -n 100 /var/audit/current",
            "database_logs": "tail -n 100 /usr/local/var/log/mysql/error.log",
            "kernel_logs": "log show --predicate 'subsystem == \"com.apple.kernel\"' --last 1d",
            "firewall_logs": "sudo pfctl -s all",
            "user_activity_logs": "last -n 100",
        },
    }

    log_data = {}
    system_commands = commands.get(system_type, {})

    for log_type, command in system_commands.items():
        try:
            log_output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True).strip()
            log_data[log_type] = {
                "timestamp": current_time,
                "logs": log_output if log_output else "No logs available."
            }
        except subprocess.CalledProcessError:
            log_data[log_type] = {
                "timestamp": current_time,
                "logs": "Error collecting logs."
            }

    return log_data

API_IP = "http://192.168.68.112:5000/api/logs"  # Replace with your API IP and port

def send_logs():
    logs = collect_logs()
    system_name = socket.gethostname()  # Get system name
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    payload = {
        "system_name": system_name,
        "timestamp": timestamp,
        "logs": logs
    }

    try:
        response = requests.post(API_IP, json=payload, timeout=5)

        if response.status_code == 200:
            print(f"Logs successfully sent to API at {API_IP}")
        else:
            print(f"Failed to send logs. Status Code: {response.status_code}, Response: {response.text}")

    except requests.exceptions.RequestException as e:
        print(f"Error sending logs to API: {e}")

# Run the script every 5 seconds
if __name__ == "__main__":
    request_admin()  # Ensure admin/root access before running
    while True:
        send_logs()
        time.sleep(5)