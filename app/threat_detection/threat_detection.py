import json
from pymongo import MongoClient
from datetime import datetime, timedelta

# Load Security Rules
with open("rules.json", "r") as file:
    RULES = json.load(file)

# MongoDB Connection
MONGO_URI = "mongodb+srv://admin:admin123@cluster0.s5qtd.mongodb.net"
DATABASE_NAME = "SOCPlatform"
LOGS_COLLECTION = "Logs"
ALERTS_COLLECTION = "Alerts"

client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]
logs_col = db[LOGS_COLLECTION]
alerts_col = db[ALERTS_COLLECTION]

# Function to insert alerts into MongoDB
def raise_alert(alert_type, message, log_data):
    alert = {
        "alert_type": alert_type,
        "message": message,
        "timestamp": datetime.utcnow().isoformat(),
        "log_data": log_data
    }
    alerts_col.insert_one(alert)
    print(f"[ALERT] {alert_type}: {message}")

# Rule 1: Detect Failed Login Attempts
def detect_failed_logins():
    if not RULES["failed_login_attempts"]["enabled"]:
        return

    threshold = RULES["failed_login_attempts"]["threshold"]
    time_window = RULES["failed_login_attempts"]["time_window"]

    time_limit = datetime.utcnow() - timedelta(minutes=time_window)

    failed_logins = logs_col.find({
        "system_logs.event": "failed_login",
        "timestamp": {"$gte": time_limit.isoformat()}
    })

    ip_count = {}
    for log in failed_logins:
        ip = log["system_logs"]["ip"]
        ip_count[ip] = ip_count.get(ip, 0) + 1

        if ip_count[ip] >= threshold:
            raise_alert("Failed Login Attempt", f"Multiple failed logins from {ip}", log)

# Rule 2: Detect Data Exfiltration
def detect_data_exfiltration():
    if not RULES["data_exfiltration"]["enabled"]:
        return

    threshold = RULES["data_exfiltration"]["threshold"]

    large_transfers = logs_col.find({
        "network_logs.data_transferred": {"$gte": threshold}
    })

    for log in large_transfers:
        raise_alert("Data Exfiltration", "Unusual large data transfer detected", log)

# Rule 3: Detect Blacklisted IP Access
def detect_blacklisted_ips():
    blacklisted_ips = set(RULES["blacklisted_ips"])

    logs = logs_col.find({
        "network_logs.src_ip": {"$in": list(blacklisted_ips)}
    })

    for log in logs:
        raise_alert("Blacklisted IP Access", f"Blacklisted IP {log['network_logs']['src_ip']} accessed the system", log)

# Run Threat Detection
def run_threat_detection():
    detect_failed_logins()
    detect_data_exfiltration()
    detect_blacklisted_ips()
    print("Threat detection completed.")

# Execute
if __name__ == "__main__":
    run_threat_detection()
