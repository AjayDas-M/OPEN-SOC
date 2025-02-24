from pymongo import MongoClient
import json
import gridfs

# MongoDB Connection
MONGO_URI = "mongodb+srv://admin:admin123@cluster0.s5qtd.mongodb.net"
DATABASE_NAME = "SOCPlatform"
LOGS_COLLECTION = "Logs"
THREAT_COLLECTION = "Threats"

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]
logs_col = db[LOGS_COLLECTION]
threats_col = db[THREAT_COLLECTION]
fs = gridfs.GridFS(db)

# Load whitelist & blacklist rules
with open("rules.json", "r") as file:
    rules = json.load(file)

whitelist = set(rules["whitelist"])
blacklist = set(rules["blacklist"])

# Function to analyze logs for threats
def analyze_logs():
    logs = logs_col.find()  # Fetch all logs

    for log in logs:
        detected_threats = []

        # Analyze Firewall Logs
        if log["firewall_logs"]:
            for entry in log["firewall_logs"]:
                source_ip = entry.get("source_ip")
                if source_ip in blacklist:
                    detected_threats.append({"type": "Blacklisted IP Detected", "ip": source_ip})

        # Analyze Network Logs (Check PCAP Files)
        if log["network_logs"]:
            try:
                pcap_data = fs.get(log["network_logs"]).read().decode(errors="ignore")
                for ip in blacklist:
                    if ip in pcap_data:
                        detected_threats.append({"type": "Suspicious Network Activity", "ip": ip})
            except Exception as e:
                print(f"Error reading PCAP file: {e}")

        # Analyze System Logs (Check for High CPU/Memory Usage)
        if log["system_logs"]:
            if log["system_logs"]["cpu_usage"] > 80:  # Adjust threshold as needed
                detected_threats.append({"type": "High CPU Usage", "cpu": log["system_logs"]["cpu_usage"]})
            if log["system_logs"]["memory_usage"] > 85:  # Adjust threshold as needed
                detected_threats.append({"type": "High Memory Usage", "memory": log["system_logs"]["memory_usage"]})

        # Analyze External Logs (Check for Blacklisted Threats)
        if log["external_logs"]:
            for entry in log["external_logs"]:
                malicious_ip = entry.get("malicious_ip")
                if malicious_ip and malicious_ip in blacklist:
                    detected_threats.append({"type": "Threat Found in External Logs", "ip": malicious_ip})

        # Insert detected threats into MongoDB
        if detected_threats:
            threat_entry = {
                "log_id": log["_id"],
                "timestamp": log["timestamp"],
                "threats": detected_threats
            }
            threats_col.insert_one(threat_entry)
            print(f"Threat detected: {threat_entry}")

# Run analysis
if __name__ == "__main__":
    analyze_logs()
