from pymongo import MongoClient
import json
import gridfs

# MongoDB connection
MONGO_URI = "mongodb+srv://admin:admin123@cluster0.s5qtd.mongodb.net/"
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

# Function to analyze logs for blacklisted IPs
def analyze_logs():
    logs = logs_col.find()  # Fetch all logs

    for log in logs:
        detected_threats = []

        # Check firewall logs for blacklisted IPs
        if log["firewall_logs"]:
            firewall_file = fs.get(log["firewall_logs"]).read().decode()
            for ip in blacklist:
                if ip in firewall_file:
                    detected_threats.append({"type": "Blacklisted IP", "ip": ip})

        # Check network logs for suspicious connections
        if log["network_logs"]:
            network_file = fs.get(log["network_logs"]).read().decode()
            for ip in blacklist:
                if ip in network_file:
                    detected_threats.append({"type": "Suspicious Network Activity", "ip": ip})

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
