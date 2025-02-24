from pymongo import MongoClient
import json
import glob
import os
import gridfs
from datetime import datetime

# MongoDB connection string
MONGO_URI = "mongodb+srv://admin:admin123@cluster0.s5qtd.mongodb.net"
DATABASE_NAME = "SOCPlatform"
COLLECTION_NAME = "Logs"
PROCESSED_FILES_COLLECTION = "ProcessedFiles"

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]
collection = db[COLLECTION_NAME]
fs = gridfs.GridFS(db)
processed_files_col = db[PROCESSED_FILES_COLLECTION]  # To track inserted files

# Define log directories
LOG_DIRS = {
    "system_logs": "logs/system_logs/*.json",
    "network_logs": "logs/network_logs/*.pcap",
    "firewall_logs": "logs/firewall_logs/*.json",
    "external_logs": "logs/external_logs/*.json"
}

# Function to check if a file was already inserted
def is_file_processed(filename):
    return processed_files_col.find_one({"filename": filename}) is not None

# Function to mark a file as processed
def mark_file_as_processed(filename):
    processed_files_col.insert_one({"filename": filename, "timestamp": datetime.now().isoformat()})

# Function to store logs in GridFS
def store_file_in_gridfs(filepath):
    with open(filepath, "rb") as file:
        file_id = fs.put(file, filename=os.path.basename(filepath))
    return file_id

# Function to insert logs into MongoDB
def insert_logs():
    timestamp = datetime.now().isoformat()
    logs = {"timestamp": timestamp, "system_logs": None, "network_logs": None, "firewall_logs": None, "external_logs": None}

    for log_type, log_pattern in LOG_DIRS.items():
        log_files = glob.glob(log_pattern)

        for log_file in log_files:
            if not is_file_processed(log_file):
                if log_type == "network_logs":  # PCAP files
                    logs[log_type] = store_file_in_gridfs(log_file)
                else:  # JSON logs
                    with open(log_file, "r") as file:
                        try:
                            data = json.load(file)
                            logs[log_type] = data
                        except json.JSONDecodeError:
                            print(f"Error decoding JSON in file: {log_file}")

                mark_file_as_processed(log_file)

    # Insert log metadata into MongoDB
    collection.insert_one(logs)
    print("Logs inserted into MongoDB:", logs)

# Run the function
if __name__ == "__main__":
    insert_logs()
