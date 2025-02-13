from pymongo import MongoClient
import json
import glob
import os
import gridfs
from datetime import datetime

# MongoDB connection string
MONGO_URI = "mongodb+srv://admin:admin123@cluster0.s5qtd.mongodb.net/"
DATABASE_NAME = "SOCPlatform"
COLLECTION_NAME = "Logs"
PROCESSED_FILES_COLLECTION = "ProcessedFiles"

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]
collection = db[COLLECTION_NAME]
fs = gridfs.GridFS(db)
processed_files_col = db[PROCESSED_FILES_COLLECTION]  # To track inserted files

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

    # Collect logs from files
    logs = {
        "timestamp": timestamp,
        "system_logs": None,
        "network_logs": None,
        "firewall_logs": None,
        "external_logs": None
    }

    # Process system logs (JSON)
    for file in glob.glob("logs/system_log_*.json"):
        if not is_file_processed(file):
            logs["system_logs"] = store_file_in_gridfs(file)
            mark_file_as_processed(file)

    # Process network logs (PCAP)
    for file in glob.glob("logs/network_log_*.pcap"):
        if not is_file_processed(file):
            logs["network_logs"] = store_file_in_gridfs(file)
            mark_file_as_processed(file)

    # Process firewall logs (JSON)
    for file in glob.glob("logs/firewall_log_*.json"):
        if not is_file_processed(file):
            logs["firewall_logs"] = store_file_in_gridfs(file)
            mark_file_as_processed(file)

    # Process external logs (JSON)
    for file in glob.glob("logs/external_log_*.json"):
        if not is_file_processed(file):
            logs["external_logs"] = store_file_in_gridfs(file)
            mark_file_as_processed(file)

    # Insert log metadata into MongoDB
    collection.insert_one(logs)
    print("Logs inserted with file references:", logs)

# Run the function
if __name__ == "__main__":
    insert_logs()

    print("Log collection complete.")