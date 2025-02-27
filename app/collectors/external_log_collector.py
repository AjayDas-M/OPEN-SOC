import requests
import json
import os
from datetime import datetime

# Create logs directory if not exists
if not os.path.exists("logs/external_logs"):
    os.makedirs("logs/external_logs")

# API Endpoint (Placeholder API for now)
API_URL = "https://jsonplaceholder.typicode.com/posts"  # Simulating external logs

# Function to fetch logs from an external API
def fetch_external_logs():
    log_filename = f"logs/external_logs/external_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    try:
        response = requests.get(API_URL)
        logs = response.json()  # Convert response to JSON

        # Save logs to file
        with open(log_filename, "w") as file:
            json.dump(logs, file, indent=4)

        print(f"External logs saved: {log_filename}")

    except Exception as e:
        print(f"Error fetching external logs: {e}")

# Run the function
if __name__ == "__main__":
    fetch_external_logs()

    print("External log collection complete.")
