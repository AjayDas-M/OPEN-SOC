from flask import Flask, render_template, redirect, url_for, send_from_directory
import subprocess
from pymongo import MongoClient
from bson import ObjectId
import os

app = Flask(__name__)

# Secure MongoDB connection using environment variable
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://admin:admin123@cluster0.s5qtd.mongodb.net")
client = MongoClient(MONGO_URI)
db = client["SOCPlatform"]  # Change to your database name
collection = db["Logs"]  # Change to your collection name

@app.route('/')
def index():
    logs = list(collection.find({}, {"_id": 0}))  # Fetch logs excluding MongoDB ID
    
    for log in logs:
        # Identify and store all available log types in the entry
        log['log_types'] = []
        for key in ['system_logs', 'network_logs', 'firewall_logs', 'external_logs']:
            if key in log and log[key]:
                log['log_types'].append(key.replace('_', ' ').title())
            if isinstance(log.get(key), ObjectId):
                log[key] = str(log[key])
    
    return render_template('index.html', title="OPEN-SOC", logs=logs)

@app.route('/collect_logs')
def collect_logs():
    try:
        # Run all log collection scripts
        subprocess.Popen(["python3", "./collectors/run_all_collectors.py"])
        return redirect(url_for('index'))
    except Exception as e:
        return f"An error occurred while collecting logs: {str(e)}", 500

@app.route('/download/<path:filename>')
def download_pcap(filename):
    return send_from_directory('logs/network_logs', filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
