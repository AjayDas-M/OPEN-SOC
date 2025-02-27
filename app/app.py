from flask import Flask, render_template, redirect, url_for, send_from_directory
import subprocess
from pymongo import MongoClient
from bson import ObjectId

app = Flask(__name__)

# MongoDB connection
MONGO_URI = "mongodb+srv://admin:admin123@cluster0.s5qtd.mongodb.net"
client = MongoClient(MONGO_URI)
db = client["SOCPlatform"]  # Change to your database name
collection = db["Logs"]  # Change to your collection name

@app.route('/')
def index():
    logs = list(collection.find({}, {"_id": 0}))  # Fetch logs excluding MongoDB ID
    # Convert ObjectId to string if present
    for log in logs:
        if 'network_logs' in log and isinstance(log['network_logs'], ObjectId):
            log['network_logs'] = str(log['network_logs'])
        if 'system_logs' in log and isinstance(log['system_logs'], ObjectId):
            log['system_logs'] = str(log['system_logs'])
        if 'firewall_logs' in log and isinstance(log['firewall_logs'], ObjectId):
            log['firewall_logs'] = str(log['firewall_logs'])
        if 'external_logs' in log and isinstance(log['external_logs'], ObjectId):
            log['external_logs'] = str(log['external_logs'])
    return render_template('index.html', title="OPEN-SOC", logs=logs)

@app.route('/collect_logs')
def collect_logs():
    # Run all log collection scripts
    subprocess.Popen(["python3", "collectors/run_all_collectors.py"])
    return redirect(url_for('index'))

@app.route('/download/<path:filename>')
def download_pcap(filename):
    return send_from_directory('logs/network_logs', filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)