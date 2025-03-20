from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
import platform
import os
import io
import re
import urllib.parse
import ctypes
import sys
import subprocess
from datetime import datetime, timedelta
from pymongo import MongoClient
import concurrent.futures
import threading
from flask_socketio import SocketIO
import re
import json
import threading
from flask_socketio import SocketIO
from pymongo import MongoClient
from sentence_transformers import SentenceTransformer
import numpy as np



app = Flask(__name__)
# Initialize Flask WebSocket (for real-time UI alerts)
socketio = SocketIO(app, message_queue="redis://", cors_allowed_origins="*")  # Use Redis for scaling

# Load MiniLM model for AI-based detection
model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')


# Secret key for session management
app.secret_key = "your_secret_key"
app.permanent_session_lifetime = timedelta(hours=1)  # Session expires in 1 hour

# MongoDB connection details
username = urllib.parse.quote_plus("admin_user")
password = urllib.parse.quote_plus("@admin_user")
cluster_name = "sop"

# MongoDB client connection
try:
    uri = f"mongodb+srv://{username}:{password}@{cluster_name}.y49v4.mongodb.net/?retryWrites=true&w=majority&appName={cluster_name}"
    client = MongoClient(uri, serverSelectionTimeoutMS=60000)
    db = client["log_dashboard"]
    print("[✅] MongoDB connected successfully!")
except Exception as e:
    print(f"[!] MongoDB Connection Error: {e}")
    sys.exit(1)

# Ensure script runs with admin privileges (Windows/Linux/macOS)
def request_admin():
    if platform.system() == "Windows":
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[*] Requesting Admin Privileges...")
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{os.path.abspath(__file__)}" --elevated', None, 1)
                sys.exit(0)
        except Exception as e:
            print(f"[!] Error requesting admin privileges: {e}")
            sys.exit(1)
    elif platform.system() in ["Linux", "Darwin"]:
        if os.geteuid() != 0:
            print("[*] Please run the script with sudo for elevated privileges.")
            sys.exit(1)

# Execute shell commands securely
def execute_command(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        return output.strip() if output else "✅ No logs available."
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e}"
    except Exception as e:
        return f"Unexpected error: {e}"

# Collect logs across platforms (Windows, Linux, macOS)
def collect_logs():
    logs = {
        "system_logs": "",
        "security_logs": "",
        "application_logs": "",
        "access_logs": "",
        "crash_logs": "",
        "network_logs": "",
        "audit_logs": "",
        "database_logs": "",
        "kernel_logs": "",
        "firewall_logs": "",
        "user_activity_logs": "",
    }

    system_type = platform.system()

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

    system_commands = commands.get(system_type, {})

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {key: executor.submit(execute_command, cmd) for key, cmd in system_commands.items()}
        for key, future in futures.items():
            logs[key] = future.result()

    return logs

# Save logs and threats asynchronously
def save_logs_and_threats_async(logs):
    def process_logs():
        for category, data in logs.items():
            collection = db[category]
            collection.update_one(
                {"log_data": data},
                {"$set": {
                    "system_type": platform.system(),
                    "threats": detect_threats(data),
                    "timestamp": datetime.now()
                }},
                upsert=True
            )
    threading.Thread(target=process_logs).start()



# Threat patterns and corresponding mitigations
threat_mitigation = {
    "failed": "Check user authentication and enforce strong passwords.",
    "error": "Investigate the error and review logs thoroughly.",
    "unauthorized": "Review access controls and enforce least privilege.",
    "attack": "Enable firewall rules and conduct vulnerability scans.",
    "denied": "Ensure proper permissions for authorized users.",
    "intrusion": "Monitor for suspicious activities and implement IDS.",
    "breach": "Validate systems and enforce data encryption.",
    "malware": "Run antivirus scans and isolate infected systems.",
    "exploit": "Patch vulnerable systems and monitor access.",
    "rootkit": "Perform rootkit scans and validate kernel integrity."
}

# Rule-based threat patterns with severity levels

rule_based_patterns = {
    "brute-force": {"pattern": r"(failed login|multiple failed attempts|password incorrect)", "severity": "medium"},
    "unauthorized escalation": {"pattern": r"(sudo failed|unauthorized access|privilege escalation)", "severity": "high"},
    "suspicious process": {"pattern": r"(unknown binary|unexpected process execution)", "severity": "medium"},
}

@app.route("/update_rule_patterns", methods=["POST"])
def update_rule_patterns():
    data = request.json
    rule_name = data.get("name")
    rule_pattern = data.get("pattern")
    rule_severity = data.get("severity")

    if not rule_name or not rule_pattern or not rule_severity:
        return jsonify({"message": "Invalid input"}), 400

    rule_based_patterns[rule_name] = {"pattern": rule_pattern, "severity": rule_severity}
    return jsonify({"message": f"Rule '{rule_name}' updated successfully!"})



# Automated mitigation actions for high-severity threats
mitigation_actions = {
    "unauthorized escalation": "Disable account and enforce MFA.",
    "intrusion": "Isolate endpoint and alert security team.",
    "breach": "Trigger data encryption and log all access attempts.",
    "malware": "Quarantine system and run a deep scan.",
}

# Global alert list (for UI notifications)
alerts = []

def detect_threats(log_data):
    threats = []
    lines = log_data.splitlines()

    # Load historical logs from MongoDB
    historical_entries = list(db.historical_logs.find().limit(100))
    historical_texts = [entry["log_data"] for entry in historical_entries]
    
    # Encode historical logs for anomaly detection
    if historical_texts:
        historical_embeddings = model.encode(historical_texts, convert_to_numpy=True)
    else:
        historical_embeddings = np.array([])

    for line in lines:
        threat_detected = False
        severity = "low"  # Default severity

        # Rule-Based Detection with Severity Classification
        for threat_type, details in rule_based_patterns.items():
            if re.search(details["pattern"], line, re.IGNORECASE):
                severity = details["severity"]
                mitigation = threat_mitigation.get(threat_type, "No specific mitigation available.")
                action = mitigation_actions.get(threat_type, "Monitor and investigate.")

                threat = {
                    "log": line,
                    "type": threat_type,
                    "method": "rule-based",
                    "severity": severity,
                    "mitigation": mitigation,
                    "action": action if severity == "high" else "Monitor"
                }

                threats.append(threat)
                threat_detected = True

                # If severity is high, trigger UI alert & log action
                if severity == "high":
                    trigger_alert(threat)
                    log_action(threat)

                break  # Stop further checks if a rule-based threat is found

        # Anomaly-Based Detection
        if not threat_detected and historical_embeddings.size > 0:
            log_embedding = model.encode([line], convert_to_numpy=True)
            similarity = np.dot(historical_embeddings, log_embedding.T).max()
            
            if similarity < 0.7:  # Threshold for anomaly detection
                severity = "medium"
                threat = {
                    "log": line,
                    "type": "anomaly",
                    "method": "anomaly-based",
                    "severity": severity,
                    "mitigation": "Investigate unusual behavior and review security logs.",
                    "action": "Monitor"
                }
                threats.append(threat)

        # AI-Based Detection (NLP Embeddings)
        if not threat_detected and historical_embeddings.size > 0:
            log_embedding = model.encode([line], convert_to_numpy=True)
            similarity_scores = np.dot(historical_embeddings, log_embedding.T)
            
            if any(score > 0.8 for score in similarity_scores):  # Threshold for AI detection
                severity = "high"
                threat = {
                    "log": line,
                    "type": "similar attack pattern",
                    "method": "AI-based",
                    "severity": severity,
                    "mitigation": "Review related incidents and enhance security monitoring.",
                    "action": "Alert SOC team"
                }
                threats.append(threat)
                trigger_alert(threat)
                log_action(threat)

    return threats

# *Trigger UI Notification for High-Severity Threats*
def trigger_alert(threat):
    alerts.append(threat)  # Store in global alert list
    socketio.emit('new_alert', json.dumps(threat))  # Send alert via WebSocket
    print(f"[⚠ ALERT] {threat['type']} detected: {threat['log']}")

# *Log Automated Actions Taken*
def log_action(threat):
    db.automated_actions.insert_one({
        "log": threat["log"],
        "threat_type": threat["type"],
        "action_taken": threat["action"],
        "timestamp": datetime.now()
    })
    print(f"[✅ ACTION] {threat['action']} executed for {threat['type']}")

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from flask import Flask, request, jsonify
import subprocess

@app.route('/api/block_ip', methods=['POST'])
def block_ip():
    data = request.json
    ip = data.get("ip")
    if not ip:
        return jsonify({"status": "error", "message": "Invalid IP address"}), 400

    try:
        # Log action in MongoDB
        db.automated_actions.insert_one({
            "action": "Block IP",
            "ip": ip,
            "timestamp": datetime.now(),
            "status": "Executed"
        })

        # Execute firewall rule (Modify based on OS)
        command = f"sudo iptables -A INPUT -s {ip} -j DROP"  # Linux (For Windows, use netsh)
        subprocess.run(command, shell=True, check=True)

        return jsonify({"status": "success", "message": f"🚫 IP {ip} has been blocked!"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/isolate_ip', methods=['POST'])
def isolate_ip():
    data = request.json
    ip = data.get("ip")
    if not ip:
        return jsonify({"status": "error", "message": "Invalid IP address"}), 400

    try:
        # Log action in MongoDB
        db.automated_actions.insert_one({
            "action": "Isolate IP",
            "ip": ip,
            "timestamp": datetime.now(),
            "status": "Executed"
        })

        # Example: Isolate IP (modify based on network setup)
        command = f"sudo iptables -A INPUT -s {ip} -j REJECT"  # Linux (For Windows, use netsh)
        subprocess.run(command, shell=True, check=True)

        return jsonify({"status": "success", "message": f"🔒 IP {ip} has been isolated!"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
import matplotlib.pyplot as plt
import tempfile

def generate_graphs(threat_counts, severity_counts):
    """Generates bar and pie charts for threats and saves them as images."""
    temp_files = []

    # Bar Chart - Threat Types
    bar_chart_path = tempfile.mktemp(suffix=".png")
    plt.figure(figsize=(5, 3))
    plt.bar(list(threat_counts.keys()), list(threat_counts.values()), color='blue')
    plt.xlabel("Threat Type")
    plt.ylabel("Count")
    plt.title("Threats by Type")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(bar_chart_path)
    plt.close()
    temp_files.append(bar_chart_path)

    # Pie Chart - Threat Severity
    pie_chart_path = tempfile.mktemp(suffix=".png")
    plt.figure(figsize=(4, 3))
    plt.pie(list(severity_counts.values()), labels=list(severity_counts.keys()),
            autopct='%1.1f%%', colors=['red', 'orange', 'yellow'])
    plt.title("Threat Severity Distribution")
    plt.savefig(pie_chart_path)
    plt.close()
    temp_files.append(pie_chart_path)

    return temp_files

from flask import Flask, Response
from pymongo import MongoClient
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import io

# *List of all log collections*
log_collections = [
    "access_logs", "application_logs", "audit_logs", "crash_logs",
    "database_logs", "external_logs", "firewall_logs", "kernel_logs",
    "network_logs", "security_logs", "system_logs", "user_activity_logs"
]

def count_all_logs():
    """Count total logs from all log collections in the database."""
    return sum(db[collection].count_documents({}) for collection in log_collections)

@app.route('/download_report', methods=['GET'])
def download_report():
    try:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()

        # *Report Title*
        elements.append(Paragraph("<b>SOC Platform -Report</b>", styles['Title']))
        elements.append(Spacer(1, 10))

        # *Count total logs and threats*
        total_logs = count_all_logs()
        detected_threats = db["threats"].count_documents({}) if "threats" in db.list_collection_names() else 0

        elements.append(Paragraph(f"Total Logs Collected: <b>{total_logs}</b>", styles['Normal']))
        elements.append(Paragraph(f"Total Detected Threats: <b>{detected_threats}</b>", styles['Normal']))
        elements.append(Spacer(1, 10))

        # *Fetch detailed threat data*
        threats = list(db["threats"].find({}, {"_id": 0})) if "threats" in db.list_collection_names() else []

        # *Graph Generation (If threats exist)*
        if detected_threats > 0:
            threat_counts = {}
            severity_counts = {"High": 0, "Medium": 0, "Low": 0}
            for threat in threats:
                threat_type = threat.get("threat_type", "Unknown")
                severity = threat.get("severity", "Low")
                threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            graph_paths = generate_graphs(threat_counts, severity_counts)
            for path in graph_paths:
                img = Image(path, width=400, height=250)
                elements.append(img)
                elements.append(Spacer(1, 10))
        else:
            elements.append(Paragraph("No detected threats available to generate graphs.", styles['Normal']))

        # *Threat Details Table*
        if threats:
            headers = ["Timestamp", "System", "Threat Type", "Severity", "Action Taken"]
            table_data = [headers]
            for threat in threats:
                row = [
                    threat.get("timestamp", "N/A"),
                    threat.get("system", "N/A"),
                    threat.get("threat_type", "Unknown"),
                    threat.get("severity", "Low"),
                    threat.get("action_taken", "None")
                ]
                table_data.append(row)

            table = Table(table_data, colWidths=[100] * len(headers))
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ]))
            elements.append(Paragraph("<b>Threat Details</b>", styles['Heading2']))
            elements.append(table)
            elements.append(Spacer(1, 10))
        else:
            elements.append(Paragraph("No threat details available.", styles['Normal']))

        # *Build PDF*
        doc.build(elements)
        buffer.seek(0)

        return Response(buffer, mimetype='application/pdf',
                        headers={"Content-Disposition": "attachment;filename=SOC_Report.pdf"})
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return Response("Internal Server Error: " + str(e), status=500)

# Routes
@app.route('/login', methods=["GET", "POST"])
def login():
    error = None

    # Redirect logged-in users to logs page
    if session.get("logged_in"):
        return redirect(url_for("display_logs"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Default credentials
        default_username = "admin_user"
        default_password = "@admin_user"

        # Retrieve stored credentials from MongoDB (if any)
        stored_credentials = db.credentials.find_one({})

        # Authentication Logic:
        if stored_credentials:
            # Use updated credentials if present
            if username == stored_credentials.get("username") and password == stored_credentials.get("password"):
                session["logged_in"] = True
                print(f"[✅] Login Successful: {username}")
                return redirect(url_for("display_logs"))
        else:
            # Allow default credentials only if no updated ones exist
            if username == default_username and password == default_password:
                session["logged_in"] = True
                print("[✅] Login Successful (Default Credentials)")
                return redirect(url_for("display_logs"))

        # Handle invalid login
        session["error"] = "Invalid username or password"
        return redirect(url_for("login"))  # Redirect after failed login

    # Retrieve and clear error from session
    error = session.pop("error", None)

    return render_template("login.html", error=error)

@app.route('/')
def display_logs():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    # Collect internal system logs
    logs = collect_logs()

    # Process and save threats asynchronously for internal logs
    save_logs_and_threats_async(logs)

    # Get the admin system's name
    system_name = platform.node()

    # Fetch external system logs from MongoDB
    external_logs = db.external_logs.aggregate([
    # Your existing aggregation pipeline
], allowDiskUse=True)  # Enable disk-based sorting  # Exclude _id

    # Format external logs: Each system has its own logs and threats
    formatted_external_logs = {
        entry["system_name"]: {
            "logs": entry["logs"],
            "detected_threats": entry.get("detected_threats", [])
        }
        for entry in external_logs
    }

    return render_template(
        'logs.html',
        logs=logs,
        system_name=system_name,  # Admin system name
        external_logs=formatted_external_logs  # External system logs & threats
    )


@app.route('/api/logs', methods=['POST'])
def receive_logs():
    try:
        data = request.get_json()

        # Validate incoming data
        if not data or 'system_name' not in data or 'logs' not in data:
            return jsonify({"error": "Invalid data format"}), 400

        system_name = data['system_name']
        raw_logs = data['logs']
        timestamp = data.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        print(f"[✅] Received logs from {system_name}. Processing and storing...")

        # ✅ Process logs the same way as admin system logs
        processed_logs = {}
        for category, log_content in raw_logs.items():
            processed_logs[category] = {
                "timestamp": timestamp,
                "logs": log_content
            }

        # ✅ Detect threats
        detected_threats = detect_threats(str(raw_logs))

        # ✅ Store logs in MongoDB like admin system logs
        db.external_logs.insert_one({
            "system_name": system_name,
            "logs": processed_logs,
            "timestamp": timestamp,
            "detected_threats": detected_threats
            }
            )

        # ✅ Send logs to frontend for real-time display
        socketio.emit('new_external_log', {
            "system_name": system_name,
            "logs": processed_logs,
            "detected_threats": detected_threats,
            "timestamp": timestamp
        }, namespace='/')

        print(f"[✅] Logs from {system_name} stored in MongoDB and sent to frontend.")

        return jsonify({"status": "success", "message": "Logs processed, stored, and broadcasted"}), 200

    except Exception as e:
        print(f"[!] Error processing external logs: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/change_credentials', methods=['POST'])
def change_credentials():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    new_username = request.form.get("new_username")
    new_password = request.form.get("new_password")

    if new_username and new_password:
        # Update session with new credentials
        session["username"] = new_username
        session["password"] = new_password
        print(f"[✅] Credentials Updated: {new_username}")

        # Update credentials in MongoDB
        db.credentials.update_one({}, {"$set": {"username": new_username, "password": new_password}}, upsert=True)

        # Redirect to the logs page with updated credentials
        return redirect(url_for("display_logs"))

    return redirect(url_for("display_logs"))  

@app.route('/logout')
def logout():
    session.clear()  # Clear session on logout
    print("[🚪] User logged out")
    return redirect(url_for("login"))   

if __name__ == '__main__':
    if "--elevated" not in sys.argv:
        request_admin()
    app.run(host="0.0.0.0",port=5000,debug=True)