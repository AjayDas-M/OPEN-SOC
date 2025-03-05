from pymongo import MongoClient
from datetime import datetime
from sentence_transformers import SentenceTransformer
import numpy as np
from sklearn.ensemble import IsolationForest

# Load AI Model (Sentence Transformer)
model = SentenceTransformer("all-MiniLM-L6-v2")

# MongoDB Connection
MONGO_URI = "mongodb+srv://admin:admin123@cluster0.s5qtd.mongodb.net"
DATABASE_NAME = "SOCPlatform"
LOGS_COLLECTION = "Logs"
ALERTS_COLLECTION = "Alerts"

client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]
logs_col = db[LOGS_COLLECTION]
alerts_col = db[ALERTS_COLLECTION]

# Function to insert AI-detected alerts into MongoDB
def raise_ai_alert(log_data, anomaly_score):
    alert = {
        "alert_type": "AI Anomaly Detection",
        "message": f"Anomalous log detected with score: {anomaly_score}",
        "timestamp": datetime.utcnow().isoformat(),
        "log_data": log_data,
        "anomaly_score": anomaly_score
    }
    alerts_col.insert_one(alert)
    print(f"[ALERT] AI detected an anomaly: {log_data}")

# Fetch logs and preprocess them
def fetch_logs():
    logs = list(logs_col.find({}, {"_id": 0, "system_logs": 1, "network_logs": 1, "firewall_logs": 1, "external_logs": 1}))
    log_texts = []

    for log in logs:
        log_text = str(log.get("system_logs", "")) + str(log.get("network_logs", "")) + \
                   str(log.get("firewall_logs", "")) + str(log.get("external_logs", ""))
        log_texts.append(log_text)

    return logs, log_texts

# Convert logs to embeddings
def get_log_embeddings(log_texts):
    return model.encode(log_texts)

# Perform anomaly detection
def detect_anomalies():
    logs, log_texts = fetch_logs()
    if not logs:
        print("No logs found for AI analysis.")
        return

    embeddings = get_log_embeddings(log_texts)

    # Train Isolation Forest (unsupervised anomaly detection)
    iso_forest = IsolationForest(contamination=0.1, random_state=42)
    anomaly_scores = iso_forest.fit_predict(embeddings)

    # Raise alerts for anomalies
    for i, score in enumerate(anomaly_scores):
        if score == -1:  # Anomalous log detected
            raise_ai_alert(logs[i], anomaly_scores[i])

    print("AI Threat Detection Completed.")

# Run AI-based threat detection
if __name__ == "__main__":
    detect_anomalies()
