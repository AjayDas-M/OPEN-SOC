import streamlit as st
import pymongo
from pymongo import MongoClient
import pandas as pd

# MongoDB connection
MONGO_URI = "mongodb+srv://admin:admin123@cluster0.s5qtd.mongodb.net"
client = MongoClient(MONGO_URI)
db = client["SOCPlatform"]  # Change to your database name
collection = db["Logs"]  # Change to your collection name

# Streamlit UI
st.title("OPEN-SOC: Log Monitoring")

# Fetch logs from MongoDB
def fetch_logs():
    logs = list(collection.find({}, {"_id": 0}))  # Exclude MongoDB ID field
    return logs

# Load logs
logs = fetch_logs()

# Convert logs to DataFrame for filtering
df = pd.DataFrame(logs)

# Filters
log_types = ["system_logs", "network_logs", "firewall_logs", "external_logs"]
selected_type = st.selectbox("Select Log Type", log_types)
date_filter = st.date_input("Filter by Date")

# Apply filtering
if selected_type in df.columns:
    df = df[["timestamp", selected_type]]  # Show only selected log type
    df = df[df["timestamp"].str.startswith(str(date_filter))]

# Display logs
st.write("### Filtered Logs")
st.dataframe(df)
