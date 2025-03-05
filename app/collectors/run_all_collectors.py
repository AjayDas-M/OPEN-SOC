import subprocess

# Define log collection scripts with hardcoded sudo password
scripts = [
    "python3 collectors/system_log_collector.py",
    "echo '1' | sudo -S python3 collectors/network_log_collector.py",
    "python3 collectors/firewall_log_collector.py",
    "python3 collectors/external_log_collector.py"
]

# Run all scripts in parallel
processes = [subprocess.Popen(script, shell=True) for script in scripts]

# Wait for all scripts to finish
for process in processes:
    process.wait()
# for process in processes:
#     process.wait(timeout=300)  # Adjust timeout as needed

# Run the store_logs_mongodb script after all collections are finished
subprocess.Popen("python3 collectors/store_logs_mongodb.py", shell=True)
print("All log collection scripts have finished. Now storing logs in MongoDB.")
