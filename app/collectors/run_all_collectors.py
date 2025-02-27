import subprocess

# Define log collection scripts
scripts = [
    "python3 ./collectors/system_log_collector.py",
    "sudo python3 ./collectors/network_log_collector.py",
    "python3 ./collectors/firewall_log_collector.py",
    "python3 ./collectors/external_log_collector.py",
    "python3 ./collectors/store_logs_mongodb.py"
]

# Run all scripts in parallel
processes = [subprocess.Popen(script, shell=True) for script in scripts]

# Wait for all scripts to finish
for process in processes:
    process.wait()

print("All log collection scripts have finished.")
