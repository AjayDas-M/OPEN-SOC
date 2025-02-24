import subprocess

# Define log collection scripts
scripts = [
    "python3 ./log_collection/system_log_collector.py",
    "sudo python3 ./log_collection/network_log_collector.py",
    "python3 ./log_collection/firewall_log_collector.py",
    "python3 ./log_collection/external_log_collector.py"
]

# Run all scripts in parallel
processes = [subprocess.Popen(script, shell=True) for script in scripts]

# Wait for all scripts to finish
for process in processes:
    process.wait()

print("All log collection scripts have finished.")
