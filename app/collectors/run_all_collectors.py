import subprocess
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define log collection scripts with timeout (in seconds)
scripts = [
    {"command": "python3 collectors/system_log_collector.py", "timeout": 300},
    {"command": "sudo python3 collectors/network_log_collector.py", "timeout": 600},
    {"command": "python3 collectors/firewall_log_collector.py", "timeout": 300},
    {"command": "python3 collectors/external_log_collector.py", "timeout": 300},
    {"command": "python3 collectors/store_logs_mongodb.py", "timeout": 600}
]

# Run all scripts in parallel with timeout handling
processes = []
for script in scripts:
    try:
        process = subprocess.Popen(script["command"], shell=True)
        processes.append({"process": process, "timeout": script["timeout"], "start_time": time.time()})
        logging.info(f"Started script: {script['command']} (timeout: {script['timeout']}s)")
    except Exception as e:
        logging.error(f"Failed to start script {script['command']}: {str(e)}")
        logging.error(f"Error details: {e.__class__.__name__} - {str(e)}")

# Wait for all scripts to finish with timeout handling
for proc_info in processes:
    try:
        # Calculate remaining time
        elapsed_time = time.time() - proc_info["start_time"]
        remaining_time = max(0, proc_info["timeout"] - elapsed_time)
        
        # Wait with timeout
        proc_info["process"].wait(timeout=remaining_time)
        
        if proc_info["process"].returncode != 0:
            logging.error(f"Script finished with exit code: {proc_info['process'].returncode}")
        else:
            logging.info(f"Script finished successfully with exit code: {proc_info['process'].returncode}")
    except subprocess.TimeoutExpired:
        proc_info["process"].terminate()
        logging.error(f"Script timed out after {proc_info['timeout']} seconds: {proc_info['command']}")
    except Exception as e:
        logging.error(f"Error waiting for script to complete: {str(e)}")

logging.info("All log collection scripts have finished.")
