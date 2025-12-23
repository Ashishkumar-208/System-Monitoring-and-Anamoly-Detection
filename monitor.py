# monitor.py

import os
import time
import socket
import psutil

LOG_DIR = "./logs"
NETWORK_LOG_FILE = os.path.join(LOG_DIR, "network_connections_log.txt")
PROCESS_LOG_FILE = os.path.join(LOG_DIR, "processes_log.txt")

# Config
NETWORK_INTERVAL = 5        # seconds
PROCESS_INTERVAL = 10       # seconds
CPU_THRESHOLD = 80.0        # %
MEM_THRESHOLD = 80.0        # %

SUSPICIOUS_PROCESSES = [
    "nmap", "msfconsole", "nc", "netcat", "hydra", "sqlmap"
]


def ensure_log_dir():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR, exist_ok=True)


def monitor_network_connections(interval=NETWORK_INTERVAL, log_file=NETWORK_LOG_FILE):
    ensure_log_dir()
    previous_connections = set()

    while True:
        current_connections = set()

        for connection in psutil.net_connections(kind="inet"):
            laddr = connection.laddr
            raddr = connection.raddr
            status = connection.status
            if raddr:
                current_connections.add((laddr, raddr, status))

        new_connections = current_connections - previous_connections
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

        with open(log_file, "a") as f:
            for connection in new_connections:
                laddr, raddr, status = connection
                local_ip = f"{laddr.ip}:{laddr.port}"
                remote_ip = f"{raddr.ip}:{raddr.port}"

                suspicious_flag = ""
                # Example: mark non-local IPs as suspicious-ish (demo)
                if not remote_ip.startswith("127.") and not remote_ip.startswith("192.168"):
                    suspicious_flag = " [POSSIBLE-FOREIGN-IP]"

                f.write(f"{timestamp} - {local_ip} -> {remote_ip} - {status}{suspicious_flag}\n")

        previous_connections = current_connections
        time.sleep(interval)


def monitor_system_processes(
    interval=PROCESS_INTERVAL,
    cpu_threshold=CPU_THRESHOLD,
    mem_threshold=MEM_THRESHOLD,
    log_file=PROCESS_LOG_FILE,
):
    ensure_log_dir()

    while True:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

        with open(log_file, "a") as f:
            for process in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
                pid = process.info["pid"]
                name = process.info["name"] or "unknown"
                cpu_percent = process.info["cpu_percent"]
                mem_percent = process.info["memory_percent"]

                severity = None

                if name.lower() in SUSPICIOUS_PROCESSES:
                    severity = "HIGH"
                elif cpu_percent > cpu_threshold or mem_percent > mem_threshold:
                    severity = "MEDIUM"

                if severity:
                    f.write(
                        f"{timestamp} - [{severity}] {name} (PID: {pid}) "
                        f"- CPU: {cpu_percent:.2f}%, MEM: {mem_percent:.2f}%\n"
                    )

        time.sleep(interval)

