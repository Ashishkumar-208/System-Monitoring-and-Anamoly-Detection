# app.py

import os
from flask import Flask, render_template

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")

FILE_LOG = os.path.join(LOG_DIR, "file_log.txt")
PROC_LOG = os.path.join(LOG_DIR, "processes_log.txt")
NET_LOG = os.path.join(LOG_DIR, "network_connections_log.txt")
ALERTS_LOG = os.path.join(LOG_DIR, "alerts_log.txt")


def read_last_lines(path, limit=50):
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        lines = f.readlines()
    return [line.strip() for line in lines[-limit:]]


@app.route("/")
def dashboard():
    file_logs = read_last_lines(FILE_LOG, limit=50)
    proc_logs = read_last_lines(PROC_LOG, limit=50)
    net_logs = read_last_lines(NET_LOG, limit=50)
    alert_logs = read_last_lines(ALERTS_LOG, limit=50)

    total_events = len(file_logs) + len(proc_logs) + len(net_logs)
    critical_alerts = len(alert_logs)
    blocked_actions = 0      # future me agar "BLOCKED" word logs me add karein to yahan se count
    ml_score = 0.0           # agar baad me score log karoge to calculate kar sakte ho

    metrics = {
        "total_events": total_events,
        "critical_alerts": critical_alerts,
        "blocked_actions": blocked_actions,
        "ml_score": ml_score,
    }

    return render_template(
        "dashboard.html",
        metrics=metrics,
        file_logs=file_logs,
        proc_logs=proc_logs,
        net_logs=net_logs,
        alert_logs=alert_logs,
    )


if __name__ == "__main__":
    app.run(debug=True)

