# idps.py

import os
import time
import fnmatch
import threading

from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileDeletedEvent,
    FileMovedEvent,
    FileModifiedEvent,
)

from monitor import monitor_network_connections, monitor_system_processes
from detector import AdvancedAnomalyDetector

LOG_DIR = "./logs"
LAB_DIR = "./lab"

FILE_LOG = os.path.join(LOG_DIR, "file_log.txt")
ALERTS_LOG = os.path.join(LOG_DIR, "alerts_log.txt")


def ensure_directories():
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(LAB_DIR, exist_ok=True)


def log_alert(message, severity, context):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    with open(ALERTS_LOG, "a") as f:
        f.write(f"{timestamp} - [{severity}] {message} - {context}\n")


class IDPSEventHandler(FileSystemEventHandler):
    def __init__(self, ignore_patterns=None, anomaly_detector=None):
        super().__init__()
        self.ignore_patterns = ignore_patterns or []
        self.anomaly_detector = anomaly_detector

    def _get_event_type(self, event):
        if isinstance(event, FileCreatedEvent):
            return 0
        elif isinstance(event, FileDeletedEvent):
            return 1
        elif isinstance(event, FileMovedEvent):
            return 2
        elif isinstance(event, FileModifiedEvent):
            return 3
        else:
            return -1

    def _get_event_vector(self, event):
        event_type = self._get_event_type(event)
        if event_type == -1:
            return None

        file_size = 0
        if os.path.exists(event.src_path):
            try:
                file_size = os.path.getsize(event.src_path)
            except (OSError, PermissionError):
                file_size = 0

        return [event_type, file_size]

    def should_ignore(self, path):
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False

    def log_event(self, event_type, path):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        with open(FILE_LOG, "a") as log_file:
            log_file.write(f"{timestamp} - {event_type} - {path}\n")

    def _handle_event(self, event, action_name):
        if self.should_ignore(event.src_path):
            return

        feature_vector = self._get_event_vector(event)
        meta = {
            "path": event.src_path,
            "event": action_name,
        }

        if feature_vector is not None and self.anomaly_detector:
            self.anomaly_detector.add_event(feature_vector, meta=meta)

        print(f"[FILE-ALERT] {event.src_path} has been {action_name}.")
        self.log_event(action_name, event.src_path)

    def on_created(self, event):
        self._handle_event(event, "created")

    def on_deleted(self, event):
        self._handle_event(event, "deleted")

    def on_moved(self, event):
        # moving has dest_path too
        if self.should_ignore(event.src_path) and self.should_ignore(event.dest_path):
            return

        feature_vector = self._get_event_vector(event)
        meta = {
            "path": f"{event.src_path} -> {event.dest_path}",
            "event": "moved",
        }

        if feature_vector is not None and self.anomaly_detector:
            self.anomaly_detector.add_event(feature_vector, meta=meta)

        print(f"[FILE-ALERT] {event.src_path} has been moved to {event.dest_path}.")
        self.log_event("moved", f"{event.src_path} -> {event.dest_path}")

    def on_modified(self, event):
        self._handle_event(event, "modified")


def main():
    ensure_directories()

    paths_to_monitor = [LAB_DIR]    # ./lab folder
    ignore_patterns = ["*.tmp", "*.log"]

    anomaly_detector = AdvancedAnomalyDetector(
        threshold=10,
        time_window=60,
        train_interval=30,
        max_samples=1000,
        alert_callback=log_alert,
    )

    event_handler = IDPSEventHandler(
        ignore_patterns=ignore_patterns,
        anomaly_detector=anomaly_detector,
    )

    observer = Observer()

    for path in paths_to_monitor:
        observer.schedule(event_handler, path, recursive=True)

    observer.start()
    print(f"[IDPS] File monitoring started on: {paths_to_monitor}")
    print(f"[IDPS] Logs directory: {os.path.abspath(LOG_DIR)}")

    # Start network monitor thread
    network_monitor_thread = threading.Thread(
        target=monitor_network_connections,
        daemon=True,
    )
    network_monitor_thread.start()
    print("[IDPS] Network monitoring started.")

    # Start process monitor thread
    process_monitor_thread = threading.Thread(
        target=monitor_system_processes,
        daemon=True,
    )
    process_monitor_thread.start()
    print("[IDPS] Process monitoring started.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[IDPS] Stopping observer...")
        observer.stop()

    observer.join()
    print("[IDPS] Shutdown complete.")


if __name__ == "__main__":
    main()

