import os
import re
import sys
import time
from collections import defaultdict, deque
from datetime import datetime
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# --- CONFIGURATION ---
LOG_FILE = "/var/log/auth.log"
FAILED_THRESHOLD = 5         
TIME_WINDOW = 10             

# MongoDB Configurations
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "security_logs"
COLLECTION_NAME = "alerts"

# --- REGEX PATTERNS ---
FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d\.]+) port"
)
ACCEPTED_PATTERN = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d\.]+) port"
)


class IntrusionDetector:
    def __init__(self):
        self.failure_tracker = defaultdict(deque)
        self.db_client = None
        self.db_collection = None
        self.init_db()

    def init_db(self):
        """Initializes the connection to the local MongoDB database."""
        try:
            # Short 2-second timeout to check if local MongoDB is up and running
            self.db_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
            # Force a call to verify connection status
            self.db_client.admin.command('ping')
            
            self.db_collection = self.db_client[DB_NAME][COLLECTION_NAME]
            print(f"[*] Successfully connected to MongoDB database: '{DB_NAME}'")
        except ConnectionFailure:
            print("\033[91m[!] Database connection failed.\033[0m Ensure MongoDB is running locally (`sudo systemctl status mongod`).")
            print("[*] Running in local-only fallback mode (Console logging only).\n")
            self.db_collection = None

    def log_to_mongo(self, document: dict):
        """Helper to insert security events cleanly into MongoDB."""
        if self.db_collection:
            try:
                self.db_collection.insert_one(document)
            except Exception as e:
                print(f"[\033[91mERROR\033[0m] Failed to write to MongoDB: {e}")

    def process_line(self, line: str):
        # 1. Check for Failed Logins
        failed_match = FAILED_PATTERN.search(line)
        if failed_match:
            user = failed_match.group("user")
            ip = failed_match.group("ip")
            self.register_failure(ip, user)
            return

        # 2. Check for Successful Logins
        accepted_match = ACCEPTED_PATTERN.search(line)
        if accepted_match:
            user = accepted_match.group("user")
            ip = accepted_match.group("ip")
            print(f"[\033[92mSUCCESS\033[0m] {datetime.now()} - User '{user}' logged in from {ip}")
            
            # Reset local threshold count tracker
            if ip in self.failure_tracker:
                del self.failure_tracker[ip]

    def register_failure(self, ip: str, user: str):
        now = time.time()
        failures = self.failure_tracker[ip]
        failures.append(now)

        # Evict stale timestamps
        while failures and now - failures[0] > TIME_WINDOW:
            failures.popleft()

        total_failures = len(failures)
        print(f"[\033[93mWARN\033[0m] {datetime.now()} - Failed login attempt for '{user}' from {ip} (Total: {total_failures} in {TIME_WINDOW}s)")

        # Log warning signature to MongoDB
        self.log_to_mongo({
            "timestamp": datetime.utcnow(),
            "event_type": "auth_failure",
            "source_ip": ip,
            "username": user,
            "failure_count_in_window": total_failures,
            "severity": "LOW"
        })

        # Trigger alert if threshold is breached
        if total_failures >= FAILED_THRESHOLD:
            self.trigger_alert(ip, user, total_failures)

    def trigger_alert(self, ip: str, last_user: str, count: int):
        print(f"\n\033[91m[!!! ALERT !!!] POSSIBLE BRUTE FORCE DETECTED\033[0m")
        print(f"IP Address \033[1m{ip}\033[0m generated {count} failed logins in under {TIME_WINDOW} seconds.\n")

        # Log higher severity alert to MongoDB
        self.log_to_mongo({
            "timestamp": datetime.utcnow(),
            "event_type": "brute_force_alert",
            "source_ip": ip,
            "last_targeted_username": last_user,
            "total_attempts": count,
            "time_window_seconds": TIME_WINDOW,
            "severity": "CRITICAL"
        })


def tail_file(filepath):
    try:
        with open(filepath, "r") as f:
            f.seek(0, os.SEEK_END)
            print(f"[*] Actively monitoring {filepath} for suspicious auth behavior...")
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                yield line
    except PermissionError:
        print(f"[!] Error: Root privileges required to read {filepath}. Try running with sudo.")
        sys.exit(1)
    except FileNotFoundError:
        print(f"[!] Error: Log file {filepath} not found.")
        sys.exit(1)


if __name__ == "__main__":
    detector = IntrusionDetector()
    try:
        for log_line in tail_file(LOG_FILE):
            detector.process_line(log_line)
    except KeyboardInterrupt:
        print("\n[*] Shutting down real-time log analyzer. Stay secure!")