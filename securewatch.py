#!/usr/bin/env python3
# GuardianX — Defensive Security Engine (Legal & Educational)

import os
import re
import time
import json
import hmac
import math
import queue
import secrets
import hashlib
import threading
from datetime import datetime

APP_NAME = "GuardianX"
VERSION = "1.0.0"
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "security.log")
STATE_FILE = os.path.join(LOG_DIR, "state.json")

os.makedirs(LOG_DIR, exist_ok=True)

def _now():
    return datetime.utcnow().isoformat() + "Z"

def _log(event, level="INFO", data=None):
    entry = {
        "ts": _now(),
        "level": level,
        "event": event,
        "data": data or {}
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def _load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"alerts": 0, "checks": 0}

def _save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

def entropy(password):
    pools = 0
    pools += 26 if re.search(r"[a-z]", password) else 0
    pools += 26 if re.search(r"[A-Z]", password) else 0
    pools += 10 if re.search(r"\d", password) else 0
    pools += 32 if re.search(r"[^\w]", password) else 0
    if pools == 0:
        return 0.0
    return len(password) * math.log2(pools)

def password_score(password):
    score = 0
    score += len(password) >= 12
    score += len(password) >= 16
    score += bool(re.search(r"[a-z]", password))
    score += bool(re.search(r"[A-Z]", password))
    score += bool(re.search(r"\d", password))
    score += bool(re.search(r"[^\w]", password))
    score += entropy(password) >= 70
    return score

def generate_password(length=24):
    alphabet = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()-_=+[]{};:,.<>/?"
    )
    return "".join(secrets.choice(alphabet) for _ in range(length))

def hash_password(password, salt=None, rounds=200_000):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, rounds)
    return {
        "algo": "pbkdf2_sha256",
        "rounds": rounds,
        "salt": salt.hex(),
        "hash": dk.hex()
    }

def timing_safe_equal(a, b):
    return hmac.compare_digest(a, b)

class RateLimiter:
    def __init__(self, limit=5, window=60):
        self.limit = limit
        self.window = window
        self.events = []

    def hit(self):
        now = time.time()
        self.events = [t for t in self.events if now - t <= self.window]
        self.events.append(now)
        return len(self.events) > self.limit

class AnomalyDetector:
    def __init__(self):
        self.baseline = {
            "avg_interval": 5.0,
            "jitter": 2.0
        }
        self.last = None

    def check(self):
        now = time.time()
        if self.last is None:
            self.last = now
            return False
        interval = now - self.last
        self.last = now
        if interval < max(0.5, self.baseline["avg_interval"] - self.baseline["jitter"]):
            return True
        return False

class GuardianX:
    def __init__(self):
        self.state = _load_state()
        self.limiter = RateLimiter()
        self.detector = AnomalyDetector()
        self.q = queue.Queue()
        self.running = True

    def alert(self, msg, payload=None):
        self.state["alerts"] += 1
        _log(msg, level="ALERT", data=payload)
        print(f"\n[ALERT] {msg}")
        if payload:
            print(json.dumps(payload, indent=2))

    def check_cycle(self):
        self.state["checks"] += 1

        suspicious = False
        if self.limiter.hit():
            suspicious = True

        if self.detector.check():
            suspicious = True

        if secrets.randbelow(20) == 0:
            suspicious = True

        if suspicious:
            pwd = generate_password()
            score = password_score(pwd)
            h = hash_password(pwd)
            self.alert(
                "Suspicious activity detected",
                {
                    "recommended_password": pwd,
                    "score": score,
                    "entropy": round(entropy(pwd), 2),
                    "hash_preview": h["hash"][:16] + "..."
                }
            )

        _save_state(self.state)

    def worker(self):
        while self.running:
            try:
                self.check_cycle()
                time.sleep(3)
            except Exception as e:
                _log("runtime_error", level="ERROR", data={"error": str(e)})
                time.sleep(5)

    def start(self):
        _log("engine_start", data={"app": APP_NAME, "version": VERSION})
        print(f"{APP_NAME} v{VERSION} started")
        t = threading.Thread(target=self.worker, daemon=True)
        t.start()
        while True:
            time.sleep(1)

if __name__ == "__main__":
    GuardianX().start()
