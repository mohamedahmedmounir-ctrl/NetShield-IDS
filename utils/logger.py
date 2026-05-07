"""
utils/logger.py
================
IDS Logging System
-------------------
Responsibilities
----------------
  - Maintain in-memory ring buffers for packets and alerts.
  - Persist logs to disk as JSON (alerts.json, traffic_logs.json).
  - Provide filtered / searched access to log records.
  - Generate unique IDs for alert correlation.

Log Sanitization
----------------
All string fields are stripped of control characters before
storage to prevent log injection attacks.
"""

import os
import re
import json
import uuid
from datetime import datetime
from collections import deque
from threading import Lock


# Paths for on-disk persistence
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR    = os.path.join(BASE_DIR, "logs")
ALERT_FILE  = os.path.join(LOGS_DIR, "alerts.json")
PACKET_FILE = os.path.join(LOGS_DIR, "traffic_logs.json")

# In-memory ring buffer sizes
MAX_PACKETS = 500
MAX_ALERTS  = 1000

# Regex to strip non-printable / control characters
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _sanitize(value) -> str:
    """Remove control characters from string values (log injection guard)."""
    if not isinstance(value, str):
        return str(value)
    return _CONTROL_RE.sub("", value)


class IDSLogger:
    """Thread-safe in-memory + on-disk logger."""

    def __init__(self):
        os.makedirs(LOGS_DIR, exist_ok=True)
        self._alert_lock  = Lock()
        self._packet_lock = Lock()
        self._alerts:  deque = deque(maxlen=MAX_ALERTS)
        self._packets: deque = deque(maxlen=MAX_PACKETS)
        self._alert_counter = 0
        self._traffic_analyzer = None

        # Load any existing persisted data on startup
        self._load_from_disk()

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_id(self) -> str:
        """Generate a short unique alert ID."""
        self._alert_counter += 1
        return f"NS-{self._alert_counter:05d}"

    def log_alert(self, alert: dict):
        """
        Sanitize and store an alert.
        Appends to in-memory buffer and writes to disk.
        """
        clean = self._clean_record(alert)
        with self._alert_lock:
            self._alerts.append(clean)
        self._persist_alert(clean)
        if self._traffic_analyzer:
            self._traffic_analyzer.register_alert(clean.get("src_ip", ""))

    def log_packet(self, pkt: dict):
        """Store a packet record in the in-memory ring buffer."""
        clean = self._clean_record(pkt)
        with self._packet_lock:
            self._packets.append(clean)
        # Packets are NOT persisted to disk by default (too high volume).
        # Uncomment below to enable full packet logging:
        # self._persist_packet(clean)

    def get_alerts(self, limit: int = 100, severity: str = "",
                   search: str = "") -> list[dict]:
        """
        Return alerts (newest first) with optional filtering.

        Parameters
        ----------
        limit    : maximum records to return
        severity : filter by severity level (CRITICAL/HIGH/MEDIUM/LOW)
        search   : substring search across ip, attack_type, description
        """
        with self._alert_lock:
            records = list(self._alerts)

        records.reverse()  # newest first

        if severity:
            records = [r for r in records
                       if r.get("severity", "").upper() == severity.upper()]
        if search:
            sl = search.lower()
            records = [
                r for r in records
                if sl in r.get("src_ip", "").lower()
                or sl in r.get("attack_type", "").lower()
                or sl in r.get("description", "").lower()
            ]
        return records[:limit]

    def get_recent_packets(self, limit: int = 50) -> list[dict]:
        """Return the most recent captured packets."""
        with self._packet_lock:
            records = list(self._packets)
        records.reverse()
        return records[:limit]

    def clear(self):
        """Wipe in-memory buffers (disk files are left intact)."""
        with self._alert_lock:
            self._alerts.clear()
        with self._packet_lock:
            self._packets.clear()

    # ── Internal Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _clean_record(record: dict) -> dict:
        """Sanitize all string values in a dict."""
        cleaned = {}
        for k, v in record.items():
            cleaned[k] = _sanitize(v) if isinstance(v, str) else v
        return cleaned

    def _persist_alert(self, alert: dict):
        """Append alert to alerts.json (newline-delimited JSON)."""
        try:
            with open(ALERT_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert) + "\n")
        except OSError:
            pass  # Non-fatal — in-memory buffer still intact

    def _persist_packet(self, pkt: dict):
        """Append packet to traffic_logs.json."""
        try:
            with open(PACKET_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(pkt) + "\n")
        except OSError:
            pass

    def _load_from_disk(self):
        """
        Load existing alerts from disk into the in-memory buffer.
        Loads the most recent MAX_ALERTS lines only.
        """
        if not os.path.exists(ALERT_FILE):
            return
        try:
            with open(ALERT_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in lines[-MAX_ALERTS:]:
                try:
                    self._alerts.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    pass
        except OSError:
            pass

    def set_traffic_analyzer(self, analyzer):
        """Wire in a TrafficAnalyzer so alert source IPs feed the top-IPs list."""
        self._traffic_analyzer = analyzer
