"""
detector/traffic_analyzer.py
=============================
Traffic Analytics Engine
--------------------------
Aggregates packet data into statistics used by the dashboard:
  - Protocol distribution
  - Top source/destination IPs by volume
  - Per-minute traffic timelines
  - Network-wide threat score computation
  - Bandwidth usage estimates
"""

from collections import defaultdict, deque
from datetime import datetime, timedelta
import random


class TrafficAnalyzer:
    """
    Maintains running counters and time-series buckets for
    traffic visualisation on the dashboard.
    """

    # Maximum number of 1-minute timeline buckets to keep
    TIMELINE_BUCKETS = 30

    def __init__(self):
        self.reset()

    def reset(self):
        """Clear all aggregated statistics."""
        self._protocol_counts:  defaultdict = defaultdict(int)
        self._src_ip_counts:    defaultdict = defaultdict(int)
        self._dst_ip_counts:    defaultdict = defaultdict(int)
        self._alert_ip_counts:  defaultdict = defaultdict(int)
        self._bytes_total:      int         = 0
        self._packets_total:    int         = 0
        self._alerts_total:     int         = 0

        # Timeline: {minute_key: {"packets": N, "alerts": N, "bytes": N}}
        self._timeline:         dict        = {}

        # Per-IP port sets (for anomaly scoring)
        self._ip_ports:         defaultdict = defaultdict(set)

        # Rolling threat indicators (last 100 packets)
        self._threat_indicators: deque      = deque(maxlen=100)

    # ── Public API ────────────────────────────────────────────────────────────

    def update(self, pkt: dict):
        """Ingest one packet and update all counters."""
        self._protocol_counts[pkt["protocol"]] += 1
        self._src_ip_counts[pkt["src_ip"]]     += 1
        self._dst_ip_counts[pkt["dst_ip"]]     += 1
        self._bytes_total  += pkt["size"]
        self._packets_total += 1
        self._ip_ports[pkt["src_ip"]].add(pkt["dst_port"])

        # Timeline bucket (round to current minute)
        bucket = datetime.now().strftime("%H:%M")
        if bucket not in self._timeline:
            self._timeline[bucket] = {"packets": 0, "alerts": 0, "bytes": 0}
        self._timeline[bucket]["packets"] += 1
        self._timeline[bucket]["bytes"]   += pkt["size"]

        # Lightweight threat indicator: SYN-heavy or ICMP traffic
        if pkt.get("flags") == "SYN" or pkt["protocol"] == "ICMP":
            self._threat_indicators.append(1)
        else:
            self._threat_indicators.append(0)

    def register_alert(self, src_ip: str):
        """Called by the logger when a new alert is logged."""
        self._alert_ip_counts[src_ip] += 1
        self._alerts_total += 1
        bucket = datetime.now().strftime("%H:%M")
        if bucket in self._timeline:
            self._timeline[bucket]["alerts"] += 1

    def compute_threat_score(self) -> int:
        """
        Compute a 0-100 network-wide threat score.

        Formula:
          - 40% weight: ratio of threat-indicator packets to total
          - 30% weight: number of unique suspicious IPs (capped)
          - 30% weight: alert density in the last minute
        """
        if not self._threat_indicators:
            return random.randint(5, 15)  # baseline idle noise

        # Component 1: threat-indicator packet ratio
        indicator_ratio = sum(self._threat_indicators) / len(self._threat_indicators)
        c1 = indicator_ratio * 40

        # Component 2: unique suspicious IPs (> 5 ports scanned)
        suspicious_ips = sum(
            1 for ip, ports in self._ip_ports.items() if len(ports) > 5
        )
        c2 = min(30, suspicious_ips * 3)

        # Component 3: alert density
        bucket = datetime.now().strftime("%H:%M")
        recent_alerts = self._timeline.get(bucket, {}).get("alerts", 0)
        c3 = min(30, recent_alerts * 2)

        score = int(c1 + c2 + c3)
        return max(1, min(100, score))

    def get_summary(self) -> dict:
        """Return a full analytics summary for the dashboard."""
        return {
            "total_packets":   self._packets_total,
            "total_bytes":     self._bytes_total,
            "total_alerts":    self._alerts_total,
            "protocols":       dict(self._protocol_counts),
            "top_sources":     self._top_n(self._src_ip_counts, 5),
            "top_destinations": self._top_n(self._dst_ip_counts, 5),
            "bandwidth_mbps":  round(self._bytes_total / 1_048_576, 2),
        }

    def get_protocol_stats(self) -> dict:
        """Return protocol distribution as a list of {protocol, count, pct}."""
        total = sum(self._protocol_counts.values()) or 1
        return [
            {
                "protocol": proto,
                "count":    count,
                "pct":      round(count / total * 100, 1),
            }
            for proto, count in sorted(
                self._protocol_counts.items(),
                key=lambda x: x[1], reverse=True
            )
        ]

    def get_top_ips(self, n: int = 10) -> list[dict]:
        """Return top N suspicious IPs by alert count."""
        sorted_ips = sorted(
            self._alert_ip_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:n]
        results = []
        for ip, count in sorted_ips:
            port_count = len(self._ip_ports.get(ip, set()))
            score = min(100, count * 12 + port_count * 2)
            results.append({
                "ip":          ip,
                "alert_count": count,
                "ports_hit":   port_count,
                "risk_score":  score,
                "severity":    "CRITICAL" if score >= 80 else
                               "HIGH"     if score >= 60 else
                               "MEDIUM"   if score >= 40 else "LOW",
            })
        return results

    def get_timeline(self) -> list[dict]:
        """
        Return the last TIMELINE_BUCKETS minutes of traffic data,
        filling gaps with zeros so charts render smoothly.
        """
        # Build full range for the last N minutes
        now    = datetime.now()
        result = []
        for i in range(self.TIMELINE_BUCKETS - 1, -1, -1):
            bucket = (now - timedelta(minutes=i)).strftime("%H:%M")
            data   = self._timeline.get(bucket, {})
            result.append({
                "time":    bucket,
                "packets": data.get("packets", 0),
                "alerts":  data.get("alerts", 0),
                "bytes":   data.get("bytes", 0),
            })
        return result

    # ── Internal Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _top_n(counter: defaultdict, n: int) -> list[dict]:
        return [
            {"ip": ip, "count": count}
            for ip, count in sorted(
                counter.items(), key=lambda x: x[1], reverse=True
            )[:n]
        ]
