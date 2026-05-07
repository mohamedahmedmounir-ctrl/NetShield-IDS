"""
detector/threat_rules.py
=========================
Rule-Based Threat Detection Engine
------------------------------------
How Intrusion Detection Works (Rule-Based)
-------------------------------------------
Each incoming packet is tested against a set of deterministic
rules. When a rule fires, it produces an alert dict that is
forwarded to the logger and displayed on the dashboard.

Rule categories implemented here:
  1. Port Scan Detection   – many SYN packets to different ports
  2. Brute-Force Detection – repeated SSH/RDP/FTP connections
  3. ICMP Flood Detection  – high volume of ICMP from one source
  4. Suspicious Port Access – access to sensitive service ports
  5. Data Exfiltration     – unusually large outbound packets
  6. Known Bad IPs         – static block-list of malicious CIDRs
  7. Telnet / Cleartext    – insecure protocol usage

Threat Scoring
--------------
Each rule assigns a numeric severity score (0–100).
  90-100 → CRITICAL
  70- 89 → HIGH
  40- 69 → MEDIUM
  10- 39 → LOW
"""

from datetime import datetime
from collections import defaultdict


# ── Static Block-List (sample known-bad IP prefixes) ─────────────────────────
KNOWN_BAD_IPS = {
    "185.220.101.",  # Tor exit nodes
    "45.33.32.",     # Known scanner
    "194.165.16.",   # Malware C2
    "103.79.78.",    # Botnet
    "2.56.57.",      # Phishing host
    "91.193.75.",    # Ransomware C2
}

# Ports that should never be externally accessible
SENSITIVE_PORTS = {
    22:    ("SSH",        70, "Verify SSH access policy"),
    23:    ("Telnet",     85, "Block Telnet — cleartext protocol"),
    3306:  ("MySQL",      80, "Database exposed — restrict access"),
    5432:  ("PostgreSQL", 80, "Database exposed — restrict access"),
    3389:  ("RDP",        75, "RDP exposed — high bruteforce risk"),
    27017: ("MongoDB",    82, "MongoDB exposed — check auth settings"),
    6379:  ("Redis",      80, "Redis exposed — often unauthenticated"),
    1433:  ("MSSQL",      80, "MSSQL exposed — restrict to LAN"),
}


class ThreatRuleEngine:
    """
    Stateful rule engine.

    Internal counters per source IP allow the engine to detect
    multi-packet attack patterns like port scanning or brute force.
    """

    def __init__(self):
        # Per-IP counters (reset periodically in production)
        self._syn_counts:   defaultdict = defaultdict(int)   # SYN packets per src
        self._icmp_counts:  defaultdict = defaultdict(int)   # ICMP per src
        self._port_history: defaultdict = defaultdict(set)   # dst ports per src
        self._conn_fails:   defaultdict = defaultdict(int)   # RST/failed per src
        self._alert_ids = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, pkt: dict) -> dict | None:
        """
        Run all rules against a single packet.

        Returns an alert dict if any rule fires, else None.
        Only the highest-severity matching rule is returned per packet.
        """
        alerts = []

        # Update state counters
        self._update_state(pkt)

        # Run each rule
        checks = [
            self._rule_known_bad_ip,
            self._rule_port_scan,
            self._rule_brute_force,
            self._rule_icmp_flood,
            self._rule_sensitive_port,
            self._rule_data_exfiltration,
            self._rule_cleartext_protocol,
        ]
        for rule in checks:
            alert = rule(pkt)
            if alert:
                alerts.append(alert)

        if not alerts:
            return None

        # Return the highest-severity alert
        return max(alerts, key=lambda a: a["score"])

    # ── State Update ──────────────────────────────────────────────────────────

    def _update_state(self, pkt: dict):
        src = pkt["src_ip"]
        if pkt.get("flags") == "SYN":
            self._syn_counts[src] += 1
            self._port_history[src].add(pkt["dst_port"])
        if pkt["protocol"] == "ICMP":
            self._icmp_counts[src] += 1
        if pkt.get("flags") == "RST":
            self._conn_fails[src] += 1

    # ── Rule Implementations ──────────────────────────────────────────────────

    def _rule_known_bad_ip(self, pkt: dict) -> dict | None:
        """Check source IP against block-list."""
        src = pkt["src_ip"]
        for prefix in KNOWN_BAD_IPS:
            if src.startswith(prefix):
                return self._make_alert(
                    pkt         = pkt,
                    attack_type = "Known Malicious IP",
                    description = f"Traffic from known-bad IP range {prefix}*",
                    score       = 92,
                    severity    = "CRITICAL",
                    action      = "Block source IP immediately and investigate."
                )
        return None

    def _rule_port_scan(self, pkt: dict) -> dict | None:
        """Detect port scanning: many distinct ports probed from one source."""
        src        = pkt["src_ip"]
        port_count = len(self._port_history[src])
        syn_count  = self._syn_counts[src]

        if port_count >= 15 or syn_count >= 20:
            score = min(95, 60 + port_count * 2)
            return self._make_alert(
                pkt         = pkt,
                attack_type = "Port Scan Detected",
                description = (
                    f"Source scanned {port_count} distinct ports "
                    f"({syn_count} SYN packets)."
                ),
                score       = score,
                severity    = "HIGH" if score < 80 else "CRITICAL",
                action      = "Block source IP; review firewall rules."
            )
        return None

    def _rule_brute_force(self, pkt: dict) -> dict | None:
        """Detect brute-force: many RST or failed connections on auth ports."""
        src      = pkt["src_ip"]
        dst_port = pkt["dst_port"]
        fails    = self._conn_fails[src]

        AUTH_PORTS = {22, 23, 3389, 21, 110, 143}
        if dst_port in AUTH_PORTS and fails >= 8:
            service = SENSITIVE_PORTS.get(dst_port, ("", 0, ""))[0] or \
                      pkt.get("service", "Auth Service")
            score = min(90, 55 + fails * 2)
            return self._make_alert(
                pkt         = pkt,
                attack_type = "Brute-Force Attack",
                description = (
                    f"Repeated failed connections to {service} "
                    f"({fails} attempts from {src})."
                ),
                score       = score,
                severity    = "HIGH" if score < 80 else "CRITICAL",
                action      = f"Temporarily ban {src}; enable MFA on {service}."
            )
        return None

    def _rule_icmp_flood(self, pkt: dict) -> dict | None:
        """Detect ICMP flood / ping-of-death style traffic."""
        if pkt["protocol"] != "ICMP":
            return None
        src   = pkt["src_ip"]
        count = self._icmp_counts[src]
        if count >= 30:
            score = min(85, 50 + count)
            return self._make_alert(
                pkt         = pkt,
                attack_type = "ICMP Flood",
                description = f"{count} ICMP packets from {src} — potential DoS.",
                score       = score,
                severity    = "HIGH",
                action      = "Rate-limit ICMP; consider null-routing source."
            )
        return None

    def _rule_sensitive_port(self, pkt: dict) -> dict | None:
        """Alert when external traffic reaches sensitive service ports."""
        dst_port = pkt["dst_port"]
        src      = pkt["src_ip"]
        # Only flag external sources
        if src.startswith(("192.168.", "10.", "172.")):
            return None
        if dst_port in SENSITIVE_PORTS:
            name, base_score, action = SENSITIVE_PORTS[dst_port]
            # Add small jitter so alerts aren't all identical scores
            score = min(95, base_score)
            sev   = "CRITICAL" if score >= 80 else "HIGH"
            return self._make_alert(
                pkt         = pkt,
                attack_type = f"Sensitive Port Access ({name})",
                description = (
                    f"External IP {src} accessed {name} "
                    f"(port {dst_port}) from outside the network."
                ),
                score       = score,
                severity    = sev,
                action      = action
            )
        return None

    def _rule_data_exfiltration(self, pkt: dict) -> dict | None:
        """Flag unusually large outbound packets that may indicate data theft."""
        if pkt["direction"] == "outbound" and pkt["size"] > 1200:
            score = min(78, 45 + int(pkt["size"] / 100))
            return self._make_alert(
                pkt         = pkt,
                attack_type = "Possible Data Exfiltration",
                description = (
                    f"Large outbound packet ({pkt['size']} bytes) "
                    f"to {pkt['dst_ip']}."
                ),
                score       = score,
                severity    = "MEDIUM",
                action      = "Inspect payload; verify destination is authorised."
            )
        return None

    def _rule_cleartext_protocol(self, pkt: dict) -> dict | None:
        """Warn about Telnet or FTP usage (cleartext credentials)."""
        if pkt["dst_port"] in (23, 21) and pkt["protocol"] == "TCP":
            proto = "Telnet" if pkt["dst_port"] == 23 else "FTP"
            return self._make_alert(
                pkt         = pkt,
                attack_type = f"Cleartext Protocol ({proto})",
                description = (
                    f"{proto} used by {pkt['src_ip']} — "
                    "credentials transmitted in plaintext."
                ),
                score       = 60,
                severity    = "MEDIUM",
                action      = f"Replace {proto} with SSH/SFTP immediately."
            )
        return None

    # ── Alert Factory ─────────────────────────────────────────────────────────

    @staticmethod
    def _make_alert(pkt: dict, attack_type: str, description: str,
                    score: int, severity: str, action: str) -> dict:
        """Build a standardised alert dictionary."""
        return {
            "timestamp":   datetime.now().isoformat(timespec="seconds"),
            "src_ip":      pkt["src_ip"],
            "dst_ip":      pkt["dst_ip"],
            "src_port":    pkt.get("src_port", 0),
            "dst_port":    pkt.get("dst_port", 0),
            "protocol":    pkt.get("protocol", "N/A"),
            "attack_type": attack_type,
            "description": description,
            "score":       score,
            "severity":    severity,
            "action":      action,
            "source":      "Rule Engine",
        }
