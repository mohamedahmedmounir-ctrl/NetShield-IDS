"""
detector/packet_sniffer.py
===========================
Packet Sniffer Module
---------------------
In a real deployment this module uses Scapy to capture raw
network frames from a live interface (requires root/admin).

For portfolio / demo mode it includes a built-in traffic
simulator that generates realistic-looking packets without
needing elevated privileges — so the project runs anywhere.

How Packet Sniffing Works
--------------------------
1. A raw socket is opened on a network interface.
2. Every frame arriving at that interface is passed to a
   callback function before the OS hands it to the normal
   TCP/IP stack.
3. We parse the Ethernet / IP / TCP / UDP headers to extract
   metadata (src IP, dst IP, ports, protocol, size).
4. That metadata is fed into the detection pipeline.

Scapy Usage (real mode, needs root):
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    sniff(iface="eth0", prn=packet_callback, store=False)
"""

import random
import time
from datetime import datetime

# ── Realistic test data pools ─────────────────────────────────────────────────

INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30",
    "192.168.1.50", "10.0.0.5",    "10.0.0.12",
]

EXTERNAL_IPS = [
    "45.33.32.156",   "185.220.101.47", "194.165.16.11",
    "103.79.78.20",   "91.108.4.1",     "198.54.117.12",
    "162.243.144.82", "104.21.60.230",  "5.188.206.14",
    "77.88.55.70",    "134.209.24.11",  "46.101.7.99",
    "2.56.57.1",      "185.130.5.1",    "91.193.75.201",
]

PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "FTP", "SSH"]

# Common ports mapped to service names
PORT_SERVICES = {
    22:   "SSH",    23:   "Telnet",  25:   "SMTP",
    53:   "DNS",    80:   "HTTP",    443:  "HTTPS",
    3306: "MySQL",  3389: "RDP",     8080: "HTTP-Alt",
    21:   "FTP",    110:  "POP3",    143:  "IMAP",
    6379: "Redis",  27017:"MongoDB", 5432: "PostgreSQL",
    1433: "MSSQL",  8443: "HTTPS-Alt",
}

# Ports associated with common scanning / attack patterns
SCAN_PORTS   = [22, 23, 80, 443, 3389, 8080, 21, 25, 110, 3306, 5432, 8443]
RANDOM_PORTS = list(range(1024, 9999))


class PacketSniffer:
    """
    Manages packet capture (real or simulated).

    Attributes
    ----------
    mode : str
        "live" for real Scapy capture, "simulate" for demo mode.
    interface : str
        Network interface name (live mode only).
    """

    def __init__(self, mode: str = "simulate", interface: str = "eth0"):
        self.mode      = mode
        self.interface = interface
        self._pkt_id   = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def simulate_packets(self, count: int = 10) -> list[dict]:
        """
        Generate `count` simulated network packets.

        Each packet is a dict containing the fields that the
        detection engine expects:
            src_ip, dst_ip, protocol, src_port, dst_port,
            size, timestamp, flags, service, direction
        """
        packets = []
        for _ in range(count):
            pkt = self._make_packet()
            packets.append(pkt)
        return packets

    def warm_up(self, logger, traffic_anal, rule_engine, anomaly_det, state):
        """
        Inject ~120 seconds of synthetic history so the dashboard
        charts have data immediately on first load.
        """
        for _ in range(300):
            pkt = self._make_packet(backdate_seconds=random.randint(0, 120))
            state["packets_captured"] += 1
            alert = rule_engine.analyze(pkt)
            if alert:
                alert["id"] = logger.generate_id()
                logger.log_alert(alert)
                state["threats_detected"] += 1
            a2 = anomaly_det.analyze(pkt)
            if a2:
                a2["id"] = logger.generate_id()
                logger.log_alert(a2)
                state["threats_detected"] += 1
            traffic_anal.update(pkt)
            logger.log_packet(pkt)

    # ── Real Scapy Capture (requires root) ───────────────────────────────────

    def capture(self, callback):
        """
        Start live packet capture using Scapy.
        Requires root / administrator privileges.

        Usage
        -----
        sniffer.capture(callback=my_handler)

        The callback receives one dict per packet (same schema
        as simulate_packets output).
        """
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP

            def _scapy_handler(raw_pkt):
                parsed = self._parse_scapy(raw_pkt)
                if parsed:
                    callback(parsed)

            sniff(
                iface=self.interface,
                prn=_scapy_handler,
                store=False,
                filter="ip"
            )
        except ImportError:
            raise RuntimeError(
                "Scapy not installed. Run: pip install scapy\n"
                "Also requires root/admin privileges."
            )

    # ── Internal Helpers ──────────────────────────────────────────────────────

    def _next_id(self) -> int:
        self._pkt_id += 1
        return self._pkt_id

    def _make_packet(self, backdate_seconds: int = 0) -> dict:
        """Build one simulated packet dict."""
        # Decide direction
        if random.random() < 0.6:
            src_ip = random.choice(INTERNAL_IPS)
            dst_ip = random.choice(EXTERNAL_IPS)
            direction = "outbound"
        else:
            src_ip = random.choice(EXTERNAL_IPS)
            dst_ip = random.choice(INTERNAL_IPS)
            direction = "inbound"

        # Protocol selection (weighted)
        protocol = random.choices(
            PROTOCOLS,
            weights=[25, 15, 8, 20, 20, 7, 3, 2],
            k=1
        )[0]

        # Port selection
        if random.random() < 0.4:
            dst_port = random.choice(SCAN_PORTS)
        else:
            dst_port = random.choice(list(PORT_SERVICES.keys()))
        src_port = random.randint(1024, 65535)

        service = PORT_SERVICES.get(dst_port, "Unknown")

        # Packet size
        if protocol == "ICMP":
            size = random.randint(28, 84)
        elif protocol in ("HTTP", "HTTPS"):
            size = random.randint(200, 1500)
        else:
            size = random.randint(40, 1460)

        # TCP flags (only relevant for TCP)
        flags = ""
        if protocol == "TCP":
            flags = random.choice(["SYN", "SYN-ACK", "ACK", "FIN", "RST",
                                   "SYN", "SYN", "ACK", "ACK"])

        ts = datetime.now()
        if backdate_seconds:
            from datetime import timedelta
            ts = ts - timedelta(seconds=backdate_seconds)

        return {
            "id":        self._next_id(),
            "timestamp": ts.isoformat(timespec="seconds"),
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "src_port":  src_port,
            "dst_port":  dst_port,
            "protocol":  protocol,
            "size":      size,
            "flags":     flags,
            "service":   service,
            "direction": direction,
            "ttl":       random.randint(48, 128),
        }

    def _parse_scapy(self, raw_pkt) -> dict | None:
        """Parse a real Scapy packet into our standard dict format."""
        try:
            from scapy.all import IP, TCP, UDP, ICMP
            if not raw_pkt.haslayer(IP):
                return None

            ip  = raw_pkt[IP]
            pkt = {
                "id":        self._next_id(),
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "src_ip":    ip.src,
                "dst_ip":    ip.dst,
                "src_port":  0,
                "dst_port":  0,
                "protocol":  "IP",
                "size":      len(raw_pkt),
                "flags":     "",
                "ttl":       ip.ttl,
                "service":   "Unknown",
                "direction": "inbound",
            }

            if raw_pkt.haslayer(TCP):
                tcp = raw_pkt[TCP]
                pkt.update({
                    "protocol": "TCP",
                    "src_port": tcp.sport,
                    "dst_port": tcp.dport,
                    "flags":    str(tcp.flags),
                    "service":  PORT_SERVICES.get(tcp.dport, "Unknown"),
                })
            elif raw_pkt.haslayer(UDP):
                udp = raw_pkt[UDP]
                pkt.update({
                    "protocol": "UDP",
                    "src_port": udp.sport,
                    "dst_port": udp.dport,
                    "service":  PORT_SERVICES.get(udp.dport, "Unknown"),
                })
            elif raw_pkt.haslayer(ICMP):
                pkt["protocol"] = "ICMP"

            return pkt
        except Exception:
            return None
