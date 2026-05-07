"""
utils/config.py
================
Centralised configuration for NetShield IDS.
All tunable parameters live here to avoid hard-coding.
"""

import os


class Config:
    """Application-wide settings."""

    # -- Flask --
    DEBUG         = os.getenv("IDS_DEBUG", "true").lower() == "true"
    HOST          = os.getenv("IDS_HOST", "0.0.0.0")
    PORT          = int(os.getenv("IDS_PORT", "5000"))
    SECRET_KEY    = os.getenv("IDS_SECRET", "netshield-dev-secret")

    # -- Monitoring --
    INTERFACE     = os.getenv("IDS_IFACE", "\\Device\\NPF_{BEF42E0E-A88C-4696-B408-05426B222047}")
    SIMULATE_MODE = False   # Real Scapy capture enabled
    PACKETS_PER_SECOND = 15

    # -- Detection Thresholds --
    PORT_SCAN_THRESHOLD   = 15
    SYN_FLOOD_THRESHOLD   = 20
    ICMP_FLOOD_THRESHOLD  = 30
    BRUTE_FORCE_THRESHOLD = 8
    EXFIL_SIZE_THRESHOLD  = 1200

    # -- Logging --
    MAX_PACKET_LOG = 500
    MAX_ALERT_LOG  = 1000

    # -- Dashboard --
    REFRESH_INTERVAL_MS = 2000


