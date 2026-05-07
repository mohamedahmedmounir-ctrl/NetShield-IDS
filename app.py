"""
NetShield IDS - Main Application Entry Point
=============================================
A Smart Intrusion Detection System built with Flask.
Monitors network traffic, detects threats, and provides
a real-time cybersecurity dashboard.

Author: NetShield IDS
Version: 1.0.0
"""

import os
import json
import time
import threading
import random
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, Response
from collections import defaultdict

# Import our custom modules
from detector.packet_sniffer import PacketSniffer
from detector.threat_rules import ThreatRuleEngine
from detector.anomaly_detector import AnomalyDetector
from detector.traffic_analyzer import TrafficAnalyzer
from utils.logger import IDSLogger
from utils.config import Config
from utils.helpers import format_bytes, get_severity_color

# ── Flask App Initialization ──────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()

# ── Global System Components ──────────────────────────────────────────────────
config       = Config()
ids_logger   = IDSLogger()
sniffer      = PacketSniffer(
    mode      = "simulate" if config.SIMULATE_MODE else "live",
    interface = config.INTERFACE,
)
rule_engine  = ThreatRuleEngine()
anomaly_det  = AnomalyDetector()
traffic_anal = TrafficAnalyzer()

# Live state shared between threads
system_state = {
    "monitoring":       False,
    "packets_captured": 0,
    "threats_detected": 0,
    "start_time":       None,
    "interface":        "Simulated" if config.SIMULATE_MODE else config.INTERFACE,
}


# ── Shared packet handler (used by both live and simulate modes) ──────────────

def _process_packet(pkt: dict):
    """Run one packet through the full detection + logging pipeline."""
    system_state["packets_captured"] += 1

    # 1. Rule-based detection
    rule_alert = rule_engine.analyze(pkt)
    if rule_alert:
        rule_alert["id"] = ids_logger.generate_id()
        ids_logger.log_alert(rule_alert)
        traffic_anal.register_alert(pkt["src_ip"])
        system_state["threats_detected"] += 1

    # 2. ML / anomaly detection
    anomaly_alert = anomaly_det.analyze(pkt)
    if anomaly_alert:
        anomaly_alert["id"] = ids_logger.generate_id()
        ids_logger.log_alert(anomaly_alert)
        traffic_anal.register_alert(pkt["src_ip"])
        system_state["threats_detected"] += 1

    # 3. Traffic analytics
    traffic_anal.update(pkt)

    # 4. Raw packet log (capped at MAX_PACKET_LOG)
    ids_logger.log_packet(pkt)


# ── Background Monitoring Thread ──────────────────────────────────────────────

def monitoring_loop():
    """
    Starts packet capture in the appropriate mode:
      - SIMULATE_MODE=True  → generates synthetic packets internally
      - SIMULATE_MODE=False → calls Scapy sniff() on the real interface
    """
    if config.SIMULATE_MODE:
        # ── Simulation mode ───────────────────────────────────────────────────
        while system_state["monitoring"]:
            packets = sniffer.simulate_packets(count=random.randint(5, 25))
            for pkt in packets:
                _process_packet(pkt)
            time.sleep(1)

    else:
        # ── Live capture mode ─────────────────────────────────────────────────
        print(f"[NetShield] Starting live capture on {config.INTERFACE}")
        try:
            sniffer.capture(callback=_process_packet)
        except RuntimeError as e:
            # Scapy not installed or no admin privileges
            print(f"[ERROR] Live capture failed: {e}")
            print("[NetShield] Falling back to simulation mode.")
            config.SIMULATE_MODE = True
            system_state["interface"] = "Simulated (fallback)"
            # Restart in simulate mode
            while system_state["monitoring"]:
                packets = sniffer.simulate_packets(count=random.randint(5, 25))
                for pkt in packets:
                    _process_packet(pkt)
                time.sleep(1)
        except Exception as e:
            print(f"[ERROR] Unexpected capture error: {e}")
            system_state["monitoring"] = False


# ── Flask Routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main dashboard."""
    return render_template("index.html", config=config)


# ---------- System Control ----------

@app.route("/api/start", methods=["POST"])
def start_monitoring():
    """Start the IDS monitoring engine."""
    if not system_state["monitoring"]:
        system_state["monitoring"] = True
        system_state["start_time"] = datetime.now().isoformat()
        t = threading.Thread(target=monitoring_loop, daemon=True)
        t.start()
        mode = "simulation" if config.SIMULATE_MODE else f"live ({config.INTERFACE})"
        return jsonify({"status": "started", "message": f"IDS monitoring started in {mode} mode"})
    return jsonify({"status": "already_running", "message": "IDS already running"})


@app.route("/api/stop", methods=["POST"])
def stop_monitoring():
    """Stop the IDS monitoring engine."""
    system_state["monitoring"] = False
    return jsonify({"status": "stopped", "message": "IDS monitoring stopped"})


@app.route("/api/status")
def get_status():
    """Return current system status and high-level counters."""
    uptime = "N/A"
    if system_state["start_time"]:
        start = datetime.fromisoformat(system_state["start_time"])
        delta = datetime.now() - start
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        uptime = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    return jsonify({
        "monitoring":       system_state["monitoring"],
        "packets_captured": system_state["packets_captured"],
        "threats_detected": system_state["threats_detected"],
        "uptime":           uptime,
        "interface":        system_state["interface"],
        "start_time":       system_state["start_time"],
        "mode":             "simulation" if config.SIMULATE_MODE else "live",
    })


# ---------- Live Data Feeds ----------

@app.route("/api/packets")
def get_packets():
    """Return the most recent captured packets."""
    limit = int(request.args.get("limit", 50))
    packets = ids_logger.get_recent_packets(limit)
    return jsonify({"packets": packets, "total": system_state["packets_captured"]})


@app.route("/api/alerts")
def get_alerts():
    """Return alerts, optionally filtered by severity or search term."""
    limit    = int(request.args.get("limit", 100))
    severity = request.args.get("severity", "")
    search   = request.args.get("search", "")
    alerts   = ids_logger.get_alerts(limit=limit, severity=severity, search=search)
    return jsonify({"alerts": alerts, "total": system_state["threats_detected"]})


@app.route("/api/analytics")
def get_analytics():
    """Return aggregated traffic analytics for dashboard charts."""
    return jsonify(traffic_anal.get_summary())


@app.route("/api/top-ips")
def get_top_ips():
    """Return the top suspicious IP addresses by alert count."""
    return jsonify({"top_ips": traffic_anal.get_top_ips(10)})


@app.route("/api/threat-score")
def get_threat_score():
    """Return the current network-wide threat score (0-100)."""
    score = traffic_anal.compute_threat_score()
    level = ("CRITICAL" if score >= 80 else
             "HIGH"     if score >= 60 else
             "MEDIUM"   if score >= 40 else "LOW")
    return jsonify({"score": score, "level": level,
                    "color": get_severity_color(level)})


# ---------- Manual Packet Injection (for testing/demo) ----------

@app.route("/api/inject", methods=["POST"])
def inject_packets():
    """
    Manually inject crafted packets into the detection pipeline.
    Useful for testing alert rules without real attack traffic.

    POST body: {"packets": [ {packet dict}, ... ]}
    """
    data    = request.get_json(force=True)
    packets = data.get("packets", [])
    injected = 0
    for pkt in packets:
        pkt.setdefault("id",        system_state["packets_captured"] + injected + 1)
        pkt.setdefault("timestamp", datetime.now().isoformat(timespec="seconds"))
        pkt.setdefault("flags",     "")
        pkt.setdefault("service",   "Unknown")
        pkt.setdefault("direction", "inbound")
        pkt.setdefault("ttl",       64)
        _process_packet(pkt)
        injected += 1
    return jsonify({"injected": injected,
                    "threats_triggered": system_state["threats_detected"]})


# ---------- Log Management ----------

@app.route("/api/logs/export")
def export_logs():
    """Export all logs as a JSON file download."""
    data = {
        "exported_at": datetime.now().isoformat(),
        "system":      system_state,
        "alerts":      ids_logger.get_alerts(limit=10000),
        "packets":     ids_logger.get_recent_packets(1000),
    }
    return Response(
        json.dumps(data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=netshield_export.json"}
    )


@app.route("/api/logs/clear", methods=["POST"])
def clear_logs():
    """Clear all in-memory logs (does not touch disk files)."""
    ids_logger.clear()
    system_state["packets_captured"] = 0
    system_state["threats_detected"] = 0
    traffic_anal.reset()
    return jsonify({"status": "cleared"})


# ---------- Charts & Stats ----------

@app.route("/api/protocol-stats")
def protocol_stats():
    return jsonify(traffic_anal.get_protocol_stats())


@app.route("/api/timeline")
def timeline():
    """Return per-minute packet / alert counts for the timeline chart."""
    return jsonify(traffic_anal.get_timeline())


# ── Main Entry Point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    mode_label = "SIMULATION" if config.SIMULATE_MODE else f"LIVE  ({config.INTERFACE})"
    print(f"""
╔══════════════════════════════════════════════════╗
║          NetShield IDS  v1.0.0                   ║
║   Smart Intrusion Detection System               ║
║   Mode      → {mode_label:<34}║
║   Dashboard → http://127.0.0.1:5000              ║
╚══════════════════════════════════════════════════╝
    """)

    # Wire traffic analyzer into logger for alert-IP tracking
    ids_logger.set_traffic_analyzer(traffic_anal)

    # Seed demo data only in simulation mode (live mode starts empty)
    if config.SIMULATE_MODE:
        sniffer.warm_up(ids_logger, traffic_anal, rule_engine, anomaly_det, system_state)

    app.run(debug=config.DEBUG, host=config.HOST, port=config.PORT, use_reloader=False)
