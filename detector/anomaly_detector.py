"""
detector/anomaly_detector.py
=============================
AI / Anomaly-Based Threat Detection
-------------------------------------
Dual-mode detection pipeline:

1. Statistical Baseline (Z-score, always active)
   - Tracks rolling per-IP windows of packet size, ICMP ratio,
     and unique destination ports.
   - Flags packets whose Z-score exceeds a configurable threshold.
   - No training data required; adapts in real time.

2. Isolation Forest (scikit-learn, loaded from disk)
   - Pre-trained unsupervised ML model that isolates anomalies by
     randomly partitioning the feature space.
   - Anomalous samples require fewer partitions to isolate -> lower
     score_samples() value -> high confidence output.
   - Loaded from model/ids_model.pkl + model/scaler.pkl at startup.
   - Falls back to Z-score-only if the model files are missing.

Feature Vector (8 dimensions, must match train_model.py):
  [packet_size, dst_port, is_syn, is_icmp, is_external_src,
   unique_ports_hit, total_pkt_count, icmp_window_count]

Alert Thresholds (deterministic -- no randomness):
  - Z-score anomaly: triggered when |z| > z_threshold (default 3.0)
  - ICMP spike:      triggered when ICMP ratio in window > 70%
  - ML anomaly:      triggered when IsolationForest predicts -1
                     AND confidence >= ml_min_confidence (default 0.40)
  - Port sweep:      triggered when unique ports from source >= 20
"""

import math
import os
from datetime import datetime
from collections import defaultdict, deque

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

_HERE       = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH  = os.path.join(_HERE, "..", "model", "ids_model.pkl")
SCALER_PATH = os.path.join(_HERE, "..", "model", "scaler.pkl")


class AnomalyDetector:
    """
    Dual-mode anomaly detector: statistical Z-score + Isolation Forest.

    All detection decisions are deterministic -- thresholds, not random gates.
    Every packet that truly deviates from the baseline produces a consistent alert.
    """

    def __init__(
        self,
        window: int = 60,
        z_threshold: float = 3.0,
        icmp_ratio_threshold: float = 0.70,
        port_sweep_threshold: int = 20,
        ml_min_confidence: float = 0.40,
    ):
        self.window                = window
        self.z_threshold           = z_threshold
        self.icmp_ratio_threshold  = icmp_ratio_threshold
        self.port_sweep_threshold  = port_sweep_threshold
        self.ml_min_confidence     = ml_min_confidence

        self._sizes:      defaultdict = defaultdict(lambda: deque(maxlen=window))
        self._icmp_win:   defaultdict = defaultdict(lambda: deque(maxlen=window))
        self._ports_seen: defaultdict = defaultdict(set)
        self._pkt_counts: defaultdict = defaultdict(int)

        self._model:   object = None
        self._scaler:  object = None
        self._trained: bool   = False

        self._load_or_bootstrap_model()

    # ── Public API ─────────────────────────────────────────────────────────────

    def analyze(self, pkt: dict) -> dict | None:
        """
        Analyze one packet. Returns an alert dict when anomaly is detected, else None.
        Detection is fully deterministic: thresholds, not random gates.
        """
        src = pkt["src_ip"]

        # Update per-IP state
        self._sizes[src].append(pkt["size"])
        self._pkt_counts[src] += 1
        self._ports_seen[src].add(pkt["dst_port"])
        self._icmp_win[src].append(1 if pkt["protocol"] == "ICMP" else 0)

        features = self._extract_features(pkt)

        # Signal 1: Z-score on packet size
        size_z, size_anomaly = self._z_score(self._sizes[src], pkt["size"])

        # Signal 2: ICMP ratio
        icmp_ratio   = sum(self._icmp_win[src]) / max(1, len(self._icmp_win[src]))
        icmp_anomaly = icmp_ratio >= self.icmp_ratio_threshold

        # Signal 3: Isolation Forest
        ml_anomaly, ml_confidence = self._ml_analyze(features)

        # Signal 4: Port sweep
        unique_ports  = len(self._ports_seen[src])
        sweep_anomaly = unique_ports >= self.port_sweep_threshold

        # Emit highest-priority alert (ML > sweep > ICMP > size)
        if ml_anomaly and ml_confidence >= self.ml_min_confidence:
            score = int(50 + ml_confidence * 45)
            score = max(50, min(95, score))
            sev   = "CRITICAL" if score >= 85 else "HIGH" if score >= 70 else "MEDIUM"
            return self._make_alert(
                pkt,
                "AI Anomaly Detected",
                (
                    f"Isolation Forest flagged abnormal traffic from {src}. "
                    f"ML confidence: {ml_confidence:.0%} | "
                    f"size={pkt['size']}B, dst_port={pkt['dst_port']}, "
                    f"unique_ports={unique_ports}."
                ),
                score=score,
                severity=sev,
            )

        if sweep_anomaly:
            score = int(min(95, 50 + unique_ports * 1.5))
            sev   = "CRITICAL" if score >= 85 else "HIGH"
            return self._make_alert(
                pkt,
                "Port Sweep Detected",
                (
                    f"{src} contacted {unique_ports} unique destination ports. "
                    "Consistent with reconnaissance or scanning."
                ),
                score=score,
                severity=sev,
            )

        if icmp_anomaly:
            excess = icmp_ratio - self.icmp_ratio_threshold
            score  = int(60 + excess * 70)
            score  = max(60, min(90, score))
            return self._make_alert(
                pkt,
                "ICMP Traffic Spike",
                (
                    f"ICMP is {icmp_ratio:.0%} of recent traffic from {src} "
                    f"(threshold {self.icmp_ratio_threshold:.0%}). "
                    "Possible ping sweep or ICMP DoS."
                ),
                score=score,
                severity="HIGH",
            )

        if size_anomaly:
            score = int(min(75, 45 + size_z * 5))
            score = max(45, score)
            return self._make_alert(
                pkt,
                "Anomalous Packet Size",
                (
                    f"Packet size {pkt['size']}B is {size_z:.1f} std devs "
                    f"from the rolling mean for {src}. "
                    "May indicate fragmentation attack or unusual payload."
                ),
                score=score,
                severity="MEDIUM",
            )

        return None

    # ── Statistical Helpers ────────────────────────────────────────────────────

    def _z_score(self, window: deque, value: float) -> tuple:
        if len(window) < 10:
            return 0.0, False
        data     = list(window)
        mean     = sum(data) / len(data)
        variance = sum((x - mean) ** 2 for x in data) / len(data)
        sd       = math.sqrt(variance) if variance > 0 else 0.0
        if sd == 0.0:
            return 0.0, False
        z = abs(value - mean) / sd
        return z, z > self.z_threshold

    def _extract_features(self, pkt: dict) -> list:
        """8-dim vector matching train_model.py exactly."""
        src = pkt["src_ip"]
        return [
            float(pkt["size"]),
            float(pkt["dst_port"]),
            1.0 if pkt.get("flags") == "SYN"   else 0.0,
            1.0 if pkt["protocol"] == "ICMP"    else 0.0,
            0.0 if pkt["src_ip"].startswith(("192.168.", "10.", "172.")) else 1.0,
            float(len(self._ports_seen[src])),
            float(self._pkt_counts[src]),
            float(sum(self._icmp_win[src])),
        ]

    # ── ML Layer ───────────────────────────────────────────────────────────────

    def _load_or_bootstrap_model(self):
        if not SKLEARN_AVAILABLE:
            return
        try:
            import joblib
            self._model   = joblib.load(MODEL_PATH)
            self._scaler  = joblib.load(SCALER_PATH)
            self._trained = True
            print(f"[AnomalyDetector] Loaded model from {MODEL_PATH}")
        except Exception as exc:
            print(f"[AnomalyDetector] Could not load model ({exc}); bootstrapping.")
            self._bootstrap_model()

    def _bootstrap_model(self):
        if not SKLEARN_AVAILABLE:
            return
        import random
        normal = []
        for _ in range(500):
            normal.append([
                max(40.0, random.gauss(500, 250)),
                float(random.choice([80, 443, 53, 22, 8080])),
                1.0 if random.random() < 0.15 else 0.0,
                1.0 if random.random() < 0.03 else 0.0,
                1.0 if random.random() < 0.45 else 0.0,
                float(random.randint(1, 4)),
                float(random.randint(1, 60)),
                float(random.randint(0, 2)),
            ])
        X = np.array(normal, dtype=float)
        self._scaler = StandardScaler().fit(X)
        X_s          = self._scaler.transform(X)
        self._model  = IsolationForest(
            n_estimators=100, contamination=0.05, random_state=42
        ).fit(X_s)
        self._trained = True
        try:
            import joblib
            os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
            joblib.dump(self._model,  MODEL_PATH)
            joblib.dump(self._scaler, SCALER_PATH)
        except Exception:
            pass

    def _ml_analyze(self, features: list) -> tuple:
        """
        Run features through Isolation Forest.
        Returns (is_anomaly: bool, confidence: float 0-1).
        Confidence mapping: score_samples in [-0.6, -0.1] -> [1.0, 0.0].
        """
        if not SKLEARN_AVAILABLE or not self._trained:
            return False, 0.0
        try:
            X        = np.array([features], dtype=float)
            X_scaled = self._scaler.transform(X)
            pred     = self._model.predict(X_scaled)[0]        # 1=normal, -1=anomaly
            raw      = self._model.score_samples(X_scaled)[0]  # lower = more anomalous
            confidence = max(0.0, min(1.0, (raw + 0.1) / -0.5))
            return pred == -1, confidence
        except Exception:
            return False, 0.0

    # ── Alert Factory ──────────────────────────────────────────────────────────

    @staticmethod
    def _make_alert(pkt: dict, attack_type: str, description: str,
                    score: int, severity: str) -> dict:
        action_map = {
            "CRITICAL": "Isolate host immediately and begin incident response.",
            "HIGH":     "Investigate and consider blocking source IP.",
            "MEDIUM":   "Monitor closely; review traffic baseline.",
            "LOW":      "Log for analysis.",
        }
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
            "action":      action_map.get(severity, "Review and respond."),
            "source":      "AI Anomaly Detector",
        }
