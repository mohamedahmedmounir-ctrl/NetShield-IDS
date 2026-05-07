"""
model/train_model.py
=====================
NetShield IDS -- ML Training Script
-------------------------------------
Trains an Isolation Forest anomaly detection model and saves it to disk.

Two training modes
------------------
1. SYNTHETIC (default, no dataset required)
   Generates realistic normal and attack traffic feature vectors.
   Good for initial testing. Run with no arguments:
       python model/train_model.py

2. NSL-KDD (recommended for real detection quality)
   Uses the NSL-KDD benchmark IDS dataset.
   Download KDDTrain+.txt from:
       https://www.unb.ca/cic/datasets/nsl.html
   Then run:
       python model/train_model.py --dataset /path/to/KDDTrain+.txt

   NSL-KDD feature mapping
   ------------------------
   The raw NSL-KDD file has 43 columns. We extract 8 that best match
   our live feature vector schema and are available without deep
   packet inspection:
       duration, src_bytes, dst_bytes, land, wrong_fragment,
       urgent, hot, num_failed_logins, logged_in, num_compromised
   These are normalised and mapped to our 8-dim schema as:
       [pkt_size_proxy, dst_port_proxy, is_syn, is_icmp,
        is_external, unique_ports, pkt_count, icmp_count]

Feature Vector Schema (8 dimensions)
--------------------------------------
   0  packet_size        -- bytes
   1  dst_port           -- destination port
   2  is_syn             -- 1 if SYN flag
   3  is_icmp            -- 1 if ICMP
   4  is_external_src    -- 1 if non-RFC-1918
   5  unique_ports_hit   -- distinct ports from this source
   6  total_pkt_count    -- total packets from this source
   7  icmp_window_count  -- ICMP packets in sliding window

Outputs
-------
   model/ids_model.pkl   -- trained IsolationForest (200 trees)
   model/scaler.pkl      -- fitted StandardScaler
"""

import os
import sys
import random
import argparse
import numpy as np

try:
    from sklearn.ensemble      import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics       import classification_report, confusion_matrix
    import joblib
except ImportError:
    print("ERROR: scikit-learn and joblib are required.")
    print("Install: pip install scikit-learn joblib numpy")
    sys.exit(1)

MODEL_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH  = os.path.join(MODEL_DIR, "ids_model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")

# NSL-KDD column names (42 features + label + difficulty)
NSL_COLUMNS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"
]

# NSL-KDD attack labels that map to anomaly
NSL_ATTACK_LABELS = {
    "normal": False,
    # DoS
    "neptune":True,"smurf":True,"pod":True,"teardrop":True,"back":True,
    "land":True,"ipsweep":True,"apache2":True,"mailbomb":True,"processtable":True,
    "udpstorm":True,
    # Probe
    "portsweep":True,"satan":True,"mscan":True,"nmap":True,"saint":True,
    # R2L
    "guess_passwd":True,"ftp_write":True,"imap":True,"phf":True,"multihop":True,
    "warezmaster":True,"warezclient":True,"spy":True,"xlock":True,"xsnoop":True,
    "snmpgetattack":True,"sendmail":True,"named":True,"httptunnel":True,
    "snmpguess":True,"worm":True,
    # U2R
    "buffer_overflow":True,"loadmodule":True,"rootkit":True,"perl":True,
    "sqlattack":True,"xterm":True,"ps":True,
}

# ── Synthetic Data Generation ──────────────────────────────────────────────────

def generate_normal_traffic(n: int = 2000) -> np.ndarray:
    """Realistic normal traffic feature vectors."""
    common_ports = [80, 443, 53, 22, 8080, 25, 110, 143, 3389]
    samples = []
    for _ in range(n):
        samples.append([
            max(40.0, random.gauss(500, 250)),
            float(random.choice(common_ports)),
            1.0 if random.random() < 0.15 else 0.0,
            1.0 if random.random() < 0.03 else 0.0,
            1.0 if random.random() < 0.45 else 0.0,
            float(random.randint(1, 4)),
            float(random.randint(1, 60)),
            float(random.randint(0, 2)),
        ])
    return np.array(samples, dtype=float)


def generate_attack_traffic(n: int = 400) -> np.ndarray:
    """Attack-pattern feature vectors (for evaluation only)."""
    samples = []
    for _ in range(n):
        atype = random.choice(["port_scan", "icmp_flood", "brute_force", "exfil"])
        if atype == "port_scan":
            samples.append([float(random.randint(40, 80)), float(random.randint(1, 65535)),
                             1.0, 0.0, 1.0, float(random.randint(15, 60)),
                             float(random.randint(20, 200)), 0.0])
        elif atype == "icmp_flood":
            samples.append([float(random.randint(28, 84)), 0.0,
                             0.0, 1.0, 1.0, float(random.randint(1, 3)),
                             float(random.randint(30, 500)), float(random.randint(25, 100))])
        elif atype == "brute_force":
            samples.append([float(random.randint(40, 150)),
                             float(random.choice([22, 3389, 21, 23])),
                             1.0, 0.0, 1.0, 1.0, float(random.randint(10, 80)), 0.0])
        else:  # exfil
            samples.append([float(random.randint(1200, 1500)),
                             float(random.choice([443, 80, 8080])),
                             0.0, 0.0, 1.0, float(random.randint(1, 3)),
                             float(random.randint(5, 30)), 0.0])
    return np.array(samples, dtype=float)


# ── NSL-KDD Data Loading ───────────────────────────────────────────────────────

def load_nslkdd(path: str):
    """
    Load NSL-KDD dataset and return (X_normal, X_attack, y_all).
    Maps raw features to our 8-dim schema.
    """
    import pandas as pd

    print(f"  Loading NSL-KDD from {path} ...")
    df = pd.read_csv(path, header=None, names=NSL_COLUMNS)
    df["label_lower"] = df["label"].str.lower().str.strip(".")

    # Map protocol to ICMP flag
    df["is_icmp"]     = (df["protocol_type"].str.lower() == "icmp").astype(float)

    # Proxy: use src_bytes as packet_size proxy, clip at 1500
    df["pkt_size"]    = df["src_bytes"].clip(0, 1500).astype(float)

    # Proxy: map service to a port number using a lookup
    SERVICE_PORT = {
        "http":22, "ftp":21, "smtp":25, "ssh":22, "dns":53,
        "https":443, "pop_3":110, "imap4":143, "ftp_data":20,
        "telnet":23, "finger":79, "login":513, "shell":514,
    }
    df["dst_port"]    = df["service"].str.lower().map(SERVICE_PORT).fillna(80).astype(float)

    # SYN proxy: flag == "S0" or "S1" or "S2" or "S3"
    df["is_syn"]      = df["flag"].isin(["S0","S1","S2","S3"]).astype(float)

    # External source proxy: land=0 means src != dst (inter-network)
    df["is_external"] = (df["land"] == 0).astype(float)

    # Unique ports proxy: dst_host_srv_count normalised
    df["unique_ports"]= (df["dst_host_srv_count"] / 255.0 * 10).clip(1, 60).astype(float)

    # Total pkt count proxy
    df["pkt_count"]   = df["count"].clip(1, 500).astype(float)

    # ICMP window count proxy
    df["icmp_count"]  = (df["is_icmp"] * df["count"].clip(0, 100)).astype(float)

    feature_cols = [
        "pkt_size", "dst_port", "is_syn", "is_icmp",
        "is_external", "unique_ports", "pkt_count", "icmp_count"
    ]
    X = df[feature_cols].values.astype(float)

    # Labels
    is_attack = df["label_lower"].map(lambda l: NSL_ATTACK_LABELS.get(l, True)).values
    y = np.where(is_attack, -1, 1)  # -1=attack, 1=normal (sklearn convention)

    X_normal = X[y == 1]
    X_attack = X[y == -1]

    print(f"  Normal samples : {len(X_normal)}")
    print(f"  Attack samples : {len(X_attack)}")
    return X_normal, X_attack, y


# ── Core Training ──────────────────────────────────────────────────────────────

def train(dataset_path: str = None):
    print("=" * 57)
    print("  NetShield IDS -- Model Training")
    print("=" * 57)

    if dataset_path:
        print(f"\n[1/4] Loading real dataset: NSL-KDD")
        try:
            X_normal, X_attack, _ = load_nslkdd(dataset_path)
        except Exception as e:
            print(f"      ERROR loading dataset: {e}")
            print("      Falling back to synthetic data.")
            dataset_path = None

    if not dataset_path:
        print("\n[1/4] Generating synthetic traffic data...")
        X_normal = generate_normal_traffic(2000)
        X_attack = generate_attack_traffic(400)
        print(f"      Normal samples : {len(X_normal)}")
        print(f"      Attack samples : {len(X_attack)} (evaluation only)")

    # Fit scaler on normal traffic only
    print("\n[2/4] Fitting StandardScaler on normal traffic...")
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X_normal)

    # Train Isolation Forest
    print("\n[3/4] Training Isolation Forest (200 trees)...")
    model = IsolationForest(
        n_estimators  = 200,
        contamination = 0.05,
        max_samples   = "auto",
        random_state  = 42,
        n_jobs        = -1,
    )
    model.fit(X_scaled)
    print("      Training complete.")

    # Evaluate
    print("\n[4/4] Evaluating on held-out set...")
    n_eval    = min(500, len(X_normal))
    a_eval    = min(200, len(X_attack))
    X_eval    = np.vstack([X_normal[:n_eval], X_attack[:a_eval]])
    y_true    = np.array([1]*n_eval + [-1]*a_eval)
    X_eval_sc = scaler.transform(X_eval)
    y_pred    = model.predict(X_eval_sc)

    print("\n  Classification Report (1=normal, -1=anomaly):")
    print(classification_report(
        y_true, y_pred,
        target_names=["anomaly", "normal"],
        labels=[-1, 1]
    ))

    cm = confusion_matrix(y_true, y_pred, labels=[1, -1])
    tn, fp, fn, tp = cm.ravel()
    print(f"  True Positives  (attacks caught) : {tp}")
    print(f"  False Positives (false alarms)   : {fp}")
    print(f"  True Negatives  (normal correct) : {tn}")
    print(f"  False Negatives (missed attacks) : {fn}")
    print(f"  Detection Rate                   : {tp/(tp+fn)*100:.1f}%")
    print(f"  False Alarm Rate                 : {fp/(fp+tn)*100:.1f}%")

    # Save
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model,  MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"\n  Model saved  -> {MODEL_PATH}")
    print(f"  Scaler saved -> {SCALER_PATH}")
    print("\n  Done. Restart app.py to load the new model.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetShield IDS Model Trainer")
    parser.add_argument(
        "--dataset", metavar="PATH",
        help="Path to NSL-KDD KDDTrain+.txt (optional; uses synthetic data if omitted)"
    )
    args = parser.parse_args()
    train(dataset_path=args.dataset)
