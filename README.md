# ⬡ NetShield IDS — Smart Intrusion Detection System

> A real-time network intrusion detection system with an AI-powered analysis engine and professional cybersecurity dashboard. Built for computer science portfolios and cybersecurity internship applications.

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4-F7931E?logo=scikit-learn)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📋 Overview

NetShield IDS is a student-level Smart Intrusion Detection System that monitors network traffic, applies both rule-based and machine-learning anomaly detection, and displays all security events through a modern, enterprise-inspired SOC (Security Operations Centre) dashboard.

**Key capabilities:**
- Real-time packet capture and analysis (live Scapy or built-in simulator)
- Rule-based threat detection (port scans, brute-force, ICMP floods, known-bad IPs, etc.)
- AI anomaly detection using Isolation Forest (scikit-learn)
- Dynamic threat scoring (0–100 network-wide risk index)
- Live updating dashboard with charts, alert tables, and packet streams
- Log export, search, and filtering

---

## ✨ Features

| Feature | Details |
|---|---|
| 📡 Packet Monitoring | Capture src/dst IP, protocol, ports, size, flags, service, direction |
| 🚨 Rule-Based Detection | 7 detection rules: port scan, brute-force, ICMP flood, bad IPs, etc. |
| 🤖 AI Detection | Isolation Forest anomaly detection with Z-score backup |
| 📊 Live Dashboard | Dark SOC-style UI with Chart.js charts and live polling |
| 🎯 Threat Scoring | Per-alert score (0–100) + network-wide threat index |
| 📁 Logging | In-memory ring buffers + on-disk JSON persistence |
| 🔍 Log Search | Filter alerts by severity, search by IP or attack type |
| ⬇ Export | Download all logs as JSON |

---

## 🛠 Technology Stack

**Backend**
- Python 3.11+
- Flask 3.0 (REST API + Jinja2 templating)
- Scapy (optional — live packet capture)

**Machine Learning**
- scikit-learn — Isolation Forest
- NumPy — feature extraction

**Frontend**
- Vanilla JavaScript (ES2022)
- Chart.js 4 — real-time charts
- CSS Custom Properties — dark SOC theme
- Google Fonts: Orbitron, Rajdhani, Share Tech Mono

**Storage**
- JSON flat files (newline-delimited, append-only)
- In-memory deque ring buffers

---

## 📂 Project Structure

```
NetShield-IDS/
│
├── app.py                    # Flask application & API routes
├── requirements.txt          # Python dependencies
├── README.md
│
├── detector/
│   ├── packet_sniffer.py     # Live capture (Scapy) + traffic simulator
│   ├── threat_rules.py       # Rule-based detection engine (7 rules)
│   ├── anomaly_detector.py   # AI / statistical anomaly detection
│   └── traffic_analyzer.py   # Aggregated analytics & threat scoring
│
├── logs/
│   ├── alerts.json           # Persisted alert log (newline-delimited JSON)
│   └── traffic_logs.json     # Sample packet log
│
├── templates/
│   └── index.html            # Main dashboard (Jinja2)
│
├── static/
│   ├── style.css             # Dark cybersecurity theme
│   ├── script.js             # Dashboard controller & polling
│   └── dashboard.js          # Chart.js initialisation & updates
│
├── model/
│   ├── train_model.py        # Standalone ML training script
│   ├── ids_model.pkl         # Trained Isolation Forest (generated)
│   └── scaler.pkl            # Fitted StandardScaler (generated)
│
└── utils/
    ├── logger.py             # Thread-safe IDS logger
    ├── helpers.py            # Utility functions
    └── config.py             # Centralised configuration
```

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.11 or newer
- pip

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/NetShield-IDS.git
cd NetShield-IDS
```

### 2. Create a virtual environment (recommended)
```bash
python -m venv venv

# Linux / macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. (Optional) Train the ML model
```bash
python model/train_model.py
```
This generates `model/ids_model.pkl` and `model/scaler.pkl`.

### 5. Run the application
```bash
python app.py
```

### 6. Open the dashboard
Navigate to **http://127.0.0.1:5000** in your browser.

Click **▶ START** to begin monitoring.

---

## 🎮 Usage

| Action | How |
|---|---|
| Start monitoring | Click **▶ START** in the top bar |
| Stop monitoring | Click **■ STOP** |
| View alert detail | Click any row in the Threat Alerts table |
| Filter alerts | Use the severity dropdown or search box |
| Export logs | Click **⬇ EXPORT** — downloads `netshield_export.json` |
| Clear logs | Click **⌫ CLEAR** |

---

## 🔬 How It Works

### Packet Sniffing
NetShield uses **Scapy** to open a raw socket on a network interface and intercept every IP frame before the OS network stack processes it. Each frame is parsed to extract: source/destination IP, ports, protocol, TCP flags, packet size, and TTL.

In **demo mode** (default, no root required) a built-in simulator generates realistic synthetic traffic so the dashboard is fully functional without elevated privileges.

### Rule-Based Detection
Seven deterministic rules fire when packet counters exceed thresholds:
1. **Known Bad IP** — static block-list of malicious IP ranges
2. **Port Scan** — ≥15 unique destination ports or ≥20 SYN packets from one source
3. **Brute-Force** — ≥8 failed connections to SSH/RDP/FTP ports
4. **ICMP Flood** — ≥30 ICMP packets from one source
5. **Sensitive Port** — external access to database / admin ports
6. **Data Exfiltration** — outbound packets > 1200 bytes
7. **Cleartext Protocol** — Telnet or FTP usage

### AI Anomaly Detection
An **Isolation Forest** (scikit-learn) is trained on synthetic normal-traffic feature vectors. The model assigns an anomaly score to each new packet's feature vector; packets that score below a contamination threshold (-1 prediction) trigger an AI alert. A **Z-score** baseline backup flags individual metrics (packet size, ICMP rate) that deviate significantly from the per-source rolling mean.

### Threat Scoring
The network-wide threat score (0–100) is computed as a weighted sum:
- **40%** ratio of threat-indicator packets (SYN/ICMP heavy) in the last 100 packets
- **30%** count of IPs that have probed more than 5 unique ports
- **30%** alert density in the current minute

---


---

## 🔭 Future Improvements

- [ ] Live Scapy capture with automatic interface detection
- [ ] GeoIP location mapping for source IPs
- [ ] Email / webhook alerting (Slack, PagerDuty)
- [ ] Persistent SQLite backend replacing JSON flat files
- [ ] Authentication for the dashboard
- [ ] PCAP file upload & replay analysis
- [ ] Train on real datasets (CICIDS2017, NSL-KDD)
- [ ] Docker containerisation
- [ ] Rate-based DDoS detection (token-bucket algorithm)

---

## ⚖️ Legal & Ethical Notice

This tool is developed for educational and research purposes only. Only use NetShield IDS on networks you own or have explicit written permission to monitor. Unauthorised network monitoring may be illegal in your jurisdiction.

---


---

*Built By Mohamed AHmed MOunir.*
