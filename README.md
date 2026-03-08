# Intrusion Detection System (IDS) with Real-Time Dashboard

> **A Hybrid Network Intrusion Detection System** with a SIEM-style, multi-page web dashboard — powered by Scapy, FastAPI, WebSockets, and ECharts.

---

## Table of Contents

1. [Introduction](#1-introduction-to-intrusion-detection-systems)
2. [Project Overview](#2-project-overview)
3. [Objectives](#3-objectives)
4. [Key Features](#4-key-features)
5. [What's New](#5-whats-new)
6. [System Architecture](#6-system-architecture)
7. [Data Flow and Processing](#7-data-flow-and-processing)
8. [Detection Techniques Used](#8-detection-techniques-used)
9. [Dashboard Capabilities](#9-dashboard-capabilities)
10. [Tools and Technologies](#10-tools-and-technologies)
11. [How to Run the Project](#11-how-to-run-the-project)
12. [Running on Windows (PCAP-Based Analysis)](#12-running-on-windows-pcap-based-analysis)
13. [Running on Linux (Live Packet Capture)](#13-running-on-linux-live-packet-capture)
14. [Project Structure](#14-project-structure)
15. [Benefits of the System](#15-benefits-of-the-system)
16. [Limitations](#16-limitations)
17. [Future Enhancements](#17-future-enhancements)
18. [Conclusion](#18-conclusion)

---

## 1) Introduction to Intrusion Detection Systems

An Intrusion Detection System (IDS) is a security mechanism designed to monitor network or system activities for malicious actions or policy violations. IDS plays a critical role in cybersecurity by identifying potential attacks, misuse, or abnormal behavior in real time or through offline analysis.

IDS solutions are broadly classified into:

- **Signature-Based IDS** — Detects known attack patterns using predefined rules
- **Anomaly-Based IDS** — Detects deviations from normal behavior using ML models
- **Hybrid IDS** — Combines both approaches for better accuracy

> This project implements a **Hybrid IDS** with a custom web dashboard, real-time WebSocket alerts, and contextual MITRE ATT&CK intelligence.

---

## 2) Project Overview

This project is a **Hybrid Intrusion Detection System** with a SIEM-style, multi-page web dashboard. It is capable of:

- Analyzing real network traffic and detecting threats
- Mapping them to **MITRE ATT&CK** tactics and techniques
- Pushing real-time alerts via **WebSockets** to a custom HTML/JS frontend
- Visualizing alerts with actionable security intelligence using **ECharts**

The system supports:

-  **Offline packet analysis** on Windows using PCAP files
-  **Real-time live packet capture** on Linux (via Scapy)
-  **Test mode** for development using mock packets
-  **Centralized alert storage** and multi-page visualization dashboard

---

## 3) Objectives

- Detect network-based attacks using signature and anomaly-based techniques
- Provide real-time and offline traffic analysis
- Map detected attacks to the **MITRE ATT&CK** framework
- Present alerts through a user-friendly, SOC-style multi-page dashboard
- Push real-time alerts to the frontend using **WebSockets**
- Ensure cross-platform compatibility (Windows and Linux)

---

## 4) Key Features

| Feature | Description |
|---|---|
|  Hybrid IDS | Signature + Anomaly (Isolation Forest) detection |
|  PCAP Analysis | Offline packet analysis — Windows compatible |
|  Live Capture | Real-time sniffing via Scapy — Linux |
|  Test Mode | Mock packet injection for development |
|  MITRE ATT&CK | Full tactic/technique mapping with kill chain view |
|  WebSocket Alerts | Push-based real-time alert delivery |
|  ECharts Visuals | Interactive charts (severity, timeline, top IPs, attack types) |
|  Export Reports | Export alerts to **CSV** and **PDF** (jsPDF) |
|  Alert Details Modal | Expandable per-alert detail view with traffic metadata |
|  Severity Classification | High / Medium / Low severity badges |
|  Investigation Center | Dedicated page with ECharts analytics, toggle between investigating/resolved alerts |
|  Alert Lifecycle | Full new → investigating → resolved workflow with backend persistence |
|  Packet Capture Limit | Auto-stops capture at 10,000 packets for focused analysis |
|  Multi-Page Dashboard | 6 dedicated pages: Dashboard, Alerts, Investigations, Analytics, MITRE, About |
|  FastAPI Backend | REST API + WebSocket server for alert ingestion/distribution |
|  One-Command Launch | `uv run python run.py` starts backend, capture engine, and opens dashboard |

---

## 5) What's New

> These features were added in the latest version compared to the original project.

###  Fully Custom Web Frontend (Replacing Streamlit)
The old Streamlit dashboard has been **completely replaced** with a custom, multi-page web application built using:
- **HTML + Tailwind CSS** for a sleek dark-theme SOC-style UI
- **Vanilla JavaScript** for dynamic, live-updating content
- **Apache ECharts** for rich, interactive charts

###  WebSocket Real-Time Alerts
The FastAPI backend now supports a **WebSocket endpoint** (`/ws/alerts`) that pushes new alerts instantly to all connected dashboard clients — no polling or page refresh required.

###  Multi-Page Dashboard (6 Pages)
| Page | Description |
|---|---|
| **Dashboard** | Overview with metric cards, MITRE kill chain, charts, incident grouping, and alert table |
| **Alerts** | Dedicated filterable alert feed |
| **Investigations** | Toggle between investigating/resolved alerts, ECharts pipeline donut and severity breakdown, packet detail cards with action buttons |
| **Analytics** | Deep-dive charts: severity distribution, attack types, alert timeline, top source IPs, and analytical insights |
| **MITRE ATT&CK** | Kill chain overview, technique frequency, severity-by-tactic chart, and technique list |
| **About** | Project info page |

###  Alert Details Modal
Each alert row in the dashboard opens a **detailed modal** showing:
- Attack name, severity, type, MITRE technique
- Source IP / Port, Destination IP / Port
- Traffic metadata: packet size, rate, byte rate, TCP flags, flow duration

###  Export to CSV and PDF
From the dashboard, you can export the entire alert list as:
- **CSV** — for spreadsheet/SIEM import
- **PDF** — generated client-side using **jsPDF**

###  MITRE ATT&CK Kill Chain Visualization
The dashboard now renders a **live kill chain** based on detected alerts, showing which ATT&CK tactics have been triggered. Each tile is clickable and opens a **Tactic Deep Dive** panel with technique descriptions, impact analysis, risk level, and mitigation steps.

###  Active Incidents Grouping
Alerts on the dashboard are now **grouped by source IP** in an "Active Incidents" section, giving a quick attacker-centric view.

###  Investigation Center & Alert Lifecycle
A new **Investigations** page provides a complete alert lifecycle workflow:
- **Mark Investigating** on any alert from the Dashboard modal
- View all investigating alerts on the Investigations page with full packet details
- **Mark Resolved** to move alerts to the resolved tab
- ECharts visualizations: pipeline donut (new / investigating / resolved) and severity breakdown bar chart
- Toggle between "Under Investigation" and "Resolved" tabs

###  Packet Capture Limit
Live capture now auto-stops after **10,000 packets** to prevent runaway capture sessions. Progress is logged every 1,000 packets. After reaching the limit, the terminal displays a clear banner prompting the user to analyze results on the dashboard.

###  One-Command Launcher
A unified `run.py` launcher starts the FastAPI backend, IDS capture engine, and opens the dashboard in the browser — all with one command:
```bash
uv run python run.py
```

---

## 6) System Architecture

```
Network Traffic
   |
   |──► Wireshark (.pcap) ──► PCAPReader      [Windows]
   |──► Scapy Live Capture                    [Linux]
   |──► Mock Packets (Test Mode)              [Development]
   |
Traffic Analyzer (feature extraction)
   |
Detection Engine
   |── Signature Rules (JSON-based)
   |── Anomaly Detection (Isolation Forest)
   |
Alert System
   |── Local logging (severity-based)
   |── HTTP POST to FastAPI backend
   |
FastAPI Backend (REST + WebSocket)
   |── GET   /alerts                    → fetch all alerts
   |── POST  /alerts                    → receive new alert
   |── PATCH /alerts/{timestamp}/status  → update alert lifecycle status
   |── GET   /alerts/investigating       → fetch investigating alerts
   |── GET   /alerts/resolved            → fetch resolved alerts
   |── WS    /ws/alerts                  → push to connected clients
   |
Custom HTML/JS Frontend (Tailwind + ECharts)
   |── Dashboard page
   |── Alerts page
   |── Investigations page
   |── Analytics page
   |── MITRE ATT&CK page
   |── About page
```

---

## 7) Data Flow and Processing

1. Network traffic is captured (PCAP file, live packets, or mock test packets)
2. Packets are parsed and converted into flow features by the **Traffic Analyzer**
3. **Detection Engine** evaluates traffic using:
   - Signature rules (JSON rule set)
   - Anomaly detection model (Isolation Forest)
4. **Alert System** generates structured alerts with full metadata:
   - Timestamp, attack name, severity, MITRE technique
   - Source/destination IP and port
   - Packet size, rate, TCP flags, flow duration
5. Alerts are logged locally and **HTTP-POSTed** to the FastAPI backend
6. Backend stores the alert and **broadcasts it via WebSocket** to all connected dashboard clients
7. Dashboard receives the alert and dynamically updates charts, tables, and metric cards

---

## 8) Detection Techniques Used

### 1. Signature-Based Detection
- SYN Flood detection (TCP SYN flag analysis)
- Port Scanning detection
- Pattern matching based on TCP flags, packet rate, and packet size
- Rules defined in `data/signatures/signature_rules.json`

### 2. Anomaly-Based Detection
- Machine learning model: **Isolation Forest** (scikit-learn)
- Learns normal traffic characteristics
- Flags statistically abnormal traffic patterns with a numeric anomaly score

---

## 9) Dashboard Capabilities

###  Dashboard Page
- Total alerts, high severity count, medium severity count, and last updated time
- **MITRE ATT&CK Kill Chain** visualization with tactic deep dive
- **ECharts** visualization:
  - Severity distribution
  - Alerts over time (timeline)
  - Top source IPs
- **Active Incidents** table grouped by source IP
- **Detected Alerts** table with per-row detail modal
- **Export CSV** and **Export PDF** buttons

###  Analytics Page
- Severity Distribution chart
- Attack Types distribution chart
- Alerts Over Time (temporal view)
- Top Source IPs
- **Analytical Insights** — auto-generated text insights based on alert data

###  MITRE ATT&CK Page
- ATT&CK Kill Chain Overview
- Technique Frequency chart
- Severity by Tactic chart
- Detected MITRE Techniques list with clickable detail modals

---

## 10) Tools and Technologies

**Backend**
| Tool | Purpose |
|---|---|
| Python 3.10+ | Core language |
| uv | Fast Python package manager & project runner |
| Scapy | Packet capture and parsing |
| FastAPI | REST API + WebSocket server |
| Uvicorn | ASGI server for FastAPI |
| scikit-learn | Isolation Forest anomaly detection |
| NumPy | Numerical processing |
| python-dotenv | Environment configuration |

**Frontend**
| Tool | Purpose |
|---|---|
| HTML5 | Dashboard structure |
| Tailwind CSS v3 | Dark-theme, responsive styling |
| Vanilla JavaScript | Dynamic content & WebSocket client |
| Apache ECharts | Interactive charts |
| jsPDF | Client-side PDF report export |

**Infrastructure & Analysis**
| Tool | Purpose |
|---|---|
| Wireshark | Packet capture on Windows |
| Npcap | Windows packet capture driver |
| MITRE ATT&CK Framework | Threat intelligence mapping |
| JSON Signature Rules | Signature-based detection database |

---

## 11) How to Run the Project

### Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) — fast Python package manager
- Node.js + npm (for Tailwind CSS build, one-time only)
- Npcap (for Windows live capture) or Wireshark (for PCAP mode)

### Step 1 — Install uv (if not already installed)

```bash
pip install uv
```

### Step 2 — Install all dependencies

```bash
uv sync
```

> This reads `pyproject.toml`, creates a virtual environment, and installs all packages automatically.

### Step 3 — Build Tailwind CSS (one-time, for frontend styles)

```bash
cd frontend
npm install
npm run build
```

> This compiles `assets/css/styles.css` → `public/output.css` used by all dashboard pages.

---

## 12) Running the IDS (One Command)

The easiest way to run everything is the **unified launcher**:

```bash
uv run python run.py
```

This single command will:
1. Free port 8000 if occupied
2. Start the **FastAPI backend** (`http://127.0.0.1:8000`)
3. Start the **IDS Capture Engine** (live packet capture)
4. Open the **Dashboard** in your default browser

Capture automatically stops at **10,000 packets**. The backend stays alive so you can analyze results on the dashboard.

Press **Ctrl+C** to shut down all services.

---

### Alternative: Running Components Manually

#### Start the backend only:
```bash
uv run uvicorn backend.app:app --reload
```

#### Start the IDS engine only (from the `src/` directory):
```bash
cd src
uv run python main.py
```

#### Open the dashboard:
Open `frontend/pages/dashboard.html` in your browser.
Navigate using the sidebar: Dashboard → Alerts → Investigations → Analytics → MITRE → About.

---

### PCAP Mode (Offline Analysis — Windows Friendly)

1. Capture traffic using Wireshark and save as `data/pcaps/sample.pcap`
2. Edit `src/main.py` and uncomment the PCAP mode block
3. Run:
```bash
uv run python run.py
```
Or manually:
```bash
uv run uvicorn backend.app:app --reload   # Terminal 1
cd src && uv run python main.py            # Terminal 2
```

---

###  Test Mode (Windows — no PCAP file needed)

To run IDS with **mock packets** for development/testing, edit `src/main.py` and switch:

```python
# Comment this block:
# ids = IntrusionDetectionSystem(mode="pcap")
# ids.run_pcap_mode(pcap_path)

# Uncomment this block:
ids = IntrusionDetectionSystem(mode="test")
ids.run_test_mode()
```

Then run:

```bash
cd src
python main.py
```

---

## 13) Running on Linux (Live Packet Capture)

### 1. Install required system tools

```bash
sudo apt install tcpdump
pip install uv
uv sync
```

### 2. Run with the unified launcher (recommended)

```bash
sudo uv run python run.py
```

> Root is required for live packet capture on Linux.

### 3. Or run manually

```bash
uv run uvicorn backend.app:app --reload        # Terminal 1
cd src && sudo uv run python main.py            # Terminal 2
```

Make sure `src/main.py` has live mode enabled:

```python
ids = IntrusionDetectionSystem(mode="live")
ids.run_live_mode()
```

> The dashboard connects to the FastAPI WebSocket at `ws://127.0.0.1:8000/ws/alerts` for real-time updates.

---

## 14) Project Structure

```
IDS/
│
├── run.py                      # Unified launcher — starts everything
├── pyproject.toml              # uv project config & dependencies
│
├── backend/
│   ├── __init__.py
│   └── app.py                  # FastAPI app — REST + WebSocket + status mgmt
│
├── frontend/
│   ├── assets/
│   │   ├── css/
│   │   │   └── styles.css      # Tailwind CSS source
│   │   └── js/
│   │       ├── dashboard.js    # Dashboard page logic
│   │       ├── alerts.js       # Alerts page logic
│   │       ├── investigations.js # Investigation Center logic
│   │       ├── analytics.js    # Analytics page logic
│   │       └── mitre.js        # MITRE ATT&CK page logic
│   ├── pages/
│   │   ├── dashboard.html      # Main dashboard page
│   │   ├── alerts.html         # Alerts feed page
│   │   ├── investigations.html # Investigation Center page
│   │   ├── analytics.html      # Analytics charts page
│   │   ├── mitre.html          # MITRE ATT&CK intelligence page
│   │   └── about.html          # About page
│   ├── public/
│   │   └── output.css          # Compiled Tailwind CSS output
│   ├── package.json
│   └── tailwind.config.js
│
├── data/
│   ├── pcaps/
│   │   └── sample.pcap         # Place your captured PCAP file here
│   └── signatures/
│       └── signature_rules.json
│
├── src/
│   ├── alerts/
│   │   └── alert_system.py     # Alert generation & forwarding
│   ├── analysis/
│   │   └── traffic_analyzer.py # Feature extraction
│   ├── capture/
│   │   ├── packet_capture.py   # Live capture with 10K packet limit
│   │   └── pcap_reader.py      # PCAP file reader (Windows)
│   ├── config/
│   │   └── settings.py         # Global config (thresholds, limits)
│   ├── detection/
│   │   └── detection_engine.py # Signature + anomaly detection
│   ├── utils/
│   │   └── logger.py
│   └── main.py                 # IDS entry point
│
├── requirements.txt            # Legacy pip requirements
└── README.md
```

---

## 15) Benefits of the System

1. **Real-time alerts via WebSocket** — no polling, instant updates
2. **Platform-independent design** — runs on Windows (PCAP + live) and Linux (live)
3. **One-command launch** — `uv run python run.py` starts everything
4. **Real-world traffic analysis** using actual network packets
5. **Full alert lifecycle** — new → investigating → resolved with persistence
6. **Educational and practical security insights** through MITRE ATT&CK mapping
7. **SIEM-like multi-page visualization** with 6 dedicated dashboard sections
8. **Exportable reports** — CSV and PDF for documentation and compliance
9. **Scalable and modular architecture** — easy to extend with new detection rules
10. **Suitable for academic projects, CTFs, and real-world demonstrations**

---

## 16) Limitations

1. Offline analysis only on Windows (no live packet sniffing without Npcap privilege issues)
2. Limited signature rule set (easily expandable via JSON)
3. No persistent database storage — alerts are in-memory and reset on restart
4. WebSocket requires browser same-origin access to `http://127.0.0.1:8000`
5. Designed for educational and research use — not production hardened

---

## 17) Future Enhancements

1. Database integration (PostgreSQL / MongoDB) for persistent alert storage
2. User authentication and role-based access control (RBAC)
3. Advanced ML-based behavioral analysis (LSTM, Autoencoder)
4. Live threat intelligence feeds integration (AbuseIPDB, VirusTotal)
5. SIEM and SOC tool integration (Elastic/Kibana, Splunk)
6. Docker containerization for easy deployment
7. Cloud deployment support (AWS, GCP, Azure)
8. Geolocation mapping for source IPs on an interactive world map

---

## 18) Conclusion

This project demonstrates a complete end-to-end **Hybrid Intrusion Detection System** combining traffic analysis, detection logic, a FastAPI backend with WebSocket support, and a fully custom multi-page security dashboard.

By integrating MITRE ATT&CK intelligence, real-time WebSocket alert delivery, ECharts visualizations, and exportable reports — the system goes far beyond basic alerting and provides meaningful, actionable security insights.

The modular and scalable design makes it suitable for academic projects, cybersecurity demonstrations, CTF competitions, and future research enhancements.

---
