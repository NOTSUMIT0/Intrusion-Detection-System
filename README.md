# Intrusion Detection System (IDS) with Real-Time Dashboard

## Table of Contents

1) Introduction to Intrusion Detection Systems

2) Project Overview

3) Objectives

4) Key Features

5) System Architecture

6) Data Flow and Processing

7) Detection Techniques Used

8) Dashboard Capabilities

9) Tools and Technologies

10) How to Run the Project

11) Windows (PCAP-based Analysis)

12) Linux (Live Packet Capture)

13) Project Structure

14) Benefits of the System

15) Limitations

16) Future Enhancements

17) Conclusion

----------------------------------------------------------------

### 1) Introduction to Intrusion Detection Systems

An Intrusion Detection System (IDS) is a security mechanism designed to monitor network or system activities for malicious actions or policy violations. IDS plays a critical role in cybersecurity by identifying potential attacks, misuse, or abnormal behavior in real time or through offline analysis.

- IDS solutions are broadly classified into:

- Signature-Based IDS: Detects known attack patterns.

- Anomaly-Based IDS: Detects deviations from normal behavior.

- Hybrid IDS: Combines both approaches for better accuracy.

- This project implements a hybrid IDS with visualization and contextual intelligence.

### 2) Project Overview

This project is a Hybrid Intrusion Detection System with a SIEM-style dashboard, capable of analyzing real network traffic, detecting threats, mapping them to MITRE ATT&CK techniques, and visualizing alerts with actionable security intelligence.

The system supports:

Offline packet analysis on Windows using PCAP files

Real-time live packet capture on Linux

Centralized alert storage and visualization

Security-focused explanations and mitigation guidance

### 3) Objectives

Detect network-based attacks using signature and anomaly-based techniques

Provide real-time and offline traffic analysis

Map detected attacks to the MITRE ATT&CK framework

Present alerts through a user-friendly, SOC-style dashboard

Ensure cross-platform compatibility (Windows and Linux)

### 4) Key Features

Hybrid IDS (Signature + Anomaly Detection)

PCAP-based traffic analysis (Windows compatible)

Live packet capture (Linux)

MITRE ATT&CK technique mapping

FastAPI-based backend for alert handling

Streamlit-based real-time dashboard

Severity classification (High / Medium / Low)

Risk summary and mitigation guidance

Interactive filters and charts

Stable auto-refresh without UI flickering

### 5) System Architecture

```css
Network Traffic
   |
   |--> Wireshark (.pcap) [Windows]
   |--> Live Capture (Scapy) [Linux]
   |
Traffic Analyzer
   |
Detection Engine
   |-- Signature Rules
   |-- Anomaly Detection
   |
Alert System
   |
FastAPI Backend
   |
Streamlit Dashboard
```

### 6) Data Flow and Processing

Network traffic is captured (PCAP or live packets)

Packets are parsed and converted into flow features

Detection engine evaluates traffic using:

Signature rules

Anomaly detection model

Alerts are generated with metadata

Alerts are sent to the backend API

Dashboard fetches alerts periodically and visualizes them

### 7) Detection Techniques Used
Signature-Based Detection

SYN flood detection

Port scanning detection

Pattern matching based on TCP flags, packet rate, and size

Anomaly-Based Detection

Machine learning model (Isolation Forest)

Learns normal traffic behavior

Flags statistically abnormal patterns

### 8) Dashboard Capabilities

Total alerts count and API health status

Risk summary based on alert severity

Interactive filters:

Severity

Attack type

Source IP

Charts:

Severity distribution

Alerts over time

MITRE ATT&CK intelligence:

Technique description

Impact analysis

Risk level

Recommended mitigations

### 9) Tools and Technologies

Python

Scapy

FastAPI

Streamlit

Streamlit Autorefresh

Matplotlib

Pandas

Wireshark

MITRE ATT&CK Framework

### 10) How to Run the Project
Prerequisites

Python 3.9+

pip

Wireshark (for Windows)

Npcap (installed with Wireshark)

Install dependencies:

```bash
pip install -r requirements.txt
```

### 11) Running on Windows (PCAP-Based Analysis)

1. Capture traffic using Wireshark

2. Save the capture file as:

```bash
data/pcaps/sample.pcap

```
3. Start the backend API:

```bash
python -m uvicorn ui.backend.app:app --reload --app-dir src

```
4. Run the IDS (PCAP mode):
```bash
python -m src.main
```
5. Start the dashboard:
```bash
streamlit run src/ui/frontend/dashboard.py

```
6. Open Browser:
```bash
http://localhost:8501
```

### 12) Running on Linux (Live Packet Capture)

1) Install required system tools:

```bash
sudo apt install tcpdump

```
2. Run the IDS with root privileges:
```bash
sudo python -m src.main

```
3. Start the backend API:
```bash
python -m uvicorn ui.backend.app:app --reload --app-dir src

```
4. Start the dashboard:
```bash
streamlit run src/ui/frontend/dashboard.py

```
- The IDS will now analyze live network traffic in real time.

### 13) Project Structure

```css
IDS/
│
├── data/
│   └── pcaps/
│
├── src/
│   ├── analysis/
│   ├── capture/
│   ├── detection/
│   ├── alerts/
│   ├── config/
│   ├── utils/
│   ├── ui/
│   │   ├── backend/
│   │   └── frontend/
│   └── main.py
│
├── requirements.txt
└── README.md

```

### 14) Benefits of the System

Platform-independent design

Real-world traffic analysis

Educational and practical security insights

SIEM-like visualization

Scalable and modular architecture

Suitable for academic and real-world demonstrations

### 15) Limitations

1. Offline analysis on Windows (no live sniffing)

2. Limited signature set (expandable)

3. No persistent database storage (currently in-memory)

4. Designed for educational and research use

### 16) Future Enhancements

1. Database integration (PostgreSQL / MongoDB)

2. Real-time WebSocket updates

3. Advanced ML-based behavioral analysis

4. Threat intelligence feeds

5. Role-based access control

6. SIEM and SOC tool integration

7. Cloud deployment support

### 17) Conclusion

This project demonstrates a complete end-to-end Intrusion Detection System combining traffic analysis, detection logic, backend APIs, and a real-time security dashboard. By integrating MITRE ATT&CK intelligence and providing actionable mitigation guidance, the system goes beyond basic alerting and offers meaningful security insights. The modular and scalable design makes it suitable for academic projects, demonstrations, and future research enhancements.