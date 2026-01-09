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

### 4) 
