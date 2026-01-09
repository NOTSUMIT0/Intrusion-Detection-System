from src.alerts.alert_system import AlertSystem

alert_system = AlertSystem()

threat = {
    "type": "signature",
    "name": "syn_flood",
    "severity": "high",
    "mitre_technique": "T1499"
}

features = {
    "src_ip": "10.0.0.1",
    "dst_ip": "192.168.1.10",
    "src_port": 1234,
    "dst_port": 80,
    "packet_size": 60,
    "packet_rate": 200,
    "byte_rate": 120000,
    "tcp_flags": "S"
}

alert = alert_system.generate_alert(threat, features)
print(alert)
