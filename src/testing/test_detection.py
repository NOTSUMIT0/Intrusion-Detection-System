from src.detection.detection_engine import DetectionEngine

engine = DetectionEngine("data/signatures/signature_rules.json")

features = {
    "packet_size": 60,
    "packet_rate": 200,
    "byte_rate": 8000,
    "tcp_flags": "S"
}

threats = engine.detect(features)
print(threats)
