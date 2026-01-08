import json
import numpy as np
from sklearn.ensemble import IsolationForest

class DetectionEngine:
    def __init__(self, signature_file):
        self.rules = self._load_rules(signature_file)
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.trained = False

    def _load_rules(self, path):
        with open(path) as f:
            return json.load(f)

    def train(self, normal_data):
        self.model.fit(normal_data)
        self.trained = True

    def detect(self, features):
        alerts = []

        # Signature-based
        for name, rule in self.rules.items():
            cond = rule["conditions"]
            if (
                features["packet_rate"] > cond.get("packet_rate", 0) and
                features["packet_size"] <= cond.get("packet_size", 9999)
            ):
                alerts.append({
                    "type": "signature",
                    "name": name,
                    "mitre": rule["mitre"],
                    "severity": rule["severity"]
                })

        # Anomaly-based
        if self.trained:
            vector = np.array([[features["packet_size"],
                                features["packet_rate"],
                                features["byte_rate"]]])
            score = self.model.score_samples(vector)[0]
            if score < -0.5:
                alerts.append({
                    "type": "anomaly",
                    "score": score,
                    "severity": "medium"
                })

        return alerts
