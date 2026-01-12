import json
import numpy as np
from sklearn.ensemble import IsolationForest

from utils.logger import setup_logger
from config.settings import ANOMALY_SCORE_THRESHOLD

logger = setup_logger(
    name="DetectionEngine",
    log_file="data/logs/ids_alerts.log"
)


class DetectionEngine:
    """
    Performs signature-based and anomaly-based detection
    on extracted traffic features.
    """

    def __init__(self, signature_file_path: str):
        self.signature_rules = self._load_signature_rules(signature_file_path)

        # Isolation Forest for anomaly detection
        self.anomaly_detector = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )

        self.is_trained = False

    # -----------------------------
    # Signature Rule Handling
    # -----------------------------
    def _load_signature_rules(self, file_path):
        """
        Loads signature rules from a JSON file.
        """
        try:
            with open(file_path, "r") as f:
                rules = json.load(f)
                logger.info("Signature rules loaded successfully.")
                return rules
        except Exception as e:
            logger.error(f"Failed to load signature rules: {e}")
            return {}

    # -----------------------------
    # Anomaly Model Training
    # -----------------------------
    def train_anomaly_model(self, normal_feature_vectors):
        """
        Trains the anomaly detection model
        using normal traffic feature vectors.
        """
        self.anomaly_detector.fit(normal_feature_vectors)
        self.is_trained = True
        logger.info("Anomaly detection model trained.")

    # -----------------------------
    # Detection Logic
    # -----------------------------
    def detect(self, features: dict):
        """
        Applies both detection techniques
        and returns a list of detected threats.
        """
        detected_threats = []

        # 1️⃣ Signature-based detection
        detected_threats.extend(
            self._signature_based_detection(features)
        )

        # 2️⃣ Anomaly-based detection
        if self.is_trained:
            anomaly = self._anomaly_based_detection(features)
            if anomaly:
                detected_threats.append(anomaly)

        return detected_threats

    # -----------------------------
    # Signature-based Detection
    # -----------------------------
    def _signature_based_detection(self, features):
        threats = []

        for rule_name, rule in self.signature_rules.items():
            conditions = rule.get("conditions", {})

            if self._match_conditions(features, conditions):
                threat = {
                    "type": "signature",
                    "name": rule_name,
                    "description": rule.get("description"),
                    "severity": rule.get("severity"),
                    "mitre_technique": rule.get("mitre")
                }
                threats.append(threat)
                logger.warning(f"Signature match detected: {rule_name}")

        return threats

    def _match_conditions(self, features, conditions):
        """
        Checks whether traffic features match rule conditions.
        """
        for key, threshold in conditions.items():
            if key not in features:
                return False

            if features[key] > threshold:
                continue
            else:
                return False

        return True

    # -----------------------------
    # Anomaly-based Detection
    # -----------------------------
    def _anomaly_based_detection(self, features):
        """
        Detects anomalies using Isolation Forest.
        """
        feature_vector = np.array([[
            features["packet_size"],
            features["packet_rate"],
            features["byte_rate"]
        ]])

        score = self.anomaly_detector.score_samples(feature_vector)[0]

        if score < ANOMALY_SCORE_THRESHOLD:
            logger.warning(f"Anomaly detected (score={score})")
            return {
                "type": "anomaly",
                "score": score,
                "severity": "medium"
            }

        return None
