import json
import requests
from datetime import datetime

from utils.logger import setup_logger
from config.settings import LOG_FILE_PATH

# Backend API endpoint
DEFAULT_API_URL = "http://127.0.0.1:8000/alerts"

logger = setup_logger(
    name="AlertSystem",
    log_file=LOG_FILE_PATH
)


class AlertSystem:
    """
    Handles alert generation, logging,
    and forwarding alerts to the FastAPI backend.

    This component acts as the bridge between
    IDS core logic and the SIEM/dashboard layer.
    """

    def __init__(self, api_url: str = DEFAULT_API_URL):
        self.api_url = api_url
        logger.info("Alert system initialized")

    def generate_alert(self, threat: dict, features: dict) -> dict:
        """
        Generates a structured alert and:
        1. Logs it locally
        2. Sends it to FastAPI backend
        3. Returns alert object (future use)
        """

        alert = {
            "timestamp": datetime.utcnow().isoformat(),

            # Detection metadata
            "alert_type": threat.get("type"),            # signature / anomaly
            "attack_name": threat.get("name"),
            "severity": threat.get("severity"),
            "mitre_technique": threat.get("mitre_technique"),
            "anomaly_score": threat.get("score"),

            # Network endpoints
            "source": {
                "ip": features.get("src_ip"),
                "port": features.get("src_port")
            },
            "destination": {
                "ip": features.get("dst_ip"),
                "port": features.get("dst_port")
            },

            # Traffic characteristics
            "traffic": {
                "packet_size": features.get("packet_size"),
                "packet_rate": features.get("packet_rate"),
                "byte_rate": features.get("byte_rate"),
                "tcp_flags": features.get("tcp_flags"),
                "flow_duration": features.get("flow_duration")
            }
        }

        # 1️⃣ Log locally
        self._log_alert(alert)

        # 2️⃣ Send to API
        self._send_to_api(alert)

        return alert

    # -------------------------------------------------
    # Internal helpers
    # -------------------------------------------------

    def _log_alert(self, alert: dict):
        """
        Logs alert locally with severity-based handling.
        """
        severity = alert.get("severity", "low")
        alert_json = json.dumps(alert)

        if severity == "high":
            logger.critical(alert_json)
        elif severity == "medium":
            logger.warning(alert_json)
        else:
            logger.info(alert_json)

    def _send_to_api(self, alert: dict):
        """
        Sends alert to FastAPI backend.
        Fails gracefully if API is unreachable.
        """
        try:
            response = requests.post(
                self.api_url,
                json=alert,
                timeout=2
            )

            if response.status_code == 200:
                logger.info("Alert successfully sent to backend API")
            else:
                logger.warning(
                    f"Backend API responded with status {response.status_code}"
                )

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send alert to API: {e}")
