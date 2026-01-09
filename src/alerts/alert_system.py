import json
from datetime import datetime

from src.utils.logger import setup_logger
from src.config.settings import LOG_FILE_PATH

logger = setup_logger(
    name="AlertSystem",
    log_file=LOG_FILE_PATH
)


class AlertSystem:
    """
    Handles alert generation, formatting,
    and logging for detected threats.
    """

    def __init__(self):
        logger.info("Alert system initialized")

    def generate_alert(self, threat: dict, features: dict):
        """
        Generates a structured alert object
        and logs it.
        """

        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "alert_type": threat.get("type"),
            "attack_name": threat.get("name"),
            "severity": threat.get("severity"),
            "mitre_technique": threat.get("mitre_technique"),
            "anomaly_score": threat.get("score"),
            "source": {
                "ip": features.get("src_ip"),
                "port": features.get("src_port")
            },
            "destination": {
                "ip": features.get("dst_ip"),
                "port": features.get("dst_port")
            },
            "traffic": {
                "packet_size": features.get("packet_size"),
                "packet_rate": features.get("packet_rate"),
                "byte_rate": features.get("byte_rate"),
                "tcp_flags": features.get("tcp_flags")
            }
        }

        self._log_alert(alert)
        return alert

    def _log_alert(self, alert: dict):
        """
        Logs alerts with severity-based levels.
        """

        severity = alert.get("severity", "low")

        alert_json = json.dumps(alert)

        if severity == "high":
            logger.critical(alert_json)
        elif severity == "medium":
            logger.warning(alert_json)
        else:
            logger.info(alert_json)
