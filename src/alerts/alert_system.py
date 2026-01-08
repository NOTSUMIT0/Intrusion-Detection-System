import logging
import json
from datetime import datetime

class AlertSystem:
    def __init__(self, logfile="data/logs/ids_alerts.log"):
        logging.basicConfig(
            filename=logfile,
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s"
        )
        self.logger = logging.getLogger("IDS")

    def alert(self, threat, features):
        payload = {
            "time": datetime.utcnow().isoformat(),
            "threat": threat,
            "source": features["src_ip"],
            "destination": features["dst_ip"]
        }
        self.logger.warning(json.dumps(payload))
        print("ALERT:", payload)
