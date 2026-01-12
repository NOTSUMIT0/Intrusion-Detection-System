from collections import defaultdict
from config.settings import MIN_FLOW_DURATION
from utils.logger import setup_logger


logger = setup_logger(
    name="TrafficAnalyzer",
    log_file="data/logs/ids_alerts.log"
)


class TrafficAnalyzer:
    """
    Analyzes packets and extracts flow-based features
    used by detection engines.
    """

    def __init__(self):
        self.flows = defaultdict(lambda: {
            "packet_count": 0,
            "byte_count": 0,
            "start_time": None,
            "last_time": None
        })

    def analyze(self, packet):
        """
        Processes a packet and returns extracted features.
        """

        ip = packet["IP"]
        tcp = packet["TCP"]

        flow_key = (
            ip.src,
            ip.dst,
            tcp.sport,
            tcp.dport
        )

        flow = self.flows[flow_key]
        current_time = packet.time

        if flow["start_time"] is None:
            flow["start_time"] = current_time

        flow["packet_count"] += 1
        flow["byte_count"] += len(packet)
        flow["last_time"] = current_time

        duration = max(
            flow["last_time"] - flow["start_time"],
            MIN_FLOW_DURATION
        )

        features = {
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "packet_size": len(packet),
            "packet_rate": flow["packet_count"] / duration,
            "byte_rate": flow["byte_count"] / duration,
            "tcp_flags": str(tcp.flags)
        }

        logger.debug(f"Extracted features: {features}")
        return features
