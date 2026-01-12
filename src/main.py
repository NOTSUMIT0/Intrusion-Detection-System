from capture.pcap_reader import PCAPReader
import time
import queue

from scapy.all import IP, TCP

from capture.packet_capture import PacketCapture
from analysis.traffic_analyzer import TrafficAnalyzer
from detection.detection_engine import DetectionEngine
from alerts.alert_system import AlertSystem
from config.settings import NETWORK_INTERFACE
from utils.logger import setup_logger


logger = setup_logger(
    name="IDS-Main",
    log_file="data/logs/ids_alerts.log"
)


class IntrusionDetectionSystem:
    """
    Main IDS controller that connects
    capture, analysis, detection, and alerting.
    """

    def __init__(self, mode="test"):
        """
        mode:
        - 'test'  -> Windows / mock packets
        - 'live'  -> Linux live packet capture
        """
        self.mode = mode

        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine(
            "data/signatures/signature_rules.json"
        )
        self.alert_system = AlertSystem()

        logger.info(f"IDS initialized in {self.mode.upper()} mode")


        # -----------------------------
    # PCAP MODE (WINDOWS FRIENDLY)
    # -----------------------------
    def run_pcap_mode(self, pcap_file_path):
        """
        Runs IDS on a PCAP file (offline analysis).
        """
        logger.info(f"Running IDS in PCAP mode: {pcap_file_path}")

        reader = PCAPReader(pcap_file_path)

        for packet in reader.read_packets():
            features = self.traffic_analyzer.analyze(packet)
            threats = self.detection_engine.detect(features)

            for threat in threats:
                self.alert_system.generate_alert(threat, features)

        logger.info("PCAP analysis completed")



    # -----------------------------
    # TEST MODE (WINDOWS SAFE)
    # -----------------------------
    def run_test_mode(self):
        """
        Runs IDS using mock packets
        (for Windows development & testing)
        """
        logger.info("Running IDS in TEST mode")

        test_packets = [
            IP(src="10.0.0.1", dst="192.168.1.10") /
            TCP(sport=1234, dport=80, flags="S"),

            IP(src="10.0.0.1", dst="192.168.1.10") /
            TCP(sport=1235, dport=80, flags="S"),

            IP(src="10.0.0.1", dst="192.168.1.10") /
            TCP(sport=1236, dport=80, flags="S"),
        ]

        start_time = time.time()

        for packet in test_packets:
            packet.time = time.time() - start_time

            features = self.traffic_analyzer.analyze(packet)
            threats = self.detection_engine.detect(features)

            for threat in threats:
                self.alert_system.generate_alert(threat, features)

            time.sleep(0.5)

        logger.info("TEST mode completed")

    # -----------------------------
    # LIVE MODE (LINUX ONLY)
    # -----------------------------
    def run_live_mode(self):
        """
        Runs IDS with live packet capture
        (Linux environment)
        """
        logger.info("Running IDS in LIVE mode")

        self.packet_capture.start(NETWORK_INTERFACE)

        try:
            while True:
                try:
                    packet = self.packet_capture.packet_queue.get(timeout=1)
                    features = self.traffic_analyzer.analyze(packet)
                    threats = self.detection_engine.detect(features)

                    for threat in threats:
                        self.alert_system.generate_alert(threat, features)

                except queue.Empty:
                    continue

        except KeyboardInterrupt:
            logger.info("Stopping IDS...")
            self.packet_capture.stop()


# -----------------------------
# Program Entry Point
# -----------------------------
if __name__ == "__main__":
    """
    Change mode here:
    - mode="test"  -> Windows
    - mode="live"  -> Linux
    """

    # FOR PCAP MODE UNCOMMENT BELOW:
    ids = IntrusionDetectionSystem(mode="pcap")
    ids.run_pcap_mode("data/pcaps/sample.pcap")
    #FOR TEST MODE UNCOMMENT BELOW:
    # ids = IntrusionDetectionSystem(mode="test")
    # ids.run_test_mode()


    #FOR LIVE MODE UNCOMMENT BELOW:
    # ids = IntrusionDetectionSystem(mode="live")
    # ids.run_live_mode()
