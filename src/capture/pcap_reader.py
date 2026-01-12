from scapy.all import rdpcap, IP, TCP
from utils.logger import setup_logger

logger = setup_logger(
    name="PCAPReader",
    log_file="data/logs/ids_alerts.log"
)


class PCAPReader:
    """
    Reads packets from a PCAP file
    and yields TCP/IP packets for analysis.
    """

    def __init__(self, pcap_file_path: str):
        self.pcap_file_path = pcap_file_path

    def read_packets(self):
        logger.info(f"Reading PCAP file: {self.pcap_file_path}")

        packets = rdpcap(self.pcap_file_path)

        for packet in packets:
            if IP in packet and TCP in packet:
                yield packet
