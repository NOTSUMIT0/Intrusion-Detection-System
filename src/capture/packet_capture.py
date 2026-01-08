from scapy.all import sniff, IP, TCP
import threading
import queue

from config.settings import PACKET_QUEUE_SIZE
from utils.logger import setup_logger

logger = setup_logger(
    name="PacketCapture",
    log_file="data/logs/ids_alerts.log"
)


class PacketCapture:
    """
    Responsible for capturing live network packets
    and placing them into a thread-safe queue.
    """

    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=PACKET_QUEUE_SIZE)
        self.stop_event = threading.Event()
        self.capture_thread = None

    def _packet_callback(self, packet):
        """
        Called by Scapy for every captured packet.
        Filters and enqueues valid packets.
        """
        try:
            if IP in packet and TCP in packet:
                self.packet_queue.put_nowait(packet)
        except queue.Full:
            logger.warning("Packet queue full. Dropping packet.")

    def start(self, interface):
        """
        Starts packet sniffing in a separate thread.
        """

        def capture():
            logger.info(f"Starting packet capture on interface: {interface}")
            sniff(
                iface=interface,
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda _: self.stop_event.is_set()
            )

        self.capture_thread = threading.Thread(
            target=capture,
            daemon=True
        )
        self.capture_thread.start()

    def stop(self):
        """
        Stops packet capture gracefully.
        """
        logger.info("Stopping packet capture...")
        self.stop_event.set()
        if self.capture_thread:
            self.capture_thread.join()
