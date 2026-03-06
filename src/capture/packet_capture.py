from scapy.all import sniff, IP, TCP  # type: ignore[import-untyped]
import threading
import queue
import platform
from typing import Optional

from config.settings import PACKET_QUEUE_SIZE, check_capture_backend
from utils.logger import setup_logger


logger = setup_logger(
    name="PacketCapture",
    log_file="data/logs/ids_alerts.log"
)


class PacketCapture:
    """
    Responsible for capturing live network packets
    and placing them into a thread-safe queue.

    Works on both Linux and Windows.
    Requires:
    - Linux  : libpcap (usually pre-installed)
    - Windows: Npcap (https://npcap.com/) + run as Administrator
    """

    def __init__(self):
        self.packet_queue: queue.Queue = queue.Queue(maxsize=PACKET_QUEUE_SIZE)
        self.stop_event = threading.Event()
        self.capture_thread: Optional[threading.Thread] = None

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
        Validates capture backend before starting.
        """

        # ----------------------------------
        # Pre-flight check for capture backend
        # ----------------------------------
        if not check_capture_backend():
            os_name = platform.system().lower()
            if os_name == "windows":
                logger.error(
                    "CAPTURE FAILED: Npcap is not installed or not detected.\n"
                    "  → Download from: https://npcap.com/\n"
                    "  → During install, enable 'WinPcap API-compatible Mode'\n"
                    "  → Run this script as Administrator"
                )
            else:
                logger.error(
                    "CAPTURE FAILED: libpcap is not installed.\n"
                    "  → Install with: sudo apt install libpcap-dev (Debian/Ubuntu)\n"
                    "  → Or: sudo yum install libpcap-devel (RHEL/CentOS)"
                )
            raise RuntimeError(
                "Packet capture backend not available. See log for details."
            )

        def capture():
            try:
                logger.info(
                    f"Starting packet capture on interface: {interface}"
                )
                sniff(
                    iface=interface,
                    prn=self._packet_callback,
                    store=False,
                    stop_filter=lambda _: self.stop_event.is_set()
                )
            except PermissionError:
                logger.error(
                    "Permission denied. "
                    "Run with sudo (Linux) or as Administrator (Windows)."
                )
            except OSError as e:
                logger.error(
                    f"Failed to start capture on '{interface}': {e}\n"
                    "  → Check that the interface name is correct\n"
                    "  → On Windows, ensure Npcap is installed"
                )
            except Exception as e:
                logger.error(f"Unexpected capture error: {e}")

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
