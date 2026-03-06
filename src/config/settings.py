# ==============================
# IDS Global Configuration
# ==============================

import platform
import logging

logger = logging.getLogger("IDS-Settings")


def detect_network_interface() -> str:
    """
    Auto-detects the default network interface
    for the current OS.

    - Linux  → defaults to 'eth0'
    - Windows → uses Scapy's conf.iface (auto-detected)
    - macOS  → defaults to 'en0'

    Returns the interface name as a string.
    """
    os_name = platform.system().lower()

    if os_name == "windows":
        try:
            from scapy.all import conf
            iface = conf.iface
            if iface:
                logger.info(f"Auto-detected Windows interface: {iface}")
                return str(iface)
            else:
                logger.warning(
                    "Scapy could not auto-detect a Windows interface. "
                    "Ensure Npcap is installed (https://npcap.com/)."
                )
                return "Ethernet"
        except Exception as e:
            logger.warning(
                f"Failed to detect Windows interface: {e}. "
                "Ensure Npcap is installed with WinPcap API-compatible mode."
            )
            return "Ethernet"

    elif os_name == "darwin":
        return "en0"

    else:
        # Linux and other Unix-like systems
        return "eth0"


def check_capture_backend() -> bool:
    """
    Checks whether the packet capture backend
    (Npcap on Windows, libpcap on Linux) is available.

    Returns True if capture is possible, False otherwise.
    """
    os_name = platform.system().lower()

    if os_name == "windows":
        try:
            from scapy.all import conf
            # Attempt to access the pcap layer — this will fail
            # if Npcap is not installed
            if conf.use_pcap:
                return True
            # Fallback: try to list interfaces
            from scapy.all import get_windows_if_list
            ifaces = get_windows_if_list()
            return len(ifaces) > 0
        except Exception:
            return False
    else:
        # On Linux/macOS, libpcap is almost always available
        try:
            from scapy.all import conf
            return True
        except Exception:
            return False


# ==============================
# Resolved Configuration Values
# ==============================

# Network
NETWORK_INTERFACE = detect_network_interface()

# Detection thresholds
ANOMALY_SCORE_THRESHOLD = -0.5
SIGNATURE_PACKET_RATE_THRESHOLD = 100

# Queue & performance
PACKET_QUEUE_SIZE = 1000

# Logging
LOG_FILE_PATH = "data/logs/ids_alerts.log"

# Feature safety
MIN_FLOW_DURATION = 0.0001
