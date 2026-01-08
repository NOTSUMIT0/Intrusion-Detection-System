# ==============================
# IDS Global Configuration
# ==============================

# Network
NETWORK_INTERFACE = "eth0"

# Detection thresholds
ANOMALY_SCORE_THRESHOLD = -0.5
SIGNATURE_PACKET_RATE_THRESHOLD = 100

# Queue & performance
PACKET_QUEUE_SIZE = 1000

# Logging
LOG_FILE_PATH = "data/logs/ids_alerts.log"

# Feature safety
MIN_FLOW_DURATION = 0.0001
