from collections import defaultdict
import time

class TrafficAnalyzer:
    def __init__(self):
        self.flows = defaultdict(lambda: {
            "packet_count": 0,
            "byte_count": 0,
            "start": None,
            "last": None
        })

    def analyze(self, packet):
        ip = packet["IP"]
        tcp = packet["TCP"]

        key = (ip.src, ip.dst, tcp.sport, tcp.dport)
        flow = self.flows[key]

        now = packet.time
        if flow["start"] is None:
            flow["start"] = now

        flow["packet_count"] += 1
        flow["byte_count"] += len(packet)
        flow["last"] = now

        duration = max(now - flow["start"], 0.0001)

        return {
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "packet_size": len(packet),
            "packet_rate": flow["packet_count"] / duration,
            "byte_rate": flow["byte_count"] / duration,
            "tcp_flags": str(tcp.flags)
        }
