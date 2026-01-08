from scapy.all import IP, TCP
from src.analysis.traffic_analyzer import TrafficAnalyzer

analyzer = TrafficAnalyzer()

packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(
    sport=1234, dport=80, flags="S"
)
packet.time = 1.0

features = analyzer.analyze(packet)
print(features)
