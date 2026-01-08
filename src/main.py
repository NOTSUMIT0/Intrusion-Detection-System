from capture.packet_capture import PacketCapture
from analysis.traffic_analyzer import TrafficAnalyzer
from detection.detection_engine import DetectionEngine
from alerts.alert_system import AlertSystem
import queue

def main():
    capture = PacketCapture()
    analyzer = TrafficAnalyzer()
    detector = DetectionEngine("data/signatures/signature_rules.json")
    alert_sys = AlertSystem()

    capture.start("eth0")
    print("IDS running... Press Ctrl+C to stop")

    try:
        while True:
            packet = capture.packet_queue.get(timeout=1)
            features = analyzer.analyze(packet)
            threats = detector.detect(features)

            for threat in threats:
                alert_sys.alert(threat, features)

    except KeyboardInterrupt:
        capture.stop()
        print("IDS stopped")

if __name__ == "__main__":
    main()
