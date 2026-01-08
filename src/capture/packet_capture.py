from scapy.all import sniff, IP, TCP
import threading
import queue

class PacketCapture:
  def __init__(self):
    self.packet_queue = queue.Queue(maxsize=1000)
    self.stop_event = threading.Event()

  def _packet_callback(self, packet):
    if IP in packet and TCP in packet:
      try:
        self.packet_queue.put_nowait(packet)
      except queue.Full:
        pass  # Drop packet if queue is full

  def start(self, interface="eth0"):
    def run():
      sniff(iface=interface, prn=self._packet_callback, store=False,
            stop_filter=lambda _: self.stop_event.is_set())
      
    self.thread = threading.Thread(target=run, daemon=True)
    self.thread.start()

  def stop(self):
    self.stop_event.set()
    self.thread.join()


