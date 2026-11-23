import threading
import scapy.all as scapy


class BackgroundARPSniffer:
    def __init__(self, interface, packet_callback, error_callback=None):
        self.interface = interface
        self.packet_callback = packet_callback
        self.error_callback = error_callback
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def _handle_packet(self, packet):
        if packet.haslayer(scapy.ARP):
            arp = packet[scapy.ARP]
            self.packet_callback(arp.op, arp.psrc, arp.hwsrc, arp.pdst)

    def _sniff_loop(self):
        try:
            while not self._stop_event.is_set():
                scapy.sniff(
                    iface=self.interface,
                    filter="arp",
                    prn=self._handle_packet,
                    store=False,
                    stop_filter=lambda _: self._stop_event.is_set(),
                    timeout=2,
                )
        except PermissionError:
            if self.error_callback:
                self.error_callback("Permission Denied: Please run the application with 'sudo python3 main.py'.")
        except Exception as e:
            if self.error_callback:
                self.error_callback(f"Sniffer Error on '{self.interface}': {str(e)}")
