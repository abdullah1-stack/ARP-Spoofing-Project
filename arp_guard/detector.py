import time
import subprocess
import re
from datetime import datetime


class ARPDetector:
    def __init__(self):
        # Stores trusted IP -> MAC mappings: { "192.168.100.1": "18:d6:dd:1e:80:68" }
        self.ip_mac_map = {}
        
        # Tracks which IPs are claimed by a MAC: { "aa:bb:cc:dd:ee:ff": {"192.168.100.1", "192.168.100.17"} }
        self.mac_ip_map = {}
        
        # Tracks recent ARP requests to distinguish solicited vs. unsolicited replies
        # Format: { target_ip: timestamp }
        self.recent_requests = {}
        
        # Tracks device status: "Normal", "Suspicious", or "Attack Detected"
        self.device_status = {}
        
        # Statistics counters
        self.total_packets = 0
        self.normal_packets = 0
        self.suspicious_events = 0
        
        # Event logs list for GUI and CSV export
        self.event_logs = []
        
        # Auto-detect the default gateway IP and MAC
        self.gateway_ip, self.gateway_mac = self._get_gateway_info()

    def _get_gateway_info(self):
        """Finds the local router's IP and MAC from the Linux routing/ARP table."""
        gw_ip = None
        gw_mac = None
        try:
            route_out = subprocess.check_output(["ip", "route"], text=True)
            match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", route_out)
            if match:
                gw_ip = match.group(1)
                arp_out = subprocess.check_output(["ip", "neigh", "show", gw_ip], text=True)
                mac_match = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", arp_out)
                if mac_match:
                    gw_mac = mac_match.group(1).lower()
        except Exception:
            pass
        return gw_ip, gw_mac

    def reset_state(self):
        """Clears cached tables when monitoring restarts."""
        self.ip_mac_map.clear()
        self.mac_ip_map.clear()
        self.recent_requests.clear()
        self.device_status.clear()
        self.total_packets = 0
        self.normal_packets = 0
        self.suspicious_events = 0
        self.event_logs.clear()
        self.gateway_ip, self.gateway_mac = self._get_gateway_info()

    def analyze_packet(self, op, src_ip, src_mac, dst_ip):
        """
        Analyzes a single ARP packet and returns an event dictionary:
        {timestamp, severity, src_ip, src_mac, dst_ip, message}
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_mac = src_mac.lower()
        self.total_packets += 1

        # Ignore zero/probe IPs (0.0.0.0 used during DHCP discovery)
        if src_ip == "0.0.0.0":
            self.normal_packets += 1
            return self._log_event(timestamp, "INFO", src_ip, src_mac, dst_ip, "DHCP ARP Probe (0.0.0.0) - Ignored")

        # Record ARP Requests (op == 1) so we know a reply was genuinely requested
        if op == 1:
            self.recent_requests[dst_ip] = time.time()

        # Check if this is a brand-new IP we haven't seen yet
        if src_ip not in self.ip_mac_map:
            # Before trusting a new IP, check if this MAC is already impersonating another IP!
            if src_mac in self.mac_ip_map and len(self.mac_ip_map[src_mac]) >= 1:
                existing_ips = ", ".join(self.mac_ip_map[src_mac])
                self.suspicious_events += 1
                self.device_status[src_ip] = "Suspicious"
                self.mac_ip_map[src_mac].add(src_ip)
                self.ip_mac_map[src_ip] = src_mac
                msg = f"MULTI-IP MAC ANOMALY: MAC {src_mac} now claims {src_ip} (already owns {existing_ips})"
                return self._log_event(timestamp, "WARNING", src_ip, src_mac, dst_ip, msg)

            # Normal first-time discovery
            self.ip_mac_map[src_ip] = src_mac
            self.mac_ip_map.setdefault(src_mac, set()).add(src_ip)
            self.device_status[src_ip] = "Normal"
            self.normal_packets += 1
            pkt_label = "ARP Request" if op == 1 else "ARP Reply"
            return self._log_event(timestamp, "NORMAL", src_ip, src_mac, dst_ip, f"New device mapped via {pkt_label}")

        # Case 2: Known IP seen again — check if MAC address matches our baseline
        known_mac = self.ip_mac_map[src_ip]
        if known_mac == src_mac:
            self.normal_packets += 1
            if src_ip not in self.device_status:
                self.device_status[src_ip] = "Normal"
            pkt_label = "ARP Request" if op == 1 else "ARP Reply"
            return self._log_event(timestamp, "NORMAL", src_ip, src_mac, dst_ip, f"Verified {pkt_label} ({src_ip} -> {dst_ip})")

        # Case 3: MAC ADDRESS CONFLICT DETECTED! Apply false-positive reduction heuristics
        is_gateway = (self.gateway_ip and src_ip == self.gateway_ip)
        was_requested = (src_ip in self.recent_requests) and ((time.time() - self.recent_requests[src_ip]) < 5.0)
        mac_owns_other_ips = (src_mac in self.mac_ip_map and len(self.mac_ip_map[src_mac]) >= 1)

        self.suspicious_events += 1

        # High-confidence ARP Spoofing conditions:
        # 1) Gateway MAC spoofing, OR
        # 2) Unsolicited ARP Reply (op == 2 without a recent request), OR
        # 3) Attacker MAC already mapped to another IP (MitM signature)
        if is_gateway or (op == 2 and not was_requested) or mac_owns_other_ips:
            self.device_status[src_ip] = "Attack Detected"
            reason = "Gateway Impersonation" if is_gateway else (
                "Duplicate MAC MitM Signature" if mac_owns_other_ips else "Unsolicited ARP Reply"
            )
            msg = (
                f"CRITICAL ALERT [{reason}]: IP {src_ip} MAC changed from "
                f"{known_mac} to {src_mac}!"
            )
            return self._log_event(timestamp, "ALERT", src_ip, src_mac, dst_ip, msg)
        else:
            # Single solicited change (possible legitimate NIC replacement or DHCP lease renewal)
            self.device_status[src_ip] = "Suspicious"
            msg = (
                f"SUSPICIOUS MAC CHANGE (Possible DHCP/NIC change): IP {src_ip} changed "
                f"from {known_mac} to {src_mac}. Monitoring closely."
            )
            return self._log_event(timestamp, "WARNING", src_ip, src_mac, dst_ip, msg)

    def _log_event(self, timestamp, severity, src_ip, src_mac, dst_ip, message):
        event = {
            "timestamp": timestamp,
            "severity": severity,
            "src_ip": src_ip,
            "src_mac": src_mac,
            "dst_ip": dst_ip,
            "message": message,
        }
        self.event_logs.append(event)
        return event


# Quick standalone test to verify detection rules before building the GUI
if __name__ == "__main__":
    detector = ARPDetector()
    print(f"Detected Gateway: {detector.gateway_ip} ({detector.gateway_mac})\n")

    # 1. Simulate normal router traffic
    print(detector.analyze_packet(1, "192.168.100.1", "18:d6:dd:1e:80:68", "192.168.100.17"))
    # 2. Simulate normal Windows traffic
    print(detector.analyze_packet(2, "192.168.100.17", "aa:bb:cc:11:22:33", "192.168.100.1"))
    # 3. Simulate an attacker spoofing the router IP with a fake MAC!
    print(detector.analyze_packet(2, "192.168.100.1", "de:ad:be:ef:00:01", "192.168.100.17"))
