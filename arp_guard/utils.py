import csv
import os
from datetime import datetime


def export_logs_to_csv(event_logs, output_dir="logs"):
    """Exports captured security events to a timestamped CSV file."""
    if not event_logs:
        return None, "No logs available to export yet."

    os.makedirs(output_dir, exist_ok=True)
    filename = f"arp_security_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = os.path.join(output_dir, filename)

    try:
        with open(filepath, mode="w", newline="", encoding="utf-8") as csv_file:
            fieldnames = ["timestamp", "severity", "src_ip", "src_mac", "dst_ip", "message"]
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for event in event_logs:
                writer.writerow(event)
        return filepath, f"Successfully exported {len(event_logs)} logs to {filepath}"
    except Exception as e:
        return None, f"Failed to export CSV: {str(e)}"


def get_prevention_recommendations():
    """Returns actionable defense & prevention strategies against ARP Spoofing."""
    return [
        (
            "1. Dynamic ARP Inspection (DAI) on Managed Switches",
            "Configure DAI on enterprise switches (Cisco/Juniper). DAI intercepts all ARP packets "
            "and validates IP-to-MAC bindings against a trusted DHCP Snooping database before forwarding."
        ),
        (
            "2. Static ARP Entries for Critical Infrastructure",
            "Bind your Default Gateway's IP and MAC statically on critical servers and admin workstations "
            "(e.g., 'arp -s 192.168.100.1 18:d6:dd:1e:80:68') so spoofed ARP replies are ignored."
        ),
        (
            "3. DHCP Snooping & Port Security",
            "Enable DHCP Snooping to block rogue DHCP servers, and enable Switch Port Security to limit "
            "the number of MAC addresses allowed per physical switch port."
        ),
        (
            "4. Network Segmentation (VLANs)",
            "Isolate sensitive servers, IoT devices, and guest Wi-Fi into separate VLANs. Since ARP is a "
            "Layer 2 broadcast protocol, VLANs strictly contain the blast radius of ARP spoofing."
        ),
        (
            "5. End-to-End Encryption (HTTPS, SSH, VPN)",
            "Enforce TLS/HTTPS, SSH, and VPNs across the network. Even if an attacker achieves a Layer 2 "
            "Man-in-the-Middle (MitM) position, encrypted payloads cannot be read or altered."
        ),
        (
            "6. Active ARP Monitoring & Intrusion Detection (IDS)",
            "Deploy continuous ARP monitoring tools (like this ARP Guard system or Arpwatch) to generate "
            "real-time SOC alerts whenever duplicate MACs or gateway impersonations occur."
        ),
    ]
