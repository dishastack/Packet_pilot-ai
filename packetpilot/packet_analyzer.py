
from collections import Counter, defaultdict
from datetime import datetime
from io import BytesIO
import os

import pandas as pd

from scapy.all import (
    rdpcap,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
    DNSQR,
)


class PacketAnalyzer:
    """
    PacketPilot AI - Network Packet Analyzer.

    Detection results are investigation indicators,
    not proof of malicious activity.
    """

    def __init__(self, max_packets=100000):
        self.max_packets = max_packets

    def analyze_pcap(self, file_path):
        """Analyze a PCAP or PCAPNG file from a filesystem path."""
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Capture file not found: {file_path}")

        packets = rdpcap(file_path, count=self.max_packets)
        return self.analyze_packets(packets)

    def analyze_uploaded_file(self, uploaded_file):
        """Analyze a Streamlit-style uploaded file."""
        content = uploaded_file.getvalue()
        packets = rdpcap(BytesIO(content), count=self.max_packets)
        return self.analyze_packets(packets)

    def analyze_packets(self, packets):
        """Analyze a Scapy packet collection."""
        protocol_counts = Counter()
        source_counts = Counter()
        destination_counts = Counter()
        port_counts = Counter()
        dns_queries = []
        packet_records = []
        syn_sources = defaultdict(set)
        alerts = []

        total_bytes = 0
        tcp_count = 0
        udp_count = 0
        icmp_count = 0
        arp_count = 0

        for packet_number, packet in enumerate(packets, start=1):
            packet_size = len(packet)
            total_bytes += packet_size

            timestamp = datetime.fromtimestamp(
                float(packet.time)
            ).isoformat(timespec="seconds")

            source = "Unknown"
            destination = "Unknown"
            protocol = "OTHER"
            source_port = None
            destination_port = None

            if IP in packet:
                source = packet[IP].src
                destination = packet[IP].dst
                protocol = "IPv4"

            elif IPv6 in packet:
                source = packet[IPv6].src
                destination = packet[IPv6].dst
                protocol = "IPv6"

            if TCP in packet:
                protocol = "TCP"
                tcp_count += 1

                source_port = int(packet[TCP].sport)
                destination_port = int(packet[TCP].dport)

                port_counts[destination_port] += 1

                flags = packet[TCP].flags

                # SYN without ACK: connection initiation indicator.
                if flags & 0x02 and not flags & 0x10:
                    if source != "Unknown":
                        syn_sources[source].add(destination)

            elif UDP in packet:
                protocol = "UDP"
                udp_count += 1

                source_port = int(packet[UDP].sport)
                destination_port = int(packet[UDP].dport)

                port_counts[destination_port] += 1

            elif ICMP in packet:
                protocol = "ICMP"
                icmp_count += 1

            elif ARP in packet:
                protocol = "ARP"
                arp_count += 1

                source = packet[ARP].psrc
                destination = packet[ARP].pdst

            if DNS in packet and packet[DNS].qd is not None:
                try:
                    query = packet[DNS].qd

                    if DNSQR in packet:
                        domain = query.qname.decode(
                            "utf-8", errors="replace"
                        ).rstrip(".")

                        dns_queries.append({
                            "source": source,
                            "domain": domain,
                            "timestamp": timestamp,
                        })

                except (AttributeError, UnicodeDecodeError):
                    pass

            protocol_counts[protocol] += 1

            if source != "Unknown":
                source_counts[source] += 1

            if destination != "Unknown":
                destination_counts[destination] += 1

            packet_records.append({
                "packet_number": packet_number,
                "timestamp": timestamp,
                "source": source,
                "destination": destination,
                "protocol": protocol,
                "source_port": source_port,
                "destination_port": destination_port,
                "size_bytes": packet_size,
            })

        # Generate investigation indicators.
        for source, destinations in syn_sources.items():
            if len(destinations) >= 10:
                alerts.append({
                    "severity": "High",
                    "type": "Possible SYN Scan",
                    "source": source,
                    "description": (
                        f"Observed SYN packets from {source} "
                        f"to {len(destinations)} different destinations."
                    ),
                })

        if not packets:
            alerts.append({
                "severity": "Info",
                "type": "Empty Capture",
                "source": "N/A",
                "description": "No packets were found in this capture.",
            })

        packet_df = pd.DataFrame(packet_records)
        dns_df = pd.DataFrame(
            dns_queries,
            columns=["source", "domain", "timestamp"]
        )
        alerts_df = pd.DataFrame(
            alerts,
            columns=["severity", "type", "source", "description"]
        )

        return {
            "summary": {
                "total_packets": len(packets),
                "total_bytes": total_bytes,
                "tcp_packets": tcp_count,
                "udp_packets": udp_count,
                "icmp_packets": icmp_count,
                "arp_packets": arp_count,
                "unique_sources": len(source_counts),
                "unique_destinations": len(destination_counts),
            },
            "protocol_counts": dict(protocol_counts),
            "source_counts": dict(source_counts),
            "destination_counts": dict(destination_counts),
            "port_counts": dict(port_counts),
            "dns_queries": dns_df,
            "alerts": alerts_df,
            "packets": packet_df,
        }
