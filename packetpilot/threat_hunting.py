
from collections import Counter, defaultdict
import pandas as pd


class ThreatHuntingEngine:
    """
    PacketPilot AI Threat Hunting Engine.

    Generates investigation indicators from packet metadata.
    Findings are not proof of malicious activity.
    """

    def __init__(
        self,
        port_scan_threshold=15,
        dns_query_threshold=50,
        icmp_threshold=100,
        source_packet_threshold=500
    ):
        self.port_scan_threshold = port_scan_threshold
        self.dns_query_threshold = dns_query_threshold
        self.icmp_threshold = icmp_threshold
        self.source_packet_threshold = source_packet_threshold

    def hunt(self, analysis_results):
        packets = analysis_results.get("packets", pd.DataFrame())
        dns_queries = analysis_results.get("dns_queries", pd.DataFrame())

        findings = []

        if packets.empty:
            return {
                "total_findings": 0,
                "findings": pd.DataFrame(
                    columns=[
                        "severity", "category", "source",
                        "evidence", "recommendation"
                    ]
                )
            }

        required = {
            "source", "destination", "protocol",
            "destination_port"
        }

        if not required.issubset(packets.columns):
            raise ValueError(
                "Packet data is missing required columns."
            )

        def add_finding(severity, category, source, evidence, recommendation):
            findings.append({
                "severity": severity,
                "category": category,
                "source": source,
                "evidence": evidence,
                "recommendation": recommendation
            })

        # 1. Possible TCP port scanning
        tcp_packets = packets[
            packets["protocol"] == "TCP"
        ]

        for source, group in tcp_packets.groupby("source"):
            unique_ports = group["destination_port"].dropna().nunique()

            if unique_ports >= self.port_scan_threshold:
                add_finding(
                    "High",
                    "Possible Port Scan",
                    source,
                    f"Traffic contacted {unique_ports} distinct destination ports.",
                    "Investigate connection attempts and verify the source host."
                )

        # 2. Possible horizontal network scanning
        for source, group in tcp_packets.groupby("source"):
            unique_destinations = group["destination"].nunique()

            if unique_destinations >= 10:
                add_finding(
                    "High",
                    "Possible Network Scan",
                    source,
                    f"TCP traffic contacted {unique_destinations} different destinations.",
                    "Review destination hosts and connection patterns."
                )

        # 3. High-volume DNS queries
        if not dns_queries.empty and "source" in dns_queries.columns:
            dns_counts = Counter(dns_queries["source"].dropna())

            for source, count in dns_counts.items():
                if count >= self.dns_query_threshold:
                    add_finding(
                        "Medium",
                        "High DNS Query Volume",
                        source,
                        f"Observed {count} DNS queries.",
                        "Inspect queried domains and check for unusual DNS activity."
                    )

            # 4. Unusually long DNS domains
            if "domain" in dns_queries.columns:
                for _, row in dns_queries.iterrows():
                    domain = str(row["domain"])

                    if len(domain) >= 60:
                        add_finding(
                            "Medium",
                            "Long DNS Domain",
                            row["source"],
                            f"Observed a DNS domain with {len(domain)} characters.",
                            "Inspect the domain and investigate possible encoded subdomains."
                        )

        # 5. High-volume ICMP traffic
        icmp_packets = packets[
            packets["protocol"] == "ICMP"
        ]

        icmp_counts = Counter(icmp_packets["source"].dropna())

        for source, count in icmp_counts.items():
            if count >= self.icmp_threshold:
                add_finding(
                    "Medium",
                    "High ICMP Volume",
                    source,
                    f"Observed {count} ICMP packets.",
                    "Check whether the traffic is expected diagnostic activity."
                )

        # 6. High packet volume from a single source
        source_counts = Counter(packets["source"].dropna())

        for source, count in source_counts.items():
            if count >= self.source_packet_threshold:
                add_finding(
                    "Medium",
                    "High Source Traffic Volume",
                    source,
                    f"Observed {count} packets from this source.",
                    "Review traffic volume, destination distribution and host activity."
                )

        findings_df = pd.DataFrame(
            findings,
            columns=[
                "severity",
                "category",
                "source",
                "evidence",
                "recommendation"
            ]
        )

        return {
            "total_findings": len(findings_df),
            "findings": findings_df
        }
