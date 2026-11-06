
import streamlit as st
import pandas as pd
from collections import Counter

from packetpilot.packet_analyzer import PacketAnalyzer


# ==================================================
# PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="PacketPilot AI",
    page_icon="🛡️",
    layout="wide"
)


# ==================================================
# THREAT HUNTING ENGINE
# ==================================================

class ThreatHuntingEngine:

    def __init__(self):
        self.port_scan_threshold = 15
        self.network_scan_threshold = 10
        self.dns_query_threshold = 50
        self.icmp_threshold = 100
        self.source_packet_threshold = 500

    def hunt(self, results):

        packets = results.get("packets", pd.DataFrame())
        dns_queries = results.get("dns_queries", pd.DataFrame())

        findings = []

        def add_finding(severity, category, source, evidence, recommendation):
            findings.append({
                "severity": severity,
                "category": category,
                "source": source,
                "evidence": evidence,
                "recommendation": recommendation
            })

        if packets.empty:
            return pd.DataFrame(columns=[
                "severity",
                "category",
                "source",
                "evidence",
                "recommendation"
            ])

        required_columns = {
            "source",
            "destination",
            "protocol",
            "destination_port"
        }

        if not required_columns.issubset(packets.columns):
            raise ValueError("Packet analysis data is missing required columns.")

        tcp_packets = packets[
            packets["protocol"] == "TCP"
        ]

        # ------------------------------------------
        # 1. TCP PORT SCAN DETECTION
        # ------------------------------------------

        for source, group in tcp_packets.groupby("source"):

            unique_ports = group[
                "destination_port"
            ].dropna().nunique()

            if unique_ports >= self.port_scan_threshold:

                add_finding(
                    "High",
                    "Possible TCP Port Scan",
                    source,
                    f"{unique_ports} distinct destination ports observed.",
                    "Investigate connection attempts and source host."
                )

        # ------------------------------------------
        # 2. NETWORK SCAN DETECTION
        # ------------------------------------------

        for source, group in tcp_packets.groupby("source"):

            destinations = group[
                "destination"
            ].nunique()

            if destinations >= self.network_scan_threshold:

                add_finding(
                    "High",
                    "Possible Network Scan",
                    source,
                    f"Traffic contacted {destinations} destinations.",
                    "Investigate destination hosts and traffic patterns."
                )

        # ------------------------------------------
        # 3. DNS QUERY VOLUME
        # ------------------------------------------

        if not dns_queries.empty:

            dns_counts = Counter(
                dns_queries["source"].dropna()
            )

            for source, count in dns_counts.items():

                if count >= self.dns_query_threshold:

                    add_finding(
                        "Medium",
                        "High DNS Query Volume",
                        source,
                        f"{count} DNS queries observed.",
                        "Investigate queried domains and DNS activity."
                    )

            # --------------------------------------
            # 4. LONG DNS DOMAIN DETECTION
            # --------------------------------------

            for _, row in dns_queries.iterrows():

                domain = str(row.get("domain", ""))

                if len(domain) >= 60:

                    add_finding(
                        "Medium",
                        "Unusually Long DNS Domain",
                        row.get("source", "Unknown"),
                        f"Domain length: {len(domain)} characters.",
                        "Investigate possible encoded subdomains or tunneling."
                    )

        # ------------------------------------------
        # 5. ICMP TRAFFIC DETECTION
        # ------------------------------------------

        icmp_packets = packets[
            packets["protocol"] == "ICMP"
        ]

        icmp_counts = Counter(
            icmp_packets["source"].dropna()
        )

        for source, count in icmp_counts.items():

            if count >= self.icmp_threshold:

                add_finding(
                    "Medium",
                    "High ICMP Traffic",
                    source,
                    f"{count} ICMP packets observed.",
                    "Investigate possible unusual ICMP activity."
                )

        # ------------------------------------------
        # 6. HIGH SOURCE TRAFFIC VOLUME
        # ------------------------------------------

        source_counts = Counter(
            packets["source"].dropna()
        )

        for source, count in source_counts.items():

            if count >= self.source_packet_threshold:

                add_finding(
                    "Medium",
                    "High Source Traffic Volume",
                    source,
                    f"{count} packets observed from this source.",
                    "Investigate traffic distribution and host activity."
                )

        return pd.DataFrame(
            findings,
            columns=[
                "severity",
                "category",
                "source",
                "evidence",
                "recommendation"
            ]
        )


# ==================================================
# APPLICATION HEADER
# ==================================================

st.title("🛡️ PacketPilot AI")

st.subheader("Network Traffic Analyzer")

st.write(
    "Analyze network traffic, investigate DNS activity "
    "and identify suspicious network behavior."
)

st.divider()


# ==================================================
# FILE UPLOAD
# ==================================================

uploaded_file = st.file_uploader(
    "Upload Wireshark Capture",
    type=["pcap", "pcapng"]
)


# ==================================================
# MAIN ANALYSIS
# ==================================================

if uploaded_file is not None:

    st.info(f"Selected capture: {uploaded_file.name}")

    if st.button("🚀 Analyze Network Traffic", type="primary"):

        try:

            analyzer = PacketAnalyzer(
                max_packets=100000
            )

            with st.spinner("Analyzing network packets..."):

                results = analyzer.analyze_uploaded_file(
                    uploaded_file
                )

            summary = results["summary"]

            st.success("Packet analysis completed!")

            # ======================================
            # NETWORK SUMMARY
            # ======================================

            st.header("📊 Network Summary")

            col1, col2, col3, col4 = st.columns(4)

            col1.metric(
                "Total Packets",
                summary["total_packets"]
            )

            col2.metric(
                "TCP Packets",
                summary["tcp_packets"]
            )

            col3.metric(
                "UDP Packets",
                summary["udp_packets"]
            )

            col4.metric(
                "Total Bytes",
                f'{summary["total_bytes"]:,}'
            )

            col5, col6, col7, col8 = st.columns(4)

            col5.metric("ICMP", summary["icmp_packets"])
            col6.metric("ARP", summary["arp_packets"])
            col7.metric("Unique Sources", summary["unique_sources"])
            col8.metric("Unique Destinations", summary["unique_destinations"])

            # ======================================
            # PROTOCOL ANALYSIS
            # ======================================

            st.divider()
            st.header("🌐 Protocol Intelligence")

            protocol_df = pd.DataFrame(
                list(results["protocol_counts"].items()),
                columns=["Protocol", "Packets"]
            )

            if not protocol_df.empty:

                st.bar_chart(
                    protocol_df.set_index("Protocol")
                )

                st.dataframe(
                    protocol_df,
                    use_container_width=True
                )

            # ======================================
            # SOURCE IP ANALYSIS
            # ======================================

            st.divider()
            st.header("📍 Source IP Analysis")

            source_df = pd.DataFrame(
                list(results["source_counts"].items()),
                columns=["Source IP", "Packets"]
            )

            if not source_df.empty:

                st.dataframe(
                    source_df.sort_values(
                        "Packets",
                        ascending=False
                    ),
                    use_container_width=True
                )

            # ======================================
            # DESTINATION IP ANALYSIS
            # ======================================

            st.divider()
            st.header("🎯 Destination IP Analysis")

            destination_df = pd.DataFrame(
                list(results["destination_counts"].items()),
                columns=["Destination IP", "Packets"]
            )

            if not destination_df.empty:

                st.dataframe(
                    destination_df.sort_values(
                        "Packets",
                        ascending=False
                    ),
                    use_container_width=True
                )

            # ======================================
            # DNS INVESTIGATION
            # ======================================

            st.divider()
            st.header("🔎 DNS Investigation")

            dns_df = results["dns_queries"]

            if not dns_df.empty:

                st.dataframe(
                    dns_df,
                    use_container_width=True
                )

            else:

                st.info("No DNS queries detected.")

            # ======================================
            # PACKET SECURITY ALERTS
            # ======================================

            st.divider()
            st.header("🚨 Packet Security Indicators")

            alerts_df = results["alerts"]

            if not alerts_df.empty:

                st.dataframe(
                    alerts_df,
                    use_container_width=True
                )

            else:

                st.success("No packet analyzer indicators detected.")

            # ======================================
            # THREAT HUNTING WORKBENCH
            # ======================================

            st.divider()
            st.header("🔬 Threat Hunting Workbench")

            hunter = ThreatHuntingEngine()

            findings = hunter.hunt(results)

            high_count = (
                len(findings[findings["severity"] == "High"])
                if not findings.empty else 0
            )

            medium_count = (
                len(findings[findings["severity"] == "Medium"])
                if not findings.empty else 0
            )

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "Total Findings",
                len(findings)
            )

            col2.metric(
                "High Severity",
                high_count
            )

            col3.metric(
                "Medium Severity",
                medium_count
            )

            if not findings.empty:

                st.subheader("Investigation Findings")

                st.dataframe(
                    findings,
                    use_container_width=True
                )

                st.subheader("Threat Severity Distribution")

                st.bar_chart(
                    findings["severity"].value_counts()
                )

                findings_csv = findings.to_csv(
                    index=False
                ).encode("utf-8")

                st.download_button(
                    "Download Threat Hunting Report",
                    data=findings_csv,
                    file_name="threat_hunting_report.csv",
                    mime="text/csv"
                )

            else:

                st.success(
                    "No threat hunting indicators detected."
                )

            # ======================================
            # PACKET DETAILS
            # ======================================

            st.divider()
            st.header("📦 Packet Details")

            packet_df = results["packets"]

            if not packet_df.empty:

                st.dataframe(
                    packet_df,
                    use_container_width=True
                )

                packet_csv = packet_df.to_csv(
                    index=False
                ).encode("utf-8")

                st.download_button(
                    "Download Packet Analysis CSV",
                    data=packet_csv,
                    file_name="packet_analysis.csv",
                    mime="text/csv"
                )

            # ======================================
            # COMPLETION
            # ======================================

            st.divider()

            st.success(
                "PacketPilot AI analysis completed successfully."
            )

            st.caption(
                "Threat hunting findings are heuristic investigation "
                "indicators, not confirmation of malicious activity."
            )

        except Exception as error:

            st.error(
                f"Analysis failed: {error}"
            )

else:

    st.info(
        "Upload a PCAP or PCAPNG file to begin analysis."
    )

