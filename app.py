
import streamlit as st
import pandas as pd

from packetpilot.packet_analyzer import PacketAnalyzer

st.set_page_config(
    page_title="PacketPilot AI",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ PacketPilot AI")
st.subheader("Network Traffic Analyzer")

st.write(
    "Upload a Wireshark PCAP or PCAPNG capture "
    "to investigate network traffic."
)

uploaded_file = st.file_uploader(
    "Upload network capture",
    type=["pcap", "pcapng"]
)

if uploaded_file is not None:
    if st.button("Analyze Network Traffic"):
        try:
            analyzer = PacketAnalyzer(max_packets=100000)

            with st.spinner("Analyzing packets..."):
                results = analyzer.analyze_uploaded_file(
                    uploaded_file
                )

            summary = results["summary"]

            st.success("Packet analysis completed!")

            st.header("Network Summary")

            col1, col2, col3, col4 = st.columns(4)

            col1.metric("Total Packets", summary["total_packets"])
            col2.metric("TCP", summary["tcp_packets"])
            col3.metric("UDP", summary["udp_packets"])
            col4.metric("Total Bytes", summary["total_bytes"])

            st.header("Protocol Distribution")
            protocol_df = pd.DataFrame(
                list(results["protocol_counts"].items()),
                columns=["Protocol", "Packets"]
            )

            if not protocol_df.empty:
                st.bar_chart(
                    protocol_df.set_index("Protocol")
                )

            st.header("Source IP Addresses")
            st.dataframe(
                pd.DataFrame(
                    list(results["source_counts"].items()),
                    columns=["Source IP", "Packets"]
                ),
                use_container_width=True
            )

            st.header("DNS Investigation")
            st.dataframe(
                results["dns_queries"],
                use_container_width=True
            )

            st.header("Security Indicators")
            st.dataframe(
                results["alerts"],
                use_container_width=True
            )

            st.header("Packet Details")
            st.dataframe(
                results["packets"],
                use_container_width=True
            )

        except Exception as error:
            st.error(f"Analysis failed: {error}")
