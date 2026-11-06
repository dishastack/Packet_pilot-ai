
import streamlit as st
import pandas as pd

from packetpilot.threat_hunting import ThreatHuntingEngine


def show_threat_hunting(results):

    st.divider()
    st.header("🔬 Threat Hunting Workbench")

    try:
        hunter = ThreatHuntingEngine()
        findings = hunter.hunt(results)

        if findings is None or findings.empty:
            st.success(
                "No threat hunting indicators detected."
            )
            return

        # Severity metrics
        high_count = len(
            findings[findings["severity"] == "High"]
        )

        medium_count = len(
            findings[findings["severity"] == "Medium"]
        )

        low_count = len(
            findings[findings["severity"] == "Low"]
        )

        col1, col2, col3, col4 = st.columns(4)

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

        col4.metric(
            "Low Severity",
            low_count
        )

        # Findings table
        st.subheader("Investigation Findings")

        severity_filter = st.multiselect(
            "Filter by severity",
            options=["High", "Medium", "Low"],
            default=["High", "Medium", "Low"]
        )

        filtered_findings = findings[
            findings["severity"].isin(severity_filter)
        ]

        st.dataframe(
            filtered_findings,
            use_container_width=True
        )

        # Severity chart
        st.subheader("Severity Distribution")

        severity_counts = findings[
            "severity"
        ].value_counts()

        st.bar_chart(severity_counts)

        # Download report
        report = findings.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            label="Download Threat Hunting Report",
            data=report,
            file_name="threat_hunting_report.csv",
            mime="text/csv"
        )

    except Exception as error:
        st.error(
            f"Threat Hunting error: {error}"
        )

