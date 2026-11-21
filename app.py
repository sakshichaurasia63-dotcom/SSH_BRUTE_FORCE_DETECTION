
import streamlit as st
import pandas as pd
import plotly.express as px

from log_reader import read_logs
from log_parser import parse_log
from detector import detect_brute_force
from database import get_alerts

# Page configuration
st.set_page_config(
    page_title="SSH Sentinel",
    page_icon="🛡️",
    layout="wide"
)

# Dashboard heading
st.title("🛡️ SSH SENTINEL")
st.subheader("SSH Brute-Force Detection & Security Monitoring")

st.caption("Defensive cybersecurity monitoring dashboard")

st.info("Demo mode: Dashboard is analyzing simulated SSH authentication logs.")

# Read and parse logs
logs = read_logs()

events = []

for line in logs:
    result = parse_log(line)
    if result:
        events.append(result)

df = pd.DataFrame(events)

# Detection
alerts = detect_brute_force(logs)

# Calculate statistics
total_events = len(df)

failed = len(df[df["status"] == "FAILED"]) if not df.empty else 0

successful = len(df[df["status"] == "SUCCESS"]) if not df.empty else 0

invalid = len(df[df["status"] == "INVALID_USER"]) if not df.empty else 0

suspicious = len(alerts)

# Dashboard metrics
st.divider()
st.subheader("Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", total_events)
col2.metric("Failed Logins", failed)
col3.metric("Successful Logins", successful)
col4.metric("Suspicious IPs", suspicious)

st.divider()

# Security alerts
st.subheader("🚨 Security Alerts")

if alerts:

    alert_df = pd.DataFrame(alerts)

    st.dataframe(
        alert_df,
        use_container_width=True,
        hide_index=True
    )

    st.error(
        f"{suspicious} suspicious IP address(es) detected!"
    )

else:
    st.success("No suspicious activity detected.")

# Login activity chart
st.divider()
st.subheader("📊 Authentication Activity")

if not df.empty:

    status_counts = (
        df["status"]
        .value_counts()
        .reset_index()
    )

    status_counts.columns = ["Status", "Count"]

    fig = px.bar(
        status_counts,
        x="Status",
        y="Count",
        color="Status",
        title="Login Attempts by Status",
        text="Count"
    )

    st.plotly_chart(fig, use_container_width=True)

    # IP activity
    ip_counts = (
        df.groupby("ip_address")
        .size()
        .reset_index(name="Total Events")
    )

    fig2 = px.bar(
        ip_counts,
        x="ip_address",
        y="Total Events",
        title="Authentication Events by IP Address",
        labels={"ip_address": "IP Address"}
    )

    st.plotly_chart(fig2, use_container_width=True)

# Authentication event history
st.divider()
st.subheader("📋 Authentication Event History")

if not df.empty:

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True
    )

# Database history
st.divider()
st.subheader("🗄️ Stored Security Incidents")

stored_alerts = get_alerts()

if stored_alerts:

    history_df = pd.DataFrame(
        stored_alerts,
        columns=[
            "ID",
            "IP Address",
            "Failed Attempts",
            "Risk Level",
            "Alert",
            "Created At"
        ]
    )

    st.dataframe(
        history_df,
        use_container_width=True,
        hide_index=True
    )

else:
    st.info("No incidents stored yet.")

# CSV report
st.divider()
st.subheader("📥 Download Security Report")

if not df.empty:

    csv_data = df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="Download Authentication Report",
        data=csv_data,
        file_name="ssh_sentinel_report.csv",
        mime="text/csv"
    )

st.divider()

st.caption("SSH Sentinel | HCLTech Career Shaper Project")
st.caption("Prototype using simulated SSH authentication logs.")

