import streamlit as st
import pandas as pd
from src.siem import analyze_dataframe, analyze_csv_in_chunks, load_sample

st.set_page_config(page_title="CyberSOC | SIEM", page_icon="🛡️", layout="wide")
st.title("🛡️ CyberSOC — Security Operations & SIEM")
st.caption("Defensive security event monitoring, detection, triage and reporting.")

with st.sidebar:
    st.header("Data source")
    mode = st.radio("Choose data", ["Included sample dataset", "Upload CSV log"])
    uploaded = st.file_uploader("CSV security events", type=["csv"]) if mode == "Upload CSV log" else None
    st.divider()
    failed_threshold = st.slider("Failed logins per source IP", 3, 30, 5)
    scan_threshold = st.slider("Distinct destination ports", 5, 100, 10)
    window_minutes = st.slider("Correlation window (minutes)", 1, 60, 10)

try:
    if mode == "Included sample dataset":
        df = load_sample()
        alerts = analyze_dataframe(df, failed_threshold, scan_threshold, window_minutes)
    elif uploaded is not None:
        df, alerts = analyze_csv_in_chunks(uploaded, failed_threshold, scan_threshold, window_minutes)
    else:
        st.info("Upload a CSV file to begin, or select the included sample dataset.")
        st.stop()

    high = int((alerts.severity == "High").sum()) if not alerts.empty else 0
    medium = int((alerts.severity == "Medium").sum()) if not alerts.empty else 0
    a,b,c,d = st.columns(4)
    a.metric("Events analyzed", f"{len(df):,}")
    b.metric("Detection alerts", f"{len(alerts):,}")
    c.metric("High severity", f"{high:,}")
    d.metric("Medium severity", f"{medium:,}")

    left,right = st.columns(2)
    with left:
        st.subheader("Events by type")
        st.bar_chart(df.event_type.value_counts())
    with right:
        st.subheader("Alerts by severity")
        if alerts.empty: st.success("No alerts triggered.")
        else: st.bar_chart(alerts.severity.value_counts())

    st.subheader("Detection queue")
    if not alerts.empty:
        chosen = st.multiselect("Filter severity", ["High","Medium","Low"], ["High","Medium"])
        visible = alerts[alerts.severity.isin(chosen)]
        st.dataframe(visible, use_container_width=True, hide_index=True)
        st.download_button("Download alerts CSV", visible.to_csv(index=False), "cybersoc_alerts.csv", "text/csv")
    else:
        st.info("No matching patterns found.")
    st.subheader("Recent security events")
    st.dataframe(df.tail(500), use_container_width=True, hide_index=True)
    st.download_button("Download normalized events", df.to_csv(index=False), "cybersoc_events.csv", "text/csv")
    st.caption("Alerts are investigation leads, not proof of compromise.")
except Exception as exc:
    st.error(f"Analysis failed: {exc}")
    st.info("Check the CSV schema in README.md. See docs/LARGE_DATASETS.md for scale guidance.")
