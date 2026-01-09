import requests
import streamlit as st
import pandas as pd
from datetime import datetime
from streamlit_autorefresh import st_autorefresh
import matplotlib.pyplot as plt

# -----------------------------
# MITRE ATT&CK Knowledge Base
# -----------------------------
MITRE_DB = {
    "T1499": {
        "name": "Endpoint Denial of Service",
        "description": (
            "Adversaries may perform Denial-of-Service attacks "
            "to degrade or block the availability of targeted systems. "
            "This includes flooding a target with network traffic."
        ),
        "impact": "Service disruption, system unavailability",
        "risk": "High",
        "mitigation": [
            "Apply network rate limiting",
            "Deploy firewall and IDS/IPS rules",
            "Use DDoS protection services",
            "Monitor abnormal traffic spikes"
        ]
    },
    "T1046": {
        "name": "Network Service Scanning",
        "description": (
            "Adversaries scan networks to discover services and "
            "open ports, which can later be exploited."
        ),
        "impact": "Reconnaissance, attack surface discovery",
        "risk": "Medium",
        "mitigation": [
            "Close unused ports",
            "Enable firewall port filtering",
            "Monitor scanning behavior",
            "Enable logging and alerts"
        ]
    }
}

# -----------------------------
# API Endpoint
# -----------------------------
API_URL = "http://127.0.0.1:8000/alerts"

# -----------------------------
# Page Config
# -----------------------------
st.set_page_config(
    page_title="IDS Dashboard",
    layout="wide",
)

st.title("🛡️ Intrusion Detection System Dashboard")
st.caption("Real-time monitoring of network threats & security intelligence")

# -----------------------------
# Session State Initialization
# -----------------------------
if "alerts" not in st.session_state:
    st.session_state.alerts = []

# -----------------------------
# Helper Functions
# -----------------------------
def fetch_alerts():
    try:
        response = requests.get(API_URL, timeout=2)
        if response.status_code == 200:
            return response.json().get("alerts", [])
    except requests.exceptions.RequestException:
        return []


def severity_label(severity):
    if severity == "high":
        return "🔴 High"
    elif severity == "medium":
        return "🟠 Medium"
    else:
        return "🟢 Low"


# -----------------------------
# Auto Refresh (NO FLICKER)
# -----------------------------
st_autorefresh(interval=5000, key="ids_refresh")

# -----------------------------
# Fetch & Merge Alerts
# -----------------------------
latest_alerts = fetch_alerts()

existing_timestamps = {
    alert.get("timestamp") for alert in st.session_state.alerts
}

for alert in latest_alerts:
    if alert.get("timestamp") not in existing_timestamps:
        st.session_state.alerts.append(alert)

alerts = st.session_state.alerts

# -----------------------------
# Metrics
# -----------------------------
col1, col2, col3 = st.columns(3)

col1.metric("Total Alerts", len(alerts))
col2.metric("API Status", "Online")
col3.metric("Last Updated", datetime.now().strftime("%H:%M:%S"))

st.divider()

# -----------------------------
# Risk Summary (NEW)
# -----------------------------
st.subheader("⚠️ Risk Summary")

if alerts:
    df_risk = pd.DataFrame(alerts)

    high = len(df_risk[df_risk["severity"] == "high"])
    medium = len(df_risk[df_risk["severity"] == "medium"])
    low = len(df_risk[df_risk["severity"] == "low"])

    st.info(
        f"""
        **High Risk Alerts:** {high}  
        **Medium Risk Alerts:** {medium}  
        **Low Risk Alerts:** {low}  

        🔍 High risk alerts require immediate attention.
        """
    )
else:
    st.success("No active threats detected.")

st.divider()

# -----------------------------
# Filters Section
# -----------------------------
st.subheader("🔍 Filters")

filter_col1, filter_col2, filter_col3 = st.columns(3)

df_filters = pd.DataFrame(alerts) if alerts else pd.DataFrame()

with filter_col1:
    selected_severity = st.multiselect(
        "Severity",
        options=df_filters["severity"].unique().tolist()
        if not df_filters.empty else [],
        default=df_filters["severity"].unique().tolist()
        if not df_filters.empty else []
    )

with filter_col2:
    selected_attack = st.multiselect(
        "Attack Type",
        options=df_filters["attack_name"].unique().tolist()
        if not df_filters.empty else [],
        default=df_filters["attack_name"].unique().tolist()
        if not df_filters.empty else []
    )

with filter_col3:
    selected_source_ip = st.multiselect(
        "Source IP",
        options=df_filters["source"].apply(lambda x: x["ip"]).unique().tolist()
        if not df_filters.empty else [],
        default=df_filters["source"].apply(lambda x: x["ip"]).unique().tolist()
        if not df_filters.empty else []
    )

# -----------------------------
# Charts Section
# -----------------------------
if alerts:
    st.subheader("📊 Alert Analytics")

    col_left, col_right = st.columns(2)
    df = pd.DataFrame(alerts)

    with col_left:
        st.markdown("### Severity Distribution")
        severity_counts = df["severity"].value_counts()
        fig1, ax1 = plt.subplots()
        ax1.pie(
            severity_counts,
            labels=severity_counts.index,
            autopct="%1.1f%%",
            startangle=90
        )
        ax1.axis("equal")
        st.pyplot(fig1)

    with col_right:
        st.markdown("### Alerts Over Time")
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        time_series = df.groupby(
            df["timestamp"].dt.floor("min")
        ).size()

        fig2, ax2 = plt.subplots()
        ax2.plot(time_series.index, time_series.values, marker="o")
        ax2.set_xlabel("Time")
        ax2.set_ylabel("Alerts Count")
        ax2.grid(True)
        st.pyplot(fig2)

    st.divider()

# -----------------------------
# Alerts Table (FILTERED & STABLE)
# -----------------------------
st.subheader("📋 Detected Alerts")

if alerts:
    filtered_alerts = []

    for alert in alerts:
        if (
            alert.get("severity") in selected_severity
            and alert.get("attack_name") in selected_attack
            and alert.get("source", {}).get("ip") in selected_source_ip
        ):
            filtered_alerts.append(alert)

    if filtered_alerts:
        table_data = []

        for alert in filtered_alerts:
            table_data.append({
                "Time": alert.get("timestamp"),
                "Attack": alert.get("attack_name"),
                "Severity": severity_label(alert.get("severity")),
                "Source IP": alert.get("source", {}).get("ip"),
                "Destination IP": alert.get("destination", {}).get("ip"),
                "MITRE": alert.get("mitre_technique")
            })

        df_table = pd.DataFrame(table_data)
        st.dataframe(df_table, use_container_width=True)

    else:
        st.warning("No alerts match the selected filters.")
else:
    st.info("No alerts detected yet.")

# -----------------------------
# MITRE ATT&CK Intelligence View (UPGRADED)
# -----------------------------
st.divider()
st.subheader("🧠 MITRE ATT&CK Details & Mitigation")

mitre_options = list(
    {alert.get("mitre_technique") for alert in alerts if alert.get("mitre_technique")}
)

selected_mitre = st.selectbox(
    "Select a MITRE Technique to view details",
    options=mitre_options
)

if selected_mitre and selected_mitre in MITRE_DB:
    info = MITRE_DB[selected_mitre]

    st.markdown(f"### 🔐 {selected_mitre} — {info['name']}")
    st.write(info["description"])

    st.markdown("**Impact:**")
    st.error(info["impact"])

    st.markdown("**Risk Level:**")
    st.warning(info["risk"])

    st.markdown("### 🛡️ Recommended Mitigations")
    for step in info["mitigation"]:
        st.markdown(f"- ✅ {step}")

elif selected_mitre:
    st.warning("No additional intelligence available for this technique.")
else:
    st.info("Select a MITRE technique to view explanation and defense guidance.")

st.caption("Dashboard updates every 5 seconds • Stable • SOC-style interface")
