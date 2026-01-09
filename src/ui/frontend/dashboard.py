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
        "impact": "Service disruption, system unavailability"
    },
    "T1046": {
        "name": "Network Service Scanning",
        "description": (
            "Adversaries scan networks to discover services and "
            "open ports, which can later be exploited."
        ),
        "impact": "Reconnaissance, attack surface discovery"
    }
}
# -----------------------------

# API Endpoint
API_URL = "http://127.0.0.1:8000/alerts"

# -----------------------------
# Page Config
# -----------------------------
st.set_page_config(
    page_title="IDS Dashboard",
    layout="wide",
)

st.title("🛡️ Intrusion Detection System Dashboard")
st.caption("Real-time monitoring of network threats")

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
# Auto Refresh (NO FULL RERUN)
# -----------------------------
st_autorefresh(interval=5000, key="ids_refresh")


# -----------------------------
# Fetch & Merge Alerts
# -----------------------------
latest_alerts = fetch_alerts()

# Append only NEW alerts
existing_timestamps = {
    alert["timestamp"] for alert in st.session_state.alerts
}

for alert in latest_alerts:
    if alert["timestamp"] not in existing_timestamps:
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
# Filters Section
# -----------------------------
st.subheader("🔍 Filters")

filter_col1, filter_col2, filter_col3 = st.columns(3)

# Prepare data for filters
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

    # ---- Severity Pie Chart ----
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

    # ---- Alerts Over Time ----
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
                "Source IP": alert["source"]["ip"],
                "Destination IP": alert["destination"]["ip"],
                "MITRE": alert.get("mitre_technique")
            })

        df = pd.DataFrame(table_data)
        st.dataframe(df, use_container_width=True)

    else:
        st.warning("No alerts match the selected filters.")

else:
    st.info("No alerts detected yet.")


# -----------------------------
# MITRE ATT&CK View
# -----------------------------
st.divider()
st.subheader("🧠 MITRE ATT&CK Details")

selected_mitre = st.selectbox(
    "Select a MITRE Technique to view details",
    options=list(
        {alert.get("mitre_technique") for alert in alerts if alert.get("mitre_technique")}
    ) if alerts else []
)

if selected_mitre and selected_mitre in MITRE_DB:
    mitre_info = MITRE_DB[selected_mitre]

    st.markdown(f"### 🔐 {selected_mitre} — {mitre_info['name']}")
    st.write(mitre_info["description"])

    st.markdown("**Impact:**")
    st.info(mitre_info["impact"])

elif selected_mitre:
    st.warning("No additional details available for this technique.")
else:
    st.info("Select a MITRE technique to view detailed explanation.")



st.caption("Dashboard updates every 5 seconds without flickering")
