from __future__ import annotations

import json
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "ids.db"

st.set_page_config(page_title="Network IDS Dashboard", page_icon="🛡️", layout="wide")

CSS = """
<style>
    .stApp {
        background: linear-gradient(180deg, #07111d 0%, #0c1623 100%);
        color: #e6edf7;
    }
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    .glass {
        background: rgba(17, 28, 40, 0.82);
        border: 1px solid rgba(122, 164, 211, 0.18);
        border-radius: 18px;
        padding: 1.1rem 1.15rem;
        box-shadow: 0 16px 40px rgba(6, 10, 18, 0.42);
    }
    div[data-testid="stMetricValue"] {
        font-size: 1.65rem;
        font-weight: 700;
        color: #f5f8ff;
    }
    .section-title {
        font-size: 1.2rem;
        font-weight: 700;
        color: #eef4ff;
        margin-top: 0.5rem;
        margin-bottom: 0.6rem;
    }
    .small-label {
        color: #9eb7d7;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        font-size: 0.72rem;
    }
    .status-badge {
        display: inline-block;
        padding: 0.3rem 0.7rem;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }
    .status-new { background: rgba(102, 194, 255, 0.18); color: #8dd3ff; }
    .status-investigating { background: rgba(255, 191, 94, 0.18); color: #ffd08a; }
    .status-resolved { background: rgba(127, 219, 158, 0.18); color: #a7efbb; }
    .status-closed { background: rgba(180, 190, 255, 0.18); color: #c8d0ff; }
    .status-false_positive { background: rgba(247, 120, 120, 0.15); color: #ffb3b3; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


def _connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@st.cache_data
def load_stats() -> dict:
    if not DB_PATH.exists():
        return {
            "total_flows": 0,
            "suspicious_flows": 0,
            "open_alerts": 0,
            "critical_alerts": 0,
            "average_risk_score": 0.0,
        }

    conn = _connect_db()
    row = conn.execute(
        """
        SELECT
            COUNT(*) AS total_flows,
            SUM(CASE WHEN classification IN ('SUSPICIOUS','HIGH RISK','CRITICAL INVESTIGATION') THEN 1 ELSE 0 END) AS suspicious_flows,
            (SELECT COUNT(*) FROM alerts WHERE status IN ('NEW', 'INVESTIGATING')) AS open_alerts,
            (SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL') AS critical_alerts,
            AVG(risk_score) AS average_risk_score
        FROM network_flows
        """
    ).fetchone()
    conn.close()

    if row is None:
        return {
            "total_flows": 0,
            "suspicious_flows": 0,
            "open_alerts": 0,
            "critical_alerts": 0,
            "average_risk_score": 0.0,
        }

    return {
        "total_flows": int(row["total_flows"] or 0),
        "suspicious_flows": int(row["suspicious_flows"] or 0),
        "open_alerts": int(row["open_alerts"] or 0),
        "critical_alerts": int(row["critical_alerts"] or 0),
        "average_risk_score": round(float(row["average_risk_score"] or 0), 2),
    }


@st.cache_data
def load_alerts(status: str = "ALL", severity: str = "ALL") -> pd.DataFrame:
    if not DB_PATH.exists():
        return pd.DataFrame(columns=["alert_id", "timestamp", "source_ip", "destination_ip", "protocol", "severity", "risk_score", "status", "alert_type"])

    conn = _connect_db()
    query = "SELECT * FROM alerts WHERE 1=1"
    params: list[str] = []
    if status != "ALL":
        query += " AND status = ?"
        params.append(status)
    if severity != "ALL":
        query += " AND severity = ?"
        params.append(severity)
    query += " ORDER BY created_at DESC LIMIT 200"
    df = pd.read_sql_query(query, conn, params=params)
    conn.close()
    return df


@st.cache_data
def load_flow_summary() -> pd.DataFrame:
    if not DB_PATH.exists():
        return pd.DataFrame(columns=["day", "total_flows", "suspicious_flows"])

    conn = _connect_db()
    df = pd.read_sql_query(
        """
        SELECT date(timestamp) AS day, COUNT(*) AS total_flows,
               SUM(CASE WHEN classification IN ('SUSPICIOUS','HIGH RISK','CRITICAL INVESTIGATION') THEN 1 ELSE 0 END) AS suspicious_flows
        FROM network_flows
        GROUP BY date(timestamp)
        ORDER BY day DESC
        LIMIT 14
        """,
        conn,
    )
    conn.close()
    return df


@st.cache_data
def load_alert_notes(alert_id: str) -> pd.DataFrame:
    if not DB_PATH.exists():
        return pd.DataFrame(columns=["note_id", "alert_id", "note", "created_at"])

    conn = _connect_db()
    df = pd.read_sql_query(
        "SELECT * FROM alert_notes WHERE alert_id = ? ORDER BY created_at DESC",
        conn,
        params=(alert_id,),
    )
    conn.close()
    return df


def render_metric_card(title: str, value: str | int, delta: str = ""):
    st.markdown(
        f"""
        <div class="glass">
            <div class="small-label">{title}</div>
            <div style="font-size: 2rem; font-weight: 700; margin-top: 0.5rem;">{value}</div>
            <div style="color: #aaccff; margin-top: 0.3rem; font-size: 0.85rem;">{delta}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def update_alert_status(alert_id: str, status: str, note: str | None = None) -> None:
    conn = _connect_db()
    conn.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (status, alert_id))
    if note and note.strip():
        conn.execute("INSERT INTO alert_notes (alert_id, note) VALUES (?, ?)", (alert_id, note.strip()))
    conn.commit()
    conn.close()
    st.cache_data.clear()


def add_note(alert_id: str, note: str) -> None:
    if not note or not note.strip():
        return
    conn = _connect_db()
    conn.execute("INSERT INTO alert_notes (alert_id, note) VALUES (?, ?)", (alert_id, note.strip()))
    conn.commit()
    conn.close()
    st.cache_data.clear()


def status_badge_html(status: str) -> str:
    status_key = status.strip().lower().replace(" ", "_")
    tone = "status-new" if status_key == "new" else "status-investigating" if status_key == "investigating" else "status-resolved" if status_key == "resolved" else "status-closed" if status_key == "closed" else "status-false_positive"
    return f'<span class="status-badge {tone}">{status}</span>'


st.markdown('<div class="small-label">Network Security Operations</div>', unsafe_allow_html=True)
st.markdown("<h1 style='margin-top: 0.2rem; margin-bottom: 0.6rem; color: #f5f8ff;'>Network Intrusion Detection System (IDS) Simulation</h1>", unsafe_allow_html=True)

sidebar = st.sidebar
sidebar.title("Simulation Controls")
sidebar.caption("Create synthetic network activity and refresh the analytics view.")

status_filter = sidebar.selectbox("Alert status filter", ["ALL", "NEW", "INVESTIGATING", "RESOLVED", "CLOSED", "FALSE_POSITIVE"])
severity_filter = sidebar.selectbox("Alert severity filter", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])

if sidebar.button("Generate sample dataset", use_container_width=True):
    try:
        subprocess.run(["python", "simulator/generate_dataset.py", "--count", "1000"], cwd=BASE_DIR, check=True, capture_output=True)
        st.sidebar.success("Dataset generated.")
    except subprocess.CalledProcessError as exc:
        st.sidebar.error(f"Dataset generation failed: {exc}")

if sidebar.button("Train ML model", use_container_width=True):
    try:
        subprocess.run(["python", "ml/train_model.py"], cwd=BASE_DIR, check=True, capture_output=True)
        st.sidebar.success("ML model trained.")
    except subprocess.CalledProcessError as exc:
        st.sidebar.error(f"Model training failed: {exc}")

if sidebar.button("Run live simulator", use_container_width=True):
    try:
        subprocess.Popen(["python", "simulator/traffic_simulator.py", "--mode", "mixed", "--speed", "slow", "--duration", "30"], cwd=BASE_DIR)
        st.sidebar.success("Live simulator started.")
    except Exception as exc:  # pragma: no cover
        st.sidebar.error(f"Simulator failed to start: {exc}")

stats = load_stats()
metrics = [
    ("Total Network Flows", stats["total_flows"], "+ Live telemetry"),
    ("Suspicious Traffic", stats["suspicious_flows"], "Behavioral anomalies"),
    ("Open Alerts", stats["open_alerts"], "Needs triage"),
    ("Critical Alerts", stats["critical_alerts"], "Immediate review"),
    ("Average Risk Score", f"{stats['average_risk_score']:.2f}", "Hybrid risk model"),
]

cols = st.columns(5)
for idx, (title, value, delta) in enumerate(metrics):
    with cols[idx]:
        render_metric_card(title, value, delta)

st.write("")

overview_tab, investigation_tab, analytics_tab, reports_tab = st.tabs(["Overview", "Alert Investigation", "Threat Analytics", "Reports"])

with overview_tab:
    alerts = load_alerts(status_filter, severity_filter)
    if alerts.empty:
        st.warning("No alerts match the selected filters.")
    else:
        st.markdown('<div class="section-title">Threat Overview</div>', unsafe_allow_html=True)
        severity_counts = alerts["severity"].fillna("INFO").value_counts().reindex(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], fill_value=0).reset_index()
        severity_counts.columns = ["Severity", "Count"]
        fig_severity = px.bar(
            severity_counts,
            x="Severity",
            y="Count",
            color="Severity",
            color_discrete_map={"CRITICAL": "#ff5a5f", "HIGH": "#ff9b54", "MEDIUM": "#f6d365", "LOW": "#66c2ff", "INFO": "#7de2d1"},
            title="Severity Distribution",
        )
        fig_severity.update_layout(plot_bgcolor="#0d1724", paper_bgcolor="#0d1724", font={"color": "#eaf1ff"}, margin=dict(l=20, r=20, t=40, b=20))

        alert_types = alerts["alert_type"].fillna("Unknown").value_counts().head(6).reset_index()
        alert_types.columns = ["Alert Type", "Count"]
        fig_types = px.pie(alert_types, names="Alert Type", values="Count", title="Top Alert Types")
        fig_types.update_layout(plot_bgcolor="#0d1724", paper_bgcolor="#0d1724", font={"color": "#eaf1ff"}, margin=dict(l=20, r=20, t=40, b=20))

        left_col, right_col = st.columns(2)
        with left_col:
            st.plotly_chart(fig_severity, use_container_width=True)
        with right_col:
            st.plotly_chart(fig_types, use_container_width=True)

        st.write("")
        st.markdown('<div class="section-title">Recent Security Alerts</div>', unsafe_allow_html=True)
        table_df = alerts[["alert_id", "timestamp", "source_ip", "destination_ip", "severity", "risk_score", "status", "alert_type"]].copy()
        table_df["timestamp"] = pd.to_datetime(table_df["timestamp"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M")
        st.dataframe(table_df, use_container_width=True, hide_index=True)

with investigation_tab:
    alerts = load_alerts(status_filter, severity_filter)
    if alerts.empty:
        st.warning("No alerts are available for investigation.")
    else:
        alert_options = alerts["alert_id"].tolist()
        selected_alert_id = st.selectbox("Select alert to investigate", alert_options)
        selected_alert = alerts[alerts["alert_id"] == selected_alert_id].iloc[0]

        st.markdown(f"<div class='glass'><div class='small-label'>Alert ID</div><h3>{selected_alert['alert_id']}</h3>{status_badge_html(str(selected_alert['status']))}</div>", unsafe_allow_html=True)

        left_col, right_col = st.columns(2)
        with left_col:
            st.metric("Severity", selected_alert["severity"])
            st.metric("Risk Score", float(selected_alert["risk_score"]))
            st.metric("Protocol", selected_alert["protocol"])
        with right_col:
            st.metric("Source IP", selected_alert["source_ip"])
            st.metric("Destination IP", selected_alert["destination_ip"])
            st.metric("Alert Type", selected_alert["alert_type"])

        st.markdown("### Investigation details")
        st.write(selected_alert["description"])
        st.caption(f"Observed at {selected_alert['timestamp']}")

        status_options = ["NEW", "INVESTIGATING", "RESOLVED", "CLOSED", "FALSE_POSITIVE"]
        current_status_index = status_options.index(str(selected_alert["status"])) if str(selected_alert["status"]) in status_options else 0
        next_status = st.selectbox("Update investigation status", status_options, index=current_status_index)

        note_text = st.text_area("Add investigation note", placeholder="Document findings, host impact, or analyst recommendations.")

        actions = st.columns(2)
        with actions[0]:
            if st.button("Apply status update", use_container_width=True):
                update_alert_status(selected_alert_id, next_status, note_text)
                st.success(f"Alert {selected_alert_id} marked as {next_status}.")
                st.rerun()
        with actions[1]:
            if st.button("Save note only", use_container_width=True):
                add_note(selected_alert_id, note_text)
                st.success("Investigation note saved.")
                st.rerun()

        st.markdown("### Notes")
        notes_df = load_alert_notes(selected_alert_id)
        if notes_df.empty:
            st.info("No investigation notes have been added yet.")
        else:
            st.dataframe(notes_df[["note", "created_at"]], use_container_width=True, hide_index=True)

with analytics_tab:
    alerts = load_alerts(status_filter, severity_filter)
    flow_summary = load_flow_summary()

    if alerts.empty:
        st.warning("No alert analytics are available for the selected filters.")
    else:
        severity_counts = alerts["severity"].fillna("INFO").value_counts().reindex(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], fill_value=0).reset_index()
        severity_counts.columns = ["Severity", "Count"]
        fig_severity = px.bar(severity_counts, x="Severity", y="Count", color="Severity", title="Alert Severity Distribution")
        fig_severity.update_layout(plot_bgcolor="#0d1724", paper_bgcolor="#0d1724", font={"color": "#eaf1ff"})
        st.plotly_chart(fig_severity, use_container_width=True)

        risk_scores = alerts["risk_score"].fillna(0).astype(float)
        fig_risk = px.histogram(risk_scores, nbins=12, title="Risk Score Distribution")
        fig_risk.update_layout(plot_bgcolor="#0d1724", paper_bgcolor="#0d1724", font={"color": "#eaf1ff"})
        st.plotly_chart(fig_risk, use_container_width=True)

    if not flow_summary.empty:
        flow_summary = flow_summary.sort_values("day")
        fig_flow = px.line(flow_summary, x="day", y=["total_flows", "suspicious_flows"], title="Traffic Trend")
        fig_flow.update_layout(plot_bgcolor="#0d1724", paper_bgcolor="#0d1724", font={"color": "#eaf1ff"})
        st.plotly_chart(fig_flow, use_container_width=True)

with reports_tab:
    alerts = load_alerts(status_filter, severity_filter)
    report_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    st.subheader("Operational Summary")
    summary = {
        "generated_at": report_time,
        "filters": {"status": status_filter, "severity": severity_filter},
        "totals": {
            "total_alerts": int(len(alerts)),
            "critical_alerts": int((alerts["severity"] == "CRITICAL").sum()),
            "high_alerts": int((alerts["severity"] == "HIGH").sum()),
            "average_risk": round(float(alerts["risk_score"].fillna(0).astype(float).mean()), 2) if not alerts.empty else 0.0,
        },
    }
    st.json(summary)

    csv_data = alerts[["alert_id", "timestamp", "source_ip", "destination_ip", "protocol", "severity", "risk_score", "status", "alert_type", "description"]].to_csv(index=False).encode("utf-8")
    st.download_button("Export alerts as CSV", csv_data, file_name="ids_alerts_report.csv", mime="text/csv")

    json_payload = json.dumps({"report": summary, "alerts": alerts.to_dict(orient="records")}, indent=2).encode("utf-8")
    st.download_button("Export full report as JSON", json_payload, file_name="ids_security_report.json", mime="application/json")

sidebar.markdown("---")
sidebar.write("Operational posture: Defensive monitoring enabled")
sidebar.write("Data source: Synthetic flow generation")
sidebar.write("Detection model: Signature + anomaly + optional ML")
