from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from typing import Any, Dict, List

import joblib
import pandas as pd
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ids.anomaly_detector import calculate_anomaly_score, calculate_baseline
from ids.alert_engine import generate_alert
from ids.feature_extractor import FEATURE_COLUMNS, extract_network_features
from ids.risk_engine import calculate_risk_score
from ids.rule_engine import DEFAULT_THRESHOLDS, analyze_flow

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "ids.db"
MODEL_PATH = BASE_DIR / "models" / "ids_model.joblib"

app = FastAPI(title="Network IDS Simulation API")


class FlowPayload(BaseModel):
    flow_id: str | None = None
    timestamp: str | None = None
    source_ip: str = "192.0.2.10"
    destination_ip: str = "198.51.100.20"
    source_port: int = 12345
    destination_port: int = 443
    protocol: str = "TCP"
    packet_count: int = 100
    byte_count: int = 5000
    duration_seconds: float = 1.0
    connection_count: int = 10
    failed_connection_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    average_packet_size: float = 120.0
    label: str = "NORMAL"
    scenario_type: str = "NORMAL_WEB"


class AlertStatusUpdate(BaseModel):
    status: str
    note: str | None = None


class AlertNote(BaseModel):
    note: str


def _connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = _connect_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS network_flows (
            flow_id TEXT PRIMARY KEY,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT,
            packet_count INTEGER,
            byte_count INTEGER,
            duration_seconds REAL,
            connection_count INTEGER,
            failed_connection_count INTEGER,
            syn_count INTEGER,
            rst_count INTEGER,
            average_packet_size REAL,
            label TEXT,
            scenario_type TEXT,
            classification TEXT,
            risk_score INTEGER,
            anomaly_score INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            flow_id TEXT,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            rule_id TEXT,
            alert_type TEXT,
            severity TEXT,
            risk_score INTEGER,
            anomaly_score INTEGER,
            description TEXT,
            status TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_notes (
            note_id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT,
            note TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()


def _default_baseline() -> Dict[str, Dict[str, float]]:
    dataset_path = BASE_DIR / "data" / "network_traffic.csv"
    if dataset_path.exists():
        df = pd.read_csv(dataset_path)
        if not df.empty:
            return calculate_baseline(df)
    return {
        "packet_rate": {"mean": 50.0, "std": 15.0},
        "byte_rate": {"mean": 3000.0, "std": 800.0},
        "connection_rate": {"mean": 8.0, "std": 5.0},
        "failed_connection_ratio": {"mean": 0.1, "std": 0.05},
        "destination_port_diversity": {"mean": 4.0, "std": 3.0},
    }


def _load_model_bundle() -> Any | None:
    if MODEL_PATH.exists():
        return joblib.load(MODEL_PATH)
    return None


@app.on_event("startup")
def startup_event() -> None:
    init_db()


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "network-ids-api"}


@app.post("/api/flows")
def create_flow(flow: FlowPayload) -> Dict[str, Any]:
    flow_data = flow.model_dump()
    flow_id = flow_data.get("flow_id") or f"FLOW-{len(_read_flows()) + 1:06d}"
    flow_data["flow_id"] = flow_id
    if not flow_data.get("timestamp"):
        flow_data["timestamp"] = pd.Timestamp.utcnow().isoformat()

    feature_data = extract_network_features(flow_data)
    rule_result = analyze_flow(feature_data, DEFAULT_THRESHOLDS)
    anomaly = calculate_anomaly_score(feature_data, _default_baseline())

    ml_probability = 0.0
    model_bundle = _load_model_bundle()
    if model_bundle:
        model = model_bundle["model"]
        feature_values = pd.DataFrame([feature_data], columns=FEATURE_COLUMNS)
        if "model" in model_bundle:
            probabilities = model.predict_proba(feature_values)[0]
            ml_probability = float(probabilities[1]) if len(probabilities) > 1 else 0.0

    risk = calculate_risk_score(rule_result["rule_hits"], anomaly["score"], ml_probability)
    alert = generate_alert(feature_data, rule_result["rule_hits"], anomaly["score"], risk["risk_score"], ml_probability)

    conn = _connect_db()
    conn.execute(
        """
        INSERT OR REPLACE INTO network_flows (
            flow_id, timestamp, source_ip, destination_ip, source_port, destination_port,
            protocol, packet_count, byte_count, duration_seconds, connection_count,
            failed_connection_count, syn_count, rst_count, average_packet_size, label,
            scenario_type, classification, risk_score, anomaly_score
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            flow_id,
            flow_data["timestamp"],
            flow_data["source_ip"],
            flow_data["destination_ip"],
            flow_data["source_port"],
            flow_data["destination_port"],
            flow_data["protocol"],
            flow_data["packet_count"],
            flow_data["byte_count"],
            flow_data["duration_seconds"],
            flow_data["connection_count"],
            flow_data["failed_connection_count"],
            flow_data["syn_count"],
            flow_data["rst_count"],
            flow_data["average_packet_size"],
            flow_data["label"],
            flow_data["scenario_type"],
            risk["classification"],
            risk["risk_score"],
            anomaly["score"],
        ),
    )
    conn.execute(
        """
        INSERT OR REPLACE INTO alerts (
            alert_id, flow_id, timestamp, source_ip, destination_ip, protocol, source_port,
            destination_port, rule_id, alert_type, severity, risk_score, anomaly_score,
            description, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert["alert_id"],
            flow_id,
            alert["timestamp"],
            alert["source_ip"],
            alert["destination_ip"],
            alert["protocol"],
            alert["source_port"],
            alert["destination_port"],
            alert["rule_id"],
            alert["alert_type"],
            alert["severity"],
            alert["risk_score"],
            alert["anomaly_score"],
            alert["description"],
            alert["status"],
        ),
    )
    conn.commit()
    conn.close()

    return {
        "flow_id": flow_id,
        "classification": risk["classification"],
        "risk_score": risk["risk_score"],
        "anomaly_score": anomaly["score"],
        "alert": alert,
        "rule_hits": rule_result["rule_hits"],
    }


def _read_flows() -> List[Dict[str, Any]]:
    conn = _connect_db()
    rows = conn.execute("SELECT * FROM network_flows ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.get("/api/flows")
def get_flows() -> List[Dict[str, Any]]:
    return _read_flows()


@app.get("/api/alerts")
def get_alerts() -> List[Dict[str, Any]]:
    conn = _connect_db()
    rows = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.put("/api/alerts/{alert_id}/status")
def update_alert_status(alert_id: str, payload: AlertStatusUpdate) -> Dict[str, Any]:
    conn = _connect_db()
    row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    conn.execute(
        "UPDATE alerts SET status = ? WHERE alert_id = ?",
        (payload.status, alert_id),
    )
    if payload.note:
        conn.execute(
            "INSERT INTO alert_notes (alert_id, note) VALUES (?, ?)",
            (alert_id, payload.note),
        )
    conn.commit()
    conn.close()
    return {"alert_id": alert_id, "status": payload.status}


@app.post("/api/alerts/{alert_id}/notes")
def add_alert_note(alert_id: str, payload: AlertNote) -> Dict[str, str]:
    conn = _connect_db()
    row = conn.execute("SELECT alert_id FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")
    conn.execute("INSERT INTO alert_notes (alert_id, note) VALUES (?, ?)", (alert_id, payload.note))
    conn.commit()
    conn.close()
    return {"status": "ok", "alert_id": alert_id}


@app.get("/api/dashboard/stats")
def dashboard_stats() -> Dict[str, Any]:
    conn = _connect_db()
    total_flows = conn.execute("SELECT COUNT(*) FROM network_flows").fetchone()[0]
    suspicious_flows = conn.execute("SELECT COUNT(*) FROM network_flows WHERE classification IN ('SUSPICIOUS', 'HIGH RISK', 'CRITICAL INVESTIGATION')").fetchone()[0]
    open_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('NEW', 'INVESTIGATING')").fetchone()[0]
    critical_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'").fetchone()[0]
    avg_risk = conn.execute("SELECT AVG(risk_score) FROM alerts").fetchone()[0] or 0.0
    conn.close()
    return {
        "total_flows": total_flows,
        "suspicious_flows": suspicious_flows,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "average_risk_score": round(avg_risk, 2),
    }


@app.get("/api/dashboard/traffic")
def traffic_trends() -> List[Dict[str, Any]]:
    conn = _connect_db()
    rows = conn.execute(
        "SELECT date(timestamp) AS day, COUNT(*) AS total FROM network_flows GROUP BY date(timestamp) ORDER BY day DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.get("/api/dashboard/alerts")
def recent_alerts() -> List[Dict[str, Any]]:
    conn = _connect_db()
    rows = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 20").fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.get("/api/rules")
def list_rules() -> List[Dict[str, Any]]:
    return [
        {"rule_id": "RULE_01", "name": "Excessive Connection Rate", "severity": "HIGH"},
        {"rule_id": "RULE_02", "name": "Repeated Failed Connections", "severity": "HIGH"},
        {"rule_id": "RULE_03", "name": "Unusually High Destination Port Diversity", "severity": "MEDIUM"},
        {"rule_id": "RULE_04", "name": "SYN-Heavy Connection Behavior", "severity": "HIGH"},
        {"rule_id": "RULE_05", "name": "Abnormally High Traffic Volume", "severity": "MEDIUM"},
    ]


if __name__ == "__main__":
    uvicorn.run("backend.app:app", host="0.0.0.0", port=8000, reload=False)
