from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


def generate_alert(
    flow: Dict[str, Any],
    rule_hits: List[Dict[str, Any]],
    anomaly_score: int,
    risk_score: int,
    ml_probability: float = 0.0,
) -> Dict[str, Any]:
    if rule_hits:
        primary_rule = rule_hits[0]
        alert_type = primary_rule["name"]
        rule_id = primary_rule["rule_id"]
        description = primary_rule["description"]
    else:
        alert_type = "ANOMALY_DETECTION"
        rule_id = "ANOMALY"
        description = "Statistical deviation exceeds the normal baseline."

    severity = "INFO"
    if risk_score >= 80:
        severity = "CRITICAL"
    elif risk_score >= 60:
        severity = "HIGH"
    elif risk_score >= 40:
        severity = "MEDIUM"
    elif risk_score >= 20:
        severity = "LOW"

    return {
        "alert_id": f"ALT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": flow.get("source_ip", "192.0.2.10"),
        "destination_ip": flow.get("destination_ip", "198.51.100.20"),
        "protocol": str(flow.get("protocol", "TCP")).upper(),
        "source_port": int(flow.get("source_port", 0)),
        "destination_port": int(flow.get("destination_port", 0)),
        "rule_id": rule_id,
        "alert_type": alert_type,
        "severity": severity,
        "risk_score": risk_score,
        "anomaly_score": anomaly_score,
        "ml_probability": ml_probability,
        "description": description,
        "status": "NEW",
    }


def correlate_alerts(alerts: List[Dict[str, Any]], window_seconds: int = 60) -> List[Dict[str, Any]]:
    incidents: List[Dict[str, Any]] = []
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for alert in alerts:
        key = f"{alert.get('source_ip')}-{alert.get('alert_type')}"
        grouped.setdefault(key, []).append(alert)

    for key, items in grouped.items():
        items = sorted(items, key=lambda a: a["timestamp"])
        merged_group: List[Dict[str, Any]] = []
        current_bucket: List[Dict[str, Any]] = []
        for alert in items:
            if not current_bucket:
                current_bucket = [alert]
                continue
            previous = current_bucket[-1]
            if (datetime.fromisoformat(alert["timestamp"]) - datetime.fromisoformat(previous["timestamp"]).replace(tzinfo=None)).total_seconds() <= window_seconds:
                current_bucket.append(alert)
            else:
                merged_group.append({"alert_ids": [a["alert_id"] for a in current_bucket], "alerts": current_bucket})
                current_bucket = [alert]
        if current_bucket:
            merged_group.append({"alert_ids": [a["alert_id"] for a in current_bucket], "alerts": current_bucket})
        if merged_group:
            incidents.append({"group_key": key, "buckets": merged_group})
    return incidents
