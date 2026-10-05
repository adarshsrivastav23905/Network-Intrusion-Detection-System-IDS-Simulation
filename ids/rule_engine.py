from __future__ import annotations

from typing import Any, Dict, List, Optional

from ids.feature_extractor import extract_network_features

DEFAULT_THRESHOLDS = {
    "connection_rate_threshold": 20.0,
    "failed_connection_threshold": 6,
    "failed_ratio_threshold": 0.45,
    "destination_port_threshold": 12,
    "syn_ratio_threshold": 0.25,
    "syn_count_threshold": 80,
    "traffic_volume_threshold": 50000,
}


def analyze_flow(flow: Dict[str, Any], thresholds: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
    normalized = extract_network_features(flow)
    rules = thresholds or DEFAULT_THRESHOLDS
    rule_hits: List[Dict[str, Any]] = []

    if normalized["connection_rate"] > rules["connection_rate_threshold"]:
        rule_hits.append({
            "rule_id": "RULE_01",
            "name": "Excessive Connection Rate",
            "severity": "HIGH",
            "description": "Connection rate is substantially higher than expected baseline.",
        })

    if normalized["failed_connection_count"] >= rules["failed_connection_threshold"] and normalized["failure_ratio"] >= rules["failed_ratio_threshold"]:
        rule_hits.append({
            "rule_id": "RULE_02",
            "name": "Repeated Failed Connections",
            "severity": "HIGH",
            "description": "Multiple failed connections indicate a suspicious connection pattern.",
        })

    if normalized["unique_destination_ports"] >= rules["destination_port_threshold"]:
        rule_hits.append({
            "rule_id": "RULE_03",
            "name": "Unusually High Destination Port Diversity",
            "severity": "MEDIUM",
            "description": "A single host contacted many destination ports in a short window.",
        })

    if normalized["syn_ratio"] >= rules["syn_ratio_threshold"] or normalized["syn_count"] >= rules["syn_count_threshold"]:
        rule_hits.append({
            "rule_id": "RULE_04",
            "name": "SYN-Heavy Connection Behavior",
            "severity": "HIGH",
            "description": "SYN signal dominates the flow and suggests a scan or flood-like pattern.",
        })

    if normalized["byte_count"] >= rules["traffic_volume_threshold"]:
        rule_hits.append({
            "rule_id": "RULE_05",
            "name": "Abnormally High Traffic Volume",
            "severity": "MEDIUM",
            "description": "Traffic volume exceeds expected thresholds and may indicate a burst.",
        })

    return {
        "features": normalized,
        "rule_hits": rule_hits,
        "is_suspicious": bool(rule_hits),
        "rule_count": len(rule_hits),
    }
