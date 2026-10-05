from __future__ import annotations

from typing import Any, Dict, Iterable

import pandas as pd


def calculate_baseline(df: pd.DataFrame) -> Dict[str, Dict[str, float]]:
    features = df.copy()
    features["packet_rate"] = features.get("packets_per_second", 0)
    features["byte_rate"] = features.get("bytes_per_second", 0)
    features["connection_rate"] = features.get("connection_rate", 0)
    features["failed_connection_ratio"] = features.get("failure_ratio", 0)
    features["destination_port_diversity"] = features.get("unique_destination_ports", 0)

    baseline = {}
    for key in [
        "packet_rate",
        "byte_rate",
        "connection_rate",
        "failed_connection_ratio",
        "destination_port_diversity",
    ]:
        series = pd.to_numeric(features.get(key, 0), errors="coerce").fillna(0)
        baseline[key] = {
            "mean": float(series.mean()),
            "std": float(series.std(ddof=0)) if not series.empty else 0.0,
        }
    return baseline


def calculate_anomaly_score(flow: Dict[str, Any], baseline: Dict[str, Dict[str, float]]) -> Dict[str, Any]:
    metrics = {
        "packet_rate": float(flow.get("packets_per_second", 0.0)),
        "byte_rate": float(flow.get("bytes_per_second", 0.0)),
        "connection_rate": float(flow.get("connection_rate", 0.0)),
        "failed_connection_ratio": float(flow.get("failure_ratio", 0.0)),
        "destination_port_diversity": float(flow.get("unique_destination_ports", 0.0)),
    }

    total = 0.0
    for metric_name, value in metrics.items():
        stats = baseline.get(metric_name, {"mean": 0.0, "std": 1.0})
        mean = float(stats.get("mean", 0.0))
        std = float(stats.get("std", 0.0))
        if std == 0:
            z_value = 0.0
        else:
            z_value = abs(value - mean) / std
        total += min(1.0, z_value / 3.0)

    score = int(round(min(100.0, max(0.0, total * 100.0 / 5.0))))
    return {"score": score, "metrics": metrics}
