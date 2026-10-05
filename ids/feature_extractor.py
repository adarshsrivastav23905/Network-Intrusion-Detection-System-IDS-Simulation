from __future__ import annotations

from typing import Any, Dict, Iterable, List

import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "duration",
    "bytes_per_second",
    "packets_per_second",
    "average_packet_size",
    "connection_count",
    "failed_connection_count",
    "failure_ratio",
    "syn_count",
    "rst_count",
    "syn_ratio",
    "unique_destination_ports",
    "unique_destination_ips",
    "connection_rate",
]


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def extract_network_features(record: Dict[str, Any]) -> Dict[str, float | int]:
    packet_count = max(safe_int(record.get("packet_count"), 0), 0)
    byte_count = max(safe_int(record.get("byte_count"), 0), 0)
    duration = max(safe_float(record.get("duration_seconds"), 0.0), 0.0)
    if duration == 0:
        duration = max(safe_float(record.get("duration"), 0.0), 0.0)
    if duration == 0:
        duration = 1.0

    connection_count = max(safe_int(record.get("connection_count"), 0), 0)
    failed_connection_count = max(safe_int(record.get("failed_connection_count"), 0), 0)
    syn_count = max(safe_int(record.get("syn_count"), 0), 0)
    rst_count = max(safe_int(record.get("rst_count"), 0), 0)
    destination_port = safe_int(record.get("destination_port"), 0)
    source_ip = str(record.get("source_ip", ""))
    destination_ip = str(record.get("destination_ip", ""))

    bytes_per_second = byte_count / duration if duration > 0 else 0.0
    packets_per_second = packet_count / duration if duration > 0 else 0.0
    average_packet_size = (byte_count / packet_count) if packet_count > 0 else 0.0
    failure_ratio = (failed_connection_count / connection_count) if connection_count > 0 else 0.0
    syn_ratio = (syn_count / connection_count) if connection_count > 0 else 0.0
    unique_destination_ports = safe_int(record.get("unique_destination_ports"), 1)
    if unique_destination_ports <= 0:
        unique_destination_ports = 1 if destination_port > 0 else 0
    unique_destination_ips = safe_int(record.get("unique_destination_ips"), 1)
    if unique_destination_ips <= 0:
        unique_destination_ips = 1 if destination_ip else 0
    connection_rate = connection_count / duration if duration > 0 else float(connection_count)

    return {
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration": duration,
        "bytes_per_second": bytes_per_second,
        "packets_per_second": packets_per_second,
        "average_packet_size": average_packet_size,
        "connection_count": connection_count,
        "failed_connection_count": failed_connection_count,
        "failure_ratio": failure_ratio,
        "syn_count": syn_count,
        "rst_count": rst_count,
        "syn_ratio": syn_ratio,
        "unique_destination_ports": unique_destination_ports,
        "unique_destination_ips": unique_destination_ips,
        "connection_rate": connection_rate,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": str(record.get("protocol", "TCP")).upper(),
        "label": str(record.get("label", "NORMAL")).upper(),
    }


def extract_features_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    frames: List[pd.DataFrame] = []
    for _, row in df.iterrows():
        features = extract_network_features(row.to_dict())
        frames.append(pd.DataFrame([features]))

    if not frames:
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    output = pd.concat(frames, ignore_index=True)
    return output[FEATURE_COLUMNS]
