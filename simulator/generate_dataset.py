from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

RESERVED_NETWORKS = [
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
]

SCENARIO_TYPES = [
    "NORMAL_WEB",
    "NORMAL_DNS",
    "NORMAL_SSH",
    "NORMAL_EMAIL",
    "NORMAL_DATABASE",
    "HIGH_CONNECTION_RATE",
    "REPEATED_FAILED_CONNECTIONS",
    "MULTI_PORT_PROBING_PATTERN",
    "SYN_HEAVY_PATTERN",
    "UNUSUAL_PORT_ACTIVITY",
    "HIGH_TRAFFIC_VOLUME",
]


def _make_ip(network: str, offset: int) -> str:
    base = network.split("/")[0]
    parts = base.split(".")
    parts[-1] = str((int(parts[-1]) + offset) % 256)
    return ".".join(parts)


def _pick_ip(network_index: int, offset: int) -> str:
    if network_index < 0:
        network_index = 0
    return _make_ip(RESERVED_NETWORKS[network_index % len(RESERVED_NETWORKS)], offset)


def _scenario_fields(scenario: str) -> Dict[str, float | int | str]:
    if scenario == "NORMAL_WEB":
        return {
            "label": "NORMAL",
            "source_port": random.randint(1024, 65535),
            "destination_port": 443,
            "protocol": "TCP",
            "packet_count": random.randint(25, 150),
            "byte_count": random.randint(3000, 150000),
            "duration_seconds": round(random.uniform(0.5, 3.0), 3),
            "connection_count": random.randint(1, 6),
            "failed_connection_count": random.randint(0, 1),
            "syn_count": random.randint(0, 3),
            "rst_count": random.randint(0, 2),
            "average_packet_size": random.randint(90, 350),
            "scenario_type": scenario,
        }

    if scenario == "NORMAL_DNS":
        return {
            "label": "NORMAL",
            "source_port": random.randint(1024, 65535),
            "destination_port": 53,
            "protocol": "UDP",
            "packet_count": random.randint(4, 30),
            "byte_count": random.randint(300, 5000),
            "duration_seconds": round(random.uniform(0.05, 1), 3),
            "connection_count": 1,
            "failed_connection_count": 0,
            "syn_count": 0,
            "rst_count": 0,
            "average_packet_size": random.randint(60, 180),
            "scenario_type": scenario,
        }

    if scenario == "NORMAL_SSH":
        return {
            "label": "NORMAL",
            "source_port": random.randint(1024, 65535),
            "destination_port": 22,
            "protocol": "TCP",
            "packet_count": random.randint(30, 200),
            "byte_count": random.randint(8000, 70000),
            "duration_seconds": round(random.uniform(1.0, 12.0), 3),
            "connection_count": random.randint(2, 8),
            "failed_connection_count": random.randint(0, 2),
            "syn_count": random.randint(1, 5),
            "rst_count": random.randint(0, 3),
            "average_packet_size": random.randint(120, 260),
            "scenario_type": scenario,
        }

    if scenario == "NORMAL_EMAIL":
        return {
            "label": "NORMAL",
            "source_port": random.randint(1024, 65535),
            "destination_port": 25,
            "protocol": "TCP",
            "packet_count": random.randint(8, 80),
            "byte_count": random.randint(1000, 25000),
            "duration_seconds": round(random.uniform(0.2, 10.0), 3),
            "connection_count": random.randint(1, 5),
            "failed_connection_count": random.randint(0, 1),
            "syn_count": random.randint(0, 2),
            "rst_count": random.randint(0, 1),
            "average_packet_size": random.randint(90, 200),
            "scenario_type": scenario,
        }

    if scenario == "NORMAL_DATABASE":
        return {
            "label": "NORMAL",
            "source_port": random.randint(1024, 65535),
            "destination_port": 3306,
            "protocol": "TCP",
            "packet_count": random.randint(60, 300),
            "byte_count": random.randint(15000, 250000),
            "duration_seconds": round(random.uniform(1.0, 30.0), 3),
            "connection_count": random.randint(3, 10),
            "failed_connection_count": random.randint(0, 2),
            "syn_count": random.randint(1, 10),
            "rst_count": random.randint(0, 4),
            "average_packet_size": random.randint(130, 500),
            "scenario_type": scenario,
        }

    if scenario == "HIGH_CONNECTION_RATE":
        return {
            "label": "SUSPICIOUS",
            "source_port": random.randint(10000, 65535),
            "destination_port": random.choice([443, 80, 8080, 8443]),
            "protocol": "TCP",
            "packet_count": random.randint(300, 2000),
            "byte_count": random.randint(150000, 1500000),
            "duration_seconds": round(random.uniform(1.0, 8.0), 3),
            "connection_count": random.randint(50, 300),
            "failed_connection_count": random.randint(4, 50),
            "syn_count": random.randint(20, 100),
            "rst_count": random.randint(5, 30),
            "average_packet_size": random.randint(180, 350),
            "scenario_type": scenario,
        }

    if scenario == "REPEATED_FAILED_CONNECTIONS":
        return {
            "label": "SUSPICIOUS",
            "source_port": random.randint(30000, 65535),
            "destination_port": random.choice([22, 3389, 445, 1433]),
            "protocol": "TCP",
            "packet_count": random.randint(50, 300),
            "byte_count": random.randint(8000, 160000),
            "duration_seconds": round(random.uniform(1.0, 10.0), 3),
            "connection_count": random.randint(20, 120),
            "failed_connection_count": random.randint(15, 100),
            "syn_count": random.randint(10, 70),
            "rst_count": random.randint(3, 25),
            "average_packet_size": random.randint(100, 280),
            "scenario_type": scenario,
        }

    if scenario == "MULTI_PORT_PROBING_PATTERN":
        return {
            "label": "SUSPICIOUS",
            "source_port": random.randint(1024, 65535),
            "destination_port": random.choice([21, 22, 23, 80, 443, 3389, 8080]),
            "protocol": "TCP",
            "packet_count": random.randint(100, 500),
            "byte_count": random.randint(20000, 300000),
            "duration_seconds": round(random.uniform(2.0, 25.0), 3),
            "connection_count": random.randint(20, 80),
            "failed_connection_count": random.randint(8, 35),
            "syn_count": random.randint(15, 90),
            "rst_count": random.randint(3, 20),
            "average_packet_size": random.randint(160, 290),
            "scenario_type": scenario,
        }

    if scenario == "SYN_HEAVY_PATTERN":
        return {
            "label": "SUSPICIOUS",
            "source_port": random.randint(40000, 65535),
            "destination_port": random.choice([80, 443, 22]),
            "protocol": "TCP",
            "packet_count": random.randint(300, 800),
            "byte_count": random.randint(100000, 700000),
            "duration_seconds": round(random.uniform(1.0, 6.0), 3),
            "connection_count": random.randint(30, 200),
            "failed_connection_count": random.randint(10, 60),
            "syn_count": random.randint(80, 250),
            "rst_count": random.randint(12, 60),
            "average_packet_size": random.randint(120, 300),
            "scenario_type": scenario,
        }

    if scenario == "UNUSUAL_PORT_ACTIVITY":
        return {
            "label": "SUSPICIOUS",
            "source_port": random.randint(20000, 65535),
            "destination_port": random.choice([8443, 8080, 8888, 9000]),
            "protocol": "TCP",
            "packet_count": random.randint(80, 350),
            "byte_count": random.randint(30000, 500000),
            "duration_seconds": round(random.uniform(2.0, 20.0), 3),
            "connection_count": random.randint(15, 80),
            "failed_connection_count": random.randint(6, 35),
            "syn_count": random.randint(10, 60),
            "rst_count": random.randint(4, 25),
            "average_packet_size": random.randint(130, 350),
            "scenario_type": scenario,
        }

    return {
        "label": "SUSPICIOUS",
        "source_port": random.randint(10000, 65535),
        "destination_port": random.choice([80, 443, 53]),
        "protocol": "TCP",
        "packet_count": random.randint(500, 2500),
        "byte_count": random.randint(300000, 2000000),
        "duration_seconds": round(random.uniform(5.0, 30.0), 3),
        "connection_count": random.randint(40, 200),
        "failed_connection_count": random.randint(8, 80),
        "syn_count": random.randint(20, 120),
        "rst_count": random.randint(5, 30),
        "average_packet_size": random.randint(150, 450),
        "scenario_type": "HIGH_TRAFFIC_VOLUME",
    }


def generate_synthetic_record(flow_id: int, timestamp: Optional[datetime] = None, scenario: Optional[str] = None) -> Dict[str, object]:
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    if scenario is None:
        scenario = random.choices(SCENARIO_TYPES, weights=[8, 6, 4, 4, 4, 3, 3, 3, 3, 3, 2])[0]

    fields = _scenario_fields(scenario)
    source_network_index = random.randint(0, len(RESERVED_NETWORKS) - 1)
    destination_network_index = random.randint(0, len(RESERVED_NETWORKS) - 1)
    source_ip = _pick_ip(source_network_index, random.randint(10, 200))
    destination_ip = _pick_ip(destination_network_index, random.randint(10, 200))

    return {
        "flow_id": f"FLOW-{flow_id:06d}",
        "timestamp": timestamp.isoformat(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": fields["source_port"],
        "destination_port": fields["destination_port"],
        "protocol": fields["protocol"],
        "packet_count": fields["packet_count"],
        "byte_count": fields["byte_count"],
        "duration_seconds": fields["duration_seconds"],
        "connection_count": fields["connection_count"],
        "failed_connection_count": fields["failed_connection_count"],
        "syn_count": fields["syn_count"],
        "rst_count": fields["rst_count"],
        "average_packet_size": fields["average_packet_size"],
        "label": fields["label"],
        "scenario_type": fields["scenario_type"],
        "unique_destination_ports": 1,
        "unique_destination_ips": 1,
    }


def generate_dataset(count: int = 5000, output_path: str = "data/network_traffic.csv") -> pd.DataFrame:
    random.seed(42)
    records: List[Dict[str, object]] = []
    now = datetime.now(timezone.utc)
    for idx in range(1, count + 1):
        scenario = random.choices(SCENARIO_TYPES, weights=[10, 8, 6, 6, 6, 4, 4, 4, 4, 4, 3])[0]
        record = generate_synthetic_record(idx, now - timedelta(seconds=idx), scenario)
        records.append(record)

    df = pd.DataFrame(records)
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_file, index=False)
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic safe network traffic for an IDS simulation.")
    parser.add_argument("--count", type=int, default=5000, help="Number of flow records to generate.")
    parser.add_argument("--output", default="data/network_traffic.csv", help="CSV file for generated flow data.")
    args = parser.parse_args()
    generate_dataset(args.count, args.output)
    print(f"Generated {args.count} synthetic flow records in {args.output}")
