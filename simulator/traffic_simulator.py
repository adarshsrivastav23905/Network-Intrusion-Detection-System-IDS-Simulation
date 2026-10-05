from __future__ import annotations

import argparse
import csv
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from typing import Dict, List

from simulator.generate_dataset import generate_synthetic_record


def _serialize_record(record: Dict[str, object]) -> Dict[str, object]:
    return {
        "flow_id": record["flow_id"],
        "timestamp": record["timestamp"],
        "source_ip": record["source_ip"],
        "destination_ip": record["destination_ip"],
        "source_port": record["source_port"],
        "destination_port": record["destination_port"],
        "protocol": record["protocol"],
        "packet_count": record["packet_count"],
        "byte_count": record["byte_count"],
        "duration_seconds": record["duration_seconds"],
        "connection_count": record["connection_count"],
        "failed_connection_count": record["failed_connection_count"],
        "syn_count": record["syn_count"],
        "rst_count": record["rst_count"],
        "average_packet_size": record["average_packet_size"],
        "label": record["label"],
        "scenario_type": record["scenario_type"],
    }


class TrafficSimulator:
    def __init__(self, mode: str = "mixed", speed: str = "slow", output_path: str = "data/live_traffic.csv") -> None:
        self.mode = mode.lower()
        self.speed = speed.lower()
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.flow_count = 0

    def _next_delay(self) -> float:
        delays = {"slow": 5.0, "fast": 1.0}
        return delays.get(self.speed, 5.0)

    def _generate_record(self) -> Dict[str, object]:
        if self.mode == "normal":
            scenario = random.choice(["NORMAL_WEB", "NORMAL_DNS", "NORMAL_SSH", "NORMAL_EMAIL", "NORMAL_DATABASE"])
        elif self.mode == "mixed":
            scenario = random.choice([
                "NORMAL_WEB",
                "NORMAL_DNS",
                "NORMAL_SSH",
                "NORMAL_EMAIL",
                "NORMAL_DATABASE",
                "HIGH_CONNECTION_RATE",
                "REPEATED_FAILED_CONNECTIONS",
                "MULTI_PORT_PROBING_PATTERN",
                "SYN_HEAVY_PATTERN",
            ])
        else:
            scenario = "NORMAL_WEB"

        self.flow_count += 1
        return generate_synthetic_record(self.flow_count, scenario=scenario)

    def run(self, duration_seconds: int | None = None) -> List[Dict[str, object]]:
        records: List[Dict[str, object]] = []
        stop_time = None if duration_seconds is None else time.time() + duration_seconds
        while stop_time is None or time.time() < stop_time:
            record = self._generate_record()
            records.append(_serialize_record(record))
            with self.output_path.open("a", newline="", encoding="utf-8") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=list(records[0].keys()) if records else [])
                if csv_file.tell() == 0:
                    writer.writeheader()
                writer.writerow(records[-1])
            time.sleep(self._next_delay())
        return records


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate simulated synthetic network flows.")
    parser.add_argument("--mode", choices=["normal", "mixed"], default="mixed")
    parser.add_argument("--speed", choices=["slow", "fast"], default="slow")
    parser.add_argument("--duration", type=int, default=30, help="Simulation duration in seconds.")
    parser.add_argument("--output", default="data/live_traffic.csv", help="CSV path for generated flow snapshots.")
    args = parser.parse_args()

    simulator = TrafficSimulator(mode=args.mode, speed=args.speed, output_path=args.output)
    records = simulator.run(duration_seconds=args.duration)
    print(f"Generated {len(records)} simulated records into {args.output}")
