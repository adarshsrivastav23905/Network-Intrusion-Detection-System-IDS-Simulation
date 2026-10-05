import unittest

from ids.alert_engine import generate_alert
from ids.anomaly_detector import calculate_anomaly_score, calculate_baseline
from ids.feature_extractor import extract_network_features
from ids.risk_engine import calculate_risk_score
from ids.rule_engine import analyze_flow


class TestIDSModules(unittest.TestCase):
    def setUp(self):
        self.flow = {
            "flow_id": "FLOW-0001",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 12345,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_count": 250,
            "byte_count": 60000,
            "duration_seconds": 2.0,
            "connection_count": 35,
            "failed_connection_count": 18,
            "syn_count": 100,
            "rst_count": 8,
            "average_packet_size": 240,
            "label": "SUSPICIOUS",
            "scenario_type": "HIGH_CONNECTION_RATE",
        }

    def test_feature_extraction_handles_zero_duration(self):
        flow = {**self.flow, "duration_seconds": 0}
        result = extract_network_features(flow)
        self.assertGreater(result["packets_per_second"], 0)
        self.assertGreater(result["bytes_per_second"], 0)
        self.assertGreaterEqual(result["duration"], 0)

    def test_rule_engine_detects_suspicious_pattern(self):
        result = analyze_flow(self.flow)
        self.assertTrue(result["is_suspicious"])
        self.assertGreater(result["rule_count"], 0)

    def test_anomaly_score_is_bounded(self):
        baseline = {
            "packet_rate": {"mean": 20.0, "std": 5.0},
            "byte_rate": {"mean": 1000.0, "std": 100.0},
            "connection_rate": {"mean": 5.0, "std": 2.0},
            "failed_connection_ratio": {"mean": 0.1, "std": 0.05},
            "destination_port_diversity": {"mean": 3.0, "std": 1.0},
        }
        result = calculate_anomaly_score(extract_network_features(self.flow), baseline)
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)

    def test_risk_score_is_classified(self):
        result = calculate_risk_score([{"severity": "HIGH"}], 85, 0.7)
        self.assertIn(result["classification"], {"HIGH RISK", "CRITICAL INVESTIGATION"})
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)

    def test_alert_generation(self):
        alert = generate_alert(self.flow, [{"rule_id": "RULE_02", "name": "Repeated Failed Connections", "description": "Test"}], 66, 72)
        self.assertIn("alert_id", alert)
        self.assertEqual(alert["status"], "NEW")
        self.assertIn(alert["severity"], {"LOW", "MEDIUM", "HIGH", "CRITICAL"})


if __name__ == "__main__":
    unittest.main()
