from __future__ import annotations

from typing import Any, Dict, List, Optional


def calculate_risk_score(
    rule_hits: List[Dict[str, Any]],
    anomaly_score: float,
    ml_probability: float = 0.0,
    weights: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    if weights is None:
        if ml_probability > 0:
            weights = {"rule_based": 0.4, "anomaly": 0.3, "ml": 0.3}
        else:
            weights = {"rule_based": 0.6, "anomaly": 0.4, "ml": 0.0}

    rule_strength = min(100.0, 20.0 * len(rule_hits))
    rule_strength += 15.0 if any(hit.get("severity") in {"HIGH", "CRITICAL"} for hit in rule_hits) else 0.0

    final_score = (
        weights.get("rule_based", 0.0) * rule_strength
        + weights.get("anomaly", 0.0) * float(anomaly_score)
        + weights.get("ml", 0.0) * float(ml_probability) * 100.0
    )
    final_score = max(0.0, min(100.0, final_score))

    if final_score < 20:
        classification = "NORMAL"
    elif final_score < 40:
        classification = "LOW RISK"
    elif final_score < 60:
        classification = "SUSPICIOUS"
    elif final_score < 80:
        classification = "HIGH RISK"
    else:
        classification = "CRITICAL INVESTIGATION"

    return {
        "risk_score": int(round(final_score)),
        "classification": classification,
    }
