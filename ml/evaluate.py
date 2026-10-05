from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

from ids.feature_extractor import extract_features_dataframe


def evaluate_model(model_path: str = "models/ids_model.joblib", dataset_path: str = "data/network_traffic.csv") -> dict:
    bundle = joblib.load(model_path)
    model = bundle["model"]
    df = pd.read_csv(dataset_path)
    X = extract_features_dataframe(df)
    y = df["label"].str.upper().map({"NORMAL": 0, "SUSPICIOUS": 1, "POTENTIAL_INTRUSION": 1}).fillna(1)

    predictions = model.predict(X)
    metrics = {
        "accuracy": float(accuracy_score(y, predictions)),
        "precision": float(precision_score(y, predictions, zero_division=0)),
        "recall": float(recall_score(y, predictions, zero_division=0)),
        "f1": float(f1_score(y, predictions, zero_division=0)),
        "confusion_matrix": confusion_matrix(y, predictions).tolist(),
    }
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate the trained IDS model")
    parser.add_argument("--model", default="models/ids_model.joblib")
    parser.add_argument("--dataset", default="data/network_traffic.csv")
    args = parser.parse_args()
    print(evaluate_model(args.model, args.dataset))
