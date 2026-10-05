from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from ids.feature_extractor import FEATURE_COLUMNS, extract_features_dataframe


def prepare_labels(df: pd.DataFrame) -> pd.Series:
    labels = df["label"].astype(str).str.upper()
    mapping = {"NORMAL": 0, "SUSPICIOUS": 1, "POTENTIAL_INTRUSION": 1}
    return labels.map(mapping).fillna(1)


def train_model(dataset_path: str = "data/network_traffic.csv", output_path: str = "models/ids_model.joblib") -> Dict[str, float]:
    data = pd.read_csv(dataset_path)
    feature_frame = extract_features_dataframe(data)
    y = prepare_labels(data)
    X = feature_frame

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
    }

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "feature_columns": FEATURE_COLUMNS, "metrics": metrics}, output_file)
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train a random forest IDS model")
    parser.add_argument("--dataset", default="data/network_traffic.csv")
    parser.add_argument("--output", default="models/ids_model.joblib")
    args = parser.parse_args()
    metrics = train_model(args.dataset, args.output)
    print(metrics)
