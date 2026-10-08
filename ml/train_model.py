"""
Model Training Script for AI-DT-CyberShield.
Trains an Isolation Forest anomaly detection model on behavioral cloud security logs.
Saves model artifacts (model, scaler, metadata) to ml/model/ directory.
"""

import os
import json
from datetime import datetime
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix

FEATURE_COLUMNS = [
    "requests_per_minute",
    "failed_login_count",
    "login_frequency_per_hr",
    "resource_sensitivity_level",
    "records_accessed",
    "data_download_mb",
    "is_new_device",
    "is_new_ip",
    "unusual_api_access",
    "session_duration_minutes",
    "access_time_hour",
    "behaviour_deviation_score"
]


def train_isolation_forest(
    data_path: str = "data/security_logs.csv",
    model_dir: str = "ml/model",
    contamination: float = 0.12,
    n_estimators: int = 150
):
    os.makedirs(model_dir, exist_ok=True)
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Dataset not found at {data_path}. Run dataset_generator.py first.")

    df = pd.read_csv(data_path)
    print(f"Loaded {len(df)} samples from {data_path}")

    X = df[FEATURE_COLUMNS].copy()
    y_true = df["label"].map({"NORMAL": 1, "SUSPICIOUS": -1}).values

    # Fit Scaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train Isolation Forest
    print(f"Training Isolation Forest with n_estimators={n_estimators}, contamination={contamination}...")
    iso_forest = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_samples="auto",
        random_state=42,
        n_jobs=-1
    )
    iso_forest.fit(X_scaled)

    # Predictions (+1 = Normal, -1 = Anomaly/Suspicious)
    y_pred = iso_forest.predict(X_scaled)
    raw_scores = iso_forest.decision_function(X_scaled)  # Lower is more abnormal

    report = classification_report(
        y_true, y_pred,
        target_names=["SUSPICIOUS (-1)", "NORMAL (+1)"],
        output_dict=True
    )
    cm = confusion_matrix(y_true, y_pred).tolist()

    print("\n--- Model Evaluation ---")
    print(classification_report(y_true, y_pred, target_names=["SUSPICIOUS (-1)", "NORMAL (+1)"]))
    print("Confusion Matrix:\n", confusion_matrix(y_true, y_pred))

    # Calculate calibration statistics for converting raw decision function to [0, 1] anomaly score
    min_score = float(np.min(raw_scores))
    max_score = float(np.max(raw_scores))
    mean_score = float(np.mean(raw_scores))

    # Export artifacts
    model_path = os.path.join(model_dir, "isolation_forest.joblib")
    scaler_path = os.path.join(model_dir, "scaler.joblib")
    metadata_path = os.path.join(model_dir, "model_metadata.json")

    joblib.dump(iso_forest, model_path)
    joblib.dump(scaler, scaler_path)

    metadata = {
        "model_name": "IsolationForest",
        "algorithm": "Unsupervised Isolation Forest Anomaly Detection",
        "trained_at": datetime.now().isoformat(),
        "n_samples": len(df),
        "n_estimators": n_estimators,
        "contamination": contamination,
        "feature_columns": FEATURE_COLUMNS,
        "score_calibration": {
            "min_raw_score": min_score,
            "max_raw_score": max_score,
            "mean_raw_score": mean_score,
            "threshold_zero": 0.0
        },
        "metrics": {
            "accuracy": report["accuracy"],
            "suspicious_f1": report["SUSPICIOUS (-1)"]["f1-score"],
            "normal_f1": report["NORMAL (+1)"]["f1-score"],
            "confusion_matrix": cm
        }
    }

    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nModel artifacts saved successfully:")
    print(f" - {model_path}")
    print(f" - {scaler_path}")
    print(f" - {metadata_path}")
    return metadata


if __name__ == "__main__":
    train_isolation_forest()
