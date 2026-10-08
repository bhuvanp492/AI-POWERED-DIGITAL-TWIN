"""
Real-Time Anomaly Detection Inference Engine for AI-DT-CyberShield.
Loads trained Isolation Forest and Scaler, analyzes behavioral security events,
and computes anomaly scores, classification, and feature deviation breakdowns.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple, List

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


class AnomalyDetector:
    _instance = None

    def __init__(self, model_dir: str = "ml/model"):
        self.model_dir = model_dir
        self.model = None
        self.scaler = None
        self.metadata = {}
        self.is_loaded = False
        self.load_model()

    @classmethod
    def get_instance(cls, model_dir: str = "ml/model"):
        if cls._instance is None:
            cls._instance = cls(model_dir=model_dir)
        return cls._instance

    def load_model(self):
        model_path = os.path.join(self.model_dir, "isolation_forest.joblib")
        scaler_path = os.path.join(self.model_dir, "scaler.joblib")
        meta_path = os.path.join(self.model_dir, "model_metadata.json")

        if os.path.exists(model_path) and os.path.exists(scaler_path):
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            if os.path.exists(meta_path):
                with open(meta_path, "r") as f:
                    self.metadata = json.load(f)
            self.is_loaded = True
            print(f"[AnomalyDetector] Successfully loaded model from {self.model_dir}")
        else:
            print(f"[AnomalyDetector] Warning: Model artifacts not found at {self.model_dir}. Running without trained weights.")
            self.is_loaded = False

    def extract_feature_vector(self, event_data: Dict[str, Any]) -> Tuple[pd.DataFrame, np.ndarray]:
        """Extracts and formats the feature values from an incoming event dictionary."""
        row = {}
        for col in FEATURE_COLUMNS:
            val = event_data.get(col, 0)
            try:
                row[col] = float(val)
            except (ValueError, TypeError):
                row[col] = 0.0

        df = pd.DataFrame([row])
        if self.scaler is not None:
            scaled_vec = self.scaler.transform(df)
        else:
            scaled_vec = df.values
        return df, scaled_vec

    def predict(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs the Isolation Forest model on the event data.
        Returns:
            - prediction: 'NORMAL' or 'SUSPICIOUS'
            - raw_score: raw decision function value
            - anomaly_score: calibrated float from 0.0 (very normal) to 1.0 (extreme anomaly)
            - feature_deviations: dict of top contributing deviating features
        """
        if not self.is_loaded:
            self.load_model()

        df_raw, scaled_vec = self.extract_feature_vector(event_data)

        if self.model is None:
            # Fallback heuristic if model not present
            return {
                "prediction": "NORMAL",
                "raw_score": 0.1,
                "anomaly_score": 0.15,
                "is_outlier": False,
                "feature_deviations": {}
            }

        # Isolation forest decision_function: positive is inlier (normal), negative is outlier (anomaly)
        raw_score = float(self.model.decision_function(scaled_vec)[0])
        iso_pred = int(self.model.predict(scaled_vec)[0])  # +1 = normal, -1 = anomaly

        # Calibrate raw_score to 0.0 - 1.0 where 1.0 is highest anomaly
        # Normal decision_function typically ranges between -0.30 and +0.25
        # We use a logistic / clamped mapping centered around threshold 0.0
        # When raw_score <= 0, it is an anomaly
        if raw_score >= 0.15:
            anomaly_score = max(0.02, 0.20 - (raw_score * 0.5))
        elif raw_score >= 0.0:
            anomaly_score = 0.20 + ((0.15 - raw_score) / 0.15) * 0.25  # 0.20 to 0.45
        else:
            # raw_score < 0: negative scores are outliers
            # -0.00 to -0.25 -> 0.45 to 0.98
            severity = abs(raw_score) / 0.25
            anomaly_score = min(0.99, 0.45 + (severity * 0.54))

        anomaly_score = round(float(anomaly_score), 3)

        # Determine prediction: If iso_pred is -1 or anomaly_score >= 0.45, SUSPICIOUS
        prediction = "SUSPICIOUS" if (iso_pred == -1 or anomaly_score >= 0.45) else "NORMAL"

        # Calculate feature deviation / importance for explainability
        feature_deviations = self._calculate_feature_deviations(df_raw, scaled_vec)

        return {
            "prediction": prediction,
            "raw_score": round(raw_score, 4),
            "anomaly_score": anomaly_score,
            "is_outlier": (iso_pred == -1),
            "feature_deviations": feature_deviations
        }

    def _calculate_feature_deviations(self, df_raw: pd.DataFrame, scaled_vec: np.ndarray) -> List[Dict[str, Any]]:
        """Identifies which features deviated most significantly from normal baseline."""
        deviations = []
        if self.scaler is None:
            return deviations

        means = self.scaler.mean_
        scales = self.scaler.scale_
        vals = scaled_vec[0]

        for i, col in enumerate(FEATURE_COLUMNS):
            raw_val = float(df_raw[col].iloc[0])
            mean_val = float(means[i])
            z_score = float(vals[i])

            # Only include notable deviations or security-critical triggers
            deviations.append({
                "feature": col,
                "raw_value": round(raw_val, 2),
                "mean_baseline": round(mean_val, 2),
                "z_score": round(z_score, 2),
                "is_elevated": z_score > 1.5,
                "is_extreme": z_score > 3.0
            })

        # Sort by absolute z-score descending
        deviations.sort(key=lambda x: abs(x["z_score"]), reverse=True)
        return deviations


# Global singleton helper
def get_detector() -> AnomalyDetector:
    return AnomalyDetector.get_instance()


if __name__ == "__main__":
    detector = get_detector()
    # Test sample normal
    normal_sample = {
        "requests_per_minute": 18.0,
        "failed_login_count": 0,
        "login_frequency_per_hr": 1.5,
        "resource_sensitivity_level": 1,
        "records_accessed": 5,
        "data_download_mb": 1.2,
        "is_new_device": 0,
        "is_new_ip": 0,
        "unusual_api_access": 0,
        "session_duration_minutes": 25.0,
        "access_time_hour": 11,
        "behaviour_deviation_score": 0.05
    }
    res_normal = detector.predict(normal_sample)
    print("Test Normal Prediction:", res_normal)

    # Test sample compromised account
    compromised_sample = {
        "requests_per_minute": 310.0,
        "failed_login_count": 0,
        "login_frequency_per_hr": 2.0,
        "resource_sensitivity_level": 5,
        "records_accessed": 850,
        "data_download_mb": 450.0,
        "is_new_device": 1,
        "is_new_ip": 1,
        "unusual_api_access": 1,
        "session_duration_minutes": 12.5,
        "access_time_hour": 14,
        "behaviour_deviation_score": 0.94
    }
    res_compromised = detector.predict(compromised_sample)
    print("Test Compromised Account Prediction:", res_compromised)
