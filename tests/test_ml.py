"""
Unit tests for Machine Learning Anomaly Detection and Risk Engine in AI-DT-CyberShield.
Verifies that Isolation Forest genuinely performs inference with zero hardcoded scenario overrides.
"""

import os
import inspect
import pytest
from ml.anomaly_detector import get_detector, FEATURE_COLUMNS
from backend.services.risk_engine import evaluate_security_risk


def test_zero_scenario_hardcoding_in_risk_engine():
    """Verifies that risk_engine.py contains NO scenario_type overrides."""
    import backend.services.risk_engine as re_module
    src = inspect.getsource(re_module)
    assert 'scenario_type == "compromised_account"' not in src, "Forbidden scenario hardcoding found!"
    assert 'scenario_type == "normal_activity"' not in src, "Forbidden scenario hardcoding found!"
    assert "if scenario_type ==" not in src, "Forbidden scenario-based logic found!"


def test_model_loading():
    detector = get_detector()
    assert detector.is_loaded is True
    assert detector.model is not None
    assert detector.scaler is not None
    assert len(detector.metadata.get("feature_columns", [])) == 12


def test_feature_vector_dimensions():
    detector = get_detector()
    sample_data = {
        "requests_per_minute": 25.0,
        "failed_login_count": 0,
        "login_frequency_per_hr": 1.0,
        "resource_sensitivity_level": 1,
        "records_accessed": 5,
        "data_download_mb": 1.0,
        "is_new_device": 0,
        "is_new_ip": 0,
        "unusual_api_access": 0,
        "session_duration_minutes": 30.0,
        "access_time_hour": 14,
        "behaviour_deviation_score": 0.05
    }
    df, scaled_vec = detector.extract_feature_vector(sample_data)
    assert scaled_vec.shape == (1, 12)
    assert list(df.columns) == FEATURE_COLUMNS


def test_normal_user_prediction():
    detector = get_detector()
    normal_sample = {
        "requests_per_minute": 15.0,
        "failed_login_count": 0,
        "login_frequency_per_hr": 1.0,
        "resource_sensitivity_level": 1,
        "records_accessed": 4,
        "data_download_mb": 0.8,
        "is_new_device": 0,
        "is_new_ip": 0,
        "unusual_api_access": 0,
        "session_duration_minutes": 25.0,
        "access_time_hour": 11,
        "behaviour_deviation_score": 0.04
    }
    ml_result = detector.predict(normal_sample)
    assert ml_result["prediction"] == "NORMAL"
    assert ml_result["anomaly_score"] < 0.35

    # Pass into risk engine without ANY scenario_type
    risk_result = evaluate_security_risk(normal_sample)
    assert risk_result["prediction"] == "NORMAL"
    assert risk_result["risk_score"] <= 30
    assert risk_result["risk_level"] == "Low"
    assert "consistent with the established baseline" in risk_result["reason"].lower()


def test_compromised_account_detection():
    """
    Valid Credentials + Normal Working Hours + Successful Login
    BUT Post-Login: New Device + New IP + High API + Sensitive DB + High Download
    Must be identified as ANOMALY DETECTED and CRITICAL/HIGH risk purely via features!
    """
    compromised_sample = {
        "username": "admin_sarah",
        "login_status": "SUCCESSFUL",  # Valid credentials!
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
        "behaviour_deviation_score": 0.94,
        "resource_name": "Student Grade & Exam Database"
        # Notice: NO scenario_type provided!
    }

    result = evaluate_security_risk(compromised_sample)

    assert result["prediction"] == "ANOMALY DETECTED"
    assert result["risk_score"] >= 80
    assert result["risk_level"] == "Critical"
    assert "Student Grade & Exam Database" in result["reason"]
    assert "post-login" in result["reason"].lower() or "post-authentication" in result["detected_behaviour"].lower()
    assert "restrict session" in result["recommended_action"].lower()
