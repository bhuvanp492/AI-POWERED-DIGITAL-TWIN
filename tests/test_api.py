"""
Integration tests for FastAPI endpoints in AI-DT-CyberShield,
verifying:
- Module 5.1: User Authentication, Session Management, Access Logging, and Route Protection.
- Module 5.2: Real Application Activity Ingestion, Feature Extraction, and Isolation Forest Inference.
- Module 5.3: Risk Assessment, Calibration (0-100), and Explainable AI Reasoning.
- Simulation Suite: Controlled Benchmark Scenarios.
"""

import pytest
from fastapi.testclient import TestClient
from backend.app import app
from backend.database import init_db

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


def get_auth_token(username: str = "admin", password: str = "admin123") -> str:
    res = client.post("/api/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200
    return res.json()["token"]


# =====================================================================
# MODULE 5.1: USER AUTHENTICATION & APPLICATION ACCESS TESTS
# =====================================================================

def test_index_route():
    response = client.get("/")
    assert response.status_code == 200


def test_login_valid_credentials():
    response = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "token" in data
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "Lead Security Analyst"


def test_login_invalid_password():
    response = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert response.status_code == 401
    assert "detail" in response.json()


def test_login_invalid_username():
    response = client.post("/api/auth/login", json={"username": "non_existent_user", "password": "anypassword"})
    assert response.status_code == 401
    assert "detail" in response.json()


def test_login_empty_credentials():
    response = client.post("/api/auth/login", json={"username": "", "password": ""})
    assert response.status_code == 400
    assert "detail" in response.json()


def test_protected_endpoint_without_token_denied():
    # Attempting to access protected API without token must be rejected with 401
    response = client.get("/api/events")
    assert response.status_code == 401
    assert "detail" in response.json()


def test_protected_endpoint_with_valid_token_granted():
    token = get_auth_token("admin", "admin123")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/events", headers=headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_logout_and_access_revocation():
    token = get_auth_token("admin", "admin123")
    headers = {"Authorization": f"Bearer {token}"}

    # Verify access is granted initially
    res_before = client.get("/api/events", headers=headers)
    assert res_before.status_code == 200

    # Logout
    logout_res = client.post("/api/auth/logout", headers=headers)
    assert logout_res.status_code == 200
    assert logout_res.json()["success"] is True

    # Subsequent access with revoked token must fail with 401
    res_after = client.get("/api/events", headers=headers)
    assert res_after.status_code == 401


def test_auth_event_logging():
    # Trigger login fail, valid login, and check auth logs
    client.post("/api/auth/login", json={"username": "admin", "password": "badpassword"})
    token = get_auth_token("admin", "admin123")

    headers = {"Authorization": f"Bearer {token}"}
    logs_res = client.get("/api/auth/logs", headers=headers)
    assert logs_res.status_code == 200
    logs = logs_res.json()
    assert len(logs) > 0

    event_types = [l["event_type"] for l in logs]
    assert "LOGIN_SUCCESS" in event_types
    assert "LOGIN_FAILED" in event_types


# =====================================================================
# MODULE 5.2: AI BEHAVIOUR & ANOMALY DETECTION (REAL ACTIVITY) TESTS
# =====================================================================

def test_real_normal_activity_telemetry_and_prediction():
    token = get_auth_token("student01", "student123")
    headers = {"Authorization": f"Bearer {token}"}

    action_payload = {
        "action_type": "catalog_query",
        "custom_records": 5,
        "custom_download_mb": 1.2,
        "custom_rpm": 18.0
    }

    response = client.post("/api/resources/execute-action", json=action_payload, headers=headers)
    assert response.status_code == 200
    data = response.json()

    assert data["success"] is True
    assert data["telemetry_source"] == "ACTUAL_ACTIVITY"
    assert data["authenticated_user"] == "student01"
    assert data["event"]["username"] == "student01"
    assert data["event"]["event_source"] == "ACTUAL_ACTIVITY"

    # Verify Isolation Forest evaluated the real telemetry
    assert data["analysis"]["prediction"] == "NORMAL"
    assert data["analysis"]["risk_score"] <= 30
    assert data["analysis"]["risk_level"] == "Low"


def test_real_abnormal_activity_detection():
    token = get_auth_token("admin", "admin123")
    headers = {"Authorization": f"Bearer {token}"}

    # Simulate post-login anomaly: high-privilege restricted exam DB query with burst velocity and egress
    abnormal_payload = {
        "action_type": "exam_db_access",
        "custom_records": 850,
        "custom_download_mb": 450.0,
        "custom_rpm": 310.0,
        "simulate_new_device": True,
        "simulate_new_ip": True
    }

    response = client.post("/api/resources/execute-action", json=abnormal_payload, headers=headers)
    assert response.status_code == 200
    data = response.json()

    assert data["success"] is True
    assert data["telemetry_source"] == "ACTUAL_ACTIVITY"
    assert data["event"]["event_source"] == "ACTUAL_ACTIVITY"

    # Isolation Forest evaluates feature divergence
    assert data["analysis"]["prediction"] in ["ANOMALY DETECTED", "SUSPICIOUS"]
    assert data["analysis"]["risk_score"] >= 80
    assert data["analysis"]["risk_level"] == "Critical"
    assert "Student Grade & Exam Database" in data["analysis"]["reason"]


# =====================================================================
# MODULE 5.3: RISK ASSESSMENT & EXPLAINABLE SECURITY ANALYSIS TESTS
# =====================================================================

def test_explainable_analysis_feature_deviations():
    token = get_auth_token("admin", "admin123")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Fetch recent events
    events_res = client.get("/api/events?limit=1", headers=headers)
    assert events_res.status_code == 200
    events = events_res.json()
    assert len(events) > 0
    event_id = events[0]["id"]

    # 2. Inspect explainable analysis for that event
    analysis_res = client.get(f"/api/analysis/{event_id}", headers=headers)
    assert analysis_res.status_code == 200
    analysis = analysis_res.json()

    # Risk score must be calibrated from 0 to 100
    assert 0 <= analysis["risk_score"] <= 100
    assert analysis["risk_level"] in ["Low", "Medium", "High", "Critical"]

    # Explainable narrative must be present
    assert len(analysis["detected_behaviour"]) > 0
    assert len(analysis["reason"]) > 0
    assert len(analysis["recommended_action"]) > 0

    # Feature deviations must contain z-scores
    assert isinstance(analysis["feature_deviations"], list)
    if len(analysis["feature_deviations"]) > 0:
        first_dev = analysis["feature_deviations"][0]
        assert "feature" in first_dev
        assert "z_score" in first_dev
        assert "mean_baseline" in first_dev


# =====================================================================
# SIMULATION SUITE TESTS (CONTROLLED BENCHMARK TESTING)
# =====================================================================

def test_simulate_normal_activity():
    token = get_auth_token("admin", "admin123")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/api/simulation/run", json={"scenario_id": "normal_activity"}, headers=headers)
    assert response.status_code == 200
    result = response.json()
    assert result["success"] is True
    assert result["analysis"]["prediction"] == "NORMAL"
    assert result["analysis"]["risk_score"] <= 30
    assert result["event"]["event_source"] == "SIMULATION"


def test_simulate_compromised_account():
    token = get_auth_token("admin", "admin123")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/api/simulation/run", json={"scenario_id": "compromised_account"}, headers=headers)
    assert response.status_code == 200
    result = response.json()
    assert result["success"] is True
    assert result["analysis"]["prediction"] in ["ANOMALY DETECTED", "SUSPICIOUS"]
    assert result["analysis"]["risk_score"] >= 80
    assert result["analysis"]["risk_level"] == "Critical"
    assert result["event"]["login_status"] == "SUCCESSFUL"
    assert result["event"]["event_source"] == "SIMULATION"


def test_invalid_scenario_id():
    token = get_auth_token("admin", "admin123")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/api/simulation/run", json={"scenario_id": "non_existent_scenario"}, headers=headers)
    assert response.status_code == 400


def test_get_stats():
    token = get_auth_token("admin", "admin123")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/stats", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "total_events" in data
    assert "current_security_status" in data
    assert "current_risk_level" in data
    assert data["total_events"] > 0


def test_digital_twin_endpoint():
    token = get_auth_token("admin", "admin123")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/digital-twin", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "application_status" in data
    assert "security_state" in data
    assert "nodes" in data
    assert len(data["nodes"]) == 5
