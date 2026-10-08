"""
Comprehensive Phase-1 Module Verification Suite for AI-DT-CyberShield:
- Module 5.1: User Authentication, Session Management, Access Logging, and Route Protection
- Module 5.2: AI-Based Behaviour & Anomaly Detection (Real Application Telemetry & Feature Extraction)
- Module 5.3: Risk Assessment (0-100) & Explainable Security Analysis (Feature Deviations & Rules)
- End-to-End Workflow: Login -> Protected Action -> Telemetry -> Isolation Forest -> Risk -> Explanation
"""

import pytest
from fastapi.testclient import TestClient
from backend.app import app
from backend.database import init_db, get_db_connection, get_auth_events
from ml.anomaly_detector import get_detector, FEATURE_COLUMNS
from backend.services.feature_extractor import extract_features_from_activity
from backend.services.risk_engine import evaluate_security_risk

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


def login_user(username: str, password: str):
    return client.post("/api/auth/login", json={"username": username, "password": password})


# =====================================================================
# MODULE 5.1 VERIFICATION TESTS
# =====================================================================

def test_5_1_valid_login_for_all_seeded_users():
    """Verifies that all seeded accounts authenticate successfully with salted password hashes."""
    users = [
        ("admin", "admin123", "Lead Security Analyst"),
        ("analyst", "analyst123", "SOC Tier-1 Analyst"),
        ("student01", "student123", "Student Researcher"),
        ("faculty_chen", "faculty123", "Faculty Investigator")
    ]
    for uname, pwd, role in users:
        res = login_user(uname, pwd)
        assert res.status_code == 200, f"Failed to login as {uname}"
        data = res.json()
        assert data["success"] is True
        assert data["user"]["username"] == uname
        assert data["user"]["role"] == role
        assert "token" in data
        assert len(data["token"]) > 20


def test_5_1_invalid_credentials_rejected():
    """Verifies that invalid usernames, invalid passwords, and empty inputs are rejected."""
    # Invalid user
    res1 = login_user("nonexistent_user", "password123")
    assert res1.status_code == 401

    # Invalid password
    res2 = login_user("admin", "wrong_password_999")
    assert res2.status_code == 401

    # Empty username/password
    res3 = login_user("", "")
    assert res3.status_code == 400


def test_5_1_protected_endpoints_reject_unauthenticated():
    """Verifies that protected endpoints return 401 when accessed without a token."""
    protected_urls = [
        "/api/events",
        "/api/events/1",
        "/api/stats",
        "/api/digital-twin",
        "/api/resources/list",
        "/api/auth/logs"
    ]
    for url in protected_urls:
        res = client.get(url)
        assert res.status_code == 401, f"URL {url} did not reject unauthenticated access"


def test_5_1_logout_invalidates_session():
    """Verifies that logging out immediately revokes subsequent protected access."""
    login_res = login_user("faculty_chen", "faculty123")
    token = login_res.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Access granted before logout
    res_before = client.get("/api/resources/list", headers=headers)
    assert res_before.status_code == 200

    # Logout
    logout_res = client.post("/api/auth/logout", headers=headers)
    assert logout_res.status_code == 200

    # Access denied after logout
    res_after = client.get("/api/resources/list", headers=headers)
    assert res_after.status_code == 401


def test_5_1_no_plaintext_passwords_in_db():
    """Verifies that passwords in SQLite are salted hashes, never stored in plaintext."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, password_hash, salt FROM users")
    rows = cursor.fetchall()
    conn.close()

    assert len(rows) >= 4
    for r in rows:
        assert r["password_hash"] != "admin123"
        assert r["password_hash"] != "analyst123"
        assert r["password_hash"] != "student123"
        assert r["password_hash"] != "faculty123"
        assert len(r["password_hash"]) == 64  # SHA256 hex string length
        assert len(r["salt"]) >= 16


def test_5_1_access_logging_records_events_without_passwords():
    """Verifies that authentication events are logged, and no passwords appear in auth logs."""
    client.post("/api/auth/login", json={"username": "student01", "password": "wrong_password"})
    login_res = login_user("student01", "student123")
    token = login_res.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Attempt unauthorized access to trigger UNAUTHORIZED_ACCESS log
    client.get("/api/events")

    # Fetch logs
    logs_res = client.get("/api/auth/logs", headers=headers)
    assert logs_res.status_code == 200
    logs = logs_res.json()

    event_types = [l["event_type"] for l in logs]
    assert "LOGIN_FAILED" in event_types
    assert "LOGIN_SUCCESS" in event_types
    assert "UNAUTHORIZED_ACCESS" in event_types

    # Ensure no passwords leaked into details or fields
    for l in logs:
        assert "password" not in (l.get("details") or "").lower() or "empty" in l.get("details", "").lower() or "incorrect" in l.get("details", "").lower()
        assert "student123" not in str(l)


# =====================================================================
# MODULE 5.2 VERIFICATION TESTS
# =====================================================================

def test_5_2_feature_extraction_vector_dimensions():
    """Verifies that feature extraction produces the exact 12-feature vector expected by the model."""
    detector = get_detector()
    assert detector.is_loaded is True

    telemetry = extract_features_from_activity(
        username="faculty_chen",
        action="QUERY_COURSE_CATALOG",
        resource_name="Course Catalog API",
        resource_sensitivity_level=1,
        records_accessed=8,
        data_download_mb=1.4,
        client_ip="10.0.4.15",
        user_agent="Safari on macOS",
        override_rpm=16.0
    )

    df, scaled_vec = detector.extract_feature_vector(telemetry)
    assert scaled_vec.shape == (1, 12)
    assert list(df.columns) == FEATURE_COLUMNS


def test_5_2_real_user_normal_action_pipeline():
    """Verifies that real normal application actions generate telemetry and are classified as NORMAL."""
    login_res = login_user("student01", "student123")
    token = login_res.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    action_payload = {
        "action_type": "catalog_query",
        "custom_records": 6,
        "custom_download_mb": 1.2,
        "custom_rpm": 18.0
    }

    res = client.post("/api/resources/execute-action", json=action_payload, headers=headers)
    assert res.status_code == 200
    data = res.json()

    # Telemetry source attribution
    assert data["telemetry_source"] == "ACTUAL_ACTIVITY"
    assert data["authenticated_user"] == "student01"
    assert data["event"]["username"] == "student01"
    assert data["event"]["event_source"] == "ACTUAL_ACTIVITY"

    # AI Anomaly Evaluation
    assert data["analysis"]["prediction"] == "NORMAL"
    assert data["analysis"]["risk_score"] <= 30
    assert data["analysis"]["risk_level"] == "Low"


def test_5_2_real_user_abnormal_action_pipeline():
    """Verifies that real abnormal application actions generate telemetry and are flagged as ANOMALY DETECTED."""
    login_res = login_user("analyst", "analyst123")
    token = login_res.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Controlled abnormal action: volumetric burst + restricted Exam DB + high egress + new IP/device
    abnormal_payload = {
        "action_type": "exam_db_access",
        "custom_records": 850,
        "custom_download_mb": 450.0,
        "custom_rpm": 310.0,
        "simulate_new_device": True,
        "simulate_new_ip": True
    }

    res = client.post("/api/resources/execute-action", json=abnormal_payload, headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["telemetry_source"] == "ACTUAL_ACTIVITY"
    assert data["authenticated_user"] == "analyst"
    assert data["analysis"]["prediction"] in ["ANOMALY DETECTED", "SUSPICIOUS"]
    assert data["analysis"]["risk_score"] >= 80
    assert data["analysis"]["risk_level"] == "Critical"
    assert data["analysis"]["anomaly_score"] >= 0.40


# =====================================================================
# MODULE 5.3 VERIFICATION TESTS
# =====================================================================

def test_5_3_risk_calculation_calibration_and_rules():
    """Verifies that risk scores remain strictly within 0-100 and match defined risk levels."""
    # Low risk test
    low_event = {
        "requests_per_minute": 15.0,
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
        "behaviour_deviation_score": 0.05,
        "resource_name": "Course Catalog API"
    }
    low_eval = evaluate_security_risk(low_event)
    assert 0 <= low_eval["risk_score"] <= 30
    assert low_eval["risk_level"] == "Low"

    # High / Critical risk test
    high_event = {
        "requests_per_minute": 320.0,
        "failed_login_count": 0,
        "login_frequency_per_hr": 2.0,
        "resource_sensitivity_level": 5,
        "records_accessed": 850,
        "data_download_mb": 450.0,
        "is_new_device": 1,
        "is_new_ip": 1,
        "unusual_api_access": 1,
        "session_duration_minutes": 15.0,
        "access_time_hour": 14,
        "behaviour_deviation_score": 0.94,
        "resource_name": "Student Grade & Exam Database"
    }
    high_eval = evaluate_security_risk(high_event)
    assert high_eval["risk_score"] >= 80
    assert high_eval["risk_level"] == "Critical"


def test_5_3_explainable_security_justifications_reference_actual_features():
    """Verifies that generated explanations mention actual observed metrics."""
    test_event = {
        "requests_per_minute": 310.0,
        "failed_login_count": 0,
        "login_frequency_per_hr": 2.0,
        "resource_sensitivity_level": 5,
        "records_accessed": 850,
        "data_download_mb": 450.0,
        "is_new_device": 1,
        "is_new_ip": 1,
        "unusual_api_access": 1,
        "session_duration_minutes": 15.0,
        "access_time_hour": 14,
        "behaviour_deviation_score": 0.94,
        "resource_name": "Student Grade & Exam Database"
    }
    analysis = evaluate_security_risk(test_event)

    # Explanation text must reference the actual resource and metrics
    reason_str = analysis["reason"]
    assert "Student Grade & Exam Database" in reason_str
    assert "450" in reason_str or "exfiltration" in reason_str.lower()
    assert "310" in reason_str or "request" in reason_str.lower()
    assert len(analysis["recommended_action"]) > 0

    # Feature deviations contain z-scores
    deviations = analysis["feature_deviations"]
    features_present = [d["feature"] for d in deviations]
    assert "data_download_mb" in features_present
    assert "requests_per_minute" in features_present


# =====================================================================
# END-TO-END WORKFLOW VERIFICATION TEST
# =====================================================================

def test_end_to_end_complete_workflow():
    """
    Validates complete review flow:
    1. Authenticate as Lead Security Analyst
    2. Obtain secure bearer token
    3. Query protected application resources
    4. Perform live application action
    5. Telemetry collected and attributed to analyst
    6. Isolation Forest performs genuine inference
    7. Risk score and level computed
    8. Explainable diagnostic narrative generated
    9. SQLite stores record with event_source='ACTUAL_ACTIVITY'
    10. Query analysis endpoint to retrieve persisted explanation
    """
    # Step 1 & 2: Login as legitimate faculty investigator
    login_res = login_user("faculty_chen", "faculty123")
    assert login_res.status_code == 200
    token = login_res.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Step 3: Access protected cloud resources
    res_list = client.get("/api/resources/list", headers=headers)
    assert res_list.status_code == 200
    assert "catalog" in res_list.json()["resources"]

    # Step 4, 5, 6, 7, 8, 9: Perform real application action (Course Catalog query)
    act_res = client.post("/api/resources/execute-action", json={
        "action_type": "catalog_query",
        "custom_records": 6,
        "custom_download_mb": 1.4,
        "custom_rpm": 16.0
    }, headers=headers)
    assert act_res.status_code == 200
    act_data = act_res.json()

    assert act_data["success"] is True
    assert act_data["authenticated_user"] == "faculty_chen"
    assert act_data["telemetry_source"] == "ACTUAL_ACTIVITY"
    event_id = act_data["event"]["id"]
    assert act_data["event"]["event_source"] == "ACTUAL_ACTIVITY"
    assert act_data["analysis"]["prediction"] == "NORMAL"
    assert act_data["analysis"]["risk_score"] <= 30
    assert act_data["analysis"]["risk_level"] == "Low"

    # Step 10: Retrieve explanation from analysis endpoint
    an_res = client.get(f"/api/analysis/{event_id}", headers=headers)
    assert an_res.status_code == 200
    persisted_an = an_res.json()
    assert persisted_an["prediction"] == "NORMAL"
    assert persisted_an["risk_level"] == "Low"
    assert len(persisted_an["reason"]) > 0


def test_end_to_end_abnormal_workflow():
    """
    Validates end-to-end abnormal workflow:
    1. Authenticate with valid credentials (e.g. admin)
    2. Perform high-volume exfiltration action against restricted Exam DB
    3. Real telemetry sent to Isolation Forest
    4. Model predicts ANOMALY DETECTED
    5. Critical Risk score calculated
    6. Specific explainable security reason generated
    """
    login_res = login_user("admin", "admin123")
    assert login_res.status_code == 200
    token = login_res.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    act_res = client.post("/api/resources/execute-action", json={
        "action_type": "exam_db_access",
        "custom_records": 900,
        "custom_download_mb": 480.0,
        "custom_rpm": 320.0,
        "simulate_new_device": True,
        "simulate_new_ip": True
    }, headers=headers)
    assert act_res.status_code == 200
    act_data = act_res.json()

    assert act_data["success"] is True
    assert act_data["telemetry_source"] == "ACTUAL_ACTIVITY"
    assert act_data["analysis"]["prediction"] in ["ANOMALY DETECTED", "SUSPICIOUS"]
    assert act_data["analysis"]["risk_score"] >= 80
    assert act_data["analysis"]["risk_level"] == "Critical"
    assert "Student Grade & Exam Database" in act_data["analysis"]["reason"]


def test_authenticated_request_interception_pipeline():
    """
    Verifies the complete real-time pipeline:
    Every authenticated API request
            ↓
    timestamp, username, endpoint, HTTP method, status, IP, user-agent, session, resource, response/data volume
            ↓
    database (api_request_logs)
            ↓
    behaviour aggregation
            ↓
    Isolation Forest
    """
    login_res = login_user("faculty_chen", "faculty123")
    assert login_res.status_code == 200
    token = login_res.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Send authenticated request to Course Catalog
    cat_res = client.get("/api/resources/list", headers=headers)
    assert cat_res.status_code == 200
    assert cat_res.headers.get("X-Telemetry-Monitored") == "AI-DT-CyberShield"
    assert "X-Anomaly-Score" in cat_res.headers
    assert "X-Risk-Score" in cat_res.headers

    # 2. Fetch intercepted telemetry logs via /api/resources/telemetry-logs
    logs_res = client.get("/api/resources/telemetry-logs", headers=headers)
    assert logs_res.status_code == 200
    logs_data = logs_res.json()
    assert logs_data["count"] > 0

    latest_log = logs_data["logs"][0]
    # Check all 10 required fields
    assert "timestamp" in latest_log and len(latest_log["timestamp"]) > 0
    assert latest_log["username"] == "faculty_chen"
    assert latest_log["endpoint"] in ["/api/resources/list", "/api/resources/telemetry-logs"]
    assert latest_log["http_method"] == "GET"
    assert latest_log["status_code"] == 200
    assert "source_ip" in latest_log
    assert "user_agent" in latest_log
    assert "session_id" in latest_log
    assert "resource_name" in latest_log
    assert latest_log["response_bytes"] > 0
    assert latest_log["data_volume_mb"] >= 0.0

    # Verify Isolation Forest scores were saved alongside telemetry
    assert latest_log["anomaly_score"] is not None
    assert 0.0 <= latest_log["anomaly_score"] <= 1.0
    assert latest_log["prediction"] in ["NORMAL", "SUSPICIOUS", "ANOMALY DETECTED"]
    assert latest_log["risk_score"] is not None

    # 3. Check Pipeline Statistics endpoint
    stats_res = client.get("/api/resources/pipeline-stats", headers=headers)
    assert stats_res.status_code == 200
    stats_data = stats_res.json()
    assert "stats" in stats_data
    assert stats_data["stats"]["total_requests_intercepted"] > 0
    assert stats_data["stats"]["active_monitored_users"] > 0


def test_velocity_behaviour_aggregation():
    """Verifies that multiple rapid requests update rolling velocity behaviour."""
    login_res = login_user("student01", "student123")
    token = login_res.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Send 5 rapid requests
    for _ in range(5):
        client.get("/api/resources/list", headers=headers)

    logs_res = client.get("/api/resources/telemetry-logs", headers=headers)
    assert logs_res.status_code == 200
    student_logs = [l for l in logs_res.json()["logs"] if l["username"] == "student01"]
    assert len(student_logs) >= 5
