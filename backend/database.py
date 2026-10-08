"""
SQLite Database Layer for AI-DT-CyberShield.
Manages persistent security logs, digital twin state history, users with salted password hashing,
authenticated sessions, authentication audit logs, and initial demo seeding.
"""

import os
import sqlite3
import hashlib
import secrets
import hmac
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "cyber_shield.db")


def get_db_connection() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Generates a secure PBKDF2-SHA256 password hash with 100,000 iterations and salt."""
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000
    ).hex()
    return pwd_hash, salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """Constant-time verification of candidate password against stored hash."""
    candidate_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(candidate_hash, password_hash)


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Security events table (telemetry + simulation logs)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        username TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        device_info TEXT NOT NULL,
        action TEXT NOT NULL,
        resource_name TEXT NOT NULL,
        login_status TEXT NOT NULL,
        requests_per_minute REAL NOT NULL,
        failed_login_count INTEGER NOT NULL,
        login_frequency_per_hr REAL NOT NULL,
        resource_sensitivity_level INTEGER NOT NULL,
        records_accessed INTEGER NOT NULL,
        data_download_mb REAL NOT NULL,
        is_new_device INTEGER NOT NULL,
        is_new_ip INTEGER NOT NULL,
        unusual_api_access INTEGER NOT NULL,
        session_duration_minutes REAL NOT NULL,
        access_time_hour INTEGER NOT NULL,
        behaviour_deviation_score REAL NOT NULL,
        scenario_type TEXT NOT NULL,
        prediction TEXT NOT NULL,
        anomaly_score REAL NOT NULL,
        risk_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        detected_behaviour TEXT NOT NULL,
        reason TEXT NOT NULL,
        recommended_action TEXT NOT NULL,
        event_source TEXT DEFAULT 'ACTUAL_ACTIVITY'
    )
    """)

    # Check if event_source column exists (for backwards compatibility)
    cursor.execute("PRAGMA table_info(security_events)")
    cols = [row["name"] for row in cursor.fetchall()]
    if "event_source" not in cols:
        try:
            cursor.execute("ALTER TABLE security_events ADD COLUMN event_source TEXT DEFAULT 'ACTUAL_ACTIVITY'")
        except Exception:
            pass

    # 2. Digital twin snapshot table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS digital_twin_snapshot (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        application_status TEXT NOT NULL,
        security_state TEXT NOT NULL,
        current_risk TEXT NOT NULL,
        risk_numeric INTEGER NOT NULL,
        recent_anomaly TEXT NOT NULL,
        active_threats_count INTEGER NOT NULL
    )
    """)

    # 3. Users table for Module 5.1 (User Authentication)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL,
        department TEXT NOT NULL,
        created_at TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1
    )
    """)

    # 4. Authentication events audit trail table for Module 5.1 (Application Access Logging)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        username TEXT NOT NULL,
        event_type TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        user_agent TEXT NOT NULL,
        auth_status TEXT NOT NULL,
        details TEXT
    )
    """)

    # 5. Persistent sessions table for Module 5.1
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        role TEXT NOT NULL,
        department TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        source_ip TEXT,
        user_agent TEXT
    )
    """)

    # 6. Real-time API request telemetry log table (every authenticated API request)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS api_request_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        username TEXT NOT NULL,
        endpoint TEXT NOT NULL,
        http_method TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        source_ip TEXT NOT NULL,
        user_agent TEXT NOT NULL,
        session_id TEXT NOT NULL,
        resource_name TEXT NOT NULL,
        resource_sensitivity INTEGER NOT NULL DEFAULT 1,
        response_bytes INTEGER NOT NULL DEFAULT 0,
        data_volume_mb REAL NOT NULL DEFAULT 0.0,
        anomaly_score REAL,
        prediction TEXT,
        risk_score INTEGER,
        risk_level TEXT
    )
    """)

    conn.commit()
    conn.close()

    seed_default_users_if_empty()
    seed_initial_events_if_empty()


def seed_default_users_if_empty():
    """Seeds default academic demo accounts with salted PBKDF2-SHA256 password hashes."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]

    if count == 0:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        default_users = [
            ("admin", "admin123", "Lead Security Analyst", "Cyber Defense Operations"),
            ("analyst", "analyst123", "SOC Tier-1 Analyst", "Security Operations Center"),
            ("student01", "student123", "Student Researcher", "Computer Science & Engineering"),
            ("faculty_chen", "faculty123", "Faculty Investigator", "Cybersecurity Research Lab")
        ]
        for uname, pwd, role, dept in default_users:
            p_hash, salt = hash_password(pwd)
            cursor.execute("""
                INSERT INTO users (username, password_hash, salt, role, department, created_at, is_active)
                VALUES (?, ?, ?, ?, ?, ?, 1)
            """, (uname, p_hash, salt, role, dept, now_str))
        conn.commit()
        print(f"[Database] Seeded {len(default_users)} default users with salted PBKDF2-SHA256 hashes.")
    conn.close()


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def log_auth_event(
    username: str,
    event_type: str,
    source_ip: str,
    user_agent: str,
    auth_status: str,
    details: str = ""
) -> int:
    """Logs an authentication event without storing passwords."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO auth_events (timestamp, username, event_type, source_ip, user_agent, auth_status, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (now_str, username, event_type, source_ip, user_agent, auth_status, details))
    event_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return event_id


def get_auth_events(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM auth_events ORDER BY id DESC LIMIT ? OFFSET ?
    """, (limit, offset))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def create_user_session(
    username: str,
    role: str,
    department: str,
    source_ip: str = "127.0.0.1",
    user_agent: str = "Client"
) -> str:
    conn = get_db_connection()
    cursor = conn.cursor()
    token = f"cybershield_{secrets.token_hex(24)}"
    now = datetime.now()
    created_at = now.strftime("%Y-%m-%d %H:%M:%S")
    expires_at = (now + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO sessions (token, username, role, department, created_at, expires_at, source_ip, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (token, username, role, department, created_at, expires_at, source_ip, user_agent))
    conn.commit()
    conn.close()
    return token


def get_user_session(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    # Strip 'Bearer ' if present
    if token.startswith("Bearer "):
        token = token[7:].strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions WHERE token = ?", (token,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    sess = dict(row)
    # Check expiration
    try:
        exp_time = datetime.strptime(sess["expires_at"], "%Y-%m-%d %H:%M:%S")
        if datetime.now() > exp_time:
            delete_user_session(token)
            return None
    except Exception:
        pass

    return sess


def delete_user_session(token: str) -> bool:
    if not token:
        return False
    if token.startswith("Bearer "):
        token = token[7:].strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def insert_event(event_data: Dict[str, Any]) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()

    timestamp = event_data.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    event_source = event_data.get("event_source", "ACTUAL_ACTIVITY")

    cursor.execute("""
    INSERT INTO security_events (
        timestamp, username, ip_address, device_info, action, resource_name,
        login_status, requests_per_minute, failed_login_count, login_frequency_per_hr,
        resource_sensitivity_level, records_accessed, data_download_mb,
        is_new_device, is_new_ip, unusual_api_access, session_duration_minutes,
        access_time_hour, behaviour_deviation_score, scenario_type,
        prediction, anomaly_score, risk_score, risk_level,
        detected_behaviour, reason, recommended_action, event_source
    ) VALUES (
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?
    )
    """, (
        timestamp,
        event_data.get("username", "unknown"),
        event_data.get("ip_address", "127.0.0.1"),
        event_data.get("device_info", "Generic Client"),
        event_data.get("action", "API_REQUEST"),
        event_data.get("resource_name", "General Service"),
        event_data.get("login_status", "SUCCESSFUL"),
        float(event_data.get("requests_per_minute", 15.0)),
        int(event_data.get("failed_login_count", 0)),
        float(event_data.get("login_frequency_per_hr", 1.0)),
        int(event_data.get("resource_sensitivity_level", 1)),
        int(event_data.get("records_accessed", 5)),
        float(event_data.get("data_download_mb", 1.0)),
        int(event_data.get("is_new_device", 0)),
        int(event_data.get("is_new_ip", 0)),
        int(event_data.get("unusual_api_access", 0)),
        float(event_data.get("session_duration_minutes", 30.0)),
        int(event_data.get("access_time_hour", 12)),
        float(event_data.get("behaviour_deviation_score", 0.05)),
        event_data.get("scenario_type", "custom"),
        event_data.get("prediction", "NORMAL"),
        float(event_data.get("anomaly_score", 0.15)),
        int(event_data.get("risk_score", 10)),
        event_data.get("risk_level", "Low"),
        event_data.get("detected_behaviour", "Standard authenticated activity"),
        event_data.get("reason", "All activity features within baseline thresholds."),
        event_data.get("recommended_action", "No action required. Continuous monitoring active."),
        event_source
    ))

    event_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return event_id


def get_events(limit: int = 50, offset: int = 0, filter_type: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()

    if filter_type:
        ft_upper = filter_type.upper()
        if ft_upper == "NORMAL":
            cursor.execute(
                "SELECT * FROM security_events WHERE prediction = 'NORMAL' ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset)
            )
        elif ft_upper in ["SUSPICIOUS", "ANOMALY", "ANOMALY DETECTED"]:
            cursor.execute(
                "SELECT * FROM security_events WHERE prediction != 'NORMAL' ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset)
            )
        elif filter_type.capitalize() in ["Low", "Medium", "High", "Critical"]:
            cursor.execute(
                "SELECT * FROM security_events WHERE risk_level = ? ORDER BY id DESC LIMIT ? OFFSET ?",
                (filter_type.capitalize(), limit, offset)
            )
        elif ft_upper in ["ACTUAL_ACTIVITY", "REAL_ACTIVITY"]:
            cursor.execute(
                "SELECT * FROM security_events WHERE event_source = 'ACTUAL_ACTIVITY' ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset)
            )
        elif ft_upper == "SIMULATION":
            cursor.execute(
                "SELECT * FROM security_events WHERE event_source = 'SIMULATION' ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset)
            )
        else:
            cursor.execute(
                "SELECT * FROM security_events ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset)
            )
    else:
        cursor.execute(
            "SELECT * FROM security_events ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_event_by_id(event_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_events WHERE id = ?", (event_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_activity_history(username: str, limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieves recent security telemetry events for a specific authenticated user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM security_events WHERE username = ? ORDER BY id DESC LIMIT ?",
        (username, limit)
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_user_recent_metrics(username: str, window_minutes: int = 15) -> Dict[str, Any]:
    """
    Computes statistical telemetry metrics for an authenticated user over a recent time window:
    - total requests in window
    - failed logins count in past hour
    - login frequency in past hour
    - known devices and IPs for the user
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    time_threshold = (datetime.now() - timedelta(minutes=window_minutes)).strftime("%Y-%m-%d %H:%M:%S")
    hour_threshold = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")

    # Recent request count in window
    cursor.execute(
        "SELECT COUNT(*) FROM security_events WHERE username = ? AND timestamp >= ?",
        (username, time_threshold)
    )
    req_count = cursor.fetchone()[0]

    # Failed logins in past hour
    cursor.execute(
        "SELECT COUNT(*) FROM auth_events WHERE username = ? AND event_type = 'LOGIN_FAILED' AND timestamp >= ?",
        (username, hour_threshold)
    )
    failed_logins = cursor.fetchone()[0]

    # Logins count in past hour
    cursor.execute(
        "SELECT COUNT(*) FROM auth_events WHERE username = ? AND event_type = 'LOGIN_SUCCESS' AND timestamp >= ?",
        (username, hour_threshold)
    )
    login_count = cursor.fetchone()[0]

    # Distinct known historical IPs and devices for user (from both security_events and api_request_logs)
    cursor.execute("SELECT DISTINCT ip_address FROM security_events WHERE username = ?", (username,))
    known_ips = {row[0] for row in cursor.fetchall()}
    cursor.execute("SELECT DISTINCT source_ip FROM api_request_logs WHERE username = ?", (username,))
    known_ips.update(row[0] for row in cursor.fetchall())

    cursor.execute("SELECT DISTINCT device_info FROM security_events WHERE username = ?", (username,))
    known_devices = {row[0] for row in cursor.fetchall()}
    cursor.execute("SELECT DISTINCT user_agent FROM api_request_logs WHERE username = ?", (username,))
    known_devices.update(row[0] for row in cursor.fetchall())

    conn.close()

    return {
        "requests_in_window": req_count,
        "failed_logins_1hr": failed_logins,
        "logins_1hr": max(1, login_count),
        "known_ips": known_ips,
        "known_devices": known_devices
    }


def log_api_request(
    timestamp: str,
    username: str,
    endpoint: str,
    http_method: str,
    status_code: int,
    source_ip: str,
    user_agent: str,
    session_id: str,
    resource_name: str,
    resource_sensitivity: int,
    response_bytes: int,
    data_volume_mb: float,
    anomaly_score: Optional[float] = None,
    prediction: Optional[str] = None,
    risk_score: Optional[int] = None,
    risk_level: Optional[str] = None
) -> int:
    """
    Logs an authenticated HTTP API request into api_request_logs
    capturing all 10 telemetry fields and ML evaluation scores.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO api_request_logs (
            timestamp, username, endpoint, http_method, status_code,
            source_ip, user_agent, session_id, resource_name, resource_sensitivity,
            response_bytes, data_volume_mb, anomaly_score, prediction, risk_score, risk_level
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp, username, endpoint, http_method, status_code,
        source_ip, user_agent, session_id, resource_name, resource_sensitivity,
        response_bytes, data_volume_mb, anomaly_score, prediction, risk_score, risk_level
    ))
    req_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return req_id


def get_api_request_logs(limit: int = 50, offset: int = 0, username: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves intercepted API request telemetry logs in reverse chronological order."""
    conn = get_db_connection()
    cursor = conn.cursor()
    if username:
        cursor.execute(
            "SELECT * FROM api_request_logs WHERE username = ? ORDER BY id DESC LIMIT ? OFFSET ?",
            (username, limit, offset)
        )
    else:
        cursor.execute(
            "SELECT * FROM api_request_logs ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_user_recent_api_velocity(username: str, window_seconds: int = 60) -> float:
    """Calculates requests per minute for a user over a sliding time window."""
    conn = get_db_connection()
    cursor = conn.cursor()
    threshold = (datetime.now() - timedelta(seconds=window_seconds)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "SELECT COUNT(*) FROM api_request_logs WHERE username = ? AND timestamp >= ?",
        (username, threshold)
    )
    count = cursor.fetchone()[0]
    conn.close()
    multiplier = 60.0 / max(1.0, float(window_seconds))
    return round(float(count) * multiplier, 1)


def get_user_recent_download_mb(username: str, window_minutes: int = 15) -> float:
    """Calculates cumulative data volume downloaded by user over window in MB."""
    conn = get_db_connection()
    cursor = conn.cursor()
    threshold = (datetime.now() - timedelta(minutes=window_minutes)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "SELECT SUM(data_volume_mb) FROM api_request_logs WHERE username = ? AND timestamp >= ?",
        (username, threshold)
    )
    res = cursor.fetchone()[0]
    conn.close()
    return round(float(res or 0.0), 3)


def get_telemetry_pipeline_stats() -> Dict[str, Any]:
    """Summary statistics of the real-time API telemetry pipeline."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM api_request_logs")
    total_intercepted = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(DISTINCT username) FROM api_request_logs")
    active_users = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM api_request_logs WHERE prediction = 'SUSPICIOUS'")
    anomalies_flagged = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(response_bytes) FROM api_request_logs")
    avg_bytes_row = cursor.fetchone()[0]
    avg_bytes = round(avg_bytes_row or 0.0, 1)

    cursor.execute("SELECT AVG(anomaly_score) FROM api_request_logs WHERE anomaly_score IS NOT NULL")
    avg_score_row = cursor.fetchone()[0]
    avg_score = round(avg_score_row or 0.0, 3)

    conn.close()
    return {
        "total_requests_intercepted": total_intercepted,
        "active_monitored_users": active_users,
        "anomalies_flagged": anomalies_flagged,
        "average_response_bytes": avg_bytes,
        "average_anomaly_score": avg_score
    }


def get_dashboard_stats() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM security_events")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_events WHERE prediction = 'NORMAL'")
    normal = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_events WHERE prediction != 'NORMAL'")
    suspicious = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_events WHERE risk_level IN ('High', 'Critical')")
    high_risk = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_events WHERE risk_level = 'Critical'")
    critical = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(risk_score) FROM security_events")
    avg_risk_row = cursor.fetchone()[0]
    avg_risk = round(avg_risk_row, 1) if avg_risk_row is not None else 0.0

    # Look at the most recent 5 events to determine current active state
    cursor.execute("SELECT prediction, risk_level, scenario_type FROM security_events ORDER BY id DESC LIMIT 5")
    recent = cursor.fetchall()

    recent_has_critical = any(r["risk_level"] == "Critical" for r in recent)
    recent_has_suspicious = any(r["prediction"] != "NORMAL" for r in recent)

    if recent_has_critical:
        status_label = "● ATTENTION REQUIRED"
        curr_risk = "Critical"
    elif recent_has_suspicious:
        status_label = "● ATTENTION REQUIRED"
        curr_risk = "High"
    elif high_risk > 0:
        status_label = "● ATTENTION REQUIRED"
        curr_risk = "Medium"
    else:
        status_label = "● SECURE"
        curr_risk = "Low"

    conn.close()

    return {
        "total_events": total,
        "normal_events": normal,
        "suspicious_events": suspicious,
        "high_risk_events": high_risk,
        "critical_events": critical,
        "current_security_status": status_label,
        "current_risk_level": curr_risk,
        "average_risk_score": avg_risk,
        "recent_compromised_detected": recent_has_critical
    }


def seed_initial_events_if_empty():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM security_events")
    count = cursor.fetchone()[0]
    conn.close()

    if count > 0:
        return

    print("[Database] Seeding initial baseline events...")
    now = datetime.now()

    sample_events = [
        {
            "timestamp": (now - timedelta(minutes=45)).strftime("%Y-%m-%d %H:%M:%S"),
            "username": "faculty_chen",
            "ip_address": "10.0.4.15",
            "device_info": "Safari on macOS Sonoma (Faculty Laptop)",
            "action": "QUERY_COURSE_CATALOG",
            "resource_name": "Course Catalog API",
            "login_status": "SUCCESSFUL",
            "requests_per_minute": 16.5,
            "failed_login_count": 0,
            "login_frequency_per_hr": 1.2,
            "resource_sensitivity_level": 1,
            "records_accessed": 8,
            "data_download_mb": 1.4,
            "is_new_device": 0,
            "is_new_ip": 0,
            "unusual_api_access": 0,
            "session_duration_minutes": 42.0,
            "access_time_hour": 10,
            "behaviour_deviation_score": 0.04,
            "scenario_type": "normal_activity",
            "prediction": "NORMAL",
            "anomaly_score": 0.12,
            "risk_score": 12,
            "risk_level": "Low",
            "detected_behaviour": "Standard faculty query activity",
            "reason": "Request volume, resource tier, and device telemetry remain in nominal parameters.",
            "recommended_action": "No remediation required. Standard continuous telemetry active.",
            "event_source": "ACTUAL_ACTIVITY"
        },
        {
            "timestamp": (now - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S"),
            "username": "student01",
            "ip_address": "10.0.4.22",
            "device_info": "Chrome on Windows 11 (Student Lab)",
            "action": "SUBMIT_ASSIGNMENT",
            "resource_name": "Assignment Submission Service",
            "login_status": "SUCCESSFUL",
            "requests_per_minute": 22.0,
            "failed_login_count": 0,
            "login_frequency_per_hr": 1.0,
            "resource_sensitivity_level": 2,
            "records_accessed": 3,
            "data_download_mb": 2.1,
            "is_new_device": 0,
            "is_new_ip": 0,
            "unusual_api_access": 0,
            "session_duration_minutes": 25.0,
            "access_time_hour": 11,
            "behaviour_deviation_score": 0.06,
            "scenario_type": "normal_activity",
            "prediction": "NORMAL",
            "anomaly_score": 0.15,
            "risk_score": 15,
            "risk_level": "Low",
            "detected_behaviour": "Standard student portal usage",
            "reason": "Single submission transaction with expected payload size from verified campus IP.",
            "recommended_action": "No remediation required.",
            "event_source": "ACTUAL_ACTIVITY"
        },
        {
            "timestamp": (now - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S"),
            "username": "faculty_chen",
            "ip_address": "172.16.0.12",
            "device_info": "Firefox on Ubuntu 22.04 (Research Lab)",
            "action": "ACCESS_RESEARCH_PORTAL",
            "resource_name": "Student Profile Portal",
            "login_status": "SUCCESSFUL",
            "requests_per_minute": 28.5,
            "failed_login_count": 0,
            "login_frequency_per_hr": 2.0,
            "resource_sensitivity_level": 2,
            "records_accessed": 12,
            "data_download_mb": 3.8,
            "is_new_device": 0,
            "is_new_ip": 0,
            "unusual_api_access": 0,
            "session_duration_minutes": 38.0,
            "access_time_hour": 11,
            "behaviour_deviation_score": 0.08,
            "scenario_type": "normal_activity",
            "prediction": "NORMAL",
            "anomaly_score": 0.18,
            "risk_score": 18,
            "risk_level": "Low",
            "detected_behaviour": "Verified researcher session",
            "reason": "Operational requests and bandwidth usage within accepted bounds.",
            "recommended_action": "No remediation required.",
            "event_source": "ACTUAL_ACTIVITY"
        }
    ]

    for ev in sample_events:
        insert_event(ev)
    print(f"[Database] Seeded {len(sample_events)} initial normal events. Initial state: SECURE.")


def reset_database():
    """Allows resetting demo data to fresh baseline state."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM security_events")
    cursor.execute("DELETE FROM digital_twin_snapshot")
    cursor.execute("DELETE FROM auth_events")
    cursor.execute("DELETE FROM sessions")
    cursor.execute("DELETE FROM api_request_logs")
    conn.commit()
    conn.close()
    seed_default_users_if_empty()
    seed_initial_events_if_empty()
