"""
Digital Twin State Engine for AI-DT-CyberShield.
Maintains a real-time 2D digital representation of the monitored cloud application,
including operational status, asset conditions, threat vectors, and AI protection telemetry.
"""

from datetime import datetime
from typing import Dict, Any, List
from backend.database import get_db_connection


def get_current_digital_twin_state() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()

    # Query last 10 security events to compute live twin posture
    cursor.execute("""
        SELECT * FROM security_events
        ORDER BY id DESC LIMIT 10
    """)
    recent_events = [dict(r) for r in cursor.fetchall()]
    conn.close()

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not recent_events:
        return _build_default_twin_state(now_str)

    latest_event = recent_events[0]
    critical_events = [e for e in recent_events if e.get("risk_level") == "Critical"]
    suspicious_events = [e for e in recent_events if e.get("prediction") in ["SUSPICIOUS", "ANOMALY DETECTED"]]

    # Calculate system condition
    if len(critical_events) > 0:
        sec_state = "HIGH RISK"
        app_status = "UNDER THREAT"
        current_risk_str = "Critical"
        risk_numeric = max(e["risk_score"] for e in critical_events)
        recent_anomaly_desc = f"{latest_event.get('detected_behaviour', 'Critical anomaly')} ({latest_event.get('username')})"
    elif len(suspicious_events) > 0:
        sec_state = "ATTENTION REQUIRED"
        app_status = "UNDER THREAT"
        current_risk_str = "High"
        risk_numeric = max(e["risk_score"] for e in suspicious_events)
        recent_anomaly_desc = f"{latest_event.get('detected_behaviour', 'Anomaly detected')} ({latest_event.get('username')})"
    else:
        sec_state = "LOW RISK"
        app_status = "NORMAL"
        current_risk_str = "Low"
        risk_numeric = latest_event.get("risk_score", 12)
        recent_anomaly_desc = "None detected. Continuous baseline monitoring active."

    # Asset health states based on actual telemetry
    db_target = latest_event.get("resource_name", "")
    db_status = "UNDER_ATTACK" if (len(critical_events) > 0 and latest_event.get("risk_level") == "Critical") else "NORMAL"
    user_status_label = "SUSPICIOUS" if (len(suspicious_events) > 0 or len(critical_events) > 0) else "ACTIVE"
    auth_status = "SUSPICIOUS_SESSION" if user_status_label == "SUSPICIOUS" else "HEALTHY"

    protected_resources = [
        {"name": "Course Catalog API", "sensitivity": 1, "status": "HEALTHY", "queries_min": 24},
        {"name": "Student Profile Portal", "sensitivity": 2, "status": "ELEVATED" if "Profile" in db_target and latest_event["prediction"] == "SUSPICIOUS" else "HEALTHY", "queries_min": 45},
        {"name": "Financial Aid & Tuition DB", "sensitivity": 4, "status": "INVESTIGATING" if "Financial" in db_target and latest_event["prediction"] == "SUSPICIOUS" else "HEALTHY", "queries_min": 8},
        {"name": "Student Grade & Exam DB", "sensitivity": 5, "status": "CRITICAL_ALERT" if "Student Grade" in db_target and latest_event["prediction"] == "SUSPICIOUS" else "HEALTHY", "queries_min": 12 if db_status == "NORMAL" else 310},
    ]

    nodes = [
        {
            "id": "app_gateway",
            "name": "Application & API Gateway",
            "type": "application",
            "status": "WARNING" if latest_event.get("requests_per_minute", 0) > 200 else "HEALTHY",
            "details": {
                "active_connections": 142 if latest_event.get("requests_per_minute", 0) < 200 else 490,
                "throughput": f"{latest_event.get('requests_per_minute', 20.0):.0f} req/min",
                "egress_rate": f"{latest_event.get('data_download_mb', 1.0):.1f} MB/s"
            }
        },
        {
            "id": "users_pool",
            "name": "User Identity & Sessions",
            "type": "user",
            "status": "SUSPICIOUS" if auth_status != "HEALTHY" else "ACTIVE",
            "details": {
                "active_users": 28,
                "latest_user": latest_event.get("username", "student01"),
                "device": latest_event.get("device_info", "Verified"),
                "ip": latest_event.get("ip_address", "10.0.4.15"),
                "auth_condition": auth_status
            }
        },
        {
            "id": "protected_dbs",
            "name": "Protected Resources & Databases",
            "type": "resource",
            "status": "TARGETED" if db_status != "NORMAL" else "HEALTHY",
            "details": {
                "active_resource": latest_event.get("resource_name", "Course Catalog API"),
                "records_accessed": latest_event.get("records_accessed", 5),
                "sensitivity_level": f"Tier {latest_event.get('resource_sensitivity_level', 1)}/5"
            }
        },
        {
            "id": "ai_engine",
            "name": "AI CyberShield (Isolation Forest)",
            "type": "ai_engine",
            "status": "ACTIVE",
            "details": {
                "inference_engine": "IsolationForest (n=150)",
                "last_prediction": latest_event.get("prediction", "NORMAL"),
                "anomaly_score": latest_event.get("anomaly_score", 0.12),
                "eval_latency_ms": 3.4
            }
        },
        {
            "id": "security_state",
            "name": "Digital Twin Security State",
            "type": "security_state",
            "status": "CRITICAL" if sec_state == "ATTENTION REQUIRED" and risk_numeric >= 80 else (
                "WARNING" if sec_state == "ATTENTION REQUIRED" else "HEALTHY"
            ),
            "details": {
                "condition": sec_state,
                "risk_score": f"{risk_numeric}/100 ({current_risk_str})",
                "posture": "Continuous AI Behavioural Guard"
            }
        }
    ]

    return {
        "application_status": app_status,
        "security_state": sec_state,
        "current_risk": current_risk_str,
        "risk_numeric": risk_numeric,
        "recent_anomaly": recent_anomaly_desc,
        "active_threats_count": len(suspicious_events),
        "protected_resources": protected_resources,
        "nodes": nodes,
        "last_updated": now_str
    }


def _build_default_twin_state(timestamp_str: str) -> Dict[str, Any]:
    return {
        "application_status": "ACTIVE",
        "security_state": "SECURE",
        "current_risk": "Low",
        "risk_numeric": 10,
        "recent_anomaly": "None. Initializing telemetry pipeline.",
        "active_threats_count": 0,
        "protected_resources": [
            {"name": "Course Catalog API", "sensitivity": 1, "status": "HEALTHY", "queries_min": 20},
            {"name": "Student Profile Portal", "sensitivity": 2, "status": "HEALTHY", "queries_min": 35},
            {"name": "Financial Aid & Tuition DB", "sensitivity": 4, "status": "HEALTHY", "queries_min": 5},
            {"name": "Student Grade & Exam DB", "sensitivity": 5, "status": "HEALTHY", "queries_min": 10},
        ],
        "nodes": [],
        "last_updated": timestamp_str
    }
