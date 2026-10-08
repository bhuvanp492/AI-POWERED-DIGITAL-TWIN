"""
Simulation Scenarios Generator for AI-DT-CyberShield.
Produces realistic security events for live demonstrations across 6 key threat scenarios,
including the flagship Compromised Account demonstration.
"""

import random
from datetime import datetime
from typing import Dict, Any


def get_scenario_definition(scenario_id: str) -> Dict[str, Any]:
    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    scenarios = {
        "normal_activity": {
            "title": "Normal User Activity",
            "description": "Standard legitimate student/faculty querying catalog during normal hours.",
            "data": {
                "timestamp": now_str,
                "username": random.choice(["student01", "student02", "faculty_chen"]),
                "ip_address": "10.0.4.25",
                "device_info": "Chrome 122 on Windows 11 (Verified Campus Workstation)",
                "action": "QUERY_COURSE_CATALOG",
                "resource_name": "Course Catalog API",
                "login_status": "SUCCESSFUL",
                "requests_per_minute": round(random.uniform(14.0, 26.0), 1),
                "failed_login_count": 0,
                "login_frequency_per_hr": 1.2,
                "resource_sensitivity_level": 1,
                "records_accessed": random.randint(4, 12),
                "data_download_mb": round(random.uniform(0.8, 2.4), 2),
                "is_new_device": 0,
                "is_new_ip": 0,
                "unusual_api_access": 0,
                "session_duration_minutes": 32.0,
                "access_time_hour": now.hour,
                "behaviour_deviation_score": 0.05,
                "scenario_type": "normal_activity"
            }
        },
        "repeated_logins": {
            "title": "Repeated Login Attempts",
            "description": "Credential spraying / automated brute force against administrative account.",
            "data": {
                "timestamp": now_str,
                "username": "admin_sarah",
                "ip_address": "198.51.100.42",
                "device_info": "Python-requests/2.31.0 (Automated Tool)",
                "action": "AUTHENTICATION_FAILURE_BURST",
                "resource_name": "IAM Admin Privileges Console",
                "login_status": "FAILED",
                "requests_per_minute": round(random.uniform(65.0, 110.0), 1),
                "failed_login_count": random.randint(8, 15),
                "login_frequency_per_hr": 18.0,
                "resource_sensitivity_level": 5,
                "records_accessed": 0,
                "data_download_mb": 0.04,
                "is_new_device": 1,
                "is_new_ip": 1,
                "unusual_api_access": 1,
                "session_duration_minutes": 1.2,
                "access_time_hour": now.hour,
                "behaviour_deviation_score": 0.82,
                "scenario_type": "repeated_login_attempts"
            }
        },
        "api_burst": {
            "title": "API Burst",
            "description": "High-velocity automated API flood querying backend endpoints.",
            "data": {
                "timestamp": now_str,
                "username": "guest_user",
                "ip_address": "203.0.113.89",
                "device_info": "HeadlessChrome / Linux x86_64",
                "action": "RAPID_ENDPOINT_SCRAPING",
                "resource_name": "Student Profile Portal",
                "login_status": "SUCCESSFUL",
                "requests_per_minute": round(random.uniform(340.0, 480.0), 1),
                "failed_login_count": 0,
                "login_frequency_per_hr": 3.0,
                "resource_sensitivity_level": 2,
                "records_accessed": random.randint(350, 600),
                "data_download_mb": round(random.uniform(25.0, 60.0), 1),
                "is_new_device": 1,
                "is_new_ip": 1,
                "unusual_api_access": 1,
                "session_duration_minutes": 4.5,
                "access_time_hour": now.hour,
                "behaviour_deviation_score": 0.86,
                "scenario_type": "api_burst"
            }
        },
        "sensitive_access": {
            "title": "Sensitive Resource Access",
            "description": "Unauthorized probing and mass record access into high-confidentiality records.",
            "data": {
                "timestamp": now_str,
                "username": "researcher_kim",
                "ip_address": "10.0.4.45",
                "device_info": "Firefox on Ubuntu 22.04 (Known Lab Workstation)",
                "action": "RESTRICTED_QUERY_ATTEMPT",
                "resource_name": "Financial Aid & Tuition Database",
                "login_status": "SUCCESSFUL",
                "requests_per_minute": round(random.uniform(55.0, 90.0), 1),
                "failed_login_count": 0,
                "login_frequency_per_hr": 2.5,
                "resource_sensitivity_level": 4,
                "records_accessed": random.randint(480, 800),
                "data_download_mb": round(random.uniform(35.0, 75.0), 1),
                "is_new_device": 0,
                "is_new_ip": 0,
                "unusual_api_access": 1,
                "session_duration_minutes": 22.0,
                "access_time_hour": now.hour,
                "behaviour_deviation_score": 0.79,
                "scenario_type": "sensitive_access"
            }
        },
        "large_download": {
            "title": "Large Data Download",
            "description": "Massive data exfiltration burst breaching single-session transfer quotas.",
            "data": {
                "timestamp": now_str,
                "username": "analyst_dev",
                "ip_address": "45.142.120.10",
                "device_info": "Curl 8.4.0 on Linux (Remote Shell)",
                "action": "BULK_DATABASE_EXPORT",
                "resource_name": "Student Grade & Exam Database",
                "login_status": "SUCCESSFUL",
                "requests_per_minute": round(random.uniform(85.0, 130.0), 1),
                "failed_login_count": 0,
                "login_frequency_per_hr": 2.0,
                "resource_sensitivity_level": 5,
                "records_accessed": random.randint(950, 1800),
                "data_download_mb": round(random.uniform(420.0, 680.0), 1),
                "is_new_device": 1,
                "is_new_ip": 1,
                "unusual_api_access": 1,
                "session_duration_minutes": 8.0,
                "access_time_hour": now.hour,
                "behaviour_deviation_score": 0.91,
                "scenario_type": "large_download"
            }
        },
        "compromised_account": {
            "title": "Compromised Account Simulation",
            "description": "Legitimate credentials authenticated in normal hours, followed by multi-vector post-login exfiltration.",
            "data": {
                "timestamp": now_str,
                "username": "admin_sarah",
                "ip_address": "185.220.101.5",  # New external IP
                "device_info": "HeadlessChrome on Linux x86_64 (Unrecognized Device)",
                "action": "MASS_STUDENT_RECORD_EXFILTRATION",
                "resource_name": "Student Grade & Exam Database",
                "login_status": "SUCCESSFUL",  # Valid username and password!
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
                "access_time_hour": 14,  # Normal working hours (2:15 PM)
                "behaviour_deviation_score": 0.94,
                "scenario_type": "compromised_account"
            }
        }
    }

    if scenario_id not in scenarios:
        raise ValueError(f"Unknown scenario '{scenario_id}'. Available: {list(scenarios.keys())}")

    return scenarios[scenario_id]
