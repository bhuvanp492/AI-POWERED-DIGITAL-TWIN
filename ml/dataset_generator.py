"""
Synthetic Security Dataset Generator for AI-DT-CyberShield.
Generates realistic baseline enterprise/cloud application user behaviour logs
including normal operations and varied cyber threat scenarios (e.g. credential stuffing,
API bursts, privilege abuse, mass exfiltration, and compromised accounts).
"""

import os
import random
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

USERS = [
    "student01", "student02", "student03", "faculty_chen", "faculty_patel",
    "admin_sarah", "researcher_kim", "staff_alex", "analyst_dev", "guest_user"
]

NORMAL_IPS = ["10.0.4.15", "10.0.4.22", "10.0.4.45", "192.168.1.105", "172.16.0.12"]
SUSPICIOUS_IPS = ["185.220.101.5", "198.51.100.42", "203.0.113.89", "45.142.120.10", "91.240.118.172"]

NORMAL_DEVICES = [
    "Chrome on Windows 11 (Known Workstation)",
    "Safari on macOS Sonoma (MacBook Pro)",
    "Edge on Windows 10 (Campus Lab PC)",
    "Firefox on Ubuntu 22.04 (Dev Machine)"
]

SUSPICIOUS_DEVICES = [
    "HeadlessChrome on Linux x86_64 (Automated Script)",
    "Python-requests/2.31.0 (CLI Tool)",
    "Curl/8.4.0 (Terminal)",
    "Unknown Device on Android 10 (Foreign Proxy)"
]

RESOURCES = [
    {"name": "Course Catalog API", "sensitivity": 1},
    {"name": "Campus News Feed", "sensitivity": 1},
    {"name": "Student Profile Portal", "sensitivity": 2},
    {"name": "Assignment Submission Service", "sensitivity": 2},
    {"name": "Faculty Evaluation System", "sensitivity": 3},
    {"name": "Financial Aid & Tuition Database", "sensitivity": 4},
    {"name": "Student Grade & Exam Database", "sensitivity": 5},
    {"name": "IAM Admin Privileges Console", "sensitivity": 5},
]


def generate_normal_event(base_time: datetime) -> dict:
    user = random.choice(USERS)
    res = random.choice(RESOURCES[:5])  # mostly sensitivity 1-3
    ip = random.choice(NORMAL_IPS)
    device = random.choice(NORMAL_DEVICES)
    req_per_min = round(random.uniform(5.0, 35.0), 1)
    failed_logins = 0 if random.random() > 0.08 else 1
    login_freq = round(random.uniform(0.5, 2.5), 1)
    records = random.randint(1, 20)
    data_mb = round(random.uniform(0.05, 4.2), 2)
    new_device = 0 if random.random() > 0.05 else 1
    new_ip = 0 if random.random() > 0.04 else 1
    unusual_api = 0
    session_duration = round(random.uniform(10.0, 75.0), 1)
    hour = random.choice([8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20])
    event_time = base_time.replace(hour=hour, minute=random.randint(0, 59))
    dev_score = round(random.uniform(0.01, 0.22), 3)

    return {
        "timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
        "username": user,
        "ip_address": ip,
        "device_info": device,
        "action": "API_REQUEST",
        "resource_name": res["name"],
        "login_status": "SUCCESSFUL",
        "requests_per_minute": req_per_min,
        "failed_login_count": failed_logins,
        "login_frequency_per_hr": login_freq,
        "resource_sensitivity_level": res["sensitivity"],
        "records_accessed": records,
        "data_download_mb": data_mb,
        "is_new_device": new_device,
        "is_new_ip": new_ip,
        "unusual_api_access": unusual_api,
        "session_duration_minutes": session_duration,
        "access_time_hour": hour,
        "behaviour_deviation_score": dev_score,
        "label": "NORMAL",
        "scenario_type": "normal_activity"
    }


def generate_brute_force_event(base_time: datetime) -> dict:
    user = random.choice(["admin_sarah", "faculty_chen", "root"])
    res = RESOURCES[7]  # IAM Admin Console
    ip = random.choice(SUSPICIOUS_IPS)
    device = random.choice(SUSPICIOUS_DEVICES)
    failed_logins = random.randint(6, 18)
    event_time = base_time - timedelta(minutes=random.randint(5, 60))

    return {
        "timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
        "username": user,
        "ip_address": ip,
        "device_info": device,
        "action": "AUTH_LOGIN_FAILED",
        "resource_name": res["name"],
        "login_status": "FAILED",
        "requests_per_minute": round(random.uniform(45.0, 120.0), 1),
        "failed_login_count": failed_logins,
        "login_frequency_per_hr": round(random.uniform(8.0, 25.0), 1),
        "resource_sensitivity_level": res["sensitivity"],
        "records_accessed": 0,
        "data_download_mb": 0.05,
        "is_new_device": 1,
        "is_new_ip": 1,
        "unusual_api_access": 1,
        "session_duration_minutes": round(random.uniform(0.5, 3.0), 1),
        "access_time_hour": random.randint(0, 23),
        "behaviour_deviation_score": round(random.uniform(0.65, 0.95), 3),
        "label": "SUSPICIOUS",
        "scenario_type": "repeated_login_attempts"
    }


def generate_api_burst_event(base_time: datetime) -> dict:
    user = random.choice(["student02", "guest_user", "service_worker"])
    res = random.choice(RESOURCES[:4])
    ip = random.choice(SUSPICIOUS_IPS)
    device = random.choice(SUSPICIOUS_DEVICES)
    req_per_min = round(random.uniform(220.0, 650.0), 1)

    return {
        "timestamp": base_time.strftime("%Y-%m-%d %H:%M:%S"),
        "username": user,
        "ip_address": ip,
        "device_info": device,
        "action": "API_BURST_FLOOD",
        "resource_name": res["name"],
        "login_status": "SUCCESSFUL",
        "requests_per_minute": req_per_min,
        "failed_login_count": 0,
        "login_frequency_per_hr": round(random.uniform(1.0, 4.0), 1),
        "resource_sensitivity_level": res["sensitivity"],
        "records_accessed": random.randint(100, 400),
        "data_download_mb": round(random.uniform(15.0, 85.0), 2),
        "is_new_device": 1,
        "is_new_ip": 1,
        "unusual_api_access": 1,
        "session_duration_minutes": round(random.uniform(1.0, 8.0), 1),
        "access_time_hour": random.randint(0, 23),
        "behaviour_deviation_score": round(random.uniform(0.70, 0.90), 3),
        "label": "SUSPICIOUS",
        "scenario_type": "api_burst"
    }


def generate_sensitive_access_event(base_time: datetime) -> dict:
    user = random.choice(["student01", "researcher_kim", "guest_user"])
    res = random.choice(RESOURCES[5:])  # Sensitivity 4 or 5
    ip = random.choice(NORMAL_IPS + SUSPICIOUS_IPS[:2])
    device = random.choice(NORMAL_DEVICES)

    return {
        "timestamp": base_time.strftime("%Y-%m-%d %H:%M:%S"),
        "username": user,
        "ip_address": ip,
        "device_info": device,
        "action": "UNAUTHORIZED_PRIVILEGE_ACCESS",
        "resource_name": res["name"],
        "login_status": "SUCCESSFUL",
        "requests_per_minute": round(random.uniform(30.0, 95.0), 1),
        "failed_login_count": 0,
        "login_frequency_per_hr": round(random.uniform(1.0, 3.5), 1),
        "resource_sensitivity_level": res["sensitivity"],
        "records_accessed": random.randint(250, 750),
        "data_download_mb": round(random.uniform(20.0, 80.0), 2),
        "is_new_device": 0,
        "is_new_ip": 0,
        "unusual_api_access": 1,
        "session_duration_minutes": round(random.uniform(15.0, 45.0), 1),
        "access_time_hour": random.randint(1, 6),  # Middle of the night
        "behaviour_deviation_score": round(random.uniform(0.68, 0.88), 3),
        "label": "SUSPICIOUS",
        "scenario_type": "sensitive_resource_access"
    }


def generate_large_download_event(base_time: datetime) -> dict:
    user = random.choice(["analyst_dev", "staff_alex", "student03"])
    res = RESOURCES[6]  # Student Grade & Exam Database
    ip = random.choice(SUSPICIOUS_IPS)
    device = random.choice(NORMAL_DEVICES + SUSPICIOUS_DEVICES[:1])

    return {
        "timestamp": base_time.strftime("%Y-%m-%d %H:%M:%S"),
        "username": user,
        "ip_address": ip,
        "device_info": device,
        "action": "BULK_DATA_EXPORT",
        "resource_name": res["name"],
        "login_status": "SUCCESSFUL",
        "requests_per_minute": round(random.uniform(60.0, 140.0), 1),
        "failed_login_count": 0,
        "login_frequency_per_hr": round(random.uniform(1.0, 3.0), 1),
        "resource_sensitivity_level": res["sensitivity"],
        "records_accessed": random.randint(800, 2500),
        "data_download_mb": round(random.uniform(320.0, 850.0), 2),
        "is_new_device": 1,
        "is_new_ip": 1,
        "unusual_api_access": 1,
        "session_duration_minutes": round(random.uniform(5.0, 20.0), 1),
        "access_time_hour": random.randint(0, 23),
        "behaviour_deviation_score": round(random.uniform(0.75, 0.95), 3),
        "label": "SUSPICIOUS",
        "scenario_type": "large_data_download"
    }


def generate_compromised_account_event(base_time: datetime) -> dict:
    """
    Core demonstration scenario:
    Valid Credentials + Normal Working Hours (14:15) + Successful Login
    BUT Post-Login Behaviour is malicious:
    New Device + New IP + High API Requests + Sensitive DB + Large Data Download.
    """
    user = "admin_sarah"
    res = RESOURCES[6]  # Student Grade & Exam Database (Sensitivity 5)
    ip = "185.220.101.5"  # New External IP
    device = "HeadlessChrome on Linux x86_64 (New Device)"
    event_time = base_time.replace(hour=14, minute=15)

    return {
        "timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
        "username": user,
        "ip_address": ip,
        "device_info": device,
        "action": "MASS_STUDENT_RECORD_EXFILTRATION",
        "resource_name": res["name"],
        "login_status": "SUCCESSFUL",  # Crucial: login itself was successful!
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
        "label": "SUSPICIOUS",
        "scenario_type": "compromised_account"
    }


def generate_dataset(total_samples: int = 1500, output_path: str = "data/security_logs.csv") -> pd.DataFrame:
    random.seed(42)
    np.random.seed(42)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    records = []
    base_time = datetime.now() - timedelta(days=7)

    # 88% normal events
    num_normal = int(total_samples * 0.88)
    for i in range(num_normal):
        t = base_time + timedelta(minutes=i * 7)
        records.append(generate_normal_event(t))

    # 12% diverse anomalies
    num_anomalies = total_samples - num_normal
    anomaly_generators = [
        generate_brute_force_event,
        generate_api_burst_event,
        generate_sensitive_access_event,
        generate_large_download_event,
        generate_compromised_account_event
    ]

    for i in range(num_anomalies):
        gen = random.choice(anomaly_generators)
        t = base_time + timedelta(minutes=random.randint(0, num_normal * 7))
        records.append(gen(t))

    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(output_path, index=False)
    print(f"Generated {len(df)} synthetic security logs -> {output_path}")
    print(f"Class distribution:\n{df['label'].value_counts()}")
    return df


if __name__ == "__main__":
    generate_dataset()
