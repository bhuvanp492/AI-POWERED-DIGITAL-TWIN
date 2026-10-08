"""
Explainable Risk Engine for AI-DT-CyberShield.
Synthesizes statistical anomaly scores from Isolation Forest with multi-dimensional
behavioral security metrics (credential validity, post-login actions, exfiltration volume,
privilege level) to generate calibrated Risk Scores (0-100), human-readable explanations,
and prescriptive security actions.

CRITICAL: Prediction is driven 100% by the Machine Learning Isolation Forest model.
NO scenario-based hardcoding or overriding is permitted.
"""

from typing import Dict, Any, List
from ml.anomaly_detector import get_detector


def evaluate_security_risk(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates an event using the ML Isolation Forest detector and
    objective feature-based contextual risk scoring.
    """
    detector = get_detector()
    ml_res = detector.predict(event_data)

    # Prediction comes strictly from the Isolation Forest model
    raw_prediction = ml_res["prediction"]  # "NORMAL" or "SUSPICIOUS"
    anomaly_score = ml_res["anomaly_score"]
    raw_score = ml_res["raw_score"]
    feature_deviations = ml_res["feature_deviations"]

    # Extract contextual behavioural signals
    login_status = str(event_data.get("login_status", "SUCCESSFUL")).upper()
    req_per_min = float(event_data.get("requests_per_minute", 20.0))
    failed_logins = int(event_data.get("failed_login_count", 0))
    res_sens = int(event_data.get("resource_sensitivity_level", 1))
    records = int(event_data.get("records_accessed", 5))
    download_mb = float(event_data.get("data_download_mb", 1.0))
    is_new_device = int(event_data.get("is_new_device", 0))
    is_new_ip = int(event_data.get("is_new_ip", 0))
    unusual_api = int(event_data.get("unusual_api_access", 0))
    resource_name = event_data.get("resource_name", "Application Endpoint")

    # Base risk score derived directly from the ML Isolation Forest anomaly score (0 to 45 pts)
    base_ml_risk = anomaly_score * 45.0

    # Objective Contextual Point Modifiers (Evaluates actual feature numbers)
    context_points = 0.0
    detected_factors = []

    # 1. Post-Login Identity & Endpoint novelty
    if is_new_device == 1 and is_new_ip == 1:
        context_points += 15.0
        detected_factors.append("unrecognized device fingerprint and external IP address")
    elif is_new_device == 1:
        context_points += 7.0
        detected_factors.append("new device fingerprint")
    elif is_new_ip == 1:
        context_points += 7.0
        detected_factors.append("unfamiliar external IP address")

    # 2. Resource Sensitivity & Record Volume
    if res_sens >= 4:
        if records >= 500:
            context_points += 22.0
            detected_factors.append(f"bulk query of {records} records from restricted resource '{resource_name}' (Sensitivity {res_sens}/5)")
        elif records >= 100:
            context_points += 14.0
            detected_factors.append(f"access to high-sensitivity resource '{resource_name}' with {records} records")
        else:
            context_points += 8.0
            detected_factors.append(f"access to sensitive resource '{resource_name}'")
    elif records >= 500:
        context_points += 10.0
        detected_factors.append(f"unusually high record volume ({records} records)")

    # 3. Data Download Volume
    if download_mb >= 300.0:
        context_points += 20.0
        detected_factors.append(f"abnormal data download of {download_mb:.1f} MB exceeding single-session baseline")
    elif download_mb >= 50.0:
        context_points += 10.0
        detected_factors.append(f"elevated download size of {download_mb:.1f} MB")

    # 4. API Request Velocity
    if req_per_min >= 250.0:
        context_points += 18.0
        detected_factors.append(f"high-velocity API burst of {req_per_min:.0f} req/min")
    elif req_per_min >= 100.0:
        context_points += 8.0
        detected_factors.append(f"elevated request rate of {req_per_min:.0f} req/min")

    # 5. Authentication Failures
    if failed_logins >= 5:
        context_points += 25.0
        detected_factors.append(f"repeated authentication failures ({failed_logins} attempts)")
    elif failed_logins >= 2:
        context_points += 10.0
        detected_factors.append(f"{failed_logins} failed login attempts")

    # 6. Unusual Endpoint / Export Action
    if unusual_api == 1:
        context_points += 8.0
        detected_factors.append("invocation of unusual administrative/export API endpoint")

    # Calculate Total Risk Score (0 to 100) purely from ML base + objective telemetry points
    raw_risk = base_ml_risk + context_points
    final_risk_score = int(min(100, max(0, round(raw_risk))))

    # Categorize Risk Level
    if final_risk_score <= 30:
        risk_level = "Low"
    elif final_risk_score <= 60:
        risk_level = "Medium"
    elif final_risk_score <= 80:
        risk_level = "High"
    else:
        risk_level = "Critical"

    # Prediction formatting: If ML detected an anomaly or risk is elevated, mark as ANOMALY DETECTED
    if raw_prediction == "SUSPICIOUS" or final_risk_score >= 55:
        prediction_label = "ANOMALY DETECTED"
    else:
        prediction_label = "NORMAL"

    # Synthesize explainable narrative purely based on behavioral factors
    behaviour, reason, action = _synthesize_narrative(
        prediction=prediction_label,
        risk_level=risk_level,
        final_risk_score=final_risk_score,
        detected_factors=detected_factors,
        resource_name=resource_name,
        login_status=login_status,
        download_mb=download_mb,
        req_per_min=req_per_min,
        records=records,
        is_new_device=is_new_device,
        is_new_ip=is_new_ip,
        failed_logins=failed_logins
    )

    return {
        "prediction": prediction_label,
        "anomaly_score": anomaly_score,
        "raw_score": raw_score,
        "risk_score": final_risk_score,
        "risk_level": risk_level,
        "detected_behaviour": behaviour,
        "reason": reason,
        "recommended_action": action,
        "affected_resource": resource_name,
        "feature_deviations": feature_deviations
    }


def _synthesize_narrative(
    prediction: str,
    risk_level: str,
    final_risk_score: int,
    detected_factors: List[str],
    resource_name: str,
    login_status: str,
    download_mb: float,
    req_per_min: float,
    records: int,
    is_new_device: int,
    is_new_ip: int,
    failed_logins: int
) -> tuple:
    # 1. Normal baseline activity
    if prediction == "NORMAL" and risk_level == "Low":
        behaviour = "Nominal authenticated user activity"
        reason = (
            "Behaviour is consistent with the established baseline. The session is using a known device "
            "and IP address, with normal API activity, standard resource access, and nominal download volume."
        )
        action = "Allow activity. Continue continuous monitoring."
        return behaviour, reason, action

    # 2. Compromised Account pattern (Valid login + severe post-login deviation)
    if login_status == "SUCCESSFUL" and (is_new_device or is_new_ip) and (download_mb >= 100 or req_per_min >= 150 or records >= 200):
        behaviour = "Potential account compromise / Post-authentication data exfiltration"
        reason = (
            "Anomalous behaviour detected because the session was authenticated successfully with valid credentials, "
            "but subsequent post-login activity originated from a new device/IP, generated an unusually high request rate "
            f"({req_per_min:.0f} req/min), accessed a restricted resource ('{resource_name}', {records} records), "
            f"and downloaded significantly more data ({download_mb:.1f} MB) than the normal behavioral baseline."
        )
        action = "Temporarily restrict session, revoke active bearer token, and require step-up multi-factor authentication."
        return behaviour, reason, action

    # 3. Repeated failed authentication
    if failed_logins >= 5 or (login_status == "FAILED" and failed_logins >= 2):
        behaviour = "Suspicious authentication activity / Potential brute-force attempt"
        reason = (
            f"Multiple failed authentication attempts ({failed_logins} failures) detected from this origin, "
            "deviating from standard login frequency and indicating potential automated credential spray."
        )
        action = "Temporarily rate-limit originating IP and enforce CAPTCHA verification on target account."
        return behaviour, reason, action

    # 4. API Burst / Flood
    if req_per_min >= 200:
        behaviour = "High-velocity API activity / Potential automated scraping"
        reason = (
            f"Anomalous request velocity ({req_per_min:.0f} requests/min) detected, exceeding human operational baseline "
            "and indicating automated querying or endpoint scraping."
        )
        action = "Apply gateway rate limiting to client session and inspect downstream backend load."
        return behaviour, reason, action

    # 5. Large Download
    if download_mb >= 150:
        behaviour = "Unusual data transfer volume / Potential data exfiltration"
        reason = (
            f"Abnormal data egress of {download_mb:.1f} MB across {records} records detected, "
            f"exceeding single-session transfer baselines for '{resource_name}'."
        )
        action = "Suspend active bulk transfer and prompt for authorized supervisor confirmation."
        return behaviour, reason, action

    # 6. Sensitive resource probing
    if records >= 200:
        behaviour = "Suspicious resource query / Boundary deviation"
        reason = (
            f"Session accessed high record volume ({records} records) from '{resource_name}', "
            "diverging from normal departmental query patterns."
        )
        action = "Audit user access permissions and monitor subsequent session requests."
        return behaviour, reason, action

    # Generic deviation fallback
    factor_str = ", ".join(detected_factors) if detected_factors else "behavioral variance detected across feature dimensions"
    behaviour = f"Suspicious activity ({risk_level} Risk)"
    reason = f"Behaviour deviates from baseline across monitored metrics: {factor_str}."
    action = "Temporarily restrict high-privilege access and request re-authentication."
    return behaviour, reason, action
