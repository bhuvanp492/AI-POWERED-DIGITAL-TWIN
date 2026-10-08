"""
Simulation API Router for AI-DT-CyberShield.
Drives the controlled Security Testing benchmark demonstrations, executing the entire event pipeline:
Generation -> ML Inference -> Risk Scoring -> Explainability -> SQLite Storage -> Digital Twin Update.
Events generated here are explicitly flagged with event_source='SIMULATION'.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any
from backend.models.schemas import SimulationRequest, SimulationResponse
from backend.services.simulator import get_scenario_definition
from backend.services.risk_engine import evaluate_security_risk
from backend.database import insert_event, get_event_by_id
from backend.services.twin_service import get_current_digital_twin_state
from backend.routes.auth import get_current_user

router = APIRouter(prefix="/api/simulation", tags=["simulation"])


@router.get("/scenarios")
def list_available_scenarios():
    return [
        {
            "id": "normal_activity",
            "title": "Normal User Activity",
            "description": "Standard legitimate user querying course catalog using verified workstation and IP.",
            "category": "Baseline",
            "expected_outcome": "NORMAL (Low Risk)"
        },
        {
            "id": "repeated_logins",
            "title": "Repeated Login Attempts",
            "description": "Rapid credential brute-forcing against administrative portal resulting in lockout.",
            "category": "Authentication",
            "expected_outcome": "ANOMALY DETECTED (High Risk)"
        },
        {
            "id": "api_burst",
            "title": "API Burst",
            "description": "Aggressive volumetric API request spike (380+ req/min) simulating automated scraping.",
            "category": "Application Layer",
            "expected_outcome": "ANOMALY DETECTED (High Risk)"
        },
        {
            "id": "sensitive_access",
            "title": "Sensitive Resource Access",
            "description": "Unauthorized probing and mass record query into confidential financial/exam databases.",
            "category": "Privilege Abuse",
            "expected_outcome": "ANOMALY DETECTED (Elevated Risk)"
        },
        {
            "id": "large_download",
            "title": "Large Data Download",
            "description": "Heavy data exfiltration transfer exceeding session bandwidth policies (450+ MB).",
            "category": "Data Exfiltration",
            "expected_outcome": "ANOMALY DETECTED (Critical Risk)"
        },
        {
            "id": "compromised_account",
            "title": "Compromised Account Simulation",
            "description": "Flagship Demo: Valid credentials authenticated successfully, followed by multi-vector abnormal post-login exfiltration.",
            "category": "Credential Hijack",
            "expected_outcome": "ANOMALY DETECTED (Critical Risk)"
        }
    ]


@router.post("/run", response_model=SimulationResponse)
def execute_simulation(
    request: SimulationRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    scenario_id = request.scenario_id
    try:
        scenario_def = get_scenario_definition(scenario_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    raw_event = scenario_def["data"]

    # 1. Pass raw behavioural features to ML & Risk Engine
    analysis = evaluate_security_risk(raw_event)

    # 2. Enrich event data with AI predictions and SIMULATION flag
    full_event_data = {
        **raw_event,
        "prediction": analysis["prediction"],
        "anomaly_score": analysis["anomaly_score"],
        "risk_score": analysis["risk_score"],
        "risk_level": analysis["risk_level"],
        "detected_behaviour": analysis["detected_behaviour"],
        "reason": analysis["reason"],
        "recommended_action": analysis["recommended_action"],
        "event_source": "SIMULATION"
    }

    # 3. Persist into SQLite
    event_id = insert_event(full_event_data)
    stored_event = get_event_by_id(event_id)

    # 4. Fetch updated Digital Twin posture
    twin_state = get_current_digital_twin_state()

    return {
        "success": True,
        "scenario_id": scenario_id,
        "scenario_title": scenario_def["title"],
        "event": stored_event,
        "analysis": analysis,
        "digital_twin_status": twin_state["security_state"]
    }
