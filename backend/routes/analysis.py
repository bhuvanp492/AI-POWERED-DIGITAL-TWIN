"""
AI Analysis API Router for AI-DT-CyberShield (Module 5.2 & Module 5.3).
Provides explainable AI security evaluations, feature importance breakdowns,
and ML model inspection telemetry.
Protected via Module 5.1 authentication.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any
from backend.database import get_event_by_id
from backend.services.risk_engine import evaluate_security_risk
from backend.models.schemas import AIAnalysisResult, EventCreate
from backend.routes.auth import get_current_user
from ml.anomaly_detector import get_detector

router = APIRouter(prefix="/api/analysis", tags=["analysis"])


@router.get("/model-info")
def get_model_info() -> Dict[str, Any]:
    detector = get_detector()
    return {
        "status": "ready" if detector.is_loaded else "uninitialized",
        "metadata": detector.metadata
    }


@router.get("/{event_id}", response_model=AIAnalysisResult)
def analyze_recorded_event(
    event_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    event = get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Security event with ID {event_id} not found")

    analysis = evaluate_security_risk(event)
    return analysis


@router.post("/evaluate", response_model=AIAnalysisResult)
def evaluate_custom_payload(
    payload: EventCreate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    data = payload.dict()
    analysis = evaluate_security_risk(data)
    return analysis
