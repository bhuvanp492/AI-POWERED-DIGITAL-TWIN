"""
Digital Twin API Router for AI-DT-CyberShield.
Serves real-time state and node telemetry representing the cloud application's security posture.
Protected via Module 5.1 authentication.
"""

from fastapi import APIRouter, Depends
from typing import Dict, Any
from backend.services.twin_service import get_current_digital_twin_state
from backend.routes.auth import get_current_user

router = APIRouter(prefix="/api/digital-twin", tags=["digital_twin"])


@router.get("", response_model=Dict[str, Any])
def retrieve_digital_twin_state(current_user: Dict[str, Any] = Depends(get_current_user)):
    return get_current_digital_twin_state()
