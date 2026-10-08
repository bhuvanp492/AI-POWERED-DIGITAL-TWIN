"""
Dashboard Statistics Router for AI-DT-CyberShield.
Calculates high-level cybersecurity KPI metrics for the dashboard view.
Protected via Module 5.1 authentication.
"""

from fastapi import APIRouter, Depends
from typing import Dict, Any
from backend.database import get_dashboard_stats, reset_database
from backend.models.schemas import DashboardStats
from backend.routes.auth import get_current_user

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("", response_model=DashboardStats)
def retrieve_dashboard_statistics(current_user: Dict[str, Any] = Depends(get_current_user)):
    return get_dashboard_stats()


@router.post("/reset")
def reset_to_initial_state(current_user: Dict[str, Any] = Depends(get_current_user)):
    reset_database()
    return {"status": "success", "message": "Database successfully reset to initial baseline demo state."}
