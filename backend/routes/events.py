"""
Events API Router for AI-DT-CyberShield.
Provides protected endpoints for querying recorded security events and retrieving event details.
Enforces authentication (Module 5.1).
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import List, Optional, Dict, Any
from backend.database import get_events, get_event_by_id
from backend.routes.auth import get_current_user

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("", response_model=List[Dict[str, Any]])
def list_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    filter_type: Optional[str] = Query(None, description="NORMAL, SUSPICIOUS, Low, Medium, High, Critical, ACTUAL_ACTIVITY, SIMULATION"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Protected endpoint: Lists security events from SQLite audit stream."""
    return get_events(limit=limit, offset=offset, filter_type=filter_type)


@router.get("/{event_id}", response_model=Dict[str, Any])
def retrieve_event(
    event_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Protected endpoint: Returns details for an individual security event."""
    event = get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Security event with ID {event_id} not found")
    return event
