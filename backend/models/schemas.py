"""
Pydantic Schemas for AI-DT-CyberShield.
Defines data structures for security events, AI analysis results, Digital Twin states,
and simulation requests.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class EventBase(BaseModel):
    username: str
    ip_address: str
    device_info: str
    action: str
    resource_name: str
    login_status: str = "SUCCESSFUL"
    requests_per_minute: float = 20.0
    failed_login_count: int = 0
    login_frequency_per_hr: float = 1.0
    resource_sensitivity_level: int = 1
    records_accessed: int = 5
    data_download_mb: float = 1.0
    is_new_device: int = 0
    is_new_ip: int = 0
    unusual_api_access: int = 0
    session_duration_minutes: float = 30.0
    access_time_hour: int = 14
    behaviour_deviation_score: float = 0.05
    scenario_type: Optional[str] = "custom"
    event_source: Optional[str] = "ACTUAL_ACTIVITY"


class EventCreate(EventBase):
    pass


class FeatureDeviation(BaseModel):
    feature: str
    raw_value: float
    mean_baseline: float
    z_score: float
    is_elevated: bool
    is_extreme: bool


class AIAnalysisResult(BaseModel):
    prediction: str  # "NORMAL" or "SUSPICIOUS"
    anomaly_score: float  # 0.0 to 1.0
    raw_score: float
    risk_score: int  # 0 to 100
    risk_level: str  # "Low", "Medium", "High", "Critical"
    detected_behaviour: str
    reason: str
    recommended_action: str
    affected_resource: str
    feature_deviations: List[Dict[str, Any]] = []


class SecurityEvent(EventBase):
    id: int
    timestamp: str
    prediction: str
    anomaly_score: float
    risk_score: int
    risk_level: str
    detected_behaviour: str
    reason: str
    recommended_action: str

    model_config = {"from_attributes": True}


class SimulationRequest(BaseModel):
    scenario_id: str = Field(
        ...,
        description="Scenario identifier: 'normal_activity', 'repeated_logins', 'api_burst', 'sensitive_access', 'large_download', 'compromised_account'"
    )


class SimulationResponse(BaseModel):
    success: bool
    scenario_id: str
    scenario_title: str
    event: SecurityEvent
    analysis: AIAnalysisResult
    digital_twin_status: str


class DashboardStats(BaseModel):
    total_events: int
    normal_events: int
    suspicious_events: int
    high_risk_events: int
    critical_events: int
    current_security_status: str  # "● SECURE" or "● ATTENTION REQUIRED"
    current_risk_level: str  # "Low", "Medium", "High", "Critical"
    average_risk_score: float
    recent_compromised_detected: bool


class DigitalTwinNode(BaseModel):
    id: str
    name: str
    type: str  # "application", "user", "resource", "ai_engine", "security_state"
    status: str  # "HEALTHY", "WARNING", "CRITICAL", "ACTIVE", "MONITORING"
    details: Dict[str, Any]


class DigitalTwinState(BaseModel):
    application_status: str
    security_state: str
    current_risk: str
    risk_numeric: int
    recent_anomaly: str
    active_threats_count: int
    protected_resources: List[Dict[str, Any]]
    nodes: List[DigitalTwinNode]
    last_updated: str
