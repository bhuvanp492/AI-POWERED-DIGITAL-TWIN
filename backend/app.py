"""
Main Application Entry Point for AI-DT-CyberShield.
FastAPI REST Server serving the Cybersecurity Engine, AI Inference,
Digital Twin State, Real User Activity Telemetry, Simulation APIs, and Frontend Web Application.
"""

import os
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.database import (
    init_db,
    get_user_session,
    log_api_request,
    insert_event
)
from backend.services.feature_extractor import aggregate_behaviour_from_request_telemetry
from backend.services.risk_engine import evaluate_security_risk
from backend.routes.auth import get_client_ip
from backend.routes.events import router as events_router
from backend.routes.analysis import router as analysis_router
from backend.routes.digital_twin import router as digital_twin_router
from backend.routes.stats import router as stats_router
from backend.routes.simulation import router as simulation_router
from backend.routes.auth import router as auth_router
from backend.routes.resources import router as resources_router
from ml.anomaly_detector import get_detector

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")


def resolve_endpoint_resource(endpoint: str, method: str) -> tuple[str, int]:
    """Maps HTTP API route to logical cloud resource and sensitivity level (1-5)."""
    ep = endpoint.lower()
    if "exam" in ep or "grade" in ep:
        return "Student Grade & Exam Database", 5
    elif "financial" in ep or "billing" in ep or "tuition" in ep:
        return "Financial Aid & Tuition Database", 4
    elif "auth/logs" in ep:
        return "Auth Audit Trail API", 2
    elif "auth" in ep:
        return "Authentication Service", 1
    elif "profile" in ep:
        return "Student Profile Portal", 2
    elif "catalog" in ep or "resources/list" in ep:
        return "Course Catalog API", 1
    elif "digital-twin" in ep or "twin" in ep:
        return "Digital Twin Core Engine", 2
    elif "analysis" in ep:
        return "AI Anomaly & XAI Engine", 3
    elif "simulation" in ep:
        return "Cyber Attack Simulator", 4
    elif "events" in ep:
        return "Security Telemetry API", 2
    elif "stats" in ep:
        return "SOC Dashboard Metrics API", 1
    elif "telemetry" in ep or "pipeline" in ep:
        return "Telemetry Stream API", 1
    elif "execute-action" in ep:
        return "Resource Execution Dispatcher", 2
    else:
        return "Campus Cloud Microservice", 1


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize SQLite database and warm up Isolation Forest model
    print("[AI-DT-CyberShield] Initializing Database...")
    init_db()
    print("[AI-DT-CyberShield] Pre-loading Isolation Forest Model...")
    detector = get_detector()
    if detector.is_loaded:
        print("[AI-DT-CyberShield] ML Model ready for inference.")
    else:
        print("[AI-DT-CyberShield] Warning: ML Model not found, train first via ml/train_model.py")
    yield
    print("[AI-DT-CyberShield] Shutting down...")


app = FastAPI(
    title="AI-DT-CyberShield API",
    description="AI-Powered Digital Twin for Predictive Cybersecurity of Cloud Applications",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def authenticated_telemetry_pipeline_middleware(request: Request, call_next):
    """
    Real-Time Telemetry Interception Pipeline:
    Every authenticated API request
            ↓
    timestamp, username, endpoint, HTTP method, status, IP, user-agent, session, resource, response/data volume
            ↓
    database (api_request_logs)
            ↓
    behaviour aggregation (12 features)
            ↓
    Isolation Forest & Risk Assessment
    """
    path = request.url.path

    # Only monitor /api/* routes; bypass static frontend files
    if not path.startswith("/api/"):
        return await call_next(request)

    # 1. Identify session token
    auth_header = request.headers.get("authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "token" in request.query_params:
        token = request.query_params.get("token")

    user_sess = None
    if token:
        user_sess = get_user_session(token)

    # 2. Execute downstream handler
    response = await call_next(request)

    # If unauthenticated, return response directly
    if not user_sess:
        return response

    # 3. Read response payload to compute exact response volume
    body_chunks = []
    async for chunk in response.body_iterator:
        body_chunks.append(chunk)
    body = b"".join(body_chunks)
    resp_bytes = len(body)
    data_volume_mb = round(resp_bytes / (1024 * 1024), 4)

    # Reconstruct headers
    headers_dict = dict(response.headers)
    headers_dict["content-length"] = str(resp_bytes)

    # 4. Execute the requested pipeline safely
    try:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        username = user_sess["username"]
        endpoint = path
        http_method = request.method.upper()
        status_code = response.status_code
        client_ip = get_client_ip(request)
        user_agent = request.headers.get("user-agent", "Unknown Client")[:150]
        session_id = (token[:18] + "...") if len(token) > 18 else token
        resource_name, resource_sens = resolve_endpoint_resource(endpoint, http_method)

        # Behaviour Aggregation (12 features)
        features = aggregate_behaviour_from_request_telemetry(
            username=username,
            endpoint=endpoint,
            http_method=http_method,
            status_code=status_code,
            source_ip=client_ip,
            user_agent=user_agent,
            session_id=session_id,
            resource_name=resource_name,
            resource_sensitivity=resource_sens,
            data_volume_mb=data_volume_mb,
            response_bytes=resp_bytes,
            session_start_time=user_sess.get("created_at")
        )

        # Isolation Forest & Risk Engine Inference
        analysis = evaluate_security_risk(features)
        anomaly_score = analysis.get("anomaly_score", 0.12)
        prediction = analysis.get("prediction", "NORMAL")
        risk_score = analysis.get("risk_score", 10)
        risk_level = analysis.get("risk_level", "Low")

        # Save to SQLite database (api_request_logs)
        log_api_request(
            timestamp=now_str,
            username=username,
            endpoint=endpoint,
            http_method=http_method,
            status_code=status_code,
            source_ip=client_ip,
            user_agent=user_agent,
            session_id=session_id,
            resource_name=resource_name,
            resource_sensitivity=resource_sens,
            response_bytes=resp_bytes,
            data_volume_mb=data_volume_mb,
            anomaly_score=anomaly_score,
            prediction=prediction,
            risk_score=risk_score,
            risk_level=risk_level
        )

        # Alerting: If anomalous or high risk, record to security_events
        is_telemetry_query = endpoint.endswith("/events") or endpoint.endswith("/telemetry-logs") or endpoint.endswith("/pipeline-stats")
        if (prediction == "ANOMALY DETECTED" or risk_score >= 55 or status_code >= 400) and not is_telemetry_query and endpoint != "/api/resources/execute-action":
            sec_event = {
                **features,
                "prediction": prediction,
                "anomaly_score": anomaly_score,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "detected_behaviour": analysis.get("detected_behaviour", "Automated request telemetry anomaly"),
                "reason": analysis.get("reason", "Elevated request velocity or behavioural divergence from baseline."),
                "recommended_action": analysis.get("recommended_action", "Audit recent queries and enforce rate limiting."),
                "event_source": "ACTUAL_ACTIVITY"
            }
            insert_event(sec_event)

        headers_dict["X-Telemetry-Monitored"] = "AI-DT-CyberShield"
        headers_dict["X-Anomaly-Score"] = str(anomaly_score)
        headers_dict["X-Risk-Score"] = str(risk_score)
        headers_dict["X-Risk-Level"] = str(risk_level)

    except Exception as e:
        print(f"[Telemetry Middleware Warning] Error in pipeline: {e}")

    return Response(
        content=body,
        status_code=response.status_code,
        headers=headers_dict,
        media_type=response.media_type
    )

# Register API Routers
app.include_router(auth_router)
app.include_router(stats_router)
app.include_router(events_router)
app.include_router(analysis_router)
app.include_router(digital_twin_router)
app.include_router(simulation_router)
app.include_router(resources_router)

# Mount Static Frontend
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/")
def serve_index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {
        "project": "AI-DT-CyberShield",
        "status": "online",
        "documentation": "/docs"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=True)
