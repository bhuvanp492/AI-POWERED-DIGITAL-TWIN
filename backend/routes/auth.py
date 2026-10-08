"""
Authentication & Session Management API Router for AI-DT-CyberShield (Module 5.1).
Provides:
- Database-backed credential validation with salted PBKDF2-SHA256 password hashing.
- Cryptographic session management and Bearer token lifecycle (login, verify, logout).
- Application access logging for all authentication attempts, logouts, and unauthorized probes.
- FastAPI dependency for protecting downstream routes.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Header, Request, Depends, status
from pydantic import BaseModel

from backend.database import (
    get_user_by_username,
    verify_password,
    create_user_session,
    get_user_session,
    delete_user_session,
    log_auth_event,
    get_auth_events
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class UserProfile(BaseModel):
    username: str
    role: str
    department: str
    login_time: str


class LoginResponse(BaseModel):
    success: bool
    token: str
    user: UserProfile
    message: str


class AuthEventResponse(BaseModel):
    id: int
    timestamp: str
    username: str
    event_type: str
    source_ip: str
    user_agent: str
    auth_status: str
    details: Optional[str] = None


def get_client_ip(request: Request) -> str:
    """Safely extracts client IP address from request headers or client socket."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """
    FastAPI dependency that enforces authentication on protected endpoints.
    Extracts Bearer token or raw token from Authorization header.
    Rejects unauthenticated requests with HTTP 401 and logs unauthorized access attempts.
    """
    token = authorization
    if not token:
        # Check query param or cookies fallback if needed
        token = request.query_params.get("token")

    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "Unknown Client")[:100]

    if not token:
        log_auth_event(
            username="anonymous",
            event_type="UNAUTHORIZED_ACCESS",
            source_ip=client_ip,
            user_agent=user_agent,
            auth_status="DENIED",
            details=f"Attempted access to protected endpoint: {request.url.path}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    session = get_user_session(token)
    if not session:
        log_auth_event(
            username="unknown",
            event_type="UNAUTHORIZED_ACCESS",
            source_ip=client_ip,
            user_agent=user_agent,
            auth_status="DENIED",
            details=f"Invalid or expired token attempting access to {request.url.path}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid. Please re-authenticate.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Attach user info to request state for downstream handlers
    request.state.user = session
    return session


@router.post("/login", response_model=LoginResponse)
def login(request_payload: LoginRequest, request: Request):
    uname = (request_payload.username or "").strip()
    pwd = (request_payload.password or "").strip()

    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "Unknown Client")[:100]

    # Validate non-empty credentials
    if not uname or not pwd:
        log_auth_event(
            username=uname or "empty",
            event_type="LOGIN_FAILED",
            source_ip=client_ip,
            user_agent=user_agent,
            auth_status="FAILURE",
            details="Empty username or password provided."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and password fields are required."
        )

    # Retrieve user record from database
    user_record = get_user_by_username(uname)
    if not user_record:
        log_auth_event(
            username=uname,
            event_type="LOGIN_FAILED",
            source_ip=client_ip,
            user_agent=user_agent,
            auth_status="FAILURE",
            details="Username not found in credential store."
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed. Invalid username or password."
        )

    # Constant-time verify password hash
    is_valid = verify_password(pwd, user_record["password_hash"], user_record["salt"])
    if not is_valid:
        log_auth_event(
            username=uname,
            event_type="LOGIN_FAILED",
            source_ip=client_ip,
            user_agent=user_agent,
            auth_status="FAILURE",
            details="Incorrect password supplied for user."
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed. Invalid username or password."
        )

    # Successful authentication
    token = create_user_session(
        username=uname,
        role=user_record["role"],
        department=user_record["department"],
        source_ip=client_ip,
        user_agent=user_agent
    )

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Record successful login in access audit log
    log_auth_event(
        username=uname,
        event_type="LOGIN_SUCCESS",
        source_ip=client_ip,
        user_agent=user_agent,
        auth_status="SUCCESS",
        details="Authenticated successfully with valid salted hash."
    )

    profile = UserProfile(
        username=uname,
        role=user_record["role"],
        department=user_record["department"],
        login_time=now_str
    )

    return LoginResponse(
        success=True,
        token=token,
        user=profile,
        message=f"Welcome, {uname}. Secure session initialized."
    )


@router.post("/logout")
def logout(request: Request, authorization: Optional[str] = Header(None)):
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "Unknown Client")[:100]

    username = "unknown"
    if authorization:
        session = get_user_session(authorization)
        if session:
            username = session["username"]
        delete_user_session(authorization)

    log_auth_event(
        username=username,
        event_type="LOGOUT",
        source_ip=client_ip,
        user_agent=user_agent,
        auth_status="SUCCESS",
        details="Session terminated by user."
    )

    return {"success": True, "message": "Session terminated successfully."}


@router.get("/session")
def get_session_info(authorization: Optional[str] = Header(None)):
    """Safe session verification endpoint for frontend UI state check."""
    if authorization:
        session = get_user_session(authorization)
        if session:
            return {
                "authenticated": True,
                "user": {
                    "username": session["username"],
                    "role": session["role"],
                    "department": session["department"],
                    "login_time": session["created_at"]
                }
            }
    return {
        "authenticated": False,
        "detail": "No active session."
    }


@router.get("/logs", response_model=List[AuthEventResponse])
def list_authentication_logs(
    limit: int = 50,
    offset: int = 0,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Protected endpoint: Returns the authentication audit trail."""
    return get_auth_events(limit=limit, offset=offset)
