@echo off
echo ===================================================================
echo   AI-DT-CyberShield: AI-Powered Digital Twin for Cybersecurity
echo   Final-Year B.Tech CSE Project (Phase 1 Prototype)
echo ===================================================================
echo.
echo Starting FastAPI application server at http://127.0.0.1:8000 ...
echo Press Ctrl+C to stop the server.
echo.

py -3.12 -m uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload
pause
