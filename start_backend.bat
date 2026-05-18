@echo off
echo Starting Sentinel Nexus Server...
echo.

REM Activate virtual environment
call sentinelai\Scripts\activate.bat

REM Check if activation was successful
if %ERRORLEVEL% NEQ 0 (
    echo Failed to activate virtual environment
    pause
    exit /b 1
)

echo Virtual environment activated successfully
echo.

REM Start the server
echo Starting Sentinelops AI Server on http://localhost:8010
echo.
echo Press Ctrl+C to stop the server
echo.

uvicorn app.main:app --host 0.0.0.0 --port 8010 --reload

pause
