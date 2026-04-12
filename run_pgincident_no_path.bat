@echo off
echo ================================
echo   PgIncident Smart Launcher
echo ================================

echo.
py -3.11 --version >nul 2>nul
if %errorlevel%==0 (
    set PY_CMD=py -3.11
) else (
    echo.
    echo Python 3.11 not found.
    echo Install Python 3.11 and run again.
    pause
    exit /b
)

echo Using: %PY_CMD%

echo.
if exist venv rmdir /s /q venv

echo [1] Creating virtual environment...
%PY_CMD% -m venv venv

echo.
echo [2] Activating virtual environment...
call venv\Scripts\activate

echo.
echo [3] Installing dependencies...
%PY_CMD% -m pip install --upgrade pip
%PY_CMD% -m pip install -r requirements.txt

echo.
echo [4] Enter your ANTHROPIC API KEY:
set /p APIK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=
set ANTHROPIC_API_KEY=%APIKEY%

echo.
echo [5] Starting server...
%PY_CMD% -m uvicorn main:app --reload

pause