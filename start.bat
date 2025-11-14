@echo off
REM Smart PKI/KMS Startup Script - Handles Everything Automatically
REM This script will:
REM 1. Check if venv exists, create if needed
REM 2. Activate venv automatically
REM 3. Install/update dependencies if needed
REM 4. Initialize system if needed
REM 5. Start the server

echo ========================================
echo   PKI/KMS System - Smart Startup
echo ========================================
echo.

REM Check Python installation
echo Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo X Python not found!
    echo   Please install Python 3.8+ from: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version') do set PYTHON_VERSION=%%i
echo √ Python found: %PYTHON_VERSION%

REM Check/Create Virtual Environment
echo.
if not exist venv (
    echo Virtual environment not found. Creating...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo X Failed to create virtual environment
        pause
        exit /b 1
    )
    echo √ Virtual environment created
) else (
    echo √ Virtual environment found
)

REM Activate Virtual Environment
echo.
echo Activating virtual environment...
call venv\Scripts\activate.bat
echo √ Virtual environment activated

REM Check/Install Dependencies
echo.
python -c "import flask" >nul 2>&1
if %errorlevel% neq 0 (
    echo Dependencies not installed. Installing...
    echo.
    python -m pip install --upgrade pip --quiet
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo X Failed to install dependencies
        pause
        exit /b 1
    )
    echo √ Dependencies installed
) else (
    echo √ Dependencies already installed
)

REM Check/Initialize System
echo.
if not exist data\ca\root_ca.crt (
    echo System not initialized. Initializing...
    echo.
    python cli\init_pki.py
    if %errorlevel% neq 0 (
        echo X Failed to initialize system
        pause
        exit /b 1
    )
    echo √ System initialized
) else (
    echo √ System already initialized
)

REM All checks passed, start the server
echo.
echo ========================================
echo   Starting PKI/KMS Server
echo ========================================
echo.
echo Access at: http://localhost:5000
echo Username: admin
echo Password: admin123
echo.
echo !  Change password after first login!
echo.
echo Press Ctrl+C to stop the server
echo ========================================
echo.

REM Start the server
python run.py

REM Server stopped
echo.
echo Server stopped.
echo.
pause
