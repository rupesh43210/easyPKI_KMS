# Smart PKI/KMS Startup Script - Handles Everything Automatically
# This script will:
# 1. Check if venv exists, create if needed
# 2. Activate venv automatically
# 3. Install/update dependencies if needed
# 4. Initialize system if needed
# 5. Start the server

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PKI/KMS System - Smart Startup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Function to check if venv is properly set up
function Test-VenvSetup {
    if (-not (Test-Path "venv")) { return $false }
    if (-not (Test-Path "venv\Scripts\python.exe")) { return $false }
    if (-not (Test-Path "venv\Scripts\activate.ps1")) { return $false }
    return $true
}

# Function to check if dependencies are installed
function Test-Dependencies {
    $testImport = & "venv\Scripts\python.exe" -c "import flask" 2>&1
    return $LASTEXITCODE -eq 0
}

# Function to check if system is initialized
function Test-Initialized {
    return (Test-Path "data\ca\root_ca.crt")
}

# Check Python installation
Write-Host "Checking Python installation..." -ForegroundColor Yellow
$pythonCheck = Get-Command python -ErrorAction SilentlyContinue
if ($pythonCheck) {
    $pythonVersion = python --version 2>&1
    Write-Host "OK Python found: $pythonVersion" -ForegroundColor Green
} else {
    Write-Host "X Python not found!" -ForegroundColor Red
    Write-Host "  Please install Python 3.8+ from: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Check/Create Virtual Environment
if (-not (Test-VenvSetup)) {
    Write-Host ""
    Write-Host "Virtual environment not found. Creating..." -ForegroundColor Yellow
    python -m venv venv
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "OK Virtual environment created" -ForegroundColor Green
    } else {
        Write-Host "X Failed to create virtual environment" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
} else {
    Write-Host "OK Virtual environment found" -ForegroundColor Green
}

# Activate Virtual Environment
Write-Host ""
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& .\venv\Scripts\Activate.ps1
Write-Host "OK Virtual environment activated" -ForegroundColor Green

# Check/Install Dependencies
Write-Host ""
if (-not (Test-Dependencies)) {
    Write-Host "Dependencies not installed. Installing..." -ForegroundColor Yellow
    Write-Host ""
    
    # Upgrade pip first
    python -m pip install --upgrade pip --quiet
    
    # Install dependencies
    pip install -r requirements.txt
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "OK Dependencies installed" -ForegroundColor Green
    } else {
        Write-Host "X Failed to install dependencies" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
} else {
    Write-Host "OK Dependencies already installed" -ForegroundColor Green
}

# Check/Initialize System
Write-Host ""
if (-not (Test-Initialized)) {
    Write-Host "System not initialized. Initializing..." -ForegroundColor Yellow
    Write-Host ""
    python cli\init_pki.py
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "OK System initialized" -ForegroundColor Green
    } else {
        Write-Host "X Failed to initialize system" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
} else {
    Write-Host "OK System already initialized" -ForegroundColor Green
}

# All checks passed, start the server
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Starting PKI/KMS Server" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Access at: " -NoNewline -ForegroundColor Yellow
Write-Host "http://localhost:5000" -ForegroundColor Cyan
Write-Host "Username: " -NoNewline -ForegroundColor Yellow
Write-Host "admin" -ForegroundColor White
Write-Host "Password: " -NoNewline -ForegroundColor Yellow
Write-Host "admin123" -ForegroundColor White
Write-Host ""
Write-Host "WARNING: Change password after first login!" -ForegroundColor Red
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Start the server
python run.py

# Server stopped
Write-Host ""
Write-Host "Server stopped." -ForegroundColor Yellow
Write-Host ""
Read-Host "Press Enter to exit"
