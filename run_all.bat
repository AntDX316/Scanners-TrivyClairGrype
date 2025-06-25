@echo off
REM Single command to run all vulnerability scanners using Docker
REM No local installation required - just Docker!

echo 🚀 Running All Vulnerability Scanners with Docker
echo ================================================

REM Check if Docker is running
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker not found. Please install Docker Desktop first.
    echo    Download from: https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

REM Get target from command line argument or default to current directory
set TARGET=%1
if "%TARGET%"=="" set TARGET=.

echo 📦 Target: %TARGET%
echo 📁 Results will be saved to: results\
echo.

REM Run the Docker-based scanner
python scan_docker.py "%TARGET%"

echo.
echo ✅ All scans completed!
echo 📊 Check the results\ directory for detailed reports
echo 🌐 HTML report should open automatically in your browser

pause
