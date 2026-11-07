@echo off
if "%~1"=="" (
    python "%~dp0scan_docker.py" .
) else (
    python "%~dp0scan_docker.py" %*
)
exit /b %errorlevel%
