@echo off
REM Secure File Drop / Uploader Client GUI launcher

echo Starting Secure File Drop / Uploader Client...
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH.
    echo Please install Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

python "%~dp0uploader_gui.py"

if errorlevel 1 (
    echo.
    echo An error occurred. Check the output above.
    pause
)
