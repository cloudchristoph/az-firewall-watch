@echo off
:: start.bat  —  run az-firewall-watch from source (Windows)
::
:: Usage:
::   start.bat               normal start (setup wizard runs if .env is missing)
::   start.bat --reconfigure redo the Event Hub setup

cd /d "%~dp0"

:: Python 3.11 or newer is required; say so before building a venv that cannot run it
if not exist ".venv\Scripts\python.exe" (
    python -c "import sys; sys.exit(sys.version_info < (3, 11))" 2>nul
    if errorlevel 1 (
        echo   Python 3.11 or newer is required. Install it with: winget install Python.Python.3.13
        exit /b 1
    )
    echo   Creating Python virtual environment...
    python -m venv .venv
)
.venv\Scripts\python -c "import sys; sys.exit(sys.version_info < (3, 11))" 2>nul
if errorlevel 1 (
    echo   The virtual environment uses an older Python; Python 3.11 or newer is required.
    echo   Delete the .venv folder and run this script again.
    exit /b 1
)

.venv\Scripts\pip install -q --upgrade pip
.venv\Scripts\pip install -q -r requirements.txt

.venv\Scripts\python main.py %*
