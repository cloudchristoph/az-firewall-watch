@echo off
:: start.bat  —  run az-firewall-watch from source (Windows)
::
:: Usage:
::   start.bat               normal start (setup wizard runs if .env is missing)
::   start.bat --reconfigure redo the Event Hub setup

cd /d "%~dp0"

:: Create virtual environment if needed
if not exist ".venv\Scripts\python.exe" (
    echo   Creating Python virtual environment...
    python -m venv .venv
)

.venv\Scripts\pip install -q --upgrade pip
.venv\Scripts\pip install -q -r requirements.txt

.venv\Scripts\python main.py %*
