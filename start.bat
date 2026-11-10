@echo off
:: start.bat  —  run az-firewall-watch from source (Windows)
::
:: Usage:
::   start.bat               normal start (setup wizard runs if .env is missing)
::   start.bat --reconfigure redo the Event Hub setup

cd /d "%~dp0"

:: Python 3.11 or newer is required; say so, and what was found, before building a venv that cannot run it
if exist ".venv\Scripts\python.exe" goto check_venv
python -c "import sys; sys.exit(sys.version_info < (3, 11))" 2>nul
if not errorlevel 1 goto create_venv
set "FOUND=no Python"
for /f "delims=" %%v in ('python --version 2^>^&1 ^| findstr /r /b /c:"Python [0-9]"') do set "FOUND=%%v"
echo   Python 3.11 or newer is required (found: %FOUND%).
exit /b 1

:create_venv
echo   Creating Python virtual environment...
python -m venv .venv

:check_venv
.venv\Scripts\python -c "import sys; sys.exit(sys.version_info < (3, 11))" 2>nul
if not errorlevel 1 goto install
set "FOUND=an unknown Python"
for /f "delims=" %%v in ('.venv\Scripts\python --version 2^>^&1 ^| findstr /r /b /c:"Python [0-9]"') do set "FOUND=%%v"
echo   The virtual environment uses %FOUND%; Python 3.11 or newer is required.
echo   Delete the .venv folder and run this script again.
exit /b 1

:install
.venv\Scripts\python -m pip install -q --upgrade pip
.venv\Scripts\python -m pip install -q -r requirements.txt

.venv\Scripts\python main.py %*
