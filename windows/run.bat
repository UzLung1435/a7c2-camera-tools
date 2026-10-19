@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

fltmc >nul 2>&1
if errorlevel 1 (
  set "A7C2_LAUNCHER=%~f0"
  powershell -NoProfile -Command "Start-Process -FilePath $env:A7C2_LAUNCHER -Verb RunAs"
  exit /b %errorlevel%
)

if not exist ".venv\Scripts\python.exe" (
  where py >nul 2>&1
  if not errorlevel 1 (
    py -3 -m venv ".venv"
  ) else (
    where python >nul 2>&1
    if errorlevel 1 goto no_python
    python -m venv ".venv"
  )
  if errorlevel 1 goto setup_failed
)

".venv\Scripts\python.exe" -c "import sys; raise SystemExit(sys.version_info < (3, 10) or sys.maxsize < 2**32)"
if errorlevel 1 goto no_python

".venv\Scripts\python.exe" -c "import imageio_ffmpeg" >nul 2>&1
if errorlevel 1 if exist ".venv\.ready" del ".venv\.ready"

if not exist ".venv\.ready" (
  echo Installing Python dependencies...
  ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
  if errorlevel 1 goto setup_failed
  type nul > ".venv\.ready"
)

".venv\Scripts\python.exe" "runtime\ui.py"
exit /b %errorlevel%

:no_python
echo Python 3.10 or newer is required.
exit /b 1

:setup_failed
echo Setup failed.
exit /b 1
