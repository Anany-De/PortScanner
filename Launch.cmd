@echo off
cd /d "%~dp0"
if not exist "%~dp0.venv\Scripts\python.exe" (
  echo Create the project environment first: py -3 -m venv .venv
  pause
  exit /b 1
)
"%~dp0.venv\Scripts\python.exe" portscanner.py
if errorlevel 1 pause
