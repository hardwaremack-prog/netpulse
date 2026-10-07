@echo off
title NetPulse
cd /d "%~dp0"
where py >nul 2>nul && (py netpulse.py) || (python netpulse.py)
if errorlevel 1 (
  echo.
  echo Python 3 is needed. Get it free from https://www.python.org/downloads/  ^(tick "Add python.exe to PATH"^)
  pause
)
