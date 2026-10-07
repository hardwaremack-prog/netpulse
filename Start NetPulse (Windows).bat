@echo off
title NetPulse
cd /d "%~dp0"
set "PY="
py -3 -c "1" >nul 2>nul && set "PY=py -3"
if not defined PY python -c "1" >nul 2>nul && set "PY=python"
if not defined PY for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do if exist "%%D\python.exe" set "PY="%%D\python.exe""
if not defined PY for /d %%D in ("%ProgramFiles%\Python3*") do if exist "%%D\python.exe" set "PY="%%D\python.exe""
if not defined PY (
  echo.
  echo  Python 3 is needed to run NetPulse.
  echo  Get it free from https://www.python.org/downloads/
  echo.
  pause
  exit /b 1
)
%PY% netpulse.py %*
echo.
echo  NetPulse has stopped.
pause
