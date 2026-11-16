@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0START_CIPHERQ.ps1"
if errorlevel 1 (
  echo.
  echo CipherQ startup stopped. Read the message above, correct the indicated issue, and run this file again.
  pause
)
endlocal
