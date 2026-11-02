@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Start-Sentinel.ps1"
if errorlevel 1 (
  echo.
  echo Sentinel start failed. Read the message above.
)
echo.
pause
