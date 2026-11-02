@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Run-LAN-Scan.ps1"
if errorlevel 1 (
  echo.
  echo LAN agent finished with an error.
)
echo.
pause
