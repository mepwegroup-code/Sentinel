@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Update-Sentinel.ps1"
if errorlevel 1 (
  echo.
  echo Update failed. Check details above.
)
echo.
pause
