@echo off
title APKInspect
cd /d "%~dp0"
echo ============================================
echo   APKInspect - Android APK/AAB security GUI
echo ============================================
echo Starting local server and opening your browser...
echo (close this window or press Ctrl+C to stop)
echo.
python -m apkinspect.web
if errorlevel 1 (
  echo.
  echo Could not start. Make sure Python 3.8+ is installed and on PATH.
  pause
)
