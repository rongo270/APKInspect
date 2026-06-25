@echo off
setlocal
title APKInspect
cd /d "%~dp0"

echo ============================================
echo   APKInspect - Android APK/AAB security GUI
echo ============================================
echo Starting the local app and opening your browser...
echo (close this window to stop)
echo.

rem --- find a Python interpreter: py launcher first, then python / python3 ---
set "PY="
where py      >nul 2>&1 && set "PY=py"
if not defined PY ( where python  >nul 2>&1 && set "PY=python" )
if not defined PY ( where python3 >nul 2>&1 && set "PY=python3" )

if not defined PY (
  echo Python was not found on this computer.
  echo Run "Install APKInspect.cmd" once - it will set up Python for you - then try again.
  echo.
  pause
  exit /b 1
)

%PY% -m apkinspect.web
if errorlevel 1 (
  echo.
  echo Could not start. Make sure Python 3.8+ is installed.
  echo Tip: run "Install APKInspect.cmd" to fix this automatically.
  pause
)
endlocal
