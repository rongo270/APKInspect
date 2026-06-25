@echo off
setlocal EnableExtensions EnableDelayedExpansion
title APKInspect
cd /d "%~dp0"

echo ============================================
echo   APKInspect - Android APK/AAB security GUI
echo ============================================

rem --- find Python: py launcher first, then python / python3 ---
set "PY="
where py >nul 2>&1 && set "PY=py"
if not defined PY ( where python  >nul 2>&1 && ( python  -c "import sys" >nul 2>&1 && set "PY=python"  ) )
if not defined PY ( where python3 >nul 2>&1 && ( python3 -c "import sys" >nul 2>&1 && set "PY=python3" ) )

rem --- no Python yet: install it for the user, then ask to relaunch ---
if not defined PY (
  echo Python is needed to run APKInspect, but it was not found.
  echo.
  where winget >nul 2>&1
  if !errorlevel! == 0 (
    echo Installing Python for you via winget. Click "Yes" if Windows asks permission.
    winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements
    echo.
    echo ------------------------------------------------------------
    echo Python is installed. Please CLOSE this window and open
    echo APKInspect again so the new Python is picked up.
    echo ------------------------------------------------------------
  ) else (
    echo Opening the Python download page. Install it ^(tick "Add Python to PATH"^),
    echo then open APKInspect again.
    start "" "https://www.python.org/downloads/"
  )
  echo.
  pause
  exit /b 1
)

rem --- first run only: create an in-folder icon you can double-click (never on the Desktop) ---
if not exist "%~dp0APKInspect.lnk" (
  echo First-time setup: creating an APKInspect icon in this folder...
  set "APKI_TARGET=%~dp0APKInspect.cmd"
  set "APKI_ICON=%~dp0assets\icon.ico"
  set "APKI_WORKDIR=%~dp0"
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$ws = New-Object -ComObject WScript.Shell; $work = $env:APKI_WORKDIR.TrimEnd('\'); $lnk = $ws.CreateShortcut((Join-Path $work 'APKInspect.lnk')); $lnk.TargetPath = $env:APKI_TARGET; $lnk.WorkingDirectory = $work; $lnk.IconLocation = $env:APKI_ICON; $lnk.Description = 'APKInspect - Android APK/AAB security scanner'; $lnk.Save()"
  if exist "%~dp0APKInspect.lnk" echo Done - an APKInspect icon is now in this folder.
  echo.
)

echo Starting the local app and opening your browser...
echo (close this window to stop)
echo.
%PY% -m apkinspect.web
if errorlevel 1 (
  echo.
  echo Could not start. Make sure Python 3.8+ is installed.
  pause
)
endlocal
