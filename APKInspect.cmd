@echo off
setlocal EnableExtensions EnableDelayedExpansion
title APKInspect
cd /d "%~dp0"

echo.
echo    APKInspect
echo    Android APK / AAB security scanner
echo    ------------------------------------------
echo    Safe and open-source. It runs only on your
echo    own computer - nothing is uploaded anywhere.
echo.

rem --- find Python: py launcher first, then python / python3 ---
set "PY="
where py >nul 2>&1 && set "PY=py"
if not defined PY ( where python  >nul 2>&1 && ( python  -c "import sys" >nul 2>&1 && set "PY=python"  ) )
if not defined PY ( where python3 >nul 2>&1 && ( python3 -c "import sys" >nul 2>&1 && set "PY=python3" ) )

rem --- no Python yet: install it for the user (per-user, quietly), then relaunch ---
if not defined PY (
  echo    APKInspect needs Python - a free, trusted tool from
  echo    python.org. I can set it up for you now.
  echo.
  where winget >nul 2>&1
  if !errorlevel! == 0 (
    echo    Getting Python, please wait - this takes about a minute...
    echo    ^(If Windows asks for permission, choose Yes. That is only
    echo     Windows confirming the Python install - nothing else.^)
    set "APKI_LOG=%TEMP%\apkinspect-setup.log"
    winget install -e --id Python.Python.3.12 --scope user --silent --accept-source-agreements --accept-package-agreements > "!APKI_LOG!" 2>&1
    if !errorlevel! neq 0 winget install -e --id Python.Python.3.12 --silent --accept-source-agreements --accept-package-agreements >> "!APKI_LOG!" 2>&1
    echo.
    echo    Python is ready. Please close this window and open
    echo    APKInspect again - that is the only step left.
  ) else (
    echo    Opening the Python download page. Install it
    echo    ^(tick "Add Python to PATH"^), then open APKInspect again.
    start "" "https://www.python.org/downloads/"
  )
  echo.
  pause
  exit /b 1
)

rem --- first run only: create an in-folder icon you can double-click (never on the Desktop) ---
if not exist "%~dp0APKInspect.lnk" (
  set "APKI_TARGET=%~dp0APKInspect.cmd"
  set "APKI_ICON=%~dp0assets\icon.ico"
  set "APKI_WORKDIR=%~dp0"
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$ws = New-Object -ComObject WScript.Shell; $work = $env:APKI_WORKDIR.TrimEnd('\'); $lnk = $ws.CreateShortcut((Join-Path $work 'APKInspect.lnk')); $lnk.TargetPath = $env:APKI_TARGET; $lnk.WorkingDirectory = $work; $lnk.IconLocation = $env:APKI_ICON; $lnk.Description = 'APKInspect - Android APK/AAB security scanner'; $lnk.Save()" >nul 2>&1
)

echo    Starting APKInspect and opening your browser...
echo    Keep this window open while you use the app; close it to stop.
echo.
%PY% -m apkinspect.web
if errorlevel 1 (
  echo.
  echo    Could not start. Make sure Python 3.8+ is installed,
  echo    then open APKInspect again.
  pause
)
endlocal
