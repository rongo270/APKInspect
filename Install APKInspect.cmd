@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Install APKInspect
cd /d "%~dp0"

echo ================================================
echo   APKInspect - one-time setup
echo ================================================
echo This will:
echo   1) make sure Python is installed  (nothing else is needed)
echo   2) create an "APKInspect" icon you can double-click
echo.

rem ============================================================
rem  1) Find Python; install it automatically if it is missing
rem ============================================================
set "PY="
where py >nul 2>&1 && set "PY=py"
if not defined PY ( where python  >nul 2>&1 && ( python  -c "import sys" >nul 2>&1 && set "PY=python"  ) )
if not defined PY ( where python3 >nul 2>&1 && ( python3 -c "import sys" >nul 2>&1 && set "PY=python3" ) )

if not defined PY (
  echo Python was not found - trying to install it for you...
  echo.
  where winget >nul 2>&1
  if !errorlevel! == 0 (
    echo Installing Python via winget. You may see a Windows permission prompt - click Yes.
    winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements
    echo.
    echo ------------------------------------------------------------
    echo Python has been installed. Please CLOSE this window, then run
    echo "Install APKInspect.cmd" again so the new Python is detected.
    echo ------------------------------------------------------------
    echo.
    pause
    exit /b 0
  ) else (
    echo Could not auto-install ^(winget is not available^).
    echo Opening the official Python download page in your browser.
    echo Install it, TICK "Add Python to PATH", then run this setup again.
    start "" "https://www.python.org/downloads/"
    echo.
    pause
    exit /b 1
  )
)

echo Found Python:
%PY% --version
echo.

rem ============================================================
rem  2) Create the desktop + in-folder shortcut with the icon
rem ============================================================
set "APKI_TARGET=%~dp0APKInspect.cmd"
set "APKI_ICON=%~dp0assets\icon.ico"
set "APKI_WORKDIR=%~dp0"

echo Creating the APKInspect icon...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ws = New-Object -ComObject WScript.Shell; $work = $env:APKI_WORKDIR.TrimEnd('\'); foreach ($dir in @([Environment]::GetFolderPath('Desktop'), $work)) { $lnk = $ws.CreateShortcut((Join-Path $dir 'APKInspect.lnk')); $lnk.TargetPath = $env:APKI_TARGET; $lnk.WorkingDirectory = $work; $lnk.IconLocation = $env:APKI_ICON; $lnk.Description = 'APKInspect - Android APK/AAB security scanner'; $lnk.Save() }"

if errorlevel 1 (
  echo.
  echo Setup finished, but the shortcut could not be created automatically.
  echo You can still launch the app by double-clicking APKInspect.cmd in this folder.
) else (
  echo.
  echo All set.  An "APKInspect" icon is now on your Desktop ^(and in this folder^).
  echo Double-click it any time to scan an APK or AAB.
)
echo.
pause
endlocal
