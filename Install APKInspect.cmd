@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Install APKInspect
cd /d "%~dp0"

echo.
echo    Install APKInspect
echo    ------------------------------------------
echo    This adds two simple commands to your PC:
echo      apkinspect       (command-line scanner)
echo      apkinspect-gui   (the graphical app)
echo    so you can run them from any terminal window.
echo.
echo    Safe and open-source - it only installs this tool
echo    into your own Python. Nothing is uploaded anywhere.
echo.

rem --- find Python: py launcher first, then python / python3 ---
set "PY="
where py >nul 2>&1 && set "PY=py"
if not defined PY ( where python  >nul 2>&1 && ( python  -c "import sys" >nul 2>&1 && set "PY=python"  ) )
if not defined PY ( where python3 >nul 2>&1 && ( python3 -c "import sys" >nul 2>&1 && set "PY=python3" ) )

if not defined PY (
  echo    Python 3.8+ is needed first.
  echo    Tip: double-click APKInspect.cmd - it sets up Python for you.
  echo.
  echo    Opening the Python download page...
  start "" "https://www.python.org/downloads/"
  pause
  exit /b 1
)

echo    Using Python:
%PY% --version
echo.
echo    Installing APKInspect, please wait...
set "APKI_LOG=%TEMP%\apkinspect-install.log"
%PY% -m pip install --upgrade pip > "%APKI_LOG%" 2>&1
%PY% -m pip install . >> "%APKI_LOG%" 2>&1
if errorlevel 1 (
  echo.
  echo    Install did not finish. You can still run APKInspect any
  echo    time by double-clicking APKInspect.cmd in this folder.
  echo    Details saved to: %APKI_LOG%
  echo.
  pause
  exit /b 1
)

echo.
echo    Done - APKInspect is installed.
echo      Command line:  apkinspect path\to\app.apk
echo      Graphical app: apkinspect-gui
echo.
pause
endlocal
