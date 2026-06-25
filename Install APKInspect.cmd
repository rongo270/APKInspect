@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Install APKInspect
cd /d "%~dp0"

echo ==================================================
echo   Install APKInspect
echo ==================================================
echo.
echo This installs APKInspect into Python so you can run
echo   apkinspect       (command-line scanner)
echo   apkinspect-gui   (the graphical app)
echo from any terminal window.
echo.
echo You need Python 3.8 or newer first. If you do not have
echo it, the one-click APKInspect.cmd will install it for you.
echo.

rem --- find Python: py launcher first, then python / python3 ---
set "PY="
where py >nul 2>&1 && set "PY=py"
if not defined PY ( where python  >nul 2>&1 && ( python  -c "import sys" >nul 2>&1 && set "PY=python"  ) )
if not defined PY ( where python3 >nul 2>&1 && ( python3 -c "import sys" >nul 2>&1 && set "PY=python3" ) )

if not defined PY (
  echo Python was not found on this PC.
  echo Install Python 3.8+ from https://www.python.org/downloads/
  echo  ^(tick "Add Python to PATH" in the installer^), then run this again.
  echo  -- or just double-click APKInspect.cmd, which installs Python for you.
  echo.
  echo Opening the download page...
  start "" "https://www.python.org/downloads/"
  pause
  exit /b 1
)

echo Using:
%PY% --version
echo.
echo Installing APKInspect ^(this can take a moment^)...
%PY% -m pip install --upgrade pip >nul 2>&1
%PY% -m pip install .
if errorlevel 1 (
  echo.
  echo Install failed. You can still run APKInspect without installing
  echo by double-clicking APKInspect.cmd in this folder.
  echo.
  pause
  exit /b 1
)

echo.
echo ============================================
echo   Done. APKInspect is installed.
echo.
echo   Command line:  apkinspect path\to\app.apk
echo   Graphical app: apkinspect-gui
echo ============================================
echo.
pause
endlocal
