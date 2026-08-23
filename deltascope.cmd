@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
  py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>nul
  if %errorlevel%==0 (
    py -3 "%~dp0deltascope.py" %*
    set "rc=%errorlevel%"
    goto :done
  )
)

where python >nul 2>nul
if %errorlevel%==0 (
  python -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>nul
  if %errorlevel%==0 (
    python "%~dp0deltascope.py" %*
    set "rc=%errorlevel%"
    goto :done
  )
)

echo.
echo DeltaScope requires Python 3.10 or newer.
echo Install Python 3.10+, then run this launcher again.
set "rc=2"

:done
if not "%rc%"=="0" (
  echo.
  echo DeltaScope exited with code %rc%.
  pause
)
exit /b %rc%
