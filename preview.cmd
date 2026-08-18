@echo off
call npm run build
if errorlevel 1 exit /b %errorlevel%
echo.
echo Omega preview is available at http://localhost:4173
echo Keep this window open while previewing. Press Ctrl+C to stop it.
call npm run preview
