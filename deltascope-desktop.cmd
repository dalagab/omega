@echo off
setlocal
cd /d "%~dp0"
if exist "%~dp0dist\DeltaScope.exe" (
  start "" "%~dp0dist\DeltaScope.exe" %*
  exit /b 0
)
where go >nul 2>nul
if not %errorlevel%==0 (
  echo DeltaScope Desktop binary is not built and Go is not available.
  echo Run desktop\build.ps1 on a development machine or use deltascope.cmd.
  exit /b 2
)
echo Developer fallback: go run uses this console. Run desktop\build.ps1 for the quiet desktop executable.
pushd "%~dp0desktop"
go run ./cmd/deltascope-desktop %*
set "rc=%errorlevel%"
popd
exit /b %rc%
