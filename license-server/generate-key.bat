@echo off
setlocal
cd /d "%~dp0"
set "LICENSE_SERVER_URL=https://arinjay01.pythonanywhere.com"
set "LICENSE_ADMIN_TOKEN="

echo ========================================
echo VNM License Generator
echo ========================================
echo Server: %LICENSE_SERVER_URL%
echo.

where py >nul 2>&1
if %errorlevel%==0 (
  py generate_key.py
  goto :end
)
where python >nul 2>&1
if %errorlevel%==0 (
  python generate_key.py
  goto :end
)

echo Python is not installed or not in PATH.
:end
echo.
pause
