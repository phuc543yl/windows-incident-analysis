@echo off
setlocal
cd /d "%~dp0.."
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" "%~dp0run_sample.py" --root "%cd%"
) else (
  python "%~dp0run_sample.py" --root "%cd%"
)
set "SAMPLE_EXIT=%ERRORLEVEL%"
echo.
echo Sample runner exit code: %SAMPLE_EXIT%
pause
exit /b %SAMPLE_EXIT%
