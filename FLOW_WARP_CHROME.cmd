@echo off
set "FLOW_PWSH=pwsh.exe"
where pwsh.exe >nul 2>nul
if errorlevel 1 (
    set "FLOW_PWSH=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\powershell\pwsh.exe"
)
"%FLOW_PWSH%" -NoProfile -File "%~dp0FLOW_WARP_CHROME.ps1"
if errorlevel 1 pause
