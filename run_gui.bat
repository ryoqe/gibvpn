@echo off
cd /d "%~dp0"
set "PYTHON=%~dp0venv\Scripts\python.exe"
if not exist "%PYTHON%" set "PYTHON=python"
"%PYTHON%" gui.py
if errorlevel 1 pause
