@echo off
setlocal
cd /d "%~dp0"

rem 1. Check virtual environments
set "PY="
if exist "D:\workspace\venv_pub\Scripts\pythonw.exe" set "PY=D:\workspace\venv_pub\Scripts\pythonw.exe"
if not defined PY if exist "D:\workspace\venv_com\Scripts\pythonw.exe" set "PY=D:\workspace\venv_com\Scripts\pythonw.exe"
if not defined PY if exist "venv\Scripts\pythonw.exe" set "PY=venv\Scripts\pythonw.exe"
if not defined PY if exist ".venv\Scripts\pythonw.exe" set "PY=.venv\Scripts\pythonw.exe"

rem 2. Fallback to python.exe
if not defined PY if exist "D:\workspace\venv_pub\Scripts\python.exe" set "PY=D:\workspace\venv_pub\Scripts\python.exe"
if not defined PY if exist "D:\workspace\venv_com\Scripts\python.exe" set "PY=D:\workspace\venv_com\Scripts\python.exe"
if not defined PY set "PY=python"

start "" "%PY%" ping_scanner.py
exit /b 0
