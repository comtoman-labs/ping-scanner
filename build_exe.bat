@echo off
setlocal
cd /d "%~dp0"

rem ===== Settings =====
set "NAME=PingScanner"
set "PY="

if exist "D:\workspace\venv_pub\Scripts\python.exe" set "PY=D:\workspace\venv_pub\Scripts\python.exe"
if not defined PY if exist "D:\workspace\venv_com\Scripts\python.exe" set "PY=D:\workspace\venv_com\Scripts\python.exe"
if not defined PY if exist "venv\Scripts\python.exe" set "PY=venv\Scripts\python.exe"
if not defined PY set "PY=python"

echo ========================================================
echo   Ping Scanner - Building Standalone Single EXE File
echo ========================================================
echo.

echo [1/3] Using Python: %PY%
"%PY%" --version
if errorlevel 1 (
    echo [ERROR] Python not found.
    pause
    exit /b 1
)

echo.
echo [2/3] Checking PyInstaller...
"%PY%" -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo PyInstaller not found. Installing...
    "%PY%" -m pip install pyinstaller
    if errorlevel 1 (
        echo [ERROR] PyInstaller install failed.
        pause
        exit /b 1
    )
)

echo.
echo [3/3] Packaging single standalone EXE (--onefile)...
echo       This usually takes about 1-2 minutes. Please wait...
"%PY%" -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name "%NAME%" ^
    --icon "%~dp0icon.ico" --add-data "%~dp0icon.ico;." ^
    --distpath dist --workpath build --specpath build ^
    ping_scanner.py

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed.
    pause
    exit /b 1
)

echo.
echo ========================================================
echo [SUCCESS] Single standalone executable built successfully!
echo File location: dist\%NAME%.exe
echo ========================================================
echo (You can now deploy just this single file or upload it to GitHub Releases!)
echo ========================================================
echo.

if exist "%~dp0dist" (
    explorer.exe "%~dp0dist"
)

pause
exit /b 0
