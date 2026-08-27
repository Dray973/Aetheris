@echo off
REM ============================================================
REM  Aetheris Quantum Core - one-click installer
REM  Double-click this file. It runs the PowerShell installer,
REM  which ensures Python, downloads all dependencies, installs
REM  the program, and creates shortcuts.
REM ============================================================
title Aetheris Quantum Core - Installer

echo.
echo   Launching the Aetheris Quantum Core installer...
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
set RC=%ERRORLEVEL%

echo.
if "%RC%"=="0" (
    echo   Installation finished successfully.
) else (
    echo   Installation exited with code %RC%.
    echo   See the messages above for details.
)
echo.
pause
