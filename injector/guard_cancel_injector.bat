@echo off
:: Guard Cancel Injector — hold LB during attacks to guard-cancel
:: Run as Administrator while the game is running.
:: Press F8 to stop and restore original code.

cd /d "%~dp0"

set CSC=
for /f "delims=" %%i in ('where csc.exe 2^>nul') do set CSC=%%i
if "%CSC%"=="" (
    set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
)
if not exist "%CSC%" (
    echo ERROR: Cannot find csc.exe
    pause
    exit /b 1
)

echo Compiling GuardCancelInjector...
"%CSC%" /nologo /optimize /platform:x64 /out:GuardCancelInjector.exe GuardCancelInjector.cs
if errorlevel 1 (
    echo Compilation failed.
    pause
    exit /b 1
)

echo Starting injector...
powershell -Command "Start-Process -FilePath '.\GuardCancelInjector.exe' -Verb RunAs"
