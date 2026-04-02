@echo off
:: Guard State Scanner — finds the "is guard allowed?" flag
:: Run as Administrator while the game is running.

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

echo Compiling GuardStateScanner...
"%CSC%" /nologo /optimize /platform:x64 /out:GuardStateScanner.exe GuardStateScanner.cs
if errorlevel 1 (
    echo Compilation failed.
    pause
    exit /b 1
)

echo Starting scanner...
powershell -Command "Start-Process -FilePath '.\GuardStateScanner.exe' -Verb RunAs"
