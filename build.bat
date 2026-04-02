@echo off
if not exist build mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
if errorlevel 1 (
    echo [ERROR] CMake configuration failed.
    pause
    exit /b 1
)
cmake --build . --config Release
if errorlevel 1 (
    echo [ERROR] Build failed.
    pause
    exit /b 1
)
echo.
echo BUILD SUCCESSFUL
echo Output: build\bin\Release\CDAnimCancel.asi
pause
