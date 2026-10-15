@echo off
setlocal
title Building Inkwell Tactical DLL Injector
echo [INKWELL] Initializing build environment...

set CSC_PATH=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe

if not exist "%CSC_PATH%" (
    echo [ERROR] csc.exe compiler not found at %CSC_PATH%
    pause
    exit /b 1
)

echo [INKWELL] Compiling InkwellInjector.cs (Platform: x64, Subsystem: Windows)...
"%CSC_PATH%" /target:winexe /platform:x64 /optimize+ /out:"%~dp0InkwellInjector.exe" "%~dp0InkwellInjector.cs"

if %ERRORLEVEL% equ 0 (
    echo.
    echo =======================================================
    echo [INKWELL] BUILD SUCCESS: InkwellInjector.exe generated!
    echo =======================================================
    echo.
) else (
    echo.
    echo [ERROR] Compilation failed with error code %ERRORLEVEL%.
    echo.
)

endlocal
pause
