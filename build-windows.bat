@echo off
setlocal enabledelayedexpansion

REM Set up Visual Studio environment
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1

REM Configure build variables based on BUILD_TARGET
if "%BUILD_TARGET%"=="client" (
    set BUILD_CLIENT=ON
    set BUILD_SERVER=OFF
    set INSTALL_PREFIX=C:/output/client/windows
) else if "%BUILD_TARGET%"=="server" (
    set BUILD_CLIENT=OFF
    set BUILD_SERVER=ON
    set INSTALL_PREFIX=C:/output/server/windows
) else (
    set BUILD_CLIENT=ON
    set BUILD_SERVER=ON
    set INSTALL_PREFIX=C:/output/windows
)

REM Run CMake configure
cmake -B build-windows -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release -DBUILD_CLIENT=%BUILD_CLIENT% -DBUILD_SERVER=%BUILD_SERVER% -DBUILD_SHARED_LIBS=ON -DBUILD_DOTNET_INTEROP=ON -DBUILD_TESTS=ON -DENABLE_HARDENING=ON -DCMAKE_INSTALL_PREFIX=%INSTALL_PREFIX%
if errorlevel 1 exit /b 1

REM Build
cmake --build build-windows --config Release
if errorlevel 1 exit /b 1

REM Test
ctest --test-dir build-windows --output-on-failure -C Release
if errorlevel 1 exit /b 1

REM Install
cmake --install build-windows --config Release
if errorlevel 1 exit /b 1

endlocal
