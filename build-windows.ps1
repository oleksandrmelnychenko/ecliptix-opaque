$ErrorActionPreference = 'Stop'

Write-Host "Setting up Visual Studio environment..."

# Import Visual Studio environment variables
$vsPath = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cmd /c "`"$vsPath`" && set" | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') {
        [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2])
    }
}

Write-Host "Visual Studio environment configured successfully"

# Configure build variables based on BUILD_TARGET
if ($env:BUILD_TARGET -eq 'client') {
    $env:BUILD_CLIENT = 'ON'
    $env:BUILD_SERVER = 'OFF'
    $env:INSTALL_PREFIX = 'C:/output/client/windows'
} elseif ($env:BUILD_TARGET -eq 'server') {
    $env:BUILD_CLIENT = 'OFF'
    $env:BUILD_SERVER = 'ON'
    $env:INSTALL_PREFIX = 'C:/output/server/windows'
} else {
    $env:BUILD_CLIENT = 'ON'
    $env:BUILD_SERVER = 'ON'
    $env:INSTALL_PREFIX = 'C:/output/windows'
}

Write-Host "Build configuration:"
Write-Host "  BUILD_CLIENT: $env:BUILD_CLIENT"
Write-Host "  BUILD_SERVER: $env:BUILD_SERVER"
Write-Host "  INSTALL_PREFIX: $env:INSTALL_PREFIX"

# Run CMake configure
Write-Host "`nConfiguring with CMake..."
cmake -B build-windows -G "Visual Studio 17 2022" -A x64 `
    -DCMAKE_BUILD_TYPE=Release `
    -DBUILD_CLIENT=$env:BUILD_CLIENT `
    -DBUILD_SERVER=$env:BUILD_SERVER `
    -DBUILD_SHARED_LIBS=ON `
    -DBUILD_DOTNET_INTEROP=ON `
    -DBUILD_TESTS=ON `
    -DENABLE_HARDENING=ON `
    -DCMAKE_INSTALL_PREFIX=$env:INSTALL_PREFIX

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Build
Write-Host "`nBuilding..."
cmake --build build-windows --config Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Test
Write-Host "`nRunning tests..."
ctest --test-dir build-windows --output-on-failure -C Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Install
Write-Host "`nInstalling..."
cmake --install build-windows --config Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`nBuild completed successfully!"
