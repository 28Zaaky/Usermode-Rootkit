# XvX Usermode Rootkit with C2

Windows usermode rootkit with privilege escalation, stealth capabilities, and remote C2 management.

## Features

**Core Capabilities:**
- Token stealing for NT AUTHORITY\SYSTEM privileges
- UAC bypass mechanisms
- Process/file/registry hiding via inline hooking
- Interactive SYSTEM reverse shell (TCP port 4444)
- DLL injection into target processes
- Real-time keylogger with C2 exfiltration

**Anti-Analysis:**
- VM detection (VMware, VirtualBox, QEMU)
- Debugger detection (PEB, NtQueryInformationProcess)
- Sandbox evasion techniques

**C2 Infrastructure:**
- Flask HTTPS server with web dashboard (port 8443)
- XOR encrypted C2 communications
- Agent registration and task queuing
- Real-time keylog viewer
- SQLite backend for persistence

## Requirements

- **Build:** Visual Studio 2022 (C++17)
- **C2 Server:** Python 3.x + Flask (`pip install flask`)
- **Target:** Windows 10/11 (tested on 10.0.26200)

## Usage

```powershell
# 1. Build rootkit
.\build.ps1

# 2. Start C2 server
python c2_server.py

# 3. Deploy rootkit.exe on target
# 4. Access dashboard: https://127.0.0.1:8443
```

## Architecture

```
rootkit.exe (main)
├── Token stealing → NT AUTHORITY\SYSTEM
├── C2Client → HTTPS beaconing (XOR encrypted)
├── Keylogger → Keystroke capture
├── AntiAnalysis → VM/debugger checks
└── DLL Injection
    ├── processHooks.dll → Process hiding
    ├── fileHooks.dll → File hiding
    └── registryHooks.dll → Registry hiding
```

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

Unauthorized access to computer systems is illegal. This software is provided for security research and authorized penetration testing only. The author assumes no liability for misuse. Use responsibly.

---

**Author:** [28Zaaky](https://github.com/28Zaaky)  
**Contact:** 28zaakypro@proton.me
