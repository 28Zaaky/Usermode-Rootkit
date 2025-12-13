# Usermode Rootkit with C2

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

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

Unauthorized access to computer systems is illegal. This software is provided for security research and authorized penetration testing only. The author assumes no liability for misuse. Use responsibly.

**Contact:** 28zaakypro@proton.me
