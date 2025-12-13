# Usermode Rootkit with C2

![C2 screenshot](https://github.com/28Zaaky/Usermode-Rootkit/blob/82292f2a6d0c4f46ad9b3db686fc275e6ce17589/Capture%20d'%C3%A9cran%202025-12-12%20173844.png)

Windows usermode rootkit with privilege escalation, stealth capabilities, and remote C2 management.

> **Educational Use Only**  
> This repository contains a **proof-of-concept** of usermode rootkits techniques for research and defensive learning purposes:
>
> Running or modifying this code on machines you do not own or without explicit written authorization is **illegal and unethical**.  
> This project is for **research, learning, and defense development** only.

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
