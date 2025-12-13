# Advanced Windows Rootkit with C2 Framework

A sophisticated usermode rootkit featuring EDR bypass techniques, privilege escalation, and a professional web-based Command & Control dashboard.

## Features

- **EDR Bypass**: Indirect syscalls, NTDLL unhooking, ETW/AMSI bypass
- **Privilege Escalation**: Token stealing for SYSTEM access
- **Keylogger**: Real-time keystroke capture and exfiltration
- **Interactive SYSTEM Shell**: Reverse shell with SYSTEM privileges
- **Professional C2 Dashboard**: Modern web interface for agent management

## Quick Start

### Prerequisites
- Visual Studio 2022 (C++17)
- Python 3.x
- Flask: `pip install flask`

### Build & Run

```powershell
# Build the rootkit
.\build_debug_complete.ps1

# Start C2 server
python c2_server.py
```

Access dashboard at: `https://127.0.0.1:8443`

## ⚠️ DISCLAIMER

**FOR EDUCATIONAL PURPOSES ONLY**

This project is intended for authorized security research and educational purposes only. Unauthorized access to computer systems is illegal. The author assumes no liability for misuse of this software. Use only in controlled, authorized testing environments.

---

Created by [28Zaaky](https://github.com/28Zaaky)
