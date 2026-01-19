#include "../include/DLLInjector.h"
#include "../include/IndirectSyscalls.h"
#include "../include/APIHashing.h"
#include <tlhelp32.h>
#include <iostream>

using namespace std;

DWORD getPIDbyProcName(const char *processName)
{
    DWORD pid = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
#ifdef _DEBUG
        wcout << L"[ERROR] CreateToolhelp32Snapshot failed" << endl;
#endif
        return 0;
    }

    PROCESSENTRY32W pe32 = {0};
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32))
    {
        do
        {
            wchar_t procNameW[MAX_PATH];
            MultiByteToWideChar(CP_ACP, 0, processName, -1, procNameW, MAX_PATH);

            if (_wcsicmp(pe32.szExeFile, procNameW) == 0)
            {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

#ifdef _DEBUG
    if (pid == 0)
    {
        wcout << L"[WARN] Process not found: " << processName << endl;
    }
    else
    {
        wcout << L"[INFO] Found " << processName << L" PID: " << pid << endl;
    }
#endif

    return pid;
}

// Inject DLL into remote process via CreateRemoteThread + LoadLibraryW
bool injectDLL(const wchar_t *dllPath, DWORD targetPID)
{
    if (targetPID == 0)
    {
#ifdef _DEBUG
        wcout << L"[ERROR] Invalid PID (0)" << endl;
#endif
        return false;
    }

    auto fnOpenProcess = OpenProcess;
    auto fnVirtualAllocEx = VirtualAllocEx;
    auto fnWriteProcessMemory = WriteProcessMemory;
    auto fnCreateRemoteThread = CreateRemoteThread;
    auto fnWaitForSingleObject = WaitForSingleObject;
    auto fnVirtualFreeEx = VirtualFreeEx;
    auto fnGetProcAddress = GetProcAddress;
    auto fnGetModuleHandle = GetModuleHandleA;

    // 1. Open target process
    HANDLE hProcess = fnOpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, targetPID);

    if (!hProcess)
    {
#ifdef _DEBUG
        wcout << L"[ERROR] OpenProcess failed for PID " << targetPID
              << L" (Error: " << GetLastError() << L")" << endl;
#endif
        return false;
    }

    bool success = false;
    LPVOID pRemoteMemory = NULL;
    HANDLE hThread = NULL;

    // 2. Allocate memory in target process
    size_t dllPathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    SIZE_T bytesWritten = 0;
    HMODULE hKernel32 = NULL;
    LPVOID pLoadLibraryW = NULL;

    pRemoteMemory = fnVirtualAllocEx(hProcess, NULL, dllPathSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!pRemoteMemory)
    {
#ifdef _DEBUG
        wcout << L"[ERROR] VirtualAllocEx failed (Error: " << GetLastError() << L")" << endl;
#endif
        goto cleanup;
    }

    // 3. Write DLL path to target process
    if (!fnWriteProcessMemory(hProcess, pRemoteMemory, dllPath, dllPathSize, &bytesWritten))
    {
#ifdef _DEBUG
        wcout << L"[ERROR] WriteProcessMemory failed (Error: " << GetLastError() << L")" << endl;
#endif
        goto cleanup;
    }

    // 4. Get LoadLibraryW address
    hKernel32 = fnGetModuleHandle("kernel32.dll");
    if (!hKernel32)
    {
#ifdef _DEBUG
        wcout << L"[ERROR] GetModuleHandle(kernel32) failed" << endl;
#endif
        goto cleanup;
    }

    pLoadLibraryW = (LPVOID)fnGetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibraryW)
    {
#ifdef _DEBUG
        wcout << L"[ERROR] GetProcAddress(LoadLibraryW) failed" << endl;
#endif
        goto cleanup;
    }

    // 5. Create remote thread to call LoadLibraryW
    hThread = fnCreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryW,
        pRemoteMemory, 0, NULL);

    if (!hThread)
    {
#ifdef _DEBUG
        wcout << L"[ERROR] CreateRemoteThread failed (Error: " << GetLastError() << L")" << endl;
#endif
        goto cleanup;
    }

    // 6. Wait for LoadLibraryW to complete
    fnWaitForSingleObject(hThread, 5000); // 5 second timeout

#ifdef _DEBUG
    wcout << L"[SUCCESS] DLL injected: " << dllPath << L" -> PID " << targetPID << endl;
#endif

    success = true;

cleanup:
    if (hThread)
        CloseHandle(hThread);
    if (pRemoteMemory)
        fnVirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    if (hProcess)
        CloseHandle(hProcess);

    return success;
}

// Check if DLL is already loaded in target process
bool isDLLLoaded(DWORD targetPID, const wchar_t *dllName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, targetPID);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return false;

    MODULEENTRY32W me32 = {0};
    me32.dwSize = sizeof(MODULEENTRY32W);

    bool found = false;
    if (Module32FirstW(hSnapshot, &me32))
    {
        do
        {
            if (_wcsicmp(me32.szModule, dllName) == 0)
            {
                found = true;
                break;
            }
        } while (Module32NextW(hSnapshot, &me32));
    }

    CloseHandle(hSnapshot);
    return found;
}