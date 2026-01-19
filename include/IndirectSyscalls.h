#ifndef INDIRECT_SYSCALLS_H
#define INDIRECT_SYSCALLS_H

#include <windows.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

typedef struct _SYSCALL_STATE
{
    PVOID FreshNtdll;
    DWORD NtdllSize;
    PVOID SyscallGadget;
    BOOL Initialized;
} SYSCALL_STATE;

typedef struct _SYSCALL_TABLE
{
    DWORD NtAllocateVirtualMemory;
    DWORD NtWriteVirtualMemory;
    DWORD NtProtectVirtualMemory;
    DWORD NtCreateThreadEx;
    DWORD NtOpenProcess;
    DWORD NtQuerySystemInformation;
    DWORD NtReadVirtualMemory;
    DWORD NtClose;
    DWORD NtGetContextThread;
    DWORD NtSetContextThread;
    DWORD NtSuspendThread;
    DWORD NtResumeThread;
} SYSCALL_TABLE;

extern "C" NTSTATUS DoSyscall(
    DWORD ssn,
    PVOID syscallGadget,
    PVOID arg1,
    PVOID arg2,
    PVOID arg3,
    PVOID arg4,
    PVOID arg5,
    PVOID arg6);

class IndirectSyscalls
{
private:
    static SYSCALL_STATE g_State;
    static SYSCALL_TABLE g_SSNs;

    static BOOL LoadFreshNtdll();
    static PVOID FindSyscallGadget(PVOID moduleBase);
    static PVOID GetFunctionAddress(PVOID moduleBase, const char *functionName);
    static DWORD ExtractSSN(PVOID functionAddress);

public:
    static BOOL Initialize();
    static void Cleanup();

    static NTSTATUS SysNtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect);

    static NTSTATUS SysNtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToWrite,
        PSIZE_T NumberOfBytesWritten);

    static NTSTATUS SysNtProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        PSIZE_T NumberOfBytesToProtect,
        ULONG NewAccessProtection,
        PULONG OldAccessProtection);

    static NTSTATUS SysNtCreateThreadEx(
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
        PVOID AttributeList);

    static NTSTATUS SysNtOpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        PVOID ObjectAttributes,
        PVOID ClientId);

    static NTSTATUS SysNtReadVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToRead,
        PSIZE_T NumberOfBytesRead);

    static NTSTATUS SysNtQuerySystemInformation(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength);

    static NTSTATUS SysNtClose(HANDLE Handle);

    static NTSTATUS SysNtGetContextThread(
        HANDLE ThreadHandle,
        PCONTEXT ThreadContext);

    static NTSTATUS SysNtSetContextThread(
        HANDLE ThreadHandle,
        PCONTEXT ThreadContext);

    static NTSTATUS SysNtSuspendThread(
        HANDLE ThreadHandle,
        PULONG PreviousSuspendCount);

    static NTSTATUS SysNtResumeThread(
        HANDLE ThreadHandle,
        PULONG PreviousSuspendCount);

    static BOOL IsInitialized() { return g_State.Initialized; }
};

#endif // INDIRECT_SYSCALLS_H
