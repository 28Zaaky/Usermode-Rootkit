#include "../include/IndirectSyscalls.h"
#include <windows.h>

// Convert NTSTATUS to Win32 error code
static DWORD NtStatusToWin32Error(NTSTATUS status)
{
    if (NT_SUCCESS(status))
        return ERROR_SUCCESS;

    switch ((ULONG)status)
    {
    case 0xC0000005:
        return ERROR_ACCESS_DENIED;
    case 0xC0000008:
        return ERROR_INVALID_HANDLE;
    case 0xC000000D:
        return ERROR_INVALID_PARAMETER;
    case 0xC0000022:
        return ERROR_ACCESS_DENIED;
    case 0xC0000024:
        return ERROR_GEN_FAILURE;
    default:
        return ERROR_GEN_FAILURE;
    }
}

// Wrapper for GetThreadContext redirects to NtGetContextThread syscall
extern "C" BOOL __wrap_GetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
{
    NTSTATUS status = IndirectSyscalls::SysNtGetContextThread(hThread, lpContext);
    if (NT_SUCCESS(status))
    {
        return TRUE;
    }
    SetLastError(NtStatusToWin32Error(status));
    return FALSE;
}

// Wrapper for SetThreadContext redirects to NtSetContextThread syscall
extern "C" BOOL __wrap_SetThreadContext(HANDLE hThread, CONST CONTEXT *lpContext)
{
    NTSTATUS status = IndirectSyscalls::SysNtSetContextThread(
        hThread,
        const_cast<CONTEXT *>(lpContext));
    if (NT_SUCCESS(status))
    {
        return TRUE;
    }
    SetLastError(NtStatusToWin32Error(status));
    return FALSE;
}

// Wrapper for SuspendThread redirects to NtSuspendThread syscall
extern "C" DWORD __wrap_SuspendThread(HANDLE hThread)
{
    ULONG previousCount = 0;
    NTSTATUS status = IndirectSyscalls::SysNtSuspendThread(hThread, &previousCount);

    if (NT_SUCCESS(status))
    {
        return (DWORD)previousCount;
    }
    SetLastError(NtStatusToWin32Error(status));
    return (DWORD)-1;
}

// Wrapper for ResumeThread redirects to NtResumeThread syscall
extern "C" DWORD __wrap_ResumeThread(HANDLE hThread)
{
    ULONG previousCount = 0;
    NTSTATUS status = IndirectSyscalls::SysNtResumeThread(hThread, &previousCount);

    if (NT_SUCCESS(status))
    {
        return (DWORD)previousCount;
    }
    SetLastError(NtStatusToWin32Error(status));
    return (DWORD)-1;
}