#include "../include/APIHashing.h"
#include <winternl.h>

// Static member initialization
HMODULE APIResolver::g_hKernel32 = NULL;
HMODULE APIResolver::g_hUser32 = NULL;
HMODULE APIResolver::g_hAdvapi32 = NULL;

// Calculate djb2 hash at runtime for API name
DWORD APIResolver::HashStringRuntime(const char *str)
{
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
    {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// Search module export table for function address by hash
FARPROC APIResolver::GetFunctionByHash(HMODULE hModule, DWORD functionHash)
{
    if (!hModule)
        return NULL;

    // Get DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }

    // Get NT headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE *)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }

    // Get export directory
    DWORD exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRva)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)hModule + exportDirRva);
    DWORD *addressOfFunctions = (DWORD *)((BYTE *)hModule + exportDir->AddressOfFunctions);
    DWORD *addressOfNames = (DWORD *)((BYTE *)hModule + exportDir->AddressOfNames);
    WORD *addressOfNameOrdinals = (WORD *)((BYTE *)hModule + exportDir->AddressOfNameOrdinals);

    // Iterate through exports
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
    {
        char *functionName = (char *)((BYTE *)hModule + addressOfNames[i]);

        // Hash and compare
        if (HashStringRuntime(functionName) == functionHash)
        {
            WORD ordinal = addressOfNameOrdinals[i];
            DWORD functionRva = addressOfFunctions[ordinal];
            return (FARPROC)((BYTE *)hModule + functionRva);
        }
    }

    return NULL;
}

// Load required DLLs with minimal IAT footprint
BOOL APIResolver::Initialize()
{
    // Get kernel32.dll
    g_hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!g_hKernel32)
        return FALSE;

    // Load user32.dll if needed
    typedef HMODULE(WINAPI * pLoadLibraryA)(LPCSTR);
    pLoadLibraryA fnLoadLibraryA = (pLoadLibraryA)GetFunctionByHash(g_hKernel32, APIHash::LoadLibraryA);
    if (!fnLoadLibraryA)
        return FALSE;

    g_hUser32 = fnLoadLibraryA("user32.dll");
    g_hAdvapi32 = fnLoadLibraryA("advapi32.dll");

    return TRUE;
}

// Resolve API function address by hash from loaded DLLs
FARPROC APIResolver::ResolveAPI(DWORD apiHash)
{
    FARPROC result = NULL;

    // Try kernel32.dll first (most common)
    if (g_hKernel32)
    {
        result = GetFunctionByHash(g_hKernel32, apiHash);
        if (result)
            return result;
    }

    // Try user32.dll
    if (g_hUser32)
    {
        result = GetFunctionByHash(g_hUser32, apiHash);
        if (result)
            return result;
    }

    // Try advapi32.dll
    if (g_hAdvapi32)
    {
        result = GetFunctionByHash(g_hAdvapi32, apiHash);
        if (result)
            return result;
    }

    return NULL;
}
