#ifndef JITTER_SLEEP_H
#define JITTER_SLEEP_H

#include <windows.h>
#include <random>

inline void JitterSleep(DWORD milliseconds)
{
    if (milliseconds == 0)
    {
        return;
    }

    static thread_local std::mt19937 rng(
        static_cast<unsigned>(GetTickCount64() ^
                              reinterpret_cast<uintptr_t>(&milliseconds)));

    std::uniform_int_distribution<DWORD> dist(
        static_cast<DWORD>(milliseconds * 0.8),
        static_cast<DWORD>(milliseconds * 1.2));

    DWORD jitteredDelay = dist(rng);

    if (jitteredDelay > 60000)
    {
        jitteredDelay = 60000;
    }

    Sleep(jitteredDelay);
}

inline void ObfuscatedJitterSleep(DWORD milliseconds)
{
    if (milliseconds == 0)
    {
        return;
    }

    static thread_local std::mt19937 rng(
        static_cast<unsigned>(GetTickCount64() ^
                              reinterpret_cast<uintptr_t>(&milliseconds)));

    std::uniform_int_distribution<DWORD> dist(
        static_cast<DWORD>(milliseconds * 0.8),
        static_cast<DWORD>(milliseconds * 1.2));

    DWORD jitteredDelay = dist(rng);

    if (jitteredDelay > 60000)
    {
        jitteredDelay = 60000;
    }

    DWORD remaining = jitteredDelay;
    DWORD chunkSize = 100;
    volatile DWORD junkResult = 0;

    while (remaining > 0)
    {
        DWORD sleepTime = (remaining < chunkSize) ? remaining : chunkSize;
        Sleep(sleepTime);
        remaining -= sleepTime;

        for (int i = 0; i < 10; i++)
        {
            junkResult += GetTickCount() * (i + 1);
        }
    }
}

#endif // JITTER_SLEEP_H
