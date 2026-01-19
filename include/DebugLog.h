#ifndef DEBUG_LOG_H
#define DEBUG_LOG_H

#include <iostream>

#ifdef _DEBUG
#define LOG_DEBUG(msg) std::wcout << msg << std::endl
#define LOG_INFO(msg) std::wcout << L"[INFO] " << msg << std::endl
#define LOG_WARN(msg) std::wcout << L"[WARN] " << msg << std::endl
#define LOG_ERROR(msg) std::wcout << L"[ERROR] " << msg << std::endl
#define LOG_SUCCESS(msg) std::wcout << L"[OK] " << msg << std::endl
#define LOG_FAIL(msg) std::wcout << L"[FAIL] " << msg << std::endl
#else
#define LOG_DEBUG(msg) ((void)0)
#define LOG_INFO(msg) ((void)0)
#define LOG_WARN(msg) ((void)0)
#define LOG_ERROR(msg) ((void)0)
#define LOG_SUCCESS(msg) ((void)0)
#define LOG_FAIL(msg) ((void)0)
#endif

#endif // DEBUG_LOG_H
