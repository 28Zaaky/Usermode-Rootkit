#ifndef DLLINJECTOR_H
#define DLLINJECTOR_H

#include <windows.h>

DWORD getPIDbyProcName(const char *processName);
bool injectDLL(const wchar_t *dllPath, DWORD targetPID);
bool isDLLLoaded(DWORD targetPID, const wchar_t *dllName);

#endif // DLLINJECTOR_H