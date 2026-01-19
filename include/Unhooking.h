#ifndef UNHOOKING_H
#define UNHOOKING_H

#include <windows.h>
#include <string>

using namespace std;

typedef struct _UNHOOK_RESULT
{
    BOOL success;
    DWORD hooksFound;
    DWORD hooksRemoved;
    SIZE_T bytesRestored;
} UNHOOK_RESULT;

class NTDLLUnhooker
{
private:
    static PVOID LoadFreshNTDLL();
    static BOOL FindTextSection(PVOID moduleBase, PVOID *textStart, SIZE_T *textSize);
    static BOOL RestoreTextSection(PVOID hookedNtdll, PVOID freshNtdll);

public:
    static BOOL UnhookNTDLL(UNHOOK_RESULT *result);
};

#endif // UNHOOKING_H
