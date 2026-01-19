#ifndef IPCOBJECTS_FILE_H
#define IPCOBJECTS_FILE_H

#include <windows.h>
#include <string>
#include <sstream>
#include <vector>

using namespace std;

class MappedFile
{
private:
    HANDLE hMapFile;
    LPVOID pBuf;
    wstring name;
    DWORD size;
    bool valid;

public:
    MappedFile(const wstring &mapName, DWORD maxSize = 65536) : name(mapName), size(maxSize), valid(false)
    {
        hMapFile = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            NULL,
            PAGE_READWRITE,
            0,
            size,
            mapName.c_str());

        if (hMapFile == NULL)
        {
            hMapFile = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, mapName.c_str());
        }

        if (hMapFile != NULL)
        {
            pBuf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, size);
            if (pBuf != NULL)
            {
                valid = true;
            }
        }
    }

    ~MappedFile()
    {
        if (pBuf)
            UnmapViewOfFile(pBuf);
        if (hMapFile)
            CloseHandle(hMapFile);
    }

    bool isValid() const { return valid; }

    wstring getData() const
    {
        if (!valid)
            return L"";
        return wstring((wchar_t *)pBuf);
    }

    bool setData(const wstring &data)
    {
        if (!valid)
            return false;
        size_t dataSize = (data.length() + 1) * sizeof(wchar_t);
        if (dataSize > size)
            return false;

        ZeroMemory(pBuf, size);
        memcpy(pBuf, data.c_str(), dataSize);
        return true;
    }
};

class Serialitzator
{
public:
    static bool serializeVectorWString(const vector<wstring> &vec, const wstring &mapName)
    {
        wstringstream ss;
        for (const auto &str : vec)
        {
            ss << str << L"\n";
        }

        MappedFile mappedFile(mapName);
        return mappedFile.setData(ss.str());
    }

    static vector<wstring> deserializeVectorWString(const wstring &mapName)
    {
        vector<wstring> result;
        MappedFile mappedFile(mapName);

        if (!mappedFile.isValid())
            return result;

        wstring data = mappedFile.getData();
        wstringstream ss(data);
        wstring line;

        while (getline(ss, line))
        {
            if (!line.empty())
            {
                result.push_back(line);
            }
        }

        return result;
    }
};

inline vector<wstring> deserializeWStringVector(const wstring &mapName)
{
    return Serialitzator::deserializeVectorWString(mapName);
}

#endif // IPCOBJECTS_FILE_H
