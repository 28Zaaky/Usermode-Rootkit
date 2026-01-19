#ifndef HANDLE_WRAPPER_H
#define HANDLE_WRAPPER_H

#include <windows.h>
#include <memory>
#include <functional>

class HandleWrapper
{
private:
    HANDLE handle;
    bool ownsHandle;

public:
    HandleWrapper() : handle(nullptr), ownsHandle(false) {}

    explicit HandleWrapper(HANDLE h) : handle(h), ownsHandle(true)
    {
        if (h == INVALID_HANDLE_VALUE || h == NULL)
        {
            handle = nullptr;
            ownsHandle = false;
        }
    }

    HandleWrapper(const HandleWrapper &) = delete;
    HandleWrapper &operator=(const HandleWrapper &) = delete;

    HandleWrapper(HandleWrapper &&other) noexcept
        : handle(other.handle), ownsHandle(other.ownsHandle)
    {
        other.handle = nullptr;
        other.ownsHandle = false;
    }

    HandleWrapper &operator=(HandleWrapper &&other) noexcept
    {
        if (this != (HandleWrapper *)&other)
        {
            Close();
            handle = other.handle;
            ownsHandle = other.ownsHandle;
            other.handle = nullptr;
            other.ownsHandle = false;
        }
        return *this;
    }

    ~HandleWrapper()
    {
        Close();
    }

    void Close()
    {
        if (ownsHandle && handle)
        {
            CloseHandle(handle);
            handle = nullptr;
            ownsHandle = false;
        }
    }

    HANDLE Release()
    {
        HANDLE temp = handle;
        handle = nullptr;
        ownsHandle = false;
        return temp;
    }

    bool IsValid() const
    {
        return handle != nullptr && handle != INVALID_HANDLE_VALUE;
    }

    explicit operator bool() const
    {
        return IsValid();
    }

    HANDLE Get() const
    {
        return handle;
    }

    operator HANDLE() const
    {
        return handle;
    }

    HANDLE *operator&()
    {
        Close();
        ownsHandle = true;
        return &handle;
    }

    void Reset(HANDLE newHandle = nullptr)
    {
        Close();
        handle = newHandle;
        if (newHandle && newHandle != INVALID_HANDLE_VALUE)
        {
            ownsHandle = true;
        }
    }
};

class HInternetWrapper
{
private:
    HINTERNET handle;
    bool ownsHandle;

public:
    HInternetWrapper() : handle(nullptr), ownsHandle(false) {}

    explicit HInternetWrapper(HINTERNET h) : handle(h), ownsHandle(true)
    {
        if (h == NULL)
        {
            ownsHandle = false;
        }
    }

    ~HInternetWrapper()
    {
        Close();
    }

    HInternetWrapper(const HInternetWrapper &) = delete;
    HInternetWrapper &operator=(const HInternetWrapper &) = delete;

    HInternetWrapper(HInternetWrapper &&other) noexcept
        : handle(other.handle), ownsHandle(other.ownsHandle)
    {
        other.handle = nullptr;
        other.ownsHandle = false;
    }

    void Close()
    {
        if (ownsHandle && handle)
        {
            WinHttpCloseHandle(handle);
            handle = nullptr;
            ownsHandle = false;
        }
    }

    HINTERNET Release()
    {
        HINTERNET temp = handle;
        handle = nullptr;
        ownsHandle = false;
        return temp;
    }

    bool IsValid() const
    {
        return handle != nullptr;
    }

    explicit operator bool() const
    {
        return IsValid();
    }

    HINTERNET Get() const
    {
        return handle;
    }

    operator HINTERNET() const
    {
        return handle;
    }

    void Reset(HINTERNET newHandle = nullptr)
    {
        Close();
        handle = newHandle;
        if (newHandle)
        {
            ownsHandle = true;
        }
    }
};

#endif // HANDLE_WRAPPER_H
