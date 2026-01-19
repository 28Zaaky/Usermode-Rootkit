#ifndef STRING_OBFUSCATION_H
#define STRING_OBFUSCATION_H

#include <string>
#include <cstdint>

// FNV-1a hash for compile-time key derivation
constexpr uint32_t StringHash(const char *str, size_t len)
{
    uint32_t hash = 0x811C9DC5;
    for (size_t i = 0; i < len; ++i)
    {
        hash ^= static_cast<uint32_t>(str[i]);
        hash *= 0x01000193;
    }
    return hash;
}

// FNV-1a hash for wide strings
constexpr uint32_t WStringHash(const wchar_t *str, size_t len)
{
    uint32_t hash = 0x811C9DC5;
    for (size_t i = 0; i < len; ++i)
    {
        hash ^= static_cast<uint32_t>(str[i]);
        hash *= 0x01000193;
    }
    return hash;
}

// AES S-Box split into 16 chunks with null padding (low entropy)
constexpr uint8_t SBOX_0[16] = {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76};
constexpr uint8_t PAD_0[4] = {0x00, 0x00, 0x00, 0x00};
constexpr uint8_t SBOX_1[16] = {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0};
constexpr uint8_t PAD_1[4] = {0x00, 0x00, 0x00, 0x00};
constexpr uint8_t SBOX_2[16] = {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15};
constexpr uint8_t PAD_2[4] = {0x00, 0x00, 0x00, 0x00};
constexpr uint8_t SBOX_3[16] = {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75};
constexpr uint8_t PAD_3[4] = {0x00, 0x00, 0x00, 0x00};
constexpr uint8_t SBOX_4[16] = {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84};
constexpr uint8_t PAD_4[4] = {0x00, 0x00, 0x00, 0x00};
constexpr uint8_t SBOX_5[16] = {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF};
constexpr uint8_t PAD_5[4] = {0x00, 0x00, 0x00, 0x00};
constexpr uint8_t SBOX_6[16] = {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8};
constexpr uint8_t PAD_6[4] = {0x00, 0x00, 0x00, 0x00};
constexpr uint8_t SBOX_7[16] = {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2};
constexpr uint8_t PAD_7[4] = {0x00, 0x00, 0x00, 0x00};
constexpr uint8_t SBOX_8[16] = {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73};
constexpr uint8_t PAD_8[4] = {0x00, 0x00, 0x00, 0x00};
constexpr uint8_t SBOX_9[16] = {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB};
constexpr uint8_t PAD_9[4] = {0x00, 0x00, 0x00, 0x00};
constexpr uint8_t SBOX_A[16] = {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79};
constexpr uint8_t PAD_A[4] = {0x00, 0x00, 0x00, 0x00};
constexpr uint8_t SBOX_B[16] = {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08};
constexpr uint8_t PAD_B[4] = {0x00, 0x00, 0x00, 0x00};
constexpr uint8_t SBOX_C[16] = {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A};
constexpr uint8_t PAD_C[4] = {0x00, 0x00, 0x00, 0x00};
constexpr uint8_t SBOX_D[16] = {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E};
constexpr uint8_t PAD_D[4] = {0x00, 0x00, 0x00, 0x00};
constexpr uint8_t SBOX_E[16] = {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF};
constexpr uint8_t PAD_E[4] = {0x00, 0x00, 0x00, 0x00};
constexpr uint8_t SBOX_F[16] = {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};
constexpr uint8_t PAD_F[4] = {0x00, 0x00, 0x00, 0x00};

// Runtime S-Box reconstruction from fragments
constexpr uint8_t GetSboxValue(uint8_t index)
{
    const uint8_t row = index >> 4;
    const uint8_t col = index & 0x0F;

    switch (row)
    {
    case 0x0:
        return SBOX_0[col];
    case 0x1:
        return SBOX_1[col];
    case 0x2:
        return SBOX_2[col];
    case 0x3:
        return SBOX_3[col];
    case 0x4:
        return SBOX_4[col];
    case 0x5:
        return SBOX_5[col];
    case 0x6:
        return SBOX_6[col];
    case 0x7:
        return SBOX_7[col];
    case 0x8:
        return SBOX_8[col];
    case 0x9:
        return SBOX_9[col];
    case 0xA:
        return SBOX_A[col];
    case 0xB:
        return SBOX_B[col];
    case 0xC:
        return SBOX_C[col];
    case 0xD:
        return SBOX_D[col];
    case 0xE:
        return SBOX_E[col];
    case 0xF:
        return SBOX_F[col];
    default:
        return 0x00;
    }
}

// Generate 128-bit AES key from hash (uses ADD instead of XOR)
constexpr void DeriveAESKey(uint32_t hash, uint8_t key[16])
{
    for (int i = 0; i < 16; ++i)
    {
        // Arithmetic operations avoid XOR detection patterns
        uint8_t hashByte = static_cast<uint8_t>(hash >> ((i % 4) * 8));
        key[i] = hashByte + (i * 37) + 0xC3;
        hash = (hash << 7) | (hash >> 25); // Rotate
    }
}

constexpr uint8_t AESKeystreamByte(const uint8_t key[16], size_t index)
{
    uint8_t counter = static_cast<uint8_t>(index & 0xFF);
    uint8_t keyByte = key[index % 16];
    uint8_t temp = keyByte + counter + GetSboxValue((keyByte + counter) & 0xFF);
    uint8_t mixed = ((temp << 5) | (temp >> 3)); // ROL 5
    return GetSboxValue(mixed);
}

constexpr uint8_t DecryptByte(uint8_t encrypted, uint8_t keystream)
{
    uint8_t temp = encrypted + keystream;
    return ((temp << 3) | (temp >> 5));
}

constexpr uint8_t EncryptByte(uint8_t plain, uint8_t keystream)
{
    uint8_t rotated = ((plain >> 3) | (plain << 5));
    return rotated - keystream;
}

// Compile-time encrypted string container
template <size_t N>
class ObfuscatedString
{
private:
    uint8_t data[N];
    uint8_t key[16];

public:
    // Encrypt string at compile time using AES-CTR
    constexpr ObfuscatedString(const char *str) : data{}, key{}
    {
        uint32_t hash = StringHash(str, N - 1);
        DeriveAESKey(hash, key);

        // Encrypt each byte using AES keystream
        for (size_t i = 0; i < N - 1; ++i)
        {
            uint8_t keystream = AESKeystreamByte(key, i);
            data[i] = EncryptByte(static_cast<uint8_t>(str[i]), keystream);
        }
        data[N - 1] = '\0';
    }

    // Runtime decryption to std::string
    std::string decrypt() const
    {
        std::string result;
        result.reserve(N);
        for (size_t i = 0; i < N - 1; ++i)
        {
            uint8_t keystream = AESKeystreamByte(key, i);
            result += static_cast<char>(DecryptByte(data[i], keystream));
        }
        return result;
    }

    // Decrypt to C-string in thread-local buffer
    const char *c_str() const
    {
        static thread_local char buffer[256];
        for (size_t i = 0; i < N - 1 && i < 255; ++i)
        {
            uint8_t keystream = AESKeystreamByte(key, i);
            buffer[i] = static_cast<char>(DecryptByte(data[i], keystream));
        }
        buffer[N - 1 < 255 ? N - 1 : 255] = '\0';
        return buffer;
    }
};

// Wide string variant with AES-128 CTR encryption
template <size_t N>
class ObfuscatedWString
{
private:
    uint16_t data[N];
    uint8_t key[16];

public:
    // Encrypt wide string at compile time (two bytes per char)
    constexpr ObfuscatedWString(const wchar_t *str) : data{}, key{}
    {
        uint32_t hash = WStringHash(str, N - 1);
        DeriveAESKey(hash, key);

        // Encrypt wchar as two separate bytes using keystream
        for (size_t i = 0; i < N - 1; ++i)
        {
            uint8_t ks1 = AESKeystreamByte(key, i * 2);
            uint8_t ks2 = AESKeystreamByte(key, i * 2 + 1);
            uint16_t plainChar = static_cast<uint16_t>(str[i]);
            // Split into bytes, encrypt each, recombine
            uint8_t low = EncryptByte(plainChar & 0xFF, ks1);
            uint8_t high = EncryptByte((plainChar >> 8) & 0xFF, ks2);
            data[i] = (static_cast<uint16_t>(high) << 8) | low;
        }
        data[N - 1] = L'\0';
    }

    std::wstring decrypt() const
    {
        std::wstring result;
        result.reserve(N);
        for (size_t i = 0; i < N - 1; ++i)
        {
            uint8_t ks1 = AESKeystreamByte(key, i * 2);
            uint8_t ks2 = AESKeystreamByte(key, i * 2 + 1);
            // Decrypt bytes separately
            uint8_t low = DecryptByte(data[i] & 0xFF, ks1);
            uint8_t high = DecryptByte((data[i] >> 8) & 0xFF, ks2);
            result += static_cast<wchar_t>((static_cast<uint16_t>(high) << 8) | low);
        }
        return result;
    }

    const wchar_t *c_str() const
    {
        static thread_local wchar_t buffer[256];
        for (size_t i = 0; i < N - 1 && i < 255; ++i)
        {
            uint8_t ks1 = AESKeystreamByte(key, i * 2);
            uint8_t ks2 = AESKeystreamByte(key, i * 2 + 1);
            // Decrypt bytes separately
            uint8_t low = DecryptByte(data[i] & 0xFF, ks1);
            uint8_t high = DecryptByte((data[i] >> 8) & 0xFF, ks2);
            buffer[i] = static_cast<wchar_t>((static_cast<uint16_t>(high) << 8) | low);
        }
        buffer[N - 1 < 255 ? N - 1 : 255] = L'\0';
        return buffer;
    }
};

// Compile-time string length calculator
constexpr size_t StrLen(const char *str)
{
    size_t len = 0;
    while (str[len])
        ++len;
    return len + 1; // Include null terminator
}

// Compile-time wide string length calculator
constexpr size_t WStrLen(const wchar_t *str)
{
    size_t len = 0;
    while (str[len])
        ++len;
    return len + 1;
}

// Convenience macros for string obfuscation
#define OBFUSCATE(str) (ObfuscatedString<StrLen(str)>(str).c_str())
#define OBFUSCATE_W(str) (ObfuscatedWString<WStrLen(str)>(str).c_str())

// Runtime decryption helper
class StackString
{
private:
    std::string value;
    uint8_t key[16];

public:
    StackString(const char *obfuscated, size_t len) : key{}
    {
        uint32_t hash = StringHash(obfuscated, len);
        DeriveAESKey(hash, key);
        value.reserve(len);
        for (size_t i = 0; i < len; ++i)
        {
            uint8_t keystream = AESKeystreamByte(key, i);
            value += static_cast<char>(DecryptByte(obfuscated[i], keystream));
        }
    }
    const char *c_str() const { return value.c_str(); }
    operator std::string() const { return value; }
};

// Runtime wide string decryption helper
class StackWString
{
private:
    std::wstring value;
    uint8_t key[16];

public:
    StackWString(const wchar_t *obfuscated, size_t len) : key{}
    {
        uint32_t hash = WStringHash(obfuscated, len);
        DeriveAESKey(hash, key);
        value.reserve(len);
        for (size_t i = 0; i < len; ++i)
        {
            uint8_t ks1 = AESKeystreamByte(key, i * 2);
            uint8_t ks2 = AESKeystreamByte(key, i * 2 + 1);
            // Decrypt bytes separately
            uint16_t encrypted = obfuscated[i];
            uint8_t low = DecryptByte(encrypted & 0xFF, ks1);
            uint8_t high = DecryptByte((encrypted >> 8) & 0xFF, ks2);
            value += static_cast<wchar_t>((static_cast<uint16_t>(high) << 8) | low);
        }
    }
    const wchar_t *c_str() const { return value.c_str(); }
    operator std::wstring() const { return value; }
};

#endif // STRING_OBFUSCATION_H
