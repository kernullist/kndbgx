#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <string>

namespace knutil
{
inline std::wstring NewToken()
{
    unsigned char bytes[32] = {};
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
    {
        return {};
    }
    constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring text;
    text.reserve(64);
    for (const auto byte : bytes)
    {
        text += digits[byte >> 4];
        text += digits[byte & 15];
    }
    return text;
}
} // namespace knutil
