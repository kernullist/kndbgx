#pragma once

#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <vector>

namespace kncore
{
inline bool ValidUtf16(std::wstring_view text, bool allowNull = true)
{
    bool high = false;
    for (const wchar_t unit : text)
    {
        if ((!allowNull && unit == 0) || (high && (unit < 0xdc00 || unit > 0xdfff)) || (!high && unit >= 0xdc00 && unit <= 0xdfff))
        {
            return false;
        }
        high = !high && unit >= 0xd800 && unit <= 0xdbff;
    }
    return !high;
}

inline bool ParseUnsigned(std::wstring_view text, unsigned base, uint64_t *out)
{
    bool ok = false;
    do
    {
        if (out == nullptr || text.empty() || (base != 10 && base != 16))
        {
            break;
        }
        if (text.starts_with(L"0x") || text.starts_with(L"0X"))
        {
            base = 16;
            text.remove_prefix(2);
        }
        else if (text.starts_with(L"0n") || text.starts_with(L"0N"))
        {
            base = 10;
            text.remove_prefix(2);
        }
        if (text.empty())
        {
            break;
        }
        uint64_t value = 0;
        bool valid = true;
        for (const wchar_t ch : text)
        {
            const unsigned digit = ch >= L'0' && ch <= L'9'   ? ch - L'0'
                                   : ch >= L'a' && ch <= L'f' ? ch - L'a' + 10
                                   : ch >= L'A' && ch <= L'F' ? ch - L'A' + 10
                                                              : 255;
            if (digit >= base || value > (UINT64_MAX - digit) / base)
            {
                valid = false;
                break;
            }
            value = value * base + digit;
        }
        if (valid)
        {
            *out = value;
            ok = true;
        }
    } while (false);
    return ok;
}

inline bool ValidRange(uint64_t address, uint64_t length)
{
    return length > 0 && length - 1 <= UINT64_MAX - address;
}

inline bool FillChunk(std::span<const unsigned char> pattern, uint64_t produced, std::span<unsigned char> output)
{
    if (pattern.empty() || pattern.size() > 65536 || output.size() > 1024 * 1024)
    {
        return false;
    }
    size_t phase = static_cast<size_t>(produced % pattern.size());
    for (unsigned char &byte : output)
    {
        byte = pattern[phase];
        phase = (phase + 1) % pattern.size();
    }
    return true;
}

inline bool PlanValues(uint64_t address, unsigned width, std::span<const uint64_t> values, std::vector<unsigned char> *out)
{
    bool ok = false;
    do
    {
        if (out == nullptr || (width != 1 && width != 2 && width != 4 && width != 8) || values.empty() ||
            values.size() > (1024 * 1024) / width || !ValidRange(address, values.size() * width))
        {
            break;
        }
        const uint64_t maximum = width == 8 ? UINT64_MAX : (uint64_t(1) << (width * 8)) - 1;
        bool valid = true;
        for (const uint64_t value : values)
        {
            if (value > maximum)
            {
                valid = false;
                break;
            }
        }
        if (!valid)
        {
            break;
        }
        std::vector<unsigned char> bytes;
        bytes.reserve(values.size() * width);
        for (const uint64_t value : values)
        {
            for (unsigned i = 0; i < width; ++i)
            {
                bytes.push_back(static_cast<unsigned char>(value >> (i * 8)));
            }
        }
        *out = std::move(bytes);
        ok = true;
    } while (false);
    return ok;
}
} // namespace kncore
