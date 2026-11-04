#pragma once

#include <span>
#include <string>

namespace kncore
{
struct MemoryString
{
    std::wstring Text;
    size_t Consumed = 0;
    size_t InvalidUnits = 0;
    bool Terminated = false;
};

inline MemoryString DecodeMemoryString(std::span<const unsigned char> bytes, bool utf16)
{
    MemoryString result;
    const auto escapedByte = [&](unsigned char byte)
    {
        constexpr wchar_t hex[] = L"0123456789abcdef";
        result.Text += L"\\x";
        result.Text += hex[byte >> 4];
        result.Text += hex[byte & 15];
    };
    while (result.Consumed < bytes.size())
    {
        if (!utf16)
        {
            const auto byte = bytes[result.Consumed++];
            if (byte == 0)
            {
                result.Terminated = true;
                break;
            }
            if (byte >= 0x20 && byte < 0x7f)
            {
                result.Text += static_cast<wchar_t>(byte);
            }
            else
            {
                escapedByte(byte);
            }
            continue;
        }
        if (bytes.size() - result.Consumed < 2)
        {
            escapedByte(bytes[result.Consumed++]);
            ++result.InvalidUnits;
            break;
        }
        const auto unit = static_cast<wchar_t>(bytes[result.Consumed] | (unsigned(bytes[result.Consumed + 1]) << 8));
        result.Consumed += 2;
        if (unit == 0)
        {
            result.Terminated = true;
            break;
        }
        if (unit >= 0xd800 && unit <= 0xdbff && bytes.size() - result.Consumed >= 2)
        {
            const auto next = static_cast<wchar_t>(bytes[result.Consumed] | (unsigned(bytes[result.Consumed + 1]) << 8));
            if (next >= 0xdc00 && next <= 0xdfff)
            {
                result.Text += unit;
                result.Text += next;
                result.Consumed += 2;
                continue;
            }
        }
        if (unit >= 0xd800 && unit <= 0xdfff)
        {
            result.Text += L'\ufffd';
            ++result.InvalidUnits;
        }
        else
        {
            result.Text += unit;
        }
    }
    return result;
}
} // namespace kncore
