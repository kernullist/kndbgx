#include "Text.h"
#include "../core/Input.h"

#include <windows.h>

#include <cwctype>
#include <cstring>
#include <climits>
#include <vector>
#include <algorithm>

namespace knutil
{
size_t Utf16PrefixUnits(std::wstring_view text, size_t maximum)
{
    size_t count = std::min(text.size(), maximum);
    if (count != 0 && text[count - 1] >= 0xd800 && text[count - 1] <= 0xdbff)
    {
        --count;
    }
    return count;
}

std::wstring Utf8ToWide(const char *text)
{
    std::wstring result;

    do
    {
        if (text == nullptr || text[0] == '\0')
        {
            break;
        }

        const size_t inputBytes = strlen(text);
        if (inputBytes > INT_MAX)
        {
            break;
        }
        const int bytes = static_cast<int>(inputBytes);

        if (bytes <= 0)
        {
            break;
        }

        const int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, bytes, nullptr, 0);

        if (chars <= 0)
        {
            break;
        }

        result.resize(static_cast<size_t>(chars));
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, bytes, &result[0], chars);
    } while (false);

    return result;
}

std::string WideToUtf8(const std::wstring &text)
{
    std::string result;

    do
    {
        if (text.empty())
        {
            break;
        }

        if (text.size() > INT_MAX)
        {
            break;
        }
        const int chars = static_cast<int>(text.size());
        const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.c_str(), chars, nullptr, 0, nullptr, nullptr);

        if (bytes <= 0)
        {
            break;
        }

        result.resize(static_cast<size_t>(bytes));
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.c_str(), chars, &result[0], bytes, nullptr, nullptr);
    } while (false);

    return result;
}

std::wstring Trim(const std::wstring &text)
{
    size_t begin = 0;
    size_t end = text.size();

    while (begin < end && iswspace(text[begin]))
    {
        ++begin;
    }

    while (end > begin && iswspace(text[end - 1]))
    {
        --end;
    }

    return text.substr(begin, end - begin);
}

bool Tokenize(const std::wstring &text, std::vector<std::wstring> *tokens, std::wstring *error, std::vector<bool> *quotedArguments)
{
    bool ok = false;
    do
    {
        if (tokens == nullptr)
        {
            break;
        }
        tokens->clear();
        if (quotedArguments != nullptr)
        {
            quotedArguments->clear();
        }
        if (text.size() > 32768 || text.find_first_of(L"\r\n") != std::wstring::npos || text.find(L'\0') != std::wstring::npos)
        {
            break;
        }
        std::vector<std::wstring> parsed;
        std::vector<bool> quotedTokens;
        size_t pos = 0;
        bool valid = true;
        while (pos < text.size())
        {
            while (pos < text.size() && iswspace(text[pos]))
            {
                ++pos;
            }
            if (pos == text.size())
            {
                break;
            }
            std::wstring token;
            bool quoted = false;
            bool hadQuote = false;
            while (pos < text.size() && (quoted || !iswspace(text[pos])))
            {
                if (text[pos] == L'\0' || text[pos] == L'\r' || text[pos] == L'\n')
                {
                    valid = false;
                    break;
                }
                size_t slashes = 0;
                while (pos < text.size() && text[pos] == L'\\')
                {
                    ++slashes;
                    ++pos;
                }
                if (pos < text.size() && text[pos] == L'"')
                {
                    token.append(slashes / 2, L'\\');
                    if ((slashes % 2) != 0)
                    {
                        token.push_back(L'"');
                    }
                    else
                    {
                        quoted = !quoted;
                        hadQuote = true;
                    }
                    ++pos;
                }
                else
                {
                    token.append(slashes, L'\\');
                    if (pos < text.size() && (quoted || !iswspace(text[pos])))
                    {
                        token.push_back(text[pos++]);
                    }
                }
            }
            if (!valid || quoted || parsed.size() >= 4096)
            {
                valid = false;
                break;
            }
            parsed.push_back(std::move(token));
            quotedTokens.push_back(hadQuote);
        }
        if (!valid)
        {
            break;
        }
        *tokens = std::move(parsed);
        if (quotedArguments != nullptr)
        {
            *quotedArguments = std::move(quotedTokens);
        }
        ok = true;
    } while (false);
    if (!ok && error != nullptr)
    {
        *error = L"InvalidInput: malformed quoting or command input limit exceeded";
    }
    return ok;
}

std::vector<std::wstring> Tokenize(const std::wstring &text)
{
    std::vector<std::wstring> tokens;
    Tokenize(text, &tokens);
    return tokens;
}

bool ParseWindbgHex(const std::wstring &text, unsigned long long *value)
{
    bool ok = false;
    do
    {
        if (value == nullptr)
        {
            break;
        }
        std::wstring slice = Trim(text);
        const size_t equals = slice.find(L'=');
        const size_t space = slice.find_first_of(L" \t");
        const size_t separator = equals != std::wstring::npos ? equals : space;
        if (separator != std::wstring::npos)
        {
            const std::wstring label = Trim(slice.substr(0, separator));
            bool validLabel = label == L"rax" || label == L"rbx" || label == L"rcx" || label == L"rdx" || label == L"rsp" ||
                              label == L"rbp" || label == L"rip" || label == L"eax" || label == L"eip" || label == L"esp" ||
                              label == L"idtr";
            if (label.size() == 3 && label[0] == L'c' && label[1] == L'r' && label[2] >= L'0' && label[2] <= L'9')
            {
                validLabel = true;
            }
            if (label.starts_with(L"msr[") && label.ends_with(L"]"))
            {
                uint64_t index = 0;
                validLabel = kncore::ParseUnsigned(std::wstring_view(label).substr(4, label.size() - 5), 16, &index) && index <= UINT32_MAX;
            }
            if (!validLabel)
            {
                break;
            }
            slice = Trim(slice.substr(separator + 1));
        }
        if (slice.starts_with(L"0x") || slice.starts_with(L"0X"))
        {
            slice.erase(0, 2);
        }
        const size_t tick = slice.find(L'`');
        if (tick != std::wstring::npos)
        {
            if (tick != 8 || slice.size() != 17)
            {
                break;
            }
            slice.erase(tick, 1);
        }
        uint64_t parsed = 0;
        if (slice.size() <= 16 && slice.find_first_not_of(L"0123456789abcdefABCDEF") == std::wstring::npos &&
            kncore::ParseUnsigned(slice, 16, &parsed))
        {
            *value = parsed;
            ok = true;
        }
    } while (false);
    return ok;
}
} // namespace knutil
