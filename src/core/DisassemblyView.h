#pragma once

#include "MemoryView.h"
#include "ResultAction.h"
#include <cwctype>

namespace kncore
{
inline std::optional<std::wstring> DisassemblyViewCommand(const knjson::Value &parameters, const StoredResult *source = nullptr,
                                                        const SessionStamp *current = nullptr)
{
    auto expression = parameters.Get(L"expression").AsString(L"");
    uint64_t count = 0;
    const auto &binding = parameters.Get(L"source");
    if (!binding.IsObject() || !ParseUnsigned(parameters.Get(L"count").AsString(L""), 10, &count) ||
        (count != 16 && count != 32 && count != 64))
    {
        return std::nullopt;
    }
    if (!binding.Fields().empty())
    {
        const auto command = source != nullptr && current != nullptr && binding.Get(L"action").AsString(L"") == L"disassemble" ?
            BoundResultCommand(*source, binding, *current) : std::nullopt;
        if (!command || !command->starts_with(L"u "))
        {
            return std::nullopt;
        }
        expression = command->substr(2);
    }
    if (!ViewAddressExpression(expression))
    {
        return std::nullopt;
    }
    return L"u \"" + expression + L"\" L" + Hex(count);
}

inline std::wstring InstructionBody(const std::wstring &text, uint64_t address, const std::wstring &bytes)
{
    size_t position = 0;
    const auto token = [&]()
    {
        while (position < text.size() && std::iswspace(text[position]))
        {
            ++position;
        }
        const auto begin = position;
        while (position < text.size() && !std::iswspace(text[position]))
        {
            ++position;
        }
        return text.substr(begin, position - begin);
    };
    auto location = token();
    const auto selectorEnd = location.find(L':');
    if (selectorEnd != std::wstring::npos)
    {
        if (selectorEnd == 0 || selectorEnd > 4 ||
            !std::all_of(location.begin(), location.begin() + selectorEnd,
                [](wchar_t value)
                {
                    return (value >= L'0' && value <= L'9') || (value >= L'a' && value <= L'f') ||
                           (value >= L'A' && value <= L'F');
                }))
        {
            return text;
        }
        location.erase(0, selectorEnd + 1);
    }
    location.erase(std::remove(location.begin(), location.end(), L'`'), location.end());
    auto encoded = token();
    std::transform(encoded.begin(), encoded.end(), encoded.begin(),
        [](wchar_t value)
        {
            return static_cast<wchar_t>(std::towlower(value));
        });
    uint64_t parsed = 0;
    if (!ParseUnsigned(location, 16, &parsed) || parsed != address || bytes.empty() || encoded != bytes)
    {
        return text;
    }
    while (position < text.size() && std::iswspace(text[position]))
    {
        ++position;
    }
    auto end = text.size();
    while (end > position && std::iswspace(text[end - 1]))
    {
        --end;
    }
    return end > position ? text.substr(position, end - position) : text;
}
} // namespace kncore
