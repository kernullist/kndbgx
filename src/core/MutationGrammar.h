#pragma once

#include "Mutation.h"

namespace kncore
{
template <typename Evaluate>
bool ParseMemoryMutation(const std::wstring &command, const std::vector<std::wstring> &arguments, const std::vector<bool> &quoted,
                         Evaluate evaluate, MutationIntent *intent)
{
    MutationIntent parsed;
    parsed.CommandId = command;
    if (intent == nullptr || arguments.size() < 3 || arguments.size() != quoted.size() || !evaluate(arguments[1], &parsed.Address))
    {
        return false;
    }
    if (command == L"f")
    {
        uint64_t count = 0;
        if (arguments.size() < 4 || arguments[2].size() < 2 || towlower(arguments[2][0]) != L'l' ||
            !ParseUnsigned(arguments[2].substr(1), 16, &count) || count == 0 || count > MutationPlans::MaxBytes ||
            !ValidRange(parsed.Address, count))
        {
            return false;
        }
        std::vector<unsigned char> pattern;
        if (arguments.size() == 4 && quoted[3])
        {
            for (const auto ch : arguments[3])
            {
                if (ch < 1 || ch > 127)
                {
                    return false;
                }
                pattern.push_back(static_cast<unsigned char>(ch));
            }
        }
        else
        {
            for (size_t i = 3; i < arguments.size(); ++i)
            {
                uint64_t byte = 0;
                if (quoted[i] || !ParseUnsigned(arguments[i], 16, &byte) || byte > 255)
                {
                    return false;
                }
                pattern.push_back(static_cast<unsigned char>(byte));
            }
        }
        if (pattern.empty())
        {
            return false;
        }
        parsed.Desired.resize(static_cast<size_t>(count));
        if (!FillChunk(pattern, 0, parsed.Desired))
        {
            return false;
        }
    }
    else
    {
        const unsigned width = command == L"eb" ? 1 : command == L"ew" ? 2 : command == L"ed" ? 4 : command == L"eq" ? 8 : 0;
        std::vector<uint64_t> values;
        for (size_t i = 2; i < arguments.size(); ++i)
        {
            uint64_t value = 0;
            if (quoted[i] || !evaluate(arguments[i], &value))
            {
                return false;
            }
            values.push_back(value);
        }
        if (!PlanValues(parsed.Address, width, values, &parsed.Desired) || parsed.Desired.size() > MutationPlans::MaxBytes)
        {
            return false;
        }
    }
    parsed.NormalizedArguments = Hex(parsed.Address) + L" " + BytesHex(parsed.Desired);
    *intent = std::move(parsed);
    return true;
}
} // namespace kncore
