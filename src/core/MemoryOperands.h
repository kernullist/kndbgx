#pragma once

#include "Input.h"
#include <optional>
#include <string>

namespace kncore
{
struct MemoryOperands
{
    uint64_t Address = 0;
    std::optional<uint64_t> Extra;
    std::wstring Error;
};

template <typename Evaluate> MemoryOperands ParseMemoryOperands(const std::vector<std::wstring> &args, Evaluate evaluate)
{
    MemoryOperands result;
    uint64_t extra = 0;
    if (args.size() < 2 || args.size() > 3)
    {
        result.Error = L"Expected an address and at most one optional operand";
    }
    else if (!evaluate(args[1], &result.Address))
    {
        result.Error = L"Cannot evaluate address: " + args[1];
    }
    else if (args.size() == 3)
    {
        if (!evaluate(args[2], &extra))
        {
            result.Error = L"Cannot evaluate optional operand: " + args[2];
        }
        else
        {
            result.Extra = extra;
        }
    }
    return result;
}
} // namespace kncore
