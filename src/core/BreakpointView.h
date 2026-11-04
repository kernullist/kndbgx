#pragma once

#include "MemoryView.h"
#include "ResultAction.h"

namespace kncore
{
inline bool BreakpointOperation(const std::wstring &operation)
{
    return operation == L"breakpoint-add" || operation == L"breakpoint-remove" ||
           operation == L"breakpoint-enable" || operation == L"breakpoint-disable";
}

inline const knjson::Value *BreakpointSourceRow(const knjson::Value &binding, const StoredResult *source,
                                               const SessionStamp &current)
{
    uint64_t index = 0;
    if (source == nullptr || source->Id != binding.Get(L"resultId").AsString(L"") || source->Data.Stamp != current ||
        !current.Context.Complete() || !ParseUnsigned(binding.Get(L"index").AsString(L""), 10, &index) ||
        index >= source->Data.Rows.Items().size())
    {
        return nullptr;
    }
    const auto &row = source->Data.Rows.Items()[static_cast<size_t>(index)];
    return row.Get(L"historical").AsBool(false) ? nullptr : &row;
}

inline std::optional<std::wstring> BreakpointPlanCommand(const knjson::Value &parameters, const StoredResult *source,
                                                        const SessionStamp &current)
{
    const auto operation = parameters.Get(L"operation").AsString(L"");
    const auto &binding = parameters.Get(L"source");
    if (!BreakpointOperation(operation) || !binding.IsObject() || !MatchesStamp(current, parameters.Get(L"expectedStamp")))
    {
        return std::nullopt;
    }
    if (binding.Fields().empty())
    {
        const auto expression = parameters.Get(L"expression").AsString(L"");
        return operation == L"breakpoint-add" && ViewAddressExpression(expression) ?
            std::optional<std::wstring>(L"debug-plan breakpoint-add \"" + expression + L"\"") : std::nullopt;
    }
    const auto *row = BreakpointSourceRow(binding, source, current);
    if (row == nullptr)
    {
        return std::nullopt;
    }
    uint64_t operand = 0;
    if (operation == L"breakpoint-add")
    {
        if (source->Data.CommandId != L"u" || row->Get(L"addressSpace").AsString(L"") != L"virtual" ||
            !ParseUnsigned(row->Get(L"address").AsString(L""), 16, &operand))
        {
            return std::nullopt;
        }
        return L"debug-plan breakpoint-add " + Hex(operand);
    }
    if (source->Data.CommandId != L"breakpoints" || row->Get(L"kind").AsString(L"") != L"Breakpoint" ||
        row->Get(L"identity").AsString(L"").empty() || !ParseUnsigned(row->Get(L"id").AsString(L""), 10, &operand) ||
        operand > UINT32_MAX)
    {
        return std::nullopt;
    }
    return L"debug-plan " + operation + L" " + std::to_wstring(operand);
}
} // namespace kncore
