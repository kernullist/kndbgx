#pragma once

#include "ResultAction.h"
#include "Process.h"

namespace kncore
{
inline const knjson::Value *BoundProcessRow(const StoredResult &source, const knjson::Value &parameters,
                                          const SessionStamp &current)
{
    uint64_t index = 0;
    uint64_t address = 0;
    if (source.Id != parameters.Get(L"resultId").AsString(L"") || source.Data.CommandId != L"!dml_proc" ||
        source.Data.Stamp != current || !current.Context.Complete() ||
        !MatchesStamp(source.Data.Stamp, parameters.Get(L"expectedStamp")) ||
        (source.Data.State != Status::Success && source.Data.State != Status::Partial) ||
        !ParseUnsigned(parameters.Get(L"index").AsString(L""), 10, &index) || index >= source.Data.Rows.Items().size())
    {
        return nullptr;
    }
    const auto &row = source.Data.Rows.Items()[static_cast<size_t>(index)];
    if (row.Get(L"kind").AsString(L"") != L"Process" || row.Get(L"historical").AsBool(false) ||
        !ParseUnsigned(row.Get(L"eprocess").AsString(L""), 16, &address) || address == 0)
    {
        return nullptr;
    }
    return &row;
}

inline bool SameProcessIdentity(const knjson::Value &source, const ProcessRow &current)
{
    uint64_t pid = 0, created = 0, dtb = 0, address = 0;
    return current.PidKnown && current.CreateTimeKnown && current.DtbKnown && current.DirectoryTableBase != 0 &&
           ParseUnsigned(source.Get(L"eprocess").AsString(L""), 16, &address) && address == current.Eprocess &&
           ParseUnsigned(source.Get(L"pid").AsString(L""), 10, &pid) && pid == current.Pid &&
           ParseUnsigned(source.Get(L"createTime").AsString(L""), 10, &created) && created == current.CreateTime &&
           ParseUnsigned(source.Get(L"dtb").AsString(L""), 16, &dtb) && dtb == current.DirectoryTableBase;
}

enum class ProcessSwitchResult
{
    Success,
    Unavailable,
    Rejected,
    RestoreFailed
};

template <typename Read, typename Write> ProcessSwitchResult SwitchImplicitProcess(uint64_t address, Read read, Write write)
{
    const auto previous = read();
    if (!previous)
    {
        return ProcessSwitchResult::Unavailable;
    }
    if (*previous == address)
    {
        return ProcessSwitchResult::Success;
    }
    const bool applied = write(address);
    auto observed = read();
    if (applied && observed && *observed == address)
    {
        return ProcessSwitchResult::Success;
    }
    if (observed && *observed == *previous)
    {
        return ProcessSwitchResult::Rejected;
    }
    const bool restored = write(*previous);
    observed = read();
    return restored && observed && *observed == *previous ? ProcessSwitchResult::Rejected : ProcessSwitchResult::RestoreFailed;
}
} // namespace kncore
