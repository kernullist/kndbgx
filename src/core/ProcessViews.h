#pragma once

#include "Process.h"

namespace kncore
{
struct HandleEntry
{
    uint64_t Object = 0;
    uint64_t OwnerPid = 0;
    uint64_t Handle = 0;
    uint32_t Access = 0;
    uint16_t TypeIndex = 0;
};

inline bool ParseExtendedHandles64(std::span<const unsigned char> bytes, std::vector<HandleEntry> &entries)
{
    entries.clear();
    if (bytes.size() < 16)
    {
        return false;
    }
    uint64_t count = 0;
    std::memcpy(&count, bytes.data(), 8);
    if (count > (bytes.size() - 16) / 40 || count > 4000000)
    {
        return false;
    }
    entries.reserve(static_cast<size_t>(count));
    for (size_t i = 0; i < count; ++i)
    {
        const auto *cursor = bytes.data() + 16 + i * 40;
        HandleEntry entry;
        std::memcpy(&entry.Object, cursor, 8);
        std::memcpy(&entry.OwnerPid, cursor + 8, 8);
        std::memcpy(&entry.Handle, cursor + 16, 8);
        std::memcpy(&entry.Access, cursor + 24, 4);
        std::memcpy(&entry.TypeIndex, cursor + 30, 2);
        entries.push_back(entry);
    }
    return true;
}

inline bool ProcessVmAccess(const HandleEntry &entry, unsigned processType)
{
    return processType <= UINT16_MAX && entry.TypeIndex == processType && (entry.Access & 0x38) != 0;
}

inline bool HandleMatches(const HandleEntry &entry, std::optional<uint64_t> targetPid, std::optional<uint64_t> ownerFilter,
                          std::optional<uint64_t> targetFilter)
{
    return (!ownerFilter || entry.OwnerPid == *ownerFilter) && (!targetFilter || (targetPid && *targetPid == *targetFilter));
}

inline Result CompareProcessViews(const std::vector<ProcessRow> &kernel, const Result &kernelResult, const std::vector<ProcessRow> &host,
                                  const Result &hostResult)
{
    Result result;
    result.Source = L"TargetMemory+HostToolhelp";
    result.Consistency = L"cross-view-nonatomic";
    if (kernelResult.State != Status::Success || !kernelResult.Collected.Complete || hostResult.State != Status::Success ||
        !hostResult.Collected.Complete)
    {
        result.State = Status::Unavailable;
        result.Collected.StopReason = L"CrossViewUnavailable";
        auto inputs = knjson::Value::MakeObject();
        inputs.Set(L"kernelStatus", knjson::Value(StatusName(kernelResult.State)));
        inputs.Set(L"kernelCoverage", kernelResult.Collected.ToJson());
        inputs.Set(L"hostStatus", knjson::Value(StatusName(hostResult.State)));
        inputs.Set(L"hostError", hostResult.Error.ToJson());
        inputs.Set(L"hostCoverage", hostResult.Collected.ToJson());
        result.Limitations.Push(inputs);
        return result;
    }
    std::map<uint64_t, std::pair<const ProcessRow *, const ProcessRow *>> views;
    for (const auto &row : kernel)
    {
        if (!row.PidKnown || views[row.Pid].first != nullptr)
        {
            result.State = Status::Unavailable;
            result.Collected.StopReason = L"KernelIdentityUnavailableOrDuplicated";
            return result;
        }
        views[row.Pid].first = &row;
    }
    for (const auto &row : host)
    {
        if (!row.PidKnown || views[row.Pid].second != nullptr)
        {
            result.State = Status::Unavailable;
            result.Collected.StopReason = L"HostIdentityUnavailableOrDuplicated";
            return result;
        }
        views[row.Pid].second = &row;
    }
    for (const auto &[pid, pair] : views)
    {
        const auto *a = pair.first;
        const auto *b = pair.second;
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"ProcessCrossView"));
        row.Set(L"pid", knjson::Value(std::to_wstring(pid)));
        std::wstring observation;
        if (a == nullptr || b == nullptr)
        {
            observation = a == nullptr ? L"HostOnlyReobserveCandidate" : L"KernelOnlyReobserveCandidate";
            result.Collected.Unknown += !(a != nullptr ? a : b)->CreateTimeKnown ? 1 : 0;
        }
        else if (!a->CreateTimeKnown || !b->CreateTimeKnown)
        {
            observation = L"IdentityUnknown";
            ++result.Collected.Unknown;
        }
        else
        {
            observation = a->CreateTime == b->CreateTime ? L"SameObservedIdentity" : L"PidReusedOrViewsChanged";
        }
        row.Set(L"observation", knjson::Value(observation));
        row.Set(L"kernel", a != nullptr ? a->ToJson() : knjson::Value());
        row.Set(L"host", b != nullptr ? b->ToJson() : knjson::Value());
        result.Rows.Push(row);
        ++result.Collected.Visited;
    }
    result.Collected.Expected = result.Collected.Visited;
    result.Collected.Decoded = result.Collected.Visited;
    result.Collected.Classified = result.Collected.Visited - result.Collected.Unknown;
    result.Collected.Complete = result.Collected.Unknown == 0;
    result.State = result.Collected.Complete ? Status::Success : Status::Partial;
    result.Collected.StopReason = result.Collected.Complete ? L"ComparedAvailableViews" : L"ProcessInstanceIdentityUnavailable";
    result.Limitations.Push(knjson::Value(L"Non-atomic differences are re-observation candidates, not proof of a hidden process."));
    return result;
}
} // namespace kncore
