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

inline knjson::Value ProcessComparisonSummary(const Result &result)
{
    size_t matched = 0;
    size_t candidates = 0;
    size_t indeterminate = 0;
    for (const auto &row : result.Rows.Items())
    {
        const auto observation = row.Get(L"observation").AsString(L"");
        if (observation == L"SameObservedIdentity")
        {
            ++matched;
        }
        else if (observation == L"HostOnlyReobserveCandidate" || observation == L"KernelOnlyReobserveCandidate" ||
                 observation == L"ActiveListOnlyReobserveCandidate" || observation == L"CidOnlyReobserveCandidate" ||
                 observation == L"PidReusedOrViewsChanged")
        {
            ++candidates;
        }
        else
        {
            ++indeterminate;
        }
    }
    auto summary = knjson::Value::MakeObject();
    summary.Set(L"total", knjson::Value(std::to_wstring(result.Rows.Items().size())));
    summary.Set(L"matched", knjson::Value(std::to_wstring(matched)));
    summary.Set(L"mismatchCandidates", knjson::Value(std::to_wstring(candidates)));
    summary.Set(L"indeterminate", knjson::Value(std::to_wstring(indeterminate)));
    return summary;
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
            if (!(a != nullptr ? a : b)->CreateTimeKnown)
            {
                observation = L"IdentityUnknown";
                ++result.Collected.Unknown;
            }
            else
            {
                observation = a == nullptr ? L"HostOnlyReobserveCandidate" : L"KernelOnlyReobserveCandidate";
            }
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

inline Result CompareTargetProcessViews(const std::vector<ProcessRow> &active, const Result &activeResult,
                                        const std::vector<ProcessRow> &cid, const Result &cidResult)
{
    Result result;
    result.Source = L"TargetMemory:PsActiveProcessHead+PspCidTable";
    result.LayoutProfile = activeResult.LayoutProfile;
    result.Consistency = activeResult.Consistency == L"stopped" && cidResult.Consistency == L"stopped" ? L"stopped" : L"cross-view-nonatomic";
    const bool activeComplete = activeResult.State == Status::Success && activeResult.Collected.Complete;
    const bool cidComplete = cidResult.State == Status::Success && cidResult.Collected.Complete;
    auto inputs = knjson::Value::MakeObject();
    inputs.Set(L"activeListStatus", knjson::Value(StatusName(activeResult.State)));
    inputs.Set(L"activeListCoverage", activeResult.Collected.ToJson());
    inputs.Set(L"cidTableStatus", knjson::Value(StatusName(cidResult.State)));
    inputs.Set(L"cidTableCoverage", cidResult.Collected.ToJson());
    result.Limitations.Push(inputs);
    const auto finish = [&]()
    {
        for (const auto *input : {&activeResult, &cidResult})
        {
            if (input->State == Status::InternalFault || input->State == Status::EngineError ||
                input->State == Status::StaleContext || input->State == Status::Cancelled)
            {
                result.State = input->State;
                result.Error = input->Error;
                result.Collected.Complete = false;
                result.Collected.StopReason = L"TargetCrossViewFailed";
                break;
            }
        }
        return result;
    };
    std::map<uint64_t, std::pair<const ProcessRow *, const ProcessRow *>> views;
    for (const auto &row : active)
    {
        if (!row.PidKnown || views[row.Pid].first != nullptr)
        {
            result.State = Status::Unavailable;
            result.Collected.StopReason = L"ActiveProcessIdentityUnavailableOrDuplicated";
            return finish();
        }
        views[row.Pid].first = &row;
    }
    for (const auto &row : cid)
    {
        if (!row.PidKnown || views[row.Pid].second != nullptr)
        {
            result.State = Status::Unavailable;
            result.Collected.StopReason = L"CidProcessIdentityUnavailableOrDuplicated";
            return finish();
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
        row.Set(L"activeList", a != nullptr ? a->ToJson() : knjson::Value());
        row.Set(L"cidTable", b != nullptr ? b->ToJson() : knjson::Value());
        std::wstring observation;
        if ((a && !a->CreateTimeKnown) || (b && !b->CreateTimeKnown))
        {
            observation = L"IdentityUnknown";
            ++result.Collected.Unknown;
        }
        else if (a && b)
        {
            observation = a->Eprocess == b->Eprocess && a->CreateTime == b->CreateTime ? L"SameObservedIdentity"
                                                                                    : L"PidReusedOrViewsChanged";
        }
        else if (a && cidComplete)
        {
            observation = L"ActiveListOnlyReobserveCandidate";
        }
        else if (b && activeComplete)
        {
            observation = L"CidOnlyReobserveCandidate";
        }
        else
        {
            observation = L"OtherViewIncomplete";
            ++result.Collected.Unknown;
        }
        row.Set(L"observation", knjson::Value(observation));
        result.Rows.Push(row);
        ++result.Collected.Visited;
    }
    result.Collected.Expected = result.Collected.Visited;
    result.Collected.Decoded = result.Collected.Visited;
    result.Collected.Classified = result.Collected.Visited - result.Collected.Unknown;
    result.Collected.Complete = activeComplete && cidComplete && result.Collected.Unknown == 0;
    result.State = result.Collected.Complete ? Status::Success : views.empty() ? Status::Unavailable : Status::Partial;
    result.Collected.StopReason = result.Collected.Complete ? L"ComparedTargetProcessViews" : L"TargetCrossViewIncomplete";
    result.Limitations.Push(knjson::Value(L"Active-list/CID differences are re-observation candidates, not proof of a hidden process. "
                                          L"Processes retained during creation or teardown may appear in only one view. "
                                          L"A process removed from both views cannot be found by this comparison."));
    return finish();
}
} // namespace kncore
