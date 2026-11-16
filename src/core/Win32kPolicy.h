#pragma once

#include "Process.h"
#include "Win32kPolicyProfile.h"

namespace kncore
{
struct Win32kProcessPolicy
{
    ProcessRow Process;
    std::optional<uint64_t> Flags;
    std::optional<uint64_t> Set;
    std::optional<uint64_t> Session;
    bool NoSession = false;
    bool IdentityValid = false;
};

inline Win32kProcessPolicy ReadWin32kProcessPolicy(const DispatchSnapshot &memory, const TargetArchitecture &architecture,
                                                  const ProcessRow &process)
{
    Win32kProcessPolicy policy;
    policy.Process = process;
    const auto object = process.Eprocess;
    policy.IdentityValid = process.PidKnown && process.CreateTimeKnown &&
        memory.Number(object + 0x1d0) == process.Pid && memory.Number(object + 0x1f8) == process.CreateTime;
    if (policy.IdentityValid)
    {
        policy.Flags = memory.Number(object + 0x750, 4);
        policy.Set = memory.Number(object + 0x6e8, 4);
        const auto session = memory.Number(object + 0x2e8);
        const auto flags3 = memory.Number(object + 0x5fc, 4);
        policy.NoSession = session == 0ULL || (flags3 && (*flags3 & 0x1000) != 0);
        if (!policy.NoSession && flags3 && DispatchPointer(architecture, session))
        {
            policy.Session = memory.Number(*session + 8, 4);
            if (policy.Session == UINT32_MAX)
            {
                policy.NoSession = true;
                policy.Session.reset();
            }
        }
    }
    return policy;
}

inline const wchar_t *Win32kPolicyMode(const Win32kProcessPolicy &policy)
{
    if (!policy.Flags)
    {
        return L"Unknown";
    }
    const auto flags = *policy.Flags;
    return (flags & 0xc000) == 0xc000 ? L"Enforce and audit" : (flags & 0x4000) ? L"Enforce" :
        (flags & 0x8000) ? L"Audit only" : L"Disabled";
}

struct Win32kPolicyBitmap
{
    std::optional<uint64_t> Address;
    std::vector<unsigned char> Bytes;
    std::vector<unsigned char> Valid;

    std::optional<bool> Bit(uint32_t index, uint64_t set) const
    {
        if (index >= 1497)
        {
            return {};
        }
        // The reviewed predicate returns true for every set >= 7, before dereferencing the session.
        if (set >= 7)
        {
            return true;
        }
        if (Address == 0ULL)
        {
            return false;
        }
        const auto byte = index / 8;
        if (!Address || byte >= Bytes.size() || byte >= Valid.size() || !Valid[byte])
        {
            return {};
        }
        return (Bytes[byte] & (1u << (index % 8))) != 0;
    }
};

struct Win32kPolicySession
{
    uint64_t Root = 0;
    std::optional<uint64_t> User;
    bool HelpersVerified = false;
    std::array<Win32kPolicyBitmap, 7> Bitmaps;
};

struct Win32kPolicyDecision
{
    const wchar_t *Value = L"Unknown";
    const wchar_t *Reason = L"Policy or dispatch evidence unavailable";
    std::optional<bool> Bit;
};

inline Win32kPolicyDecision EvaluateWin32kPolicy(const Win32kProcessPolicy &policy, const Win32kPolicySession *session,
                                                uint32_t index, bool wrapperVerified)
{
    Win32kPolicyDecision decision;
    if (!policy.IdentityValid || !policy.Flags || !policy.Set || index >= 1497)
    {
        return decision;
    }
    if (policy.NoSession)
    {
        return {L"Not applicable", L"Process has no GUI session", {}};
    }
    if (!policy.Session || !session || !session->HelpersVerified || !wrapperVerified)
    {
        return decision;
    }
    decision.Bit = *policy.Set >= 7 ? std::optional<bool>(true) : session->Bitmaps[*policy.Set].Bit(index, *policy.Set);
    if ((*policy.Flags & 0xc000) == 0)
    {
        decision.Value = L"Allowed";
        decision.Reason = L"Process filtering disabled";
    }
    else if (!decision.Bit)
    {
        decision.Reason = L"Filter bitmap byte unavailable";
    }
    else if (!*decision.Bit)
    {
        decision.Value = L"Allowed";
        decision.Reason = L"Service not selected by filter bitmap";
    }
    else if (*policy.Flags & 0x4000)
    {
        decision.Value = L"Blocked";
        decision.Reason = *policy.Set >= 7 ? L"Filter set >= 7 selects every service" : L"Filter bitmap selected service and enforcement is enabled";
    }
    else
    {
        decision.Value = L"Audit only";
        decision.Reason = L"Filter bitmap selected service without enforcement";
    }
    return decision;
}

inline knjson::Value Win32kPolicyRow(const Win32kProcessPolicy &policy, const Win32kPolicySession *session)
{
    auto row = policy.Process.ToJson();
    row.Set(L"kind", knjson::Value(L"Win32kProcessPolicy"));
    row.Set(L"filterMode", knjson::Value(Win32kPolicyMode(policy)));
    row.Set(L"filterSet", OptionalNumber(policy.Set));
    row.Set(L"session", policy.NoSession ? knjson::Value(L"None") : OptionalNumber(policy.Session));
    row.Set(L"sessionId", OptionalNumber(policy.Session));
    row.Set(L"mitigationFlags", OptionalNumber(policy.Flags, true));
    const auto flag = [&](uint64_t mask)
    {
        return policy.Flags ? knjson::Value((*policy.Flags & mask) != 0) : knjson::Value();
    };
    row.Set(L"filterEnabled", flag(0x4000));
    row.Set(L"filterAudit", flag(0x8000));
    row.Set(L"win32kDisable", flag(0x1000));
    row.Set(L"win32kDisableAudit", flag(0x2000));
    row.Set(L"policyScope", knjson::Value(L"Process filter policy; syscall execution and GUI conversion are separate"));
    row.Set(L"profile", knjson::Value(L"WIN32KBASE-28000.2952-filter-policy"));
    if (session)
    {
        row.Set(L"sessionState", knjson::Value(Hex(session->Root)));
        row.Set(L"userSessionState", OptionalNumber(session->User, true));
        if (policy.Set && *policy.Set < 7)
        {
            row.Set(L"filterBitmap", OptionalNumber(session->Bitmaps[*policy.Set].Address, true));
        }
    }
    return row;
}

class Win32kPolicySnapshot
{
  public:
    DispatchSnapshot Memory;
    std::map<uint64_t, Win32kPolicySession> Sessions;
    std::array<bool, 1497> Verified{};
    std::vector<DispatchSnapshot::Range> Captures;
    std::vector<DispatchSnapshot::Range> Checks;

    template <typename Hash>
    void Capture(TargetReader &reader, const TargetArchitecture &architecture, const std::vector<ProcessRow> &processes,
                 uint64_t image, uint64_t nt, uint64_t base, WalkBudget &budget, Hash hash)
    {
        using Range = DispatchSnapshot::Range;
        const auto capture = [&](std::vector<Range> ranges, bool check = true)
        {
            Memory.Capture(reader, architecture, budget, ranges);
            Captures.insert(Captures.end(), ranges.begin(), ranges.end());
            if (check)
            {
                Checks.insert(Checks.end(), ranges.begin(), ranges.end());
            }
        };
        std::vector<Range> fields;
        for (const auto &process : processes)
        {
            fields.emplace_back(process.Eprocess + 0x1d0, 0x584);
            for (const auto &[offset, size] : {Range{0x1d0, 8}, Range{0x1f8, 8}, Range{0x2e8, 8}, Range{0x5fc, 4}, Range{0x6e8, 4}, Range{0x750, 4}})
            {
                Checks.emplace_back(process.Eprocess + offset, size);
            }
        }
        capture(fields, false);
        fields.clear();
        for (const auto &process : processes)
        {
            const auto session = Memory.Number(process.Eprocess + 0x2e8);
            if (DispatchPointer(architecture, session))
            {
                fields.emplace_back(*session + 8, 4);
            }
        }
        capture(fields);
        capture({{image + 0x89ca0, 8}, {image + 0x89cd8, 8}, {image + 0x89ce0, 4}, {image + 0x73a80, 16}});
        const auto high = Memory.Number(image + 0x89ca0);
        const auto count = Memory.Number(image + 0x89ce0, 4);
        if (!count || *count > 255 || (*count && !DispatchPointer(architecture, high)))
        {
            budget.Stop(Status::Unavailable, L"Win32kPolicySessionSlotsUnavailable");
            return;
        }
        if (*count)
        {
            capture({{*high, static_cast<size_t>(*count) * 8}});
        }
        fields.clear();
        for (uint64_t id = 0; id <= *count; ++id)
        {
            const auto root = Memory.Number(id == 0 ? image + 0x89cd8 : *high + (id - 1) * 8);
            if (DispatchPointer(architecture, root))
            {
                Sessions[id].Root = *root;
                fields.emplace_back(*root, 8);
                fields.emplace_back(*root + 0x88, 8);
            }
        }
        capture(fields);
        fields.clear();
        for (auto &[id, session] : Sessions)
        {
            session.User = Memory.Number(session.Root);
            if (DispatchPointer(architecture, session.User))
            {
                fields.emplace_back(*session.User + 0x11510, 7 * 8);
            }
            const auto api = Memory.Number(session.Root + 0x88);
            if (DispatchPointer(architecture, api))
            {
                fields.emplace_back(*api + 0x18, 8);
            }
        }
        capture(fields);
        fields.clear();
        for (auto &[id, session] : Sessions)
        {
            const auto api = Memory.Number(session.Root + 0x88);
            const auto host = DispatchPointer(architecture, api) ? Memory.Number(*api + 0x18) : std::nullopt;
            if (DispatchPointer(architecture, host))
            {
                fields.emplace_back(*host + 0x18, 16);
            }
            for (size_t set = 0; set < 7; ++set)
            {
                auto &bitmap = session.Bitmaps[set];
                bitmap.Address = DispatchPointer(architecture, session.User) ? Memory.Number(*session.User + 0x11510 + set * 8) : std::nullopt;
                if (bitmap.Address && *bitmap.Address != 0 && KernelReadRange(architecture, *bitmap.Address, 188))
                {
                    fields.emplace_back(*bitmap.Address, 188);
                }
            }
        }
        capture(fields);
        DispatchSnapshot code;
        fields = {{image + 0xa3330, 4096}, {image + 0xa4330, 1892}, {image + 0xa4a94, 1497}};
        capture(fields);
        fields.clear();
        for (uint32_t index = 0; index < 1497; ++index)
        {
            fields.emplace_back(image + 0x2fcc0 + uint64_t(index) * 176, 167);
        }
        for (const auto index : {1497, 1498})
        {
            fields.emplace_back(image + Win32kRoutes[index].Entry, Win32kRoutes[index].Size);
        }
        code.Capture(reader, architecture, budget, fields);
        const std::array<uint64_t, 7> calls{0, nt + 0x45d7c0, nt + 0x2cb700, nt + 0xc79860, nt + 0x5438f0, 0, 0};
        const bool helpers = Memory.Number(image + 0x73a88) == image + 0x9930 && Memory.Number(image + 0x73a80) == image + 0x19320 &&
            VerifyDispatchRoute(code, Win32kRoutes[1497], image, calls, hash) && VerifyDispatchRoute(code, Win32kRoutes[1498], image, calls, hash);
        for (auto &[id, session] : Sessions)
        {
            const auto api = Memory.Number(session.Root + 0x88);
            const auto host = DispatchPointer(architecture, api) ? Memory.Number(*api + 0x18) : std::nullopt;
            session.HelpersVerified = helpers && DispatchPointer(architecture, host) &&
                Memory.Number(*host + 0x18) == base + 0x1760b0 && Memory.Number(*host + 0x20) == base + 0x105450;
            for (auto &bitmap : session.Bitmaps)
            {
                if (!bitmap.Address || !*bitmap.Address || !KernelReadRange(architecture, *bitmap.Address, 188))
                {
                    continue;
                }
                for (size_t i = 0; i < 188; ++i)
                {
                    const auto byte = Memory.Number(*bitmap.Address + i, 1);
                    bitmap.Bytes.push_back(static_cast<unsigned char>(byte.value_or(0)));
                    bitmap.Valid.push_back(byte.has_value());
                }
            }
        }
        for (uint32_t i = 0; i < 1497 && CheckWalkDeadline(budget); ++i)
        {
            const auto encoded = Memory.Number(image + 0xa3330 + uint64_t(i) * 4, 4);
            Verified[i] = encoded && DecodeServiceEntry(image + 0xa3330, static_cast<int32_t>(*encoded)) == image + 0x2fcc0 + uint64_t(i) * 176 &&
                VerifyFilterWrapper(code, Win32kRoutes[i], i, image, nt) && Memory.Number(image + 0xa4a94 + i, 1).has_value();
        }
    }

    const Win32kPolicySession *Session(const Win32kProcessPolicy &policy) const
    {
        const auto found = policy.Session ? Sessions.find(*policy.Session) : Sessions.end();
        return found == Sessions.end() ? nullptr : &found->second;
    }

    void Recheck(TargetReader &reader, const TargetArchitecture &architecture, WalkBudget &budget) const
    {
        DispatchSnapshot final;
        final.Capture(reader, architecture, budget, Captures);
        for (const auto &[address, size] : Checks)
        {
            if (!CheckWalkDeadline(budget))
            {
                break;
            }
            // Compare validity per byte too: an unrelated hole must not hide a changed readable bit.
            for (size_t i = 0; i < size; ++i)
            {
                if (final.Number(address + i, 1) != Memory.Number(address + i, 1))
                {
                    budget.Stop(Status::StaleContext, L"Win32kPolicyBindingsOrBytesChanged");
                    return;
                }
            }
        }
    }
};
} // namespace kncore
