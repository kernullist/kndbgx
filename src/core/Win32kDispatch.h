#pragma once

#include "NamespaceWalk.h"
#include "Win32kDispatchProfile.h"
#include <map>

namespace kncore
{
// Snapshots contain only explicitly requested, bounded ranges from this collection.
class DispatchSnapshot
{
  public:
    using Range = std::pair<uint64_t, size_t>;

    void Capture(TargetReader &source, const TargetArchitecture &architecture, WalkBudget &budget, std::vector<Range> ranges)
    {
        CollectionReadGuard reader(source, budget);
        std::sort(ranges.begin(), ranges.end());
        for (size_t i = 0; i < ranges.size() && CheckWalkDeadline(budget);)
        {
            const auto begin = ranges[i].first;
            uint64_t end = begin + ranges[i].second;
            if (!KernelReadRange(architecture, begin, ranges[i].second) || ranges[i].second > 4096)
            {
                ++i;
                continue;
            }
            ++i;
            while (i < ranges.size() && ranges[i].first <= end + 16 && KernelReadRange(architecture, ranges[i].first, ranges[i].second) &&
                   ranges[i].first + ranges[i].second - begin <= 4096)
            {
                end = std::max(end, ranges[i].first + ranges[i].second);
                ++i;
            }
            blocks_[begin] = reader.Read(AddressSpace::Virtual, begin, static_cast<size_t>(end - begin));
        }
        CheckWalkDeadline(budget);
    }

    std::optional<uint64_t> Number(uint64_t address, size_t bytes = 8) const
    {
        auto found = blocks_.upper_bound(address);
        while (found != blocks_.begin())
        {
            --found;
            const auto offset = static_cast<size_t>(address - found->first);
            if (offset < found->second.Bytes.size())
            {
                return BlockValue(found->second, offset, bytes);
            }
        }
        return {};
    }

    std::optional<std::vector<unsigned char>> Bytes(uint64_t address, size_t size) const
    {
        std::vector<unsigned char> bytes;
        for (size_t i = 0; i < size; ++i)
        {
            const auto value = Number(address + i, 1);
            if (!value)
            {
                return {};
            }
            bytes.push_back(static_cast<unsigned char>(*value));
        }
        return bytes;
    }

  private:
    std::map<uint64_t, ReadResult> blocks_;
};

inline uint64_t DispatchRelative(uint64_t next, uint32_t displacement)
{
    return next + static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(displacement)));
}

inline uint32_t DispatchU32(const std::vector<unsigned char> &bytes, size_t offset)
{
    uint32_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof(value));
    return value;
}

template <typename Hash>
bool VerifyDispatchRoute(const DispatchSnapshot &code, const Win32kRouteProfile &route, uint64_t image,
                         const std::array<uint64_t, 7> &calls, Hash hash)
{
    if (route.Size == 0 || route.Size > 512 || route.Entry > 0xca000 || route.Size > 0xca000 - route.Entry)
    {
        return false;
    }
    auto bytes = code.Bytes(image + route.Entry, route.Size);
    if (!bytes)
    {
        return false;
    }
    for (const auto binding : route.Calls)
    {
        if (!binding)
        {
            continue;
        }
        const auto offset = binding & 0xffff;
        const auto kind = binding >> 16;
        if (kind == 0 || kind >= calls.size() || offset > bytes->size() || bytes->size() - offset < 5 ||
            (*bytes)[offset] != (kind == 6 ? 0xe9 : 0xe8))
        {
            return false;
        }
        if (kind != 6 &&
            (calls[kind] == 0 || DispatchRelative(image + route.Entry + offset + 5, DispatchU32(*bytes, offset + 1)) != calls[kind]))
        {
            return false;
        }
        std::fill_n(bytes->begin() + offset + 1, 4, static_cast<unsigned char>(0));
    }
    return hash(*bytes) == route.Hash;
}

inline bool VerifyFilterWrapper(const DispatchSnapshot &code, const Win32kRouteProfile &route, uint32_t index, uint64_t image, uint64_t nt)
{
    const auto address = image + 0x2fcc0 + uint64_t(index) * 176;
    auto bytes = code.Bytes(address, 167);
    if (!bytes || index >= 1497)
    {
        return false;
    }
    const std::pair<unsigned, uint64_t> relative[] = {{0x22, image + 0x73a88},       {0x27, image + 0xce520},
                                                      {0x32, image + route.NameRva}, {0x40, image + 0x73a80},
                                                      {0x45, image + 0xce520},       {0x4c, image + 0x9ca80},
                                                      {0x51, nt + 0x4a1be0},         {0x5c, image + 0xa3330},
                                                      {0x62, image + 0xa5074},       {0x86, image + route.FilterImport},
                                                      {0xa3, image + 0xce400}};
    for (const auto &[offset, target] : relative)
    {
        if (DispatchRelative(address + offset + 4, DispatchU32(*bytes, offset)) != target)
        {
            return false;
        }
        std::fill_n(bytes->begin() + offset, 4, static_cast<unsigned char>(0));
    }
    for (const auto offset : {0x1b, 0x39, 0x69})
    {
        if (DispatchU32(*bytes, offset) != index)
        {
            return false;
        }
        std::fill_n(bytes->begin() + offset, 4, static_cast<unsigned char>(0));
    }
    return std::equal(bytes->begin(), bytes->end(), Win32kFilterTemplate.begin());
}

struct Win32kSessionView
{
    uint32_t Id;
    uint64_t Slot;
    uint64_t Root;
    std::optional<uint64_t> Api;
};

struct Win32kDispatchTarget
{
    std::optional<uint64_t> Slot;
    std::optional<uint64_t> Routine;
    const wchar_t *State = L"Unavailable";
};

inline bool KnownDispatch(const Win32kDispatchTarget &target)
{
    const std::wstring_view state(target.State);
    return target.Routine && (state == L"Session dispatch" || state == L"Direct import" || state == L"Not registered");
}

inline uint32_t FilteredServiceReturn(uint8_t value)
{
    const auto signedValue = static_cast<int8_t>(value);
    return signedValue > 0 ? 0xc000001cu : static_cast<uint32_t>(static_cast<int32_t>(signedValue));
}

inline bool DispatchPointer(const TargetArchitecture &architecture, std::optional<uint64_t> pointer)
{
    return pointer && *pointer != 0 && *pointer % 8 == 0 && KernelReadRange(architecture, *pointer, 8);
}

inline Win32kDispatchTarget ResolveWin32kTarget(const DispatchSnapshot &pointers, const DispatchSnapshot &code,
                                                const TargetArchitecture &architecture, const Win32kRouteProfile &route,
                                                const Win32kSessionView &session, uint64_t image, bool verified)
{
    Win32kDispatchTarget result;
    if (!verified)
    {
        result.State = L"Thunk code unavailable or changed";
        return result;
    }
    if (route.Import)
    {
        result.Slot = image + route.Import;
        const auto jump = code.Number(image + route.Entry + 8, 4);
        const auto imported = pointers.Number(*result.Slot);
        if (jump)
        {
            result.Routine = DispatchRelative(image + route.Entry + 12, static_cast<uint32_t>(*jump));
        }
        result.State = result.Routine && imported && result.Routine == imported ? L"Direct import" : L"Import and direct jump differ";
    }
    else if (DispatchPointer(architecture, session.Api))
    {
        const auto host = pointers.Number(*session.Api + route.Host);
        if (DispatchPointer(architecture, host))
        {
            result.Slot = *host + route.Target;
            result.Routine = pointers.Number(*result.Slot);
            result.State = !result.Routine ? L"Target unreadable" : *result.Routine == 0 ? L"Not registered" : L"Session dispatch";
        }
    }
    if (result.Routine && *result.Routine != 0 && !architecture.KernelPointer(*result.Routine))
    {
        result.State = L"Invalid dispatch target";
    }
    return result;
}

template <typename Hash, typename Emit>
void CollectWin32kDispatch(TargetReader &reader, const TargetArchitecture &architecture, const OwnershipIndex &owners, uint64_t image,
                           uint64_t nt, uint64_t watchdog, bool filtered, WalkBudget &budget, Hash hash, Emit emit)
{
    const auto started = std::chrono::steady_clock::now();
    budget.StartTraversal(started, std::chrono::seconds(120));
    if (!budget.Report.Analysis.IsObject())
    {
        budget.Report.Analysis = knjson::Value::MakeObject();
    }
    DispatchSnapshot pointers, code;
    using Range = DispatchSnapshot::Range;
    std::vector<Range> anchors{{image + 0x89ca0, 8}, {image + 0x89cd8, 8}, {image + 0x89ce0, 4}};
    pointers.Capture(reader, architecture, budget, anchors);
    const auto high = pointers.Number(image + 0x89ca0);
    const auto low = pointers.Number(image + 0x89cd8);
    const auto count = pointers.Number(image + 0x89ce0, 4);
    if (!CheckWalkDeadline(budget))
    {
        return;
    }
    if (!count || !low || !high || *count > 255 || (*count && !DispatchPointer(architecture, high)))
    {
        budget.Stop(Status::Unavailable, L"Win32kSessionSlotsUnavailableOrOverLimit");
        return;
    }
    if (*count)
    {
        pointers.Capture(reader, architecture, budget, {{*high, static_cast<size_t>(*count) * 8}});
    }
    std::vector<Win32kSessionView> sessions;
    std::vector<Range> apiRanges;
    for (uint32_t id = 0; id <= *count && CheckWalkDeadline(budget); ++id)
    {
        const auto slot = id == 0 ? image + 0x89cd8 : *high + uint64_t(id - 1) * 8;
        const auto root = pointers.Number(slot);
        anchors.emplace_back(slot, 8);
        if (root == 0ULL)
        {
            continue;
        }
        if (!DispatchPointer(architecture, root))
        {
            ++budget.Report.Collected.Unknown;
            continue;
        }
        sessions.push_back({id, slot, *root, {}});
        apiRanges.emplace_back(*root + 0x88, 8);
        anchors.emplace_back(*root + 0x88, 8);
    }
    pointers.Capture(reader, architecture, budget, apiRanges);
    std::vector<Range> hosts, terminals;
    for (auto &session : sessions)
    {
        session.Api = pointers.Number(session.Root + 0x88);
        if (!DispatchPointer(architecture, session.Api))
        {
            ++budget.Report.Collected.Unknown;
            continue;
        }
        for (const auto &route : Win32kRoutes)
        {
            if (!route.Import)
            {
                hosts.emplace_back(*session.Api + route.Host, 8);
                anchors.emplace_back(*session.Api + route.Host, 8);
            }
        }
    }
    pointers.Capture(reader, architecture, budget, hosts);
    for (const auto &session : sessions)
    {
        for (const auto &route : Win32kRoutes)
        {
            if (route.Import)
            {
                terminals.emplace_back(image + route.Import, 8);
            }
            else if (DispatchPointer(architecture, session.Api))
            {
                const auto host = pointers.Number(*session.Api + route.Host);
                if (DispatchPointer(architecture, host))
                {
                    terminals.emplace_back(*host + route.Target, 8);
                }
            }
            if (filtered && route.FilterImport)
            {
                terminals.emplace_back(image + route.FilterImport, 8);
            }
        }
    }
    pointers.Capture(reader, architecture, budget, terminals);
    if (filtered)
    {
        pointers.Capture(reader, architecture, budget, {{image + 0x73a80, 16}, {image + 0xa4a94, 1497}});
    }
    std::vector<Range> instructions;
    for (size_t i = 0; i < Win32kRoutes.size(); ++i)
    {
        const auto &route = Win32kRoutes[i];
        instructions.emplace_back(image + route.Entry, route.Size);
        if (filtered && i < 1497)
        {
            instructions.emplace_back(image + 0x2fcc0 + i * 176, 167);
        }
    }
    code.Capture(reader, architecture, budget, instructions);
    const std::array<uint64_t, 7> calls{0, nt + 0x45d7c0, nt + 0x2cb700, nt + 0xc79860, nt + 0x5438f0, watchdog, 0};
    std::vector<bool> verified, filterVerified;
    for (size_t i = 0; i < Win32kRoutes.size() && CheckWalkDeadline(budget); ++i)
    {
        verified.push_back(VerifyDispatchRoute(code, Win32kRoutes[i], image, calls, hash));
        if (i < 1497)
        {
            filterVerified.push_back(filtered && VerifyFilterWrapper(code, Win32kRoutes[i], static_cast<uint32_t>(i), image, nt));
        }
    }
    DispatchSnapshot tables;
    tables.Capture(reader, architecture, budget, {{image + 0xa1000, 4096}, {image + 0xa2000, 1892}});
    if (filtered)
    {
        tables.Capture(reader, architecture, budget, {{image + 0xa3330, 4096}, {image + 0xa4330, 1892}});
    }
    budget.Report.Collected.Expected += sessions.size() * 1497 * (filtered ? 2 : 1);
    for (const auto &session : sessions)
    {
        if (!CheckWalkDeadline(budget))
        {
            break;
        }
        const auto predicate = ResolveWin32kTarget(pointers, code, architecture, Win32kRoutes[1497], session, image, verified[1497]);
        const auto handler = ResolveWin32kTarget(pointers, code, architecture, Win32kRoutes[1498], session, image, verified[1498]);
        for (uint32_t i = 0; i < 1497 && CheckWalkDeadline(budget); ++i)
        {
            const auto &route = Win32kRoutes[i];
            const auto target = ResolveWin32kTarget(pointers, code, architecture, route, session, image, verified[i]);
            for (unsigned variant = 0; variant < (filtered ? 2u : 1u) && CheckWalkDeadline(budget); ++variant)
            {
                if (budget.Report.Rows.Items().size() >= 65536 || budget.Report.Collected.Visited >= budget.MaxNodes)
                {
                    budget.Stop(Status::Partial, L"Win32kDispatchRowBudget");
                    break;
                }
                const auto table = image + (variant ? 0xa3330 : 0xa1000);
                const auto encoded = tables.Number(table + uint64_t(i) * 4, 4);
                const auto expectedEntry = image + (variant ? 0x2fcc0 + i * 176 : route.Entry);
                const auto entry =
                    encoded ? std::optional<uint64_t>(DecodeServiceEntry(table, static_cast<int32_t>(*encoded))) : std::nullopt;
                const auto imported = variant ? pointers.Number(image + route.FilterImport) : std::nullopt;
                const bool bridge = !variant || imported == (route.Import ? target.Routine : std::optional<uint64_t>(image + route.Entry));
                const bool helpers =
                    !variant || (pointers.Number(image + 0x73a88) == image + 0x9930 &&
                                 pointers.Number(image + 0x73a80) == image + 0x19320 && KnownDispatch(predicate) && KnownDispatch(handler));
                const bool decoded = entry == expectedEntry && verified[i] && (!variant || filterVerified[i]) && bridge && helpers;
                ++budget.Report.Collected.Visited;
                if (encoded)
                {
                    ++budget.Report.Collected.Read;
                }
                else
                {
                    ++budget.Report.Collected.Unreadable;
                }
                if (decoded)
                {
                    ++budget.Report.Collected.Decoded;
                }
                auto row = RoutineObservation(budget.Report, architecture, owners, variant ? L"FilteredShadowSSDT" : L"ShadowSSDT",
                                              table + uint64_t(i) * 4, decoded ? target.Routine : std::nullopt, RoutinePresence::Optional);
                const std::wstring state = decoded ? target.State : L"Table, thunk or import unverified";
                if (decoded && state != L"Session dispatch" && state != L"Direct import" && state != L"Not registered")
                {
                    ++budget.Report.Collected.Unknown;
                }
                row.Set(L"index", knjson::Value(std::to_wstring(i)));
                row.Set(L"serviceId", knjson::Value(Hex(0x1000 + i)));
                row.Set(L"serviceName", knjson::Value(route.Name));
                row.Set(L"session", knjson::Value(std::to_wstring(session.Id)));
                row.Set(L"sessionId", knjson::Value(std::to_wstring(session.Id)));
                row.Set(L"sessionState", knjson::Value(Hex(session.Root)));
                row.Set(L"sessionApi", OptionalNumber(session.Api, true));
                row.Set(L"entryRoutine", OptionalNumber(entry, true));
                row.Set(L"dispatchSlot", decoded ? OptionalNumber(target.Slot, true) : knjson::Value());
                row.Set(L"dispatchState", knjson::Value(variant && decoded ? L"Conditional: " + state : state));
                row.Set(L"serviceTable", knjson::Value(Hex(table)));
                row.Set(L"encodedEntry", OptionalNumber(encoded, true));
                row.Set(L"profile", knjson::Value(L"WIN32K-28000.2952-session-dispatch"));
                if (decoded && route.Entry == 0x18910)
                {
                    row.Set(L"conditionalFallback", knjson::Value(Hex(watchdog)));
                }
                if (variant)
                {
                    row.Set(L"filterPredicate", OptionalNumber(predicate.Routine, true));
                    row.Set(L"filterHandler", OptionalNumber(handler.Routine, true));
                    row.Set(L"filterImport", OptionalNumber(imported, true));
                    const auto rawReturn = pointers.Number(image + 0xa4a94 + i, 1);
                    row.Set(L"filteredReturn",
                            rawReturn ? knjson::Value(Hex(FilteredServiceReturn(static_cast<uint8_t>(*rawReturn)))) : knjson::Value());
                    if (!rawReturn)
                    {
                        ++budget.Report.Collected.Unknown;
                    }
                }
                emit(row);
            }
        }
    }
    DispatchSnapshot final;
    final.Capture(reader, architecture, budget, anchors);
    for (const auto &[address, bytes] : anchors)
    {
        if (CheckWalkDeadline(budget) && final.Number(address, bytes) != pointers.Number(address, bytes))
        {
            budget.Stop(Status::StaleContext, L"Win32kSessionBindingsChanged");
            break;
        }
    }
    budget.Report.Analysis.Set(L"win32kSessions", knjson::Value(std::to_wstring(sessions.size())));
    budget.Report.Analysis.Set(
        L"dispatchTraversalMs",
        knjson::Value(
            std::to_wstring(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count())));
}
} // namespace kncore
