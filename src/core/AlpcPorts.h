#pragma once

#include "NamespaceWalk.h"
#include "Piddb.h"
#include <map>

namespace kncore
{
inline constexpr auto AlpcTraversalTimeout = std::chrono::seconds(180);

inline void StartAlpcTraversal(WalkBudget &budget, std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now())
{
    // Serial KD latency varies; all ports and names share one cancellable bound.
    budget.StartTraversal(now, AlpcTraversalTimeout);
}

struct AlpcPortLayout
{
    NamespaceLayout Names;
    std::optional<FieldInfo> Links, Communication, Owner, State, Initialized, Type, Connection, Server, Client;

    bool Valid() const
    {
        const auto bit = [](const std::optional<FieldInfo> &field, unsigned offset, unsigned width)
        {
            return field && field->Offset == 0x1a0 && field->Size == 4 && field->Kind == FieldKind::Unsigned &&
                   field->BitOffset == offset && field->BitWidth == width && field->ValidFor(0x1d8);
        };
        return Names.Valid() && PiddbFieldMatches(Links, 0, 16, FieldKind::Composite) &&
               PiddbFieldMatches(Communication, 0x10, 8, FieldKind::Pointer) && PiddbFieldMatches(Owner, 0x18, 8, FieldKind::Pointer) &&
               PiddbFieldMatches(State, 0x1a0, 4, FieldKind::Unsigned) && bit(Initialized, 0, 1) && bit(Type, 1, 2) &&
               PiddbFieldMatches(Connection, 0, 8, FieldKind::Pointer) && PiddbFieldMatches(Server, 8, 8, FieldKind::Pointer) &&
               PiddbFieldMatches(Client, 16, 8, FieldKind::Pointer);
    }
};

struct AlpcName
{
    std::wstring State = L"Unknown";
    std::wstring Path;
};

// Directory components are cached only for this collection. No target-wide cache is retained.
class AlpcObjectNames
{
  public:
    AlpcObjectNames(TargetReader &reader, const TargetArchitecture &architecture, const NamespaceLayout &layout, uint64_t root,
                    uint8_t cookie, const std::array<uint8_t, 4> &offsets, unsigned directoryType, WalkBudget &budget)
        : reader_(reader), architecture_(architecture), layout_(layout), root_(root), cookie_(cookie), offsets_(offsets),
          directoryType_(directoryType), budget_(budget)
    {
    }

    AlpcName Resolve(uint64_t body, uint8_t mask)
    {
        if ((mask & 2) == 0)
        {
            return {L"Unnamed", {}};
        }
        auto part = ReadPart(body, mask);
        if (!part)
        {
            return {};
        }
        std::wstring path = part->Name;
        uint64_t parent = part->Parent;
        std::set<uint64_t> seen{body};
        for (unsigned depth = 0; depth < 32 && CheckWalkDeadline(budget_); ++depth)
        {
            if (parent == root_)
            {
                return {L"Named", L"\\" + path};
            }
            if (!seen.insert(parent).second || !KernelReadRange(architecture_, parent, 1) || parent % 8 != 0)
            {
                break;
            }
            const auto cached = directories_.find(parent);
            if (cached == directories_.end())
            {
                if (directories_.size() >= 4096 || parent < layout_.Body->Offset)
                {
                    break;
                }
                const uint64_t header = parent - layout_.Body->Offset;
                const auto bytes = reader_.Read(AddressSpace::Virtual, header + layout_.Type->Offset, 3);
                const auto type = BlockValue(bytes, 0, 1);
                const auto parentMask = BlockValue(bytes, 2, 1);
                if (!type || !parentMask || static_cast<uint8_t>(*type ^ cookie_ ^ (header >> 8)) != directoryType_)
                {
                    break;
                }
                directories_[parent] = ReadPart(parent, static_cast<uint8_t>(*parentMask));
            }
            const auto &component = directories_.at(parent);
            if (!component)
            {
                break;
            }
            path = component->Name + L"\\" + path;
            parent = component->Parent;
        }
        return {};
    }

    size_t DirectoriesRead() const
    {
        return directories_.size();
    }

  private:
    using Component = NamespaceNamePart;

    std::optional<Component> ReadPart(uint64_t body, uint8_t mask)
    {
        const auto offset = offsets_[mask & 3];
        if ((mask & 2) == 0 || body < layout_.Body->Offset + offset || offset < layout_.NameInfoSize || !CheckWalkDeadline(budget_))
        {
            return {};
        }
        const auto header = body - layout_.Body->Offset;
        return ReadNamespaceNamePart(reader_, architecture_, layout_, header, offset, {}, &budget_);
    }

    TargetReader &reader_;
    const TargetArchitecture &architecture_;
    const NamespaceLayout &layout_;
    uint64_t root_;
    uint8_t cookie_;
    const std::array<uint8_t, 4> &offsets_;
    unsigned directoryType_;
    WalkBudget &budget_;
    std::map<uint64_t, std::optional<Component>> directories_;
};

template <typename Emit>
void CollectAlpcPorts(TargetReader &reader, const TargetArchitecture &architecture, const AlpcPortLayout &layout, uint64_t head,
                      uint64_t root, uint64_t cookieAddress, uint64_t offsetsAddress, unsigned portType, unsigned directoryType,
                      WalkBudget &budget, Emit emit)
{
    const auto begin = std::chrono::steady_clock::now();
    StartAlpcTraversal(budget, begin);
    uint8_t cookie = 0;
    std::array<uint8_t, 4> offsets{};
    std::array<uint64_t, 2> links{};
    if (!CheckWalkDeadline(budget))
    {
        return;
    }
    if (!layout.Valid() || portType == 0 || portType > 255 || directoryType == 0 || directoryType > 255 || portType == directoryType ||
        !KernelReadRange(architecture, head, 16) || head % 8 != 0 || !KernelReadRange(architecture, root, 1) || root % 8 != 0 ||
        !KernelReadRange(architecture, cookieAddress, 1) || !KernelReadRange(architecture, offsetsAddress, 4))
    {
        budget.Stop(Status::Unavailable, L"AlpcPortLayoutUnavailable");
        return;
    }
    const bool initialized = reader.ReadExact(AddressSpace::Virtual, head, &links) &&
                             CheckWalkDeadline(budget) && reader.ReadExact(AddressSpace::Virtual, cookieAddress, &cookie) &&
                             CheckWalkDeadline(budget) &&
                             reader.ReadExact(AddressSpace::Virtual, offsetsAddress, &offsets);
    if (!CheckWalkDeadline(budget))
    {
        return;
    }
    const auto rootType = initialized ? ReadField(reader, root - layout.Names.Body->Offset, layout.Names.Type) : std::nullopt;
    if (!CheckWalkDeadline(budget))
    {
        return;
    }
    if (!rootType || static_cast<uint8_t>(*rootType ^ cookie ^ ((root - layout.Names.Body->Offset) >> 8)) != directoryType)
    {
        budget.Stop(Status::Unavailable, L"AlpcObjectDecoderUnavailable");
        return;
    }
    NamespaceReadMeter recordReads(reader), stateReads(reader), nameReads(reader), communicationReads(reader);
    AlpcObjectNames names(nameReads, architecture, layout.Names, root, cookie, offsets, directoryType, budget);
    const bool reuseCommunication = budget.Report.Consistency == L"stopped" || budget.Report.Consistency == L"dump";
    std::map<uint64_t, std::array<uint64_t, 3>> communicationCache;
    uint64_t communicationCacheHits = 0;
    uint64_t previous = head;
    uint64_t node = links[0];
    uint64_t named = 0;
    uint64_t unnamed = 0;
    const auto pointer = [&](std::optional<uint64_t> value, bool allowNull = true) -> std::optional<uint64_t>
    {
        return value && ((allowNull && *value == 0) || (architecture.KernelPointer(*value) && *value % 8 == 0)) ? value : std::nullopt;
    };
    while (node != head && CheckWalkDeadline(budget))
    {
        if (!KernelReadRange(architecture, node, 0x1a4) || !KernelReadRange(architecture, node - 0x30, 0x30) ||
            !budget.Consume(node, architecture))
        {
            if (!budget.Stopped)
            {
                budget.Stop(Status::Partial, L"InvalidAlpcPortAddress");
            }
            break;
        }
        // One bounded read covers the header, list/owner fields and port state.
        auto record = recordReads.Read(AddressSpace::Virtual, node - 0x18, 0x18 + layout.State->Offset + layout.State->Size);
        if (!CheckWalkDeadline(budget))
        {
            break;
        }
        auto state = BlockValue(record, 0x18 + layout.State->Offset, layout.State->Size);
        if (!BlockValue(record, 0, 1) || !BlockValue(record, 2, 1) || !BlockValue(record, 0x18, 8) ||
            !BlockValue(record, 0x20, 8) || !BlockValue(record, 0x28, 8) || !BlockValue(record, 0x30, 8))
        {
            // Sparse dumps or short transfers can still supply the original fields.
            record = recordReads.Read(AddressSpace::Virtual, node - 0x18, 0x38);
            if (!CheckWalkDeadline(budget))
            {
                break;
            }
        }
        const auto next = BlockValue(record, 0x18, 8);
        const auto back = BlockValue(record, 0x20, 8);
        if (!next || !back)
        {
            ++budget.Report.Collected.Unreadable;
            budget.Stop(Status::Partial, L"AlpcPortLinksUnreadable");
            break;
        }
        if (*back != previous)
        {
            budget.Stop(Status::Partial, L"InconsistentAlpcPortBacklink");
            break;
        }
        const auto body = node;
        previous = node;
        node = *next;
        ++budget.Report.Collected.Read;
        const auto rawType = BlockValue(record, 0, 1);
        const auto mask = BlockValue(record, 2, 1);
        if (!rawType || static_cast<uint8_t>(*rawType ^ cookie ^ ((body - layout.Names.Body->Offset) >> 8)) != portType)
        {
            ++budget.Report.Collected.Unknown;
            continue;
        }
        ++budget.Report.Collected.Decoded;
        const auto owner = pointer(BlockValue(record, 0x30, 8), false);
        const auto communication = pointer(BlockValue(record, 0x28, 8));
        if (!state)
        {
            state = ReadField(stateReads, body, layout.State);
        }
        if (!CheckWalkDeadline(budget))
        {
            break;
        }
        const unsigned kind = state && (*state & 1) ? static_cast<unsigned>((*state >> 1) & 3) : 0;
        const auto name = mask ? names.Resolve(body, static_cast<uint8_t>(*mask)) : AlpcName{};
        if (!CheckWalkDeadline(budget))
        {
            break;
        }
        std::optional<uint64_t> connection, server, client;
        if (communication == 0)
        {
            connection = server = client = 0;
        }
        else if (communication && KernelReadRange(architecture, *communication, 24))
        {
            const auto cached = communicationCache.find(*communication);
            if (cached != communicationCache.end())
            {
                connection = cached->second[0];
                server = cached->second[1];
                client = cached->second[2];
                ++communicationCacheHits;
            }
            else
            {
                const auto info = communicationReads.Read(AddressSpace::Virtual, *communication, 24);
                connection = pointer(BlockValue(info, 0, 8));
                server = pointer(BlockValue(info, 8, 8));
                client = pointer(BlockValue(info, 16, 8));
                // Cache only complete, validated triples from this stable collection.
                if (reuseCommunication && communicationCache.size() < 4096 && ExactBytes(info, 24) && connection && server && client &&
                    CheckWalkDeadline(budget))
                {
                    communicationCache.emplace(*communication, std::array<uint64_t, 3>{*connection, *server, *client});
                }
            }
        }
        if (!CheckWalkDeadline(budget))
        {
            break;
        }
        named += name.State == L"Named";
        unnamed += name.State == L"Unnamed";
        if (!owner || !communication || !state || kind == 0 || name.State == L"Unknown" || !connection || !server || !client)
        {
            ++budget.Report.Collected.Unknown;
        }
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"AlpcPort"));
        row.Set(L"address", knjson::Value(Hex(body)));
        row.Set(L"name", name.State == L"Named" ? knjson::Value(name.Path) : knjson::Value());
        row.Set(L"nameState", knjson::Value(name.State));
        row.Set(L"portType", kind ? knjson::Value(kind == 1   ? L"Connection"
                                                  : kind == 2 ? L"Client communication"
                                                              : L"Server communication")
                                  : knjson::Value());
        row.Set(L"portStateRaw", OptionalNumber(state, true));
        row.Set(L"ownerProcess", OptionalNumber(owner, true));
        row.Set(L"communicationInfo", OptionalNumber(communication, true));
        row.Set(L"connectionPort", OptionalNumber(connection, true));
        row.Set(L"serverPort", OptionalNumber(server, true));
        row.Set(L"clientPort", OptionalNumber(client, true));
        row.Set(L"peerPort", OptionalNumber(kind == 2   ? server
                                            : kind == 3 ? client
                                            : kind == 1 ? std::optional<uint64_t>(0)
                                                        : std::nullopt,
                                            true));
        row.Set(L"source", knjson::Value(L"AlpcpPortList"));
        emit(row);
    }
    if (CheckWalkDeadline(budget) && previous != links[1])
    {
        budget.Stop(Status::Partial, L"InconsistentAlpcPortHeadBacklink");
    }
    if (CheckWalkDeadline(budget))
    {
        std::array<uint64_t, 2> finalLinks{};
        uint8_t finalCookie = 0;
        std::array<uint8_t, 4> finalOffsets{};
        const bool stable = reader.ReadExact(AddressSpace::Virtual, head, &finalLinks) && finalLinks == links &&
                            CheckWalkDeadline(budget) && reader.ReadExact(AddressSpace::Virtual, cookieAddress, &finalCookie) &&
                            finalCookie == cookie && CheckWalkDeadline(budget) &&
                            reader.ReadExact(AddressSpace::Virtual, offsetsAddress, &finalOffsets) && finalOffsets == offsets;
        if (CheckWalkDeadline(budget) && !stable)
        {
            budget.Stop(Status::StaleContext, L"AlpcPortListOrDecoderChanged");
        }
    }
    if (CheckWalkDeadline(budget) && (budget.Report.Collected.Unknown || budget.Report.Collected.Unreadable))
    {
        budget.Stop(Status::Partial, L"AlpcPortFieldsUnavailable");
    }
    budget.Report.Analysis = knjson::Value::MakeObject();
    budget.Report.Analysis.Set(L"namedPorts", knjson::Value(std::to_wstring(named)));
    budget.Report.Analysis.Set(L"unnamedPorts", knjson::Value(std::to_wstring(unnamed)));
    budget.Report.Analysis.Set(L"nameDirectoriesRead", knjson::Value(std::to_wstring(names.DirectoriesRead())));
    budget.Report.Analysis.Set(L"traversalLimitMs", knjson::Value(std::to_wstring(
        std::chrono::duration_cast<std::chrono::milliseconds>(AlpcTraversalTimeout).count())));
    budget.Report.Analysis.Set(L"communicationCacheHits", knjson::Value(std::to_wstring(communicationCacheHits)));
    budget.Report.Analysis.Set(L"communicationCacheEntries", knjson::Value(std::to_wstring(communicationCache.size())));
    for (const auto &[name, meter] : {std::pair(L"record", &recordReads), std::pair(L"state", &stateReads),
                                     std::pair(L"name", &nameReads), std::pair(L"communication", &communicationReads)})
    {
        auto measured = knjson::Value::MakeObject();
        measured.Set(L"readRequests", knjson::Value(std::to_wstring(meter->Requests)));
        measured.Set(L"requestedBytes", knjson::Value(std::to_wstring(meter->Bytes)));
        measured.Set(L"readElapsedMs", knjson::Value(std::to_wstring(
            std::chrono::duration_cast<std::chrono::milliseconds>(meter->Elapsed).count())));
        budget.Report.Analysis.Set(name, std::move(measured));
    }
    budget.Report.Analysis.Set(
        L"traversalElapsedMs",
        knjson::Value(
            std::to_wstring(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count())));
    budget.Complete();
}

inline void AttachAlpcConnectionNames(Result &report)
{
    std::map<std::wstring, std::wstring> names;
    for (const auto &row : report.Rows.Items())
    {
        if (row.Get(L"nameState").AsString(L"") == L"Named" && row.Get(L"name").IsString())
        {
            names[row.Get(L"address").AsString(L"")] = row.Get(L"name").AsString(L"");
        }
    }
    auto rows = knjson::Value::MakeArray();
    for (auto row : report.Rows.Items())
    {
        const auto name = names.find(row.Get(L"connectionPort").AsString(L""));
        row.Set(L"connectionName", name != names.end() ? knjson::Value(name->second) : knjson::Value());
        rows.Push(row);
    }
    report.Rows = std::move(rows);
}
} // namespace kncore
