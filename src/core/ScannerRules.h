#pragma once

#include "CollectorRead.h"
#include "Ownership.h"

namespace kncore
{
inline void StartMinifilterTraversal(WalkBudget &budget,
                                    std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now())
{
    // All frames, filters and operation arrays share one cancellable deadline.
    budget.StartTraversal(now, std::chrono::seconds(60));
}

inline std::optional<uint32_t> MandatoryLabelRid(std::span<const unsigned char> sid)
{
    if (sid.size() != 12 || sid[0] != 1 || sid[1] != 1 || sid[2] != 0 || sid[3] != 0 || sid[4] != 0 || sid[5] != 0 || sid[6] != 0 ||
        sid[7] != 16)
    {
        return {};
    }
    uint32_t value = 0;
    std::memcpy(&value, sid.data() + 8, 4);
    return value;
}

struct IdtGate
{
    bool Present = false;
    bool Valid = false;
    uint64_t Handler = 0;
    unsigned Type = 0;
    unsigned Dpl = 0;
    unsigned Ist = 0;
};

inline IdtGate DecodeIdt(std::span<const unsigned char> bytes)
{
    IdtGate gate;
    if (bytes.size() != 16)
    {
        return gate;
    }
    gate.Present = (bytes[5] & 0x80) != 0;
    gate.Type = bytes[5] & 15;
    gate.Dpl = (bytes[5] >> 5) & 3;
    gate.Ist = bytes[4] & 7;
    gate.Valid = !gate.Present || ((gate.Type == 14 || gate.Type == 15) && (bytes[4] & 0xf8) == 0 && (bytes[5] & 0x10) == 0 &&
                                   bytes[12] == 0 && bytes[13] == 0 && bytes[14] == 0 && bytes[15] == 0);
    uint32_t high = 0;
    std::memcpy(&high, bytes.data() + 8, sizeof(high));
    gate.Handler = bytes[0] | (uint64_t(bytes[1]) << 8) | (uint64_t(bytes[6]) << 16) | (uint64_t(bytes[7]) << 24) | (uint64_t(high) << 32);
    return gate;
}

inline std::optional<uint64_t> DecodeServiceEntry(uint64_t table, int32_t encoded)
{
    const int64_t delta = static_cast<int64_t>(encoded) >> 4;
    if ((delta < 0 && static_cast<uint64_t>(-delta) > table) || (delta >= 0 && static_cast<uint64_t>(delta) > UINT64_MAX - table))
    {
        return {};
    }
    return delta < 0 ? table - static_cast<uint64_t>(-delta) : table + static_cast<uint64_t>(delta);
}

inline std::optional<FieldInfo> ArrayElement(const std::optional<FieldInfo> &array, uint32_t index, bool leaf = false)
{
    if (!array || array->Kind != FieldKind::Array || !array->ValidFor(UINT32_MAX) || array->BitOffset || array->BitWidth)
    {
        return {};
    }
    const auto stride = leaf ? array->LeafElementSize : array->ElementSize;
    if (!stride || *stride == 0 || array->Size % *stride != 0 || index >= array->Size / *stride ||
        static_cast<uint64_t>(array->Offset) + static_cast<uint64_t>(index) * *stride > UINT32_MAX)
    {
        return {};
    }
    FieldInfo element;
    element.Offset = array->Offset + index * *stride;
    element.Size = *stride;
    element.Source = array->Source;
    if (leaf || array->ArrayDimensions.size() == 1)
    {
        element.Kind = array->LeafKind;
        element.TypeName = array->LeafTypeName;
    }
    else if (array->ArrayDimensions.size() > 1)
    {
        element.Kind = FieldKind::Array;
        element.ArrayDimensions.assign(array->ArrayDimensions.begin() + 1, array->ArrayDimensions.end());
        element.ArrayCount = element.ArrayDimensions.front();
        element.ElementSize = element.Size / *element.ArrayCount;
        element.LeafElementSize = array->LeafElementSize;
        element.LeafKind = array->LeafKind;
        element.LeafTypeName = array->LeafTypeName;
    }
    return element.ValidFor(UINT32_MAX) ? std::optional<FieldInfo>(element) : std::nullopt;
}

enum class RoutinePresence
{
    Required,
    Optional
};

inline knjson::Value RoutineObservation(Result &report, const TargetArchitecture &architecture, const OwnershipIndex &owners,
                                        const std::wstring &family, uint64_t slot, std::optional<uint64_t> routine,
                                        RoutinePresence presence = RoutinePresence::Required)
{
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"RoutineObservation"));
    row.Set(L"family", knjson::Value(family));
    row.Set(L"slot", knjson::Value(Hex(slot)));
    row.Set(L"routine", OptionalNumber(routine, true));
    if (!routine)
    {
        row.Set(L"ownership", knjson::Value(L"Unknown"));
        ++report.Collected.Unknown;
    }
    else if (*routine == 0)
    {
        row.Set(L"ownership", knjson::Value(presence == RoutinePresence::Optional ? L"NullObserved" : L"NullRequiredRoutine"));
        if (presence == RoutinePresence::Required)
        {
            ++report.Collected.Unknown;
        }
    }
    else if (!architecture.KernelPointer(*routine))
    {
        row.Set(L"ownership", knjson::Value(L"NotCanonicalKernelAddress"));
        ++report.Collected.Unknown;
    }
    else
    {
        const auto owner = owners.Find(*routine, report.Stamp);
        row.Set(L"ownership", knjson::Value(owner.Reason));
        if (owner.Image)
        {
            row.Set(L"module", knjson::Value(owner.Image->Name));
            row.Set(L"moduleIdentity", knjson::Value(owner.Image->Identity));
            row.Set(L"moduleIdentityKind", knjson::Value(L"ImagePathTimestampSize"));
            row.Set(L"rva", knjson::Value(Hex(owner.Rva)));
        }
        if (owner.State == OwnershipState::Unknown)
        {
            ++report.Collected.Unknown;
        }
        else
        {
            ++report.Collected.Classified;
        }
    }
    row.Set(L"interpretation", knjson::Value(L"Address ownership observation; integrity and maliciousness not established"));
    return row;
}
} // namespace kncore
