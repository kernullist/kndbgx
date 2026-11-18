#pragma once

#include "CollectorRead.h"
#include "Walker.h"
#include "WfpNames.h"
#include "../util/HostCollectors.h"
#include "../util/Text.h"
#include <bit>
#include <map>
#include <span>

namespace kncore
{
static_assert(sizeof(FWPS_FILTER3) == 0x40 && offsetof(FWPS_FILTER3, filterCondition) == 0x20 &&
              offsetof(FWPS_FILTER3, action) == 0x28 && offsetof(FWPS_FILTER3, context) == 0x30);
static_assert(sizeof(FWPS_FILTER_CONDITION0) == 0x18 && offsetof(FWPS_FILTER_CONDITION0, conditionValue) == 8);
static_assert(sizeof(FWP_VALUE0) == 16 && sizeof(FWP_BYTE_BLOB) == 16 && sizeof(FWP_RANGE0) == 32);

inline bool WfpTerminalRead(Status state)
{
    return TerminalReadStatus(state);
}

inline uint64_t WfpInteger(std::span<const unsigned char> bytes, size_t offset, size_t width)
{
    uint64_t value = 0;
    if (width <= sizeof(value) && offset <= bytes.size() && width <= bytes.size() - offset)
    {
        std::memcpy(&value, bytes.data() + offset, width);
    }
    return value;
}

inline std::wstring WfpBytesText(std::span<const unsigned char> bytes)
{
    constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring value;
    value.reserve(bytes.size() * 2);
    for (auto byte : bytes)
    {
        value += digits[byte >> 4];
        value += digits[byte & 15];
    }
    return value;
}

inline std::optional<std::wstring> WfpSid(std::span<const unsigned char> bytes, size_t offset)
{
    if (offset > bytes.size() || bytes.size() - offset < 8 || bytes[offset] != 1 || bytes[offset + 1] > 15 ||
        bytes.size() - offset - 8 < size_t(bytes[offset + 1]) * 4)
    {
        return std::nullopt;
    }
    uint64_t authority = 0;
    for (size_t i = 2; i < 8; ++i)
    {
        authority = (authority << 8) | bytes[offset + i];
    }
    std::wstring text = L"S-1-" + std::to_wstring(authority);
    for (size_t i = 0; i < bytes[offset + 1]; ++i)
    {
        text += L"-" + std::to_wstring(WfpInteger(bytes, offset + 8 + i * 4, 4));
    }
    return text;
}

inline std::optional<std::wstring> WfpSecurityDescriptor(std::span<const unsigned char> bytes)
{
    // Parse only bounded self-relative bytes. Never pass target pointers to a host API.
    if (bytes.size() < 20 || bytes[0] != 1 || (WfpInteger(bytes, 2, 2) & 0x8000) == 0)
    {
        return std::nullopt;
    }
    std::wstring text = L"SD";
    for (size_t i = 0; i < 2; ++i)
    {
        const auto offset = size_t(WfpInteger(bytes, 4 + i * 4, 4));
        if (offset != 0)
        {
            if (offset < 20 || offset % 4 != 0)
            {
                return std::nullopt;
            }
            const auto sid = WfpSid(bytes, offset);
            if (!sid)
            {
                return std::nullopt;
            }
            text += (i == 0 ? L" owner=" : L" group=") + *sid;
        }
    }
    for (size_t i = 0; i < 2; ++i)
    {
        const auto control = WfpInteger(bytes, 2, 2);
        const auto offset = size_t(WfpInteger(bytes, 12 + i * 4, 4));
        text += i == 0 ? L" SACL=" : L" DACL=";
        if ((control & (i == 0 ? 0x10 : 0x4)) == 0)
        {
            text += L"Absent";
            continue;
        }
        if (offset == 0)
        {
            text += L"Null";
            continue;
        }
        if (offset < 20 || offset % 4 != 0 || offset > bytes.size() || bytes.size() - offset < 8 ||
            (bytes[offset] != 2 && bytes[offset] != 4))
        {
            return std::nullopt;
        }
        const auto size = size_t(WfpInteger(bytes, offset + 2, 2));
        const auto count = WfpInteger(bytes, offset + 4, 2);
        if (size < 8 || size > bytes.size() - offset)
        {
            return std::nullopt;
        }
        size_t cursor = offset + 8;
        text += L"[";
        for (size_t ace = 0; ace < count; ++ace)
        {
            if (cursor > offset + size || offset + size - cursor < 4)
            {
                return std::nullopt;
            }
            const auto aceSize = size_t(WfpInteger(bytes, cursor + 2, 2));
            if (aceSize < 4 || aceSize % 4 != 0 || aceSize > offset + size - cursor)
            {
                return std::nullopt;
            }
            if (ace != 0)
            {
                text += L"; ";
            }
            const auto type = bytes[cursor];
            if (type <= 3 && aceSize >= 16)
            {
                const auto sid = WfpSid(bytes.subspan(cursor, aceSize), 8);
                if (!sid)
                {
                    return std::nullopt;
                }
                constexpr const wchar_t *names[] = {L"Allow", L"Deny", L"Audit", L"Alarm"};
                text += std::wstring(names[type]) + L" flags=" + Hex(bytes[cursor + 1]) + L" mask=" +
                        Hex(WfpInteger(bytes, cursor + 4, 4)) + L" " + *sid;
            }
            else
            {
                // Preserve unsupported ACE semantics as complete raw bytes, without a verdict.
                text += L"ACE=" + WfpBytesText(bytes.subspan(cursor, aceSize));
            }
            cursor += aceSize;
        }
        text += L"]";
    }
    return text;
}

class WfpReader
{
  public:
    WfpReader(TargetReader &reader, const TargetArchitecture &architecture, WalkBudget &budget)
        : Reader(reader), Architecture(architecture), Budget(budget)
    {
    }

    TargetReader &Reader;
    const TargetArchitecture &Architecture;
    WalkBudget &Budget;
    std::map<std::tuple<uint32_t, uint64_t, bool>, knjson::Value> ValueCache;
    static constexpr size_t MaximumConditionUnits = 2 * 1024 * 1024;
    static constexpr size_t MaximumRowUnits = 4 * 1024 * 1024;
    size_t ConditionUnits = 0;
    size_t RowUnits = 0;

    bool Retain(const knjson::Value &value, bool condition)
    {
        if (Budget.Stopped && Budget.Report.State != Status::Partial)
        {
            return false;
        }
        auto &used = condition ? ConditionUnits : RowUnits;
        const auto limit = condition ? MaximumConditionUnits : MaximumRowUnits;
        const auto size = value.Write().size();
        if (used > limit || size > limit - used)
        {
            return Budget.Stop(Status::Partial, condition ? L"WfpConditionOutputBudget" : L"WfpRowOutputBudget");
        }
        used += size;
        return true;
    }

    bool Check()
    {
        Budget.StartTraversal(std::chrono::steady_clock::now(), std::chrono::seconds(180));
        if (!Budget.Stopped && Budget.Cancelled && Budget.Cancelled())
        {
            Budget.Stop(Status::Cancelled, L"Cancelled");
        }
        if (!Budget.Stopped && std::chrono::steady_clock::now() >= Budget.Deadline)
        {
            Budget.Stop(Status::Partial, L"WfpCollectionDeadline");
        }
        return !Budget.Stopped;
    }

    std::optional<std::vector<unsigned char>> Bytes(uint64_t address, size_t size, bool required = true)
    {
        if (!Check())
        {
            return std::nullopt;
        }
        if (size == 0 || size > 65536 || !Architecture.KernelPointer(address) || !ValidRange(address, size) ||
            !Architecture.KernelPointer(address + size - 1))
        {
            ++Budget.Report.Collected.Unknown;
            if (required)
            {
                Budget.Stop(Status::Partial, L"WfpInvalidRange");
            }
            return std::nullopt;
        }
        const auto read = Reader.Read(AddressSpace::Virtual, address, size);
        if (WfpTerminalRead(read.State))
        {
            Budget.Stop(read.State, L"WfpReadStopped");
            return std::nullopt;
        }
        if (!ExactBytes(read, size))
        {
            ++Budget.Report.Collected.Unreadable;
            if (required)
            {
                Budget.Stop(Status::Partial, L"WfpUnreadableMemory");
            }
            return std::nullopt;
        }
        return read.Bytes;
    }

    std::optional<uint64_t> Integer(uint64_t address, size_t size, bool required = true)
    {
        const auto bytes = Bytes(address, size, required);
        return bytes ? std::optional<uint64_t>(WfpInteger(*bytes, 0, size)) : std::nullopt;
    }

    knjson::Value Value(uint32_t type, uint64_t raw, const std::wstring &field = L"", unsigned depth = 0)
    {
        const auto cacheKey = std::make_tuple(type, raw, field.find(L"APP_ID") != std::wstring::npos);
        const auto cached = ValueCache.find(cacheKey);
        if (depth == 0 && cached != ValueCache.end())
        {
            return cached->second;
        }
        auto result = knjson::Value::MakeObject();
        result.Set(L"type", knjson::Value(std::to_wstring(type)));
        result.Set(L"raw", knjson::Value(Hex(raw)));
        result.Set(L"state", knjson::Value(L"Decoded"));
        std::optional<std::wstring> text;
        do
        {
            if (depth > 1 || !Check())
            {
                break;
            }
            if (type == FWP_EMPTY)
            {
                text = L"Empty";
            }
            else if (type >= FWP_UINT8 && type <= FWP_UINT32)
            {
                const auto value = raw & (type == FWP_UINT8 ? 0xffULL : type == FWP_UINT16 ? 0xffffULL : 0xffffffffULL);
                text = std::to_wstring(value);
            }
            else if (type == FWP_UINT64 || type == FWP_INT64 || type == FWP_DOUBLE)
            {
                const auto value = Integer(raw, 8, false);
                if (value)
                {
                    if (type == FWP_DOUBLE)
                    {
                        text = std::to_wstring(std::bit_cast<double>(*value));
                    }
                    else
                    {
                        text = type == FWP_UINT64 ? std::to_wstring(*value) : std::to_wstring(static_cast<int64_t>(*value));
                    }
                }
            }
            else if (type >= FWP_INT8 && type <= FWP_INT32)
            {
                const int64_t value = type == FWP_INT8 ? static_cast<int8_t>(raw) :
                                      type == FWP_INT16 ? static_cast<int16_t>(raw) : static_cast<int32_t>(raw);
                text = std::to_wstring(value);
            }
            else if (type == FWP_FLOAT)
            {
                text = std::to_wstring(std::bit_cast<float>(static_cast<uint32_t>(raw)));
            }
            else if (type == FWP_RANGE_TYPE)
            {
                const auto bytes = Bytes(raw, 32, false);
                if (bytes)
                {
                    auto low = Value(static_cast<uint32_t>(WfpInteger(*bytes, 0, 4)), WfpInteger(*bytes, 8, 8), field, depth + 1);
                    auto high = Value(static_cast<uint32_t>(WfpInteger(*bytes, 16, 4)), WfpInteger(*bytes, 24, 8), field, depth + 1);
                    result.Set(L"low", low);
                    result.Set(L"high", high);
                    if (!low.Get(L"value").IsNull() && !high.Get(L"value").IsNull())
                    {
                        text = low.Get(L"value").AsString(L"") + L".." + high.Get(L"value").AsString(L"");
                    }
                }
            }
            else if (type == FWP_SID)
            {
                const auto prefix = Bytes(raw, 8, false);
                if (prefix && (*prefix)[1] <= 15)
                {
                    const auto bytes = Bytes(raw, 8 + size_t((*prefix)[1]) * 4, false);
                    if (bytes)
                    {
                        text = WfpSid(*bytes, 0);
                    }
                }
            }
            else if (type == FWP_V4_ADDR_MASK || type == FWP_V6_ADDR_MASK || type == FWP_BYTE_ARRAY16_TYPE || type == FWP_BYTE_ARRAY6_TYPE)
            {
                const auto bytes = Bytes(raw, type == FWP_V4_ADDR_MASK ? 8 : type == FWP_V6_ADDR_MASK ? 17 :
                                              type == FWP_BYTE_ARRAY16_TYPE ? 16 : 6, false);
                if (bytes)
                {
                    if (type == FWP_V4_ADDR_MASK)
                    {
                        const auto ip = [](uint64_t value)
                        {
                            return std::to_wstring((value >> 24) & 255) + L"." + std::to_wstring((value >> 16) & 255) + L"." +
                                   std::to_wstring((value >> 8) & 255) + L"." + std::to_wstring(value & 255);
                        };
                        text = ip(WfpInteger(*bytes, 0, 4)) + L"/" + ip(WfpInteger(*bytes, 4, 4));
                    }
                    else if (type == FWP_V6_ADDR_MASK && (*bytes)[16] <= 128)
                    {
                        text = L"";
                        for (size_t i = 0; i < 16; i += 2)
                        {
                            *text += (i != 0 ? L":" : L"") + WfpBytesText(std::span(*bytes).subspan(i, 2));
                        }
                        *text += L"/" + std::to_wstring((*bytes)[16]);
                    }
                    else if (type != FWP_V6_ADDR_MASK)
                    {
                        text = WfpBytesText(*bytes);
                    }
                }
            }
            else if (type == FWP_BYTE_BLOB_TYPE || type == FWP_SECURITY_DESCRIPTOR_TYPE)
            {
                const auto header = Bytes(raw, 16, false);
                if (!header)
                {
                    break;
                }
                const auto size = size_t(WfpInteger(*header, 0, 4));
                const auto pointer = WfpInteger(*header, 8, 8);
                result.Set(L"byteCount", knjson::Value(std::to_wstring(size)));
                if (size == 0)
                {
                    text = L"Empty";
                    break;
                }
                if (size > 4096)
                {
                    result.Set(L"state", knjson::Value(L"ValueLimitExceeded"));
                    break;
                }
                const auto bytes = Bytes(pointer, size, false);
                if (!bytes)
                {
                    break;
                }
                result.Set(L"bytes", knjson::Value(WfpBytesText(*bytes)));
                if (type == FWP_SECURITY_DESCRIPTOR_TYPE)
                {
                    text = WfpSecurityDescriptor(*bytes);
                }
                else if (field.find(L"APP_ID") != std::wstring::npos && size % 2 == 0)
                {
                    std::wstring name(size / 2, L'\0');
                    std::memcpy(name.data(), bytes->data(), size);
                    while (!name.empty() && name.back() == L'\0')
                    {
                        name.pop_back();
                    }
                    if (ValidUtf16(name, false))
                    {
                        text = name;
                    }
                }
                else
                {
                    text = L"hex:" + WfpBytesText(*bytes);
                }
            }
        } while (false);
        result.Set(L"value", text ? knjson::Value(*text) : knjson::Value());
        if (!text)
        {
            ++Budget.Report.Collected.Unknown;
            if (result.Get(L"state").AsString(L"") == L"Decoded")
            {
                result.Set(L"state", knjson::Value(L"UnavailableOrUnsupportedValue"));
            }
        }
        else if (depth == 0 && ValueCache.size() < 2048)
        {
            ValueCache.emplace(cacheKey, result);
        }
        return result;
    }
};

struct WfpCallout
{
    uint32_t Id = 0;
    uint32_t RegistrationType = 0;
    bool Registered = false;
    bool Added = false;
    uint64_t Classify = 0;
    uint64_t Notify = 0;
    uint64_t FlowDelete = 0;
    uint64_t Device = 0;
    uint16_t Layer = 0;
    uint32_t Flags = 0;
    std::wstring Key;
    uint32_t KeyFlags = 0;
};

inline std::optional<WfpCallout> DecodeWfpCallout(std::span<const unsigned char> bytes, uint32_t id,
                                                const TargetArchitecture &architecture)
{
    if (bytes.size() != 0x60)
    {
        return std::nullopt;
    }
    WfpCallout value;
    value.Id = id;
    value.RegistrationType = static_cast<uint32_t>(WfpInteger(bytes, 0, 4));
    const auto registered = WfpInteger(bytes, 4, 4);
    const auto added = bytes[0xc];
    if (registered > 1 || added > 1 || (registered != 0 && (value.RegistrationType < 1 || value.RegistrationType > 4)))
    {
        return std::nullopt;
    }
    value.Registered = registered != 0;
    value.Added = added != 0;
    if (value.Registered)
    {
        value.Classify = WfpInteger(bytes, value.RegistrationType == 3 ? 0x28 : 0x10, 8);
        value.Notify = WfpInteger(bytes, 0x18, 8);
        value.FlowDelete = WfpInteger(bytes, 0x20, 8);
        value.Device = WfpInteger(bytes, 0x40, 8);
        if (!architecture.KernelPointer(value.Classify))
        {
            return std::nullopt;
        }
        for (const auto pointer : {value.Notify, value.FlowDelete, value.Device})
        {
            if (pointer != 0 && !architecture.KernelPointer(pointer))
            {
                return std::nullopt;
            }
        }
    }
    value.Flags = static_cast<uint32_t>(WfpInteger(bytes, 0x30, 4));
    value.Layer = static_cast<uint16_t>(WfpInteger(bytes, 0x4c, 2));
    return value;
}

struct WfpHashEntry
{
    uint64_t Node = 0;
    uint32_t Layer = 0;
    uint64_t Id = 0;
    uint64_t Internal = 0;
};

inline std::optional<uint64_t> WfpBucketHead(WfpReader &read, uint64_t directory, uint32_t tableSize, uint32_t index)
{
    if (index >= tableSize || tableSize < 128 || tableSize > 65536)
    {
        read.Budget.Stop(Status::Partial, L"WfpInvalidBucketIndex");
        return std::nullopt;
    }
    if (tableSize > 128)
    {
        const uint32_t adjusted = index + 128;
        const uint32_t bit = std::bit_width(adjusted) - 1;
        const auto segment = read.Integer(directory + uint64_t(bit - 7) * 8, 8);
        if (!segment)
        {
            return std::nullopt;
        }
        directory = *segment;
        index = adjusted ^ (1u << bit);
    }
    if (!read.Architecture.KernelPointer(directory) || !ValidRange(directory, uint64_t(index) * 16 + 16))
    {
        read.Budget.Stop(Status::Partial, L"WfpInvalidBucketDirectory");
        return std::nullopt;
    }
    return directory + uint64_t(index) * 16;
}

template <typename Visitor>
bool WalkWfpFilters(WfpReader &read, uint64_t table, uint32_t nameSpace, uint32_t layerCount, Visitor visit,
                    uint64_t &physicalNodes, uint64_t &otherNodes)
{
    auto &budget = read.Budget;
    const auto metadata = read.Bytes(table, 0x28);
    if (!metadata)
    {
        return false;
    }
    const auto size = static_cast<uint32_t>(WfpInteger(*metadata, 8, 4));
    const auto pivot = WfpInteger(*metadata, 0xc, 4);
    const auto mask = WfpInteger(*metadata, 0x10, 4);
    const auto count = WfpInteger(*metadata, 0x14, 4);
    const auto nonempty = WfpInteger(*metadata, 0x18, 4);
    const auto directory = WfpInteger(*metadata, 0x20, 8);
    if (size < 128 || size > 65536 || count > 65536 || nonempty > size || !std::has_single_bit(mask + 1) ||
        pivot > mask || mask + 1 + pivot != size || WfpInteger(*metadata, 4, 4) >= 32 ||
        WfpInteger(*metadata, 0x1c, 4) != 0 || nameSpace == 0 || layerCount == 0 || layerCount > 4096)
    {
        return budget.Stop(Status::Partial, L"WfpInvalidOrEnumeratingHashTable");
    }
    budget.Report.Collected.Expected += count;
    uint64_t observedNonempty = 0;
    std::set<uint64_t> ids;
    for (uint32_t i = 0; i < size && read.Check(); ++i)
    {
        const auto head = WfpBucketHead(read, directory, size, i);
        const auto links = head ? read.Bytes(*head, 16) : std::nullopt;
        if (!links)
        {
            return false;
        }
        auto next = WfpInteger(*links, 0, 8);
        auto previous = *head;
        if (next != *head)
        {
            ++observedNonempty;
        }
        while (next != *head)
        {
            if (!budget.Consume(next, read.Architecture))
            {
                return false;
            }
            // Other namespaces need only the common header, not the filter payload.
            const auto header = read.Bytes(next, 0x20);
            if (!header)
            {
                return false;
            }
            if (WfpInteger(*header, 8, 8) != previous || WfpInteger(*header, 0x10, 8) == 0)
            {
                return budget.Stop(Status::Partial, L"WfpHashBacklinkOrSignatureMismatch");
            }
            ++physicalNodes;
            ++budget.Report.Collected.Read;
            if (WfpInteger(*header, 0x18, 4) == nameSpace)
            {
                const auto payload = read.Bytes(next + 0x20, 16);
                if (!payload)
                {
                    return false;
                }
                WfpHashEntry entry{next, static_cast<uint32_t>(WfpInteger(*header, 0x1c, 4)),
                                   WfpInteger(*payload, 0, 8), WfpInteger(*payload, 8, 8)};
                if (entry.Layer >= layerCount || !read.Architecture.KernelPointer(entry.Internal) || !ids.insert(entry.Id).second)
                {
                    return budget.Stop(Status::Partial, L"WfpInvalidOrDuplicateFilter");
                }
                if (!visit(entry))
                {
                    return false;
                }
            }
            else
            {
                ++otherNodes;
            }
            previous = next;
            next = WfpInteger(*header, 0, 8);
        }
        if (WfpInteger(*links, 8, 8) != previous)
        {
            return budget.Stop(Status::Partial, L"WfpHashTailMismatch");
        }
    }
    if (!read.Check())
    {
        return false;
    }
    if (physicalNodes != count || observedNonempty != nonempty)
    {
        return budget.Stop(Status::Partial, L"WfpHashCountMismatch");
    }
    const auto after = read.Bytes(table, 0x28);
    if (!after || *after != *metadata)
    {
        return budget.Stopped ? false : budget.Stop(Status::Partial, L"WfpHashChangedDuringRead");
    }
    return true;
}
inline void WfpSetCalloutFields(knjson::Value &row, const kncore::WfpCallout &callout)
{
    row.Set(L"calloutId", knjson::Value(std::to_wstring(callout.Id)));
    row.Set(L"calloutKey", callout.Key.empty() ? knjson::Value() : knjson::Value(callout.Key));
    row.Set(L"registered", knjson::Value(callout.Registered));
    row.Set(L"policyEntryPresent", knjson::Value(callout.Added));
    row.Set(L"registrationTypeRaw", knjson::Value(std::to_wstring(callout.RegistrationType)));
    row.Set(L"classifyRoutine", knjson::Value(kncore::Hex(callout.Classify)));
    row.Set(L"notifyRoutine", knjson::Value(kncore::Hex(callout.Notify)));
    row.Set(L"flowDeleteRoutine", knjson::Value(kncore::Hex(callout.FlowDelete)));
    row.Set(L"device", knjson::Value(kncore::Hex(callout.Device)));
}

inline bool ReadWfpCallouts(kncore::WfpReader &read, uint64_t table, uint32_t capacity, uint64_t keyTable, uint32_t keyCapacity,
                  uint32_t layerCount, std::map<uint32_t, kncore::WfpCallout> &callouts)
{
    using namespace kncore;
    if (capacity == 0 || capacity > 65536 || keyCapacity > 65536 || keyCapacity == 0 ||
        !ValidRange(table, uint64_t(capacity) * 0x60) || !ValidRange(keyTable, uint64_t(keyCapacity) * 0x28))
    {
        return read.Budget.Stop(Status::Partial, L"WfpInvalidCalloutCapacity");
    }
    read.Budget.Report.Collected.Expected += capacity;
    for (uint32_t first = 0; first < capacity && read.Check(); first += 64)
    {
        const auto count = (std::min)(64u, capacity - first);
        const auto bytes = read.Bytes(table + uint64_t(first) * 0x60, count * 0x60);
        if (!bytes)
        {
            return false;
        }
        for (uint32_t i = 0; i < count; ++i)
        {
            const auto id = first + i;
            if (!read.Budget.Consume(table + uint64_t(id) * 0x60, read.Architecture))
            {
                return false;
            }
            ++read.Budget.Report.Collected.Read;
            const auto entry = std::span(*bytes).subspan(i * 0x60, 0x60);
            if (WfpInteger(entry, 4, 4) == 0 && entry[0xc] == 0)
            {
                continue;
            }
            auto callout = DecodeWfpCallout(entry, id, read.Architecture);
            if (!callout || (callout->Added && callout->Layer >= layerCount))
            {
                return read.Budget.Stop(Status::Partial, L"WfpInvalidCalloutRecord");
            }
            if (id >= keyCapacity)
            {
                return read.Budget.Stop(Status::Partial, L"WfpCalloutKeyMissing");
            }
            const auto key = read.Bytes(keyTable + uint64_t(id) * 0x28, 0x28);
            if (!key)
            {
                return false;
            }
            const auto state = WfpInteger(*key, 0x20, 4);
            if (WfpInteger(*key, 0x10, 4) != id || (state & 1) == 0 || (state & 2) != 0 ||
                ((state & 4) != 0) != callout->Registered)
            {
                return read.Budget.Stop(Status::Partial, L"WfpCalloutKeyStateMismatch");
            }
            GUID guid = {};
            std::memcpy(&guid, key->data(), sizeof(guid));
            wchar_t text[40] = {};
            StringFromGUID2(guid, text, static_cast<int>(std::size(text)));
            callout->Key = text;
            callout->KeyFlags = static_cast<uint32_t>(WfpInteger(*key, 0x14, 4));
            callouts.emplace(id, *callout);
        }
    }
    return !read.Budget.Stopped;
}

inline bool ReadWfpFilter(kncore::WfpReader &read, const kncore::WfpHashEntry &entry,
                const std::map<uint32_t, kncore::WfpCallout> &callouts, knjson::Value &row)
{
    using namespace kncore;
    const auto internal = read.Bytes(entry.Internal, 0x38);
    if (!internal)
    {
        return false;
    }
    const auto address = WfpInteger(*internal, 0x18, 8);
    const auto bytes = read.Bytes(address, sizeof(FWPS_FILTER3));
    if (!bytes)
    {
        return false;
    }
    if (WfpInteger(*internal, 0x30, 2) != entry.Layer || WfpInteger(*bytes, 0, 8) != entry.Id)
    {
        return read.Budget.Stop(Status::Partial, L"WfpFilterIdentityMismatch");
    }
    row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"filters"));
    row.Set(L"source", knjson::Value(L"DebugTargetRuntime"));
    row.Set(L"nameState", knjson::Value(L"NotInRuntimeSchema"));
    row.Set(L"filterId", knjson::Value(std::to_wstring(entry.Id)));
    row.Set(L"address", knjson::Value(Hex(address)));
    row.Set(L"layerId", knjson::Value(std::to_wstring(entry.Layer)));
    row.Set(L"layerName", knjson::Value(WfpLayerName(entry.Layer)));
    row.Set(L"subLayerWeight", knjson::Value(std::to_wstring(WfpInteger(*bytes, 0x18, 2))));
    row.Set(L"flags", knjson::Value(Hex(WfpInteger(*bytes, 0x1a, 2))));
    row.Set(L"context", knjson::Value(Hex(WfpInteger(*bytes, 0x30, 8))));
    row.Set(L"providerContext", knjson::Value(Hex(WfpInteger(*bytes, 0x38, 8))));
    const auto weightType = static_cast<uint32_t>(WfpInteger(*bytes, 8, 4));
    const auto weight = read.Value(weightType, WfpInteger(*bytes, 0x10, 8));
    row.Set(L"weight", weight.Get(L"value"));
    row.Set(L"weightType", knjson::Value(std::to_wstring(weightType)));
    row.Set(L"weightState", weight.Get(L"state"));
    const auto action = static_cast<uint32_t>(WfpInteger(*bytes, 0x28, 4));
    row.Set(L"action", knjson::Value(Hex(action)));
    row.Set(L"actionName", knjson::Value(knutil::WfpActionName(action)));
    if (std::wstring_view(knutil::WfpActionName(action)) == L"Unknown" || WfpLayerName(entry.Layer).starts_with(L"Layer#"))
    {
        ++read.Budget.Report.Collected.Unknown;
    }
    const bool usesCallout = (action & FWP_ACTION_FLAG_CALLOUT) != 0;
    row.Set(L"usesCallout", knjson::Value(usesCallout));
    row.Set(L"calloutKey", knjson::Value());
    row.Set(L"calloutId", knjson::Value());
    if (usesCallout)
    {
        const auto calloutId = static_cast<uint32_t>(WfpInteger(*bytes, 0x2c, 4));
        row.Set(L"calloutId", knjson::Value(std::to_wstring(calloutId)));
        const auto found = callouts.find(calloutId);
        if (found != callouts.end())
        {
            WfpSetCalloutFields(row, found->second);
        }
        else
        {
            ++read.Budget.Report.Collected.Unknown;
            row.Set(L"calloutState", knjson::Value(L"ReferencedCalloutNotObserved"));
        }
    }
    const auto count = static_cast<uint32_t>(WfpInteger(*bytes, 0x1c, 4));
    row.Set(L"conditionCount", knjson::Value(std::to_wstring(count)));
    auto conditions = knjson::Value::MakeArray();
    std::wstring summary;
    if (count > 1024)
    {
        row.Set(L"conditionsState", knjson::Value(L"ConditionLimitExceeded"));
        return read.Budget.Stop(Status::Partial, L"WfpConditionLimitExceeded");
    }
    if (count != 0)
    {
        const auto data = read.Bytes(WfpInteger(*bytes, 0x20, 8), size_t(count) * sizeof(FWPS_FILTER_CONDITION0));
        if (!data)
        {
            row.Set(L"conditionsState", knjson::Value(L"Unreadable"));
            return false;
        }
        for (uint32_t i = 0; i < count && read.Check(); ++i)
        {
            const auto offset = size_t(i) * sizeof(FWPS_FILTER_CONDITION0);
            const auto field = static_cast<uint16_t>(WfpInteger(*data, offset, 2));
            const auto match = static_cast<uint32_t>(WfpInteger(*data, offset + 4, 4));
            const auto type = static_cast<uint32_t>(WfpInteger(*data, offset + 8, 4));
            const auto name = WfpFieldName(entry.Layer, field);
            if (name.starts_with(L"Field#") || std::wstring_view(WfpMatchName(match)) == L"UnknownMatch")
            {
                ++read.Budget.Report.Collected.Unknown;
            }
            auto condition = read.Value(type, WfpInteger(*data, offset + 16, 8), name);
            condition.Set(L"fieldId", knjson::Value(std::to_wstring(field)));
            condition.Set(L"fieldName", knjson::Value(name));
            condition.Set(L"matchType", knjson::Value(std::to_wstring(match)));
            condition.Set(L"matchName", knjson::Value(WfpMatchName(match)));
            if (!read.Retain(condition, true))
            {
                break;
            }
            conditions.Push(condition);
            if (!summary.empty())
            {
                summary += L"; ";
            }
            summary += name + L" " + WfpMatchName(match) + L" " + condition.Get(L"value").AsString(L"Unknown");
            if (summary.size() > 4096)
            {
                summary.resize(knutil::Utf16PrefixUnits(summary, 4096));
                summary += L" [see conditions]";
            }
        }
    }
    row.Set(L"conditions", conditions);
    row.Set(L"conditionsState", knjson::Value(conditions.Items().size() == count ? L"Collected" : L"Partial"));
    row.Set(L"conditionSummary", knjson::Value(count == 0 ? L"None" : summary));
    return !read.Budget.Stopped;
}
} // namespace kncore
