#pragma once

#include "WfpRead.h"
#include "PeIdentity.h"
#include <fwpmtypes.h>

namespace kncore
{
// Profile offsets are verified against the target image, not the host BFE.
inline constexpr wchar_t BfeProfileId[] = L"BFE-28000.2952-C1292E0A";
static_assert(sizeof(FWPM_FILTER0) == 0xc8 && offsetof(FWPM_FILTER0, filterId) == 0xb0 &&
              offsetof(FWPM_FILTER0, action) == 0x80 && offsetof(FWPM_FILTER0, effectiveWeight) == 0xb8);
static_assert(sizeof(FWPM_PROVIDER0) == 0x40 && offsetof(FWPM_PROVIDER0, serviceName) == 0x38);
static_assert(sizeof(FWPM_SUBLAYER0) == 0x48 && offsetof(FWPM_SUBLAYER0, weight) == 0x40);
static_assert(sizeof(FWPM_CALLOUT0) == 0x58 && offsetof(FWPM_CALLOUT0, calloutId) == 0x50);
static_assert(sizeof(FWPM_LAYER0) == 0x48 && offsetof(FWPM_LAYER0, layerId) == 0x40);

class BfeProcessReader final : public TargetReader
{
  public:
    using Translate = std::function<std::optional<uint64_t>(uint64_t)>;
    BfeProcessReader(TargetReader &physical, Translate translate) : physical_(physical), translate_(std::move(translate))
    {
    }
    ReadResult Read(AddressSpace space, uint64_t address, size_t length) override
    {
        ReadResult result;
        result.Space = space;
        result.Address = address;
        result.Requested = length;
        result.State = Status::Partial;
        if (space != AddressSpace::Virtual || length == 0 || length > 65536 || address < 0x10000 ||
            address >= 0x800000000000ULL || length > 0x800000000000ULL - address)
        {
            result.State = Status::InvalidInput;
            return result;
        }
        result.Bytes.resize(length);
        result.Valid.resize(length);
        for (size_t offset = 0; offset < length;)
        {
            const auto virtualPage = (address + offset) & ~uint64_t(4095);
            auto found = pages_.find(virtualPage);
            if (found == pages_.end())
            {
                const auto page = translate_(virtualPage);
                if (!page || (*page & 4095) != 0 || !ValidRange(*page, 4096))
                {
                    return result;
                }
                if (pages_.size() >= 8192)
                {
                    pages_.clear();
                }
                found = pages_.emplace(virtualPage, *page).first;
            }
            const auto inPage = size_t((address + offset) & 4095);
            const auto size = (std::min)(length - offset, size_t(4096) - inPage);
            const auto bytes = physical_.Read(AddressSpace::Physical, found->second + inPage, size);
            for (size_t i = 0; i < size && i < bytes.Bytes.size() && i < bytes.Valid.size(); ++i)
            {
                result.Bytes[offset + i] = bytes.Bytes[i];
                result.Valid[offset + i] = bytes.Valid[i];
                result.Transferred += bytes.Valid[i] != 0;
            }
            if (!ExactBytes(bytes, size))
            {
                result.State = bytes.State == Status::Cancelled ? Status::Cancelled : Status::Partial;
                return result;
            }
            offset += size;
        }
        result.State = Status::Success;
        return result;
    }
  private:
    // One instance belongs to one stopped process; never share translations across processes.
    TargetReader &physical_;
    Translate translate_;
    std::map<uint64_t, uint64_t> pages_;
};

class BfeReader
{
  public:
    TargetReader &Reader;
    WalkBudget &Budget;
    size_t TextUnits = 0;
    size_t RecordUnits = 0;
    size_t RecordCount = 0;
    std::map<uint64_t, knjson::Value> Strings;

    BfeReader(TargetReader &reader, WalkBudget &budget) : Reader(reader), Budget(budget)
    {
    }

    static bool Range(uint64_t address, size_t size)
    {
        return size != 0 && size <= 65536 && address >= 0x10000 && address < 0x800000000000ULL &&
               size <= 0x800000000000ULL - address;
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
            Budget.Stop(Status::Partial, L"BfeReadDeadline");
        }
        return !Budget.Stopped;
    }

    std::optional<std::vector<unsigned char>> Bytes(uint64_t address, size_t size)
    {
        if (!Check())
        {
            return {};
        }
        if (!Range(address, size))
        {
            Budget.Stop(Status::Partial, L"BfeInvalidUserRange");
            return {};
        }
        const auto bytes = Reader.Read(AddressSpace::Virtual, address, size);
        if (!ExactBytes(bytes, size))
        {
            ++Budget.Report.Collected.Unreadable;
            Budget.Stop(bytes.State == Status::Cancelled ? Status::Cancelled : Status::Partial, L"BfeUnreadableMemory");
            return {};
        }
        return bytes.Bytes;
    }

    std::optional<uint64_t> Integer(uint64_t address, size_t size = 8)
    {
        const auto bytes = Bytes(address, size);
        return bytes ? std::optional<uint64_t>(WfpInteger(*bytes, 0, size)) : std::nullopt;
    }

    knjson::Value Text(uint64_t address)
    {
        if (const auto found = Strings.find(address); found != Strings.end())
        {
            return found->second;
        }
        auto result = knjson::Value::MakeObject();
        result.Set(L"state", knjson::Value(address == 0 ? L"Absent" : L"Unreadable"));
        result.Set(L"value", knjson::Value());
        std::wstring value;
        bool high = false;
        if (address != 0 && address % 2 == 0)
        {
            for (size_t offset = 0; offset < 4096 && Check();)
            {
                const size_t size = (std::min)(size_t(128), size_t(4096 - ((address + offset) & 4095)));
                if (!Range(address + offset, size))
                {
                    break;
                }
                // A terminator in the readable prefix is sufficient; bytes past it are irrelevant.
                const auto bytes = Reader.Read(AddressSpace::Virtual, address + offset, size);
                if (bytes.State == Status::Cancelled)
                {
                    Budget.Stop(Status::Cancelled, L"Cancelled");
                    break;
                }
                for (size_t i = 0; i + 1 < size; i += 2)
                {
                    if (i + 1 >= bytes.Bytes.size() || i + 1 >= bytes.Valid.size() || !bytes.Valid[i] || !bytes.Valid[i + 1])
                    {
                        goto finished;
                    }
                    const auto c = static_cast<wchar_t>(WfpInteger(bytes.Bytes, i, 2));
                    if (c == 0 && !high)
                    {
                        if (TextUnits + value.size() > 1024 * 1024 || Strings.size() >= 8192)
                        {
                            Budget.Stop(Status::Partial, L"BfeTextBudget");
                            goto finished;
                        }
                        TextUnits += value.size();
                        result.Set(L"value", knjson::Value(value));
                        result.Set(L"state", knjson::Value(value.empty() ? L"Empty" : value[0] == L'@' ? L"IndirectResource" : L"Present"));
                        goto finished;
                    }
                    const bool low = c >= 0xdc00 && c <= 0xdfff;
                    if (high != low || (c == 0 && high))
                    {
                        result.Set(L"state", knjson::Value(L"InvalidUtf16"));
                        goto finished;
                    }
                    high = c >= 0xd800 && c <= 0xdbff;
                    value += c;
                }
                offset += size;
            }
            if (!Budget.Stopped)
            {
                result.Set(L"state", knjson::Value(L"UnterminatedOrTooLong"));
            }
        }
finished:
        if (address != 0 && result.Get(L"value").IsNull())
        {
            ++Budget.Report.Collected.Unknown;
        }
        if (Strings.size() < 8192)
        {
            Strings.emplace(address, result);
        }
        return result;
    }
};

class BfeImageReader final : public ByteReader
{
  public:
    BfeImageReader(BfeReader &reader, uint64_t base, uint64_t size) : read_(reader), base_(base), size_(size)
    {
    }
    uint64_t Size() const override
    {
        return size_;
    }
    bool Read(uint64_t offset, std::span<unsigned char> bytes) override
    {
        if (!Contains(size_, offset, bytes.size()))
        {
            return false;
        }
        const auto data = read_.Bytes(base_ + offset, bytes.size());
        if (!data)
        {
            return false;
        }
        std::copy(data->begin(), data->end(), bytes.begin());
        return true;
    }
  private:
    BfeReader &read_;
    uint64_t base_;
    uint64_t size_;
};

inline bool VerifyBfeImage(BfeReader &read, uint64_t base)
{
    const auto header = read.Bytes(base, 4096);
    PeImage image;
    if (!header)
    {
        return false;
    }
    if (!ParsePeHeaders(*header, &image) || !image.Is64 || image.File.Machine != 0x8664 ||
        image.File.TimeDateStamp != 0x9b4142c3 || image.ImageSize != 0x10a000)
    {
        return read.Budget.Stop(Status::Unavailable, L"BfeImageProfileMismatch");
    }
    BfeImageReader mapped(read, base, image.ImageSize);
    const auto cv = CodeViewIdentity(mapped, image, true);
    if (read.Budget.Stopped)
    {
        return false;
    }
    constexpr std::array<unsigned char, 20> expected = {0x0a,0x2e,0x29,0xc1,0x64,0xa1,0xb2,0x36,0x9e,0xc1,0x0c,0xa2,0xc7,0x6a,0x25,0x62,1,0,0,0};
    if (!cv || *cv != expected)
    {
        return read.Budget.Stop(Status::Unavailable, L"BfePdbProfileMismatch");
    }
    static const std::pair<uint32_t, const wchar_t *> windows[] = {
        {0x38ac8, L"4869f898010000"},
        {0x38b2c, L"498d8f20010000"},
        {0x38b4c, L"488d70d8"},
        {0x38b5f, L"f6460808"},
        {0x1bfca, L"48031d9fa70d00"},
        {0x1bfea, L"488dabf0000000"},
        {0x1c01d, L"488d58f0"},
        {0x1c054, L"488d8b90000000"},
        {0x3b5e0, L"488b01c3"},
        {0x3c1c0, L"488bc1c3"},
        {0x386a0, L"488b01488b80b0000000c3"}};
    for (const auto &[rva, expectedBytes] : windows)
    {
        const auto bytes = read.Bytes(base + rva, std::wcslen(expectedBytes) / 2);
        if (!bytes)
        {
            return false;
        }
        if (WfpBytesText(*bytes) != expectedBytes)
        {
            return read.Budget.Stop(Status::Unavailable, L"BfeCodeProfileMismatch");
        }
    }
    return true;
}

struct BfeRecord
{
    unsigned Type = 0;
    uint64_t Object = 0;
    uint64_t Public = 0;
    uint64_t Id = 0;
    std::wstring Key;
    std::vector<unsigned char> Bytes;
    knjson::Value Row = knjson::Value::MakeObject();
};

inline std::wstring BfeGuid(std::span<const unsigned char> bytes, size_t offset)
{
    if (offset > bytes.size() || bytes.size() - offset < sizeof(GUID))
    {
        return {};
    }
    GUID guid;
    std::memcpy(&guid, bytes.data() + offset, sizeof(guid));
    wchar_t text[40] = {};
    StringFromGUID2(guid, text, _countof(text));
    return text;
}

inline void BfeSetText(BfeReader &read, knjson::Value &row, const wchar_t *field, uint64_t pointer)
{
    const auto text = read.Text(pointer);
    row.Set(field, text.Get(L"value"));
    row.Set(std::wstring(field) + L"State", text.Get(L"state"));
}

inline bool ReadBfeTable(BfeReader &read, const TargetArchitecture &architecture, uint64_t module, uint64_t manager,
                         unsigned type, std::vector<BfeRecord> &records)
{
    if (type != 0 && type != 2 && type != 3 && type != 4 && type != 5)
    {
        return read.Budget.Stop(Status::InvalidInput, L"BfeInvalidObjectType");
    }
    const auto descriptor = manager + type * 0x198;
    const auto data = read.Bytes(descriptor, 0x118);
    if (!data)
    {
        return false;
    }
    if (WfpInteger(*data, 0, 4) != 1 || WfpInteger(*data, 8, 4) != type ||
        WfpInteger(*data, 0x70, 8) != module + 0x3c1c0 || WfpInteger(*data, 0x78, 8) != module + 0x3b5e0)
    {
        return read.Budget.Stop(Status::Partial, L"BfeObjectDescriptorMismatch");
    }
    const auto hash = std::span(*data).subspan(0xf0);
    const auto size = uint32_t(WfpInteger(hash, 8, 4));
    const auto pivot = WfpInteger(hash, 0xc, 4);
    const auto mask = WfpInteger(hash, 0x10, 4);
    const auto count = WfpInteger(hash, 0x14, 4);
    const auto nonempty = WfpInteger(hash, 0x18, 4);
    const auto directory = WfpInteger(hash, 0x20, 8);
    if (size < 128 || size > 65536 || count > 16384 || nonempty > size || !std::has_single_bit(mask + 1) ||
        pivot > mask || mask + 1 + pivot != size || WfpInteger(hash, 4, 4) >= 32 || WfpInteger(hash, 0x1c, 4) != 0)
    {
        return read.Budget.Stop(Status::Partial, L"BfeInvalidOrEnumeratingTable");
    }
    read.Budget.Report.Collected.Expected += count;
    uint64_t seen = 0;
    uint64_t occupied = 0;
    std::set<std::wstring> keys;
    std::set<uint64_t> ids;
    for (uint32_t i = 0; i < size && read.Check(); ++i)
    {
        uint64_t segment = directory;
        auto index = i;
        if (size > 128)
        {
            const auto adjusted = i + 128;
            const auto bit = std::bit_width(adjusted) - 1;
            const auto value = read.Integer(directory + uint64_t(bit - 7) * 8);
            if (!value)
            {
                return false;
            }
            segment = *value;
            index = adjusted ^ (1u << bit);
        }
        if (!BfeReader::Range(segment, 16) || !BfeReader::Range(segment + uint64_t(index) * 16, 16))
        {
            return read.Budget.Stop(Status::Partial, L"BfeInvalidDirectory");
        }
        const auto head = segment + uint64_t(index) * 16;
        const auto links = read.Bytes(head, 16);
        if (!links)
        {
            return false;
        }
        auto next = WfpInteger(*links, 0, 8);
        auto previous = head;
        occupied += next != head;
        while (next != head)
        {
            if (!read.Check() || !read.Budget.Consume(next, architecture))
            {
                return false;
            }
            const auto object = next - 0x10;
            const auto header = read.Bytes(object, 0x98);
            if (!header)
            {
                return false;
            }
            ++seen;
            if (seen > count || WfpInteger(*header, 0, 8) != descriptor || WfpInteger(*header, 0x18, 8) != previous ||
                WfpInteger(*header, 0x20, 8) == 0)
            {
                return read.Budget.Stop(Status::Partial, L"BfeObjectLinkMismatch");
            }
            previous = next;
            next = WfpInteger(*header, 0x10, 8);
            ++read.Budget.Report.Collected.Read;
            if ((WfpInteger(*header, 8, 4) & 8) != 0)
            {
                continue;
            }
            constexpr size_t sizes[] = {0x40, 0, 0x48, 0x48, 0x58, 0xc8};
            BfeRecord record;
            record.Type = type;
            record.Object = object;
            record.Public = WfpInteger(*header, 0x90, 8);
            const auto value = read.Bytes(record.Public, sizes[type]);
            if (!value)
            {
                return false;
            }
            record.Bytes = *value;
            record.Key = BfeGuid(*value, 0);
            record.Id = type == 5 ? WfpInteger(*value, 0xb0, 8) : type == 4 ? WfpInteger(*value, 0x50, 4) :
                        type == 3 ? WfpInteger(*value, 0x40, 2) : 0;
            if (!keys.insert(record.Key).second || ((type == 3 || type == 4 || type == 5) && !ids.insert(record.Id).second))
            {
                return read.Budget.Stop(Status::Partial, L"BfeDuplicateIdentity");
            }
            auto &row = record.Row;
            constexpr const wchar_t *kinds[] = {L"providers", L"", L"sublayers", L"layers", L"callouts", L"filters"};
            row.Set(L"kind", knjson::Value(kinds[type]));
            row.Set(L"source", knjson::Value(L"DebugTargetBfe"));
            row.Set(L"managementState", knjson::Value(L"Present"));
            row.Set(L"managementAddress", knjson::Value(Hex(record.Public)));
            row.Set(L"key", knjson::Value(record.Key));
            row.Set(L"managementFlags", knjson::Value(Hex(WfpInteger(*value, 0x20, 4))));
            BfeSetText(read, row, L"name", WfpInteger(*value, 0x10, 8));
            BfeSetText(read, row, L"description", WfpInteger(*value, 0x18, 8));
            if (type == 2 || type == 4 || type == 5)
            {
                const auto provider = WfpInteger(*value, 0x28, 8);
                row.Set(L"providerKey", knjson::Value());
                row.Set(L"providerState", knjson::Value(provider == 0 ? L"NotSpecified" : L"Unresolved"));
                if (provider != 0)
                {
                    const auto key = read.Bytes(provider, 16);
                    if (!key)
                    {
                        return false;
                    }
                    row.Set(L"providerKey", knjson::Value(BfeGuid(*key, 0)));
                }
            }
            if (type == 0)
            {
                BfeSetText(read, row, L"serviceName", WfpInteger(*value, 0x38, 8));
            }
            if (type == 2)
            {
                row.Set(L"weight", knjson::Value(std::to_wstring(WfpInteger(*value, 0x40, 2))));
            }
            if (type == 3)
            {
                row.Set(L"layerId", knjson::Value(std::to_wstring(record.Id)));
                row.Set(L"layerName", knjson::Value(WfpLayerName(static_cast<uint32_t>(record.Id))));
                row.Set(L"fieldCount", knjson::Value(std::to_wstring(WfpInteger(*value, 0x24, 4))));
                row.Set(L"subLayer", knjson::Value(BfeGuid(*value, 0x30)));
            }
            if (type == 4 || type == 5)
            {
                row.Set(L"layer", knjson::Value(BfeGuid(*value, 0x40)));
                row.Set(type == 4 ? L"calloutId" : L"filterId", knjson::Value(std::to_wstring(record.Id)));
            }
            if (type == 5)
            {
                row.Set(L"subLayer", knjson::Value(BfeGuid(*value, 0x50)));
                row.Set(L"managementConditionCount", knjson::Value(std::to_wstring(WfpInteger(*value, 0x70, 4))));
                row.Set(L"managementAction", knjson::Value(Hex(WfpInteger(*value, 0x80, 4))));
            }
            const auto units = row.Write().size();
            if (read.RecordCount >= 8192 || read.RecordUnits > 2 * 1024 * 1024 || units > 2 * 1024 * 1024 - read.RecordUnits)
            {
                return read.Budget.Stop(Status::Partial, L"BfeRecordBudget");
            }
            read.RecordUnits += units;
            ++read.RecordCount;
            records.push_back(std::move(record));
            ++read.Budget.Report.Collected.Decoded;
        }
        if (previous != WfpInteger(*links, 8, 8))
        {
            return read.Budget.Stop(Status::Partial, L"BfeBucketTailMismatch");
        }
    }
    const auto final = read.Bytes(descriptor, 0x118);
    if (!final || *final != *data || seen != count || occupied != nonempty)
    {
        return read.Budget.Stopped ? false : read.Budget.Stop(Status::Partial, L"BfeTableChangedOrCountMismatch");
    }
    return !read.Budget.Stopped;
}

inline std::optional<uint64_t> FindBfeModule(BfeReader &read, uint64_t peb)
{
    const auto ldr = read.Integer(peb + 0x18);
    const auto links = ldr ? read.Bytes(*ldr + 0x10, 16) : std::nullopt;
    if (!links)
    {
        return {};
    }
    const auto head = *ldr + 0x10;
    auto node = WfpInteger(*links, 0, 8);
    auto previous = head;
    uint64_t found = 0;
    std::set<uint64_t> seen;
    while (node != head && read.Check())
    {
        if (seen.size() >= 512 || !seen.insert(node).second)
        {
            read.Budget.Stop(Status::Partial, L"BfeModuleListCycleOrLimit");
            return {};
        }
        const auto entry = read.Bytes(node, 0x68);
        if (!entry)
        {
            return {};
        }
        if (WfpInteger(*entry, 8, 8) != previous)
        {
            read.Budget.Stop(Status::Partial, L"BfeModuleListUnreadableOrChanged");
            return {};
        }
        if (WfpInteger(*entry, 0x58, 2) == 14 && WfpInteger(*entry, 0x5a, 2) >= 14)
        {
            const auto name = read.Bytes(WfpInteger(*entry, 0x60, 8), 14);
            if (!name)
            {
                return {};
            }
            std::wstring text;
            for (size_t i = 0; i < 14; i += 2)
            {
                text += wchar_t(WfpInteger(*name, i, 2));
            }
            if (_wcsicmp(text.c_str(), L"bfe.dll") == 0)
            {
                if (found != 0)
                {
                    read.Budget.Stop(Status::Partial, L"BfeDuplicateModule");
                    return {};
                }
                found = WfpInteger(*entry, 0x30, 8);
            }
        }
        previous = node;
        node = WfpInteger(*entry, 0, 8);
    }
    const auto final = read.Bytes(head, 16);
    if (!final || *final != *links || previous != WfpInteger(*links, 8, 8))
    {
        if (!read.Budget.Stopped)
        {
            read.Budget.Stop(Status::Partial, L"BfeModuleListChanged");
        }
        return {};
    }
    return read.Budget.Stopped ? std::nullopt : std::optional<uint64_t>(found);
}

inline void BfeJoinReference(knjson::Value &row, const std::vector<BfeRecord> &records, unsigned type,
                             const wchar_t *keyField, const wchar_t *prefix, bool complete)
{
    const auto key = row.Get(keyField).AsString(L"");
    if (key.empty())
    {
        row.Set(std::wstring(prefix) + L"State", knjson::Value(L"NotSpecified"));
        return;
    }
    const auto found = std::find_if(records.begin(), records.end(), [&](const BfeRecord &record)
    {
        return record.Type == type && record.Key == key;
    });
    row.Set(std::wstring(prefix) + L"State", knjson::Value(found == records.end() ? complete ? L"NotPresentInBfe" : L"Unavailable" : L"Matched"));
    if (found != records.end())
    {
        for (const auto field : {L"name", L"nameState", L"description", L"descriptionState", L"serviceName", L"serviceNameState", L"weight", L"providerKey"})
        {
            auto suffix = std::wstring(field);
            suffix[0] = wchar_t(towupper(suffix[0]));
            row.Set(std::wstring(prefix) + (suffix == L"Weight" ? L"ManagementWeight" : suffix), found->Row.Get(field));
        }
    }
}

inline bool EnrichBfeRow(knjson::Value &row, const std::vector<BfeRecord> &records, bool complete)
{
    const bool filter = row.Get(L"kind").AsString(L"") == L"filters";
    const auto id = row.Get(filter ? L"filterId" : L"calloutId").AsString(L"");
    const auto found = std::find_if(records.begin(), records.end(), [&](const BfeRecord &record)
    {
        return record.Type == (filter ? 5u : 4u) && std::to_wstring(record.Id) == id;
    });
    row.Set(L"managementSource", knjson::Value(L"DebugTargetBfe"));
    if (found == records.end())
    {
        row.Set(L"managementState", knjson::Value(complete ? L"NotPresentInBfe" : L"Unavailable"));
        row.Set(L"nameState", knjson::Value(complete ? L"NotPresentInBfe" : L"Unavailable"));
        return true;
    }
    const auto &record = *found;
    bool matches = true;
    if (filter)
    {
        matches = row.Get(L"action").AsString(L"") == record.Row.Get(L"managementAction").AsString(L"") &&
                  row.Get(L"conditionCount").AsString(L"") == record.Row.Get(L"managementConditionCount").AsString(L"");
        const auto layer = std::find_if(records.begin(), records.end(), [&](const BfeRecord &item)
        {
            return item.Type == 3 && std::to_wstring(item.Id) == row.Get(L"layerId").AsString(L"");
        });
        matches = matches && layer != records.end() && layer->Key == record.Row.Get(L"layer").AsString(L"");
        const auto sublayer = std::find_if(records.begin(), records.end(), [&](const BfeRecord &item)
        {
            return item.Type == 2 && item.Key == record.Row.Get(L"subLayer").AsString(L"");
        });
        matches = matches && sublayer != records.end() &&
                  sublayer->Row.Get(L"weight").AsString(L"") == row.Get(L"subLayerWeight").AsString(L"");
        if (row.Get(L"usesCallout").AsBool(false))
        {
            matches = matches && row.Get(L"calloutKey").AsString(L"") == BfeGuid(record.Bytes, 0x84);
        }
    }
    else
    {
        matches = row.Get(L"calloutKey").AsString(L"") == record.Key;
    }
    if (!matches)
    {
        row.Set(L"managementState", knjson::Value(L"RuntimeIdentityMismatch"));
        row.Set(L"nameState", knjson::Value(L"RuntimeIdentityMismatch"));
        return false;
    }
    for (const auto &[key, value] : record.Row.Fields())
    {
        if (key != L"kind" && key != L"source" && key != L"managementState" && (filter || key != L"key"))
        {
            row.Set(key, value);
        }
    }
    row.Set(L"managementState", knjson::Value(L"Matched"));
    BfeJoinReference(row, records, 0, L"providerKey", L"provider", complete);
    if (filter)
    {
        BfeJoinReference(row, records, 2, L"subLayer", L"subLayer", complete);
    }
    return true;
}
} // namespace kncore
