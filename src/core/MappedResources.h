#pragma once

#include "WfpRead.h"
#include "PeResources.h"
#include <memory>

namespace kncore
{
struct ResourceLayout
{
    std::map<std::wstring, FieldInfo> Fields;
    bool Add(const wchar_t *name, const std::optional<FieldInfo> &field, uint32_t size, bool bits = false)
    {
        if (!field || field->Size != size || !field->ValidFor(4096) || bits != field->BitOffset.has_value() ||
            bits != field->BitWidth.has_value())
        {
            return false;
        }
        Fields.emplace(name, *field);
        return true;
    }
    uint32_t Extent(std::initializer_list<const wchar_t *> names) const
    {
        uint32_t size = 0;
        for (const auto name : names)
        {
            const auto &field = Fields.at(name);
            size = (std::max)(size, field.Offset + field.Size);
        }
        return size;
    }
    uint64_t Value(std::span<const unsigned char> bytes, const wchar_t *name) const
    {
        const auto &field = Fields.at(name);
        auto value = WfpInteger(bytes, field.Offset, field.Size);
        if (field.BitOffset && field.BitWidth)
        {
            value >>= *field.BitOffset;
            value &= *field.BitWidth == 64 ? UINT64_MAX : (uint64_t(1) << *field.BitWidth) - 1;
        }
        return value;
    }
};

struct ResourceMapping
{
    uint64_t Process = 0;
    uint64_t Address = 0;
    uint64_t Subsection = 0;
    uint64_t ControlArea = 0;
    uint64_t FileObject = 0;
    std::wstring Path;
    std::wstring Name;
};

class ResourceMemory
{
  public:
    TargetReader &Reader;
    const TargetArchitecture &Architecture;
    WalkBudget &Budget;
    std::wstring Error;
    size_t Reads = 0;
    size_t BytesRead = 0;
    ResourceMemory(TargetReader &reader, const TargetArchitecture &architecture, WalkBudget &budget)
        : Reader(reader), Architecture(architecture), Budget(budget)
    {
    }
    bool Check()
    {
        Budget.StartTraversal(std::chrono::steady_clock::now(), std::chrono::seconds(180));
        if (!Budget.Stopped && Budget.Cancelled && Budget.Cancelled())
        {
            Budget.Stop(Status::Cancelled, L"Cancelled");
        }
        if (!Budget.Stopped && (Reads >= 65536 || BytesRead >= 32 * 1024 * 1024 || std::chrono::steady_clock::now() >= Budget.Deadline))
        {
            Budget.Stop(Status::Partial, L"ResourceReadBudget");
        }
        return !Budget.Stopped;
    }
    std::optional<std::vector<unsigned char>> Bytes(uint64_t address, size_t size, AddressSpace space = AddressSpace::Virtual)
    {
        if (!Check())
        {
            Error = Budget.Report.Collected.StopReason;
            return {};
        }
        if (size == 0 || size > 65536 || !ValidRange(address, size) ||
            (space == AddressSpace::Virtual && (!Architecture.KernelPointer(address) || !Architecture.KernelPointer(address + size - 1))))
        {
            Error = L"ResourceAddressInvalid";
            return {};
        }
        ++Reads;
        BytesRead += size;
        const auto bytes = Reader.Read(space, address, size);
        if (WfpTerminalRead(bytes.State))
        {
            Budget.Stop(bytes.State, L"ResourceReadStopped");
        }
        if (!ExactBytes(bytes, size))
        {
            Error = WfpTerminalRead(bytes.State) ? L"ResourceReadStopped" : L"ResourcePageUnavailable";
            return {};
        }
        return bytes.Bytes;
    }
};

inline std::wstring ResourceBaseName(const std::wstring &path)
{
    auto name = path.substr(path.find_last_of(L"\\/") + 1);
    for (auto &c : name)
    {
        if (c >= L'A' && c <= L'Z')
        {
            c += L'a' - L'A';
        }
    }
    return name;
}

class ResourceMappingCatalog
{
  public:
    ResourceMemory &Memory;
    const ResourceLayout &Layout;
    std::vector<ResourceMapping> Mappings;
    bool Complete = true;
    size_t Nodes = 0;
    ResourceMappingCatalog(ResourceMemory &memory, const ResourceLayout &layout) : Memory(memory), Layout(layout)
    {
    }
    bool Scan(uint64_t process, const std::set<std::wstring> &wanted)
    {
        const auto &rootField = Layout.Fields.at(L"root");
        const auto rootBytes = Memory.Bytes(process + rootField.Offset, 8);
        if (!rootBytes)
        {
            Complete = false;
            return false;
        }
        std::vector<uint64_t> stack{WfpInteger(*rootBytes, 0, 8)};
        std::set<uint64_t> seen;
        while (!stack.empty() && Memory.Check())
        {
            const auto node = stack.back();
            stack.pop_back();
            if (node == 0)
            {
                continue;
            }
            if (++Nodes > 32768 || seen.size() >= 8192 || !seen.insert(node).second)
            {
                Memory.Error = L"ResourceVadCycleOrLimit";
                Complete = false;
                return false;
            }
            const auto core = Memory.Bytes(node, Layout.Extent({L"left", L"right", L"start", L"startHigh", L"private"}));
            if (!core)
            {
                Complete = false;
                continue;
            }
            stack.push_back(Layout.Value(*core, L"right"));
            stack.push_back(Layout.Value(*core, L"left"));
            if (Layout.Value(*core, L"private") != 0)
            {
                continue;
            }
            const auto subsectionBytes = Memory.Bytes(node + Layout.Fields.at(L"subsection").Offset, 8);
            if (!subsectionBytes)
            {
                Complete = false;
            }
            const auto subsection = subsectionBytes ? WfpInteger(*subsectionBytes, 0, 8) : 0;
            if (subsection == 0)
            {
                continue;
            }
            const auto controlBytes = Memory.Bytes(subsection + Layout.Fields.at(L"control").Offset, 8);
            const auto control = controlBytes ? WfpInteger(*controlBytes, 0, 8) : 0;
            if (control == 0)
            {
                Complete = false;
                continue;
            }
            auto cached = files_.find(control);
            if (cached == files_.end())
            {
                ResourceMapping file;
                const auto pointer = Memory.Bytes(control + Layout.Fields.at(L"filePointer").Offset, 8);
                if (!pointer)
                {
                    Complete = false;
                }
                const auto refBits = *Layout.Fields.at(L"refCount").BitWidth;
                file.FileObject = pointer ? WfpInteger(*pointer, 0, 8) & ~((uint64_t(1) << refBits) - 1) : 0;
                if (file.FileObject != 0)
                {
                    const auto descriptor = Memory.Bytes(file.FileObject + Layout.Fields.at(L"fileName").Offset, 16);
                    if (descriptor)
                    {
                        const auto length = size_t(WfpInteger(*descriptor, 0, 2));
                        const auto maximum = WfpInteger(*descriptor, 2, 2);
                        if (length != 0 && length <= maximum && length <= 2048 && length % 2 == 0)
                        {
                            const auto text = Memory.Bytes(WfpInteger(*descriptor, 8, 8), length);
                            if (text && ResourceUtf16(*text, file.Path))
                            {
                                file.Name = ResourceBaseName(file.Path);
                            }
                        }
                    }
                    if (file.Name.empty())
                    {
                        Complete = false;
                    }
                }
                cached = files_.emplace(control, std::move(file)).first;
            }
            const auto &file = cached->second;
            if (file.Name.empty() || !wanted.contains(file.Name) || !retained_.insert(control).second)
            {
                continue;
            }
            if (Mappings.size() >= 64)
            {
                Complete = false;
                Memory.Error = L"ResourceMappingLimit";
                return false;
            }
            auto mapping = file;
            mapping.Process = process;
            mapping.ControlArea = control;
            mapping.Subsection = subsection;
            mapping.Address = (Layout.Value(*core, L"start") | (Layout.Value(*core, L"startHigh") << 32)) << 12;
            Mappings.push_back(std::move(mapping));
        }
        if (!Memory.Check())
        {
            Complete = false;
        }
        return Complete;
    }
  private:
    std::map<uint64_t, ResourceMapping> files_;
    std::set<uint64_t> retained_;
};

// Read file offsets through section prototype PTEs, including standby pages.
// An unmapped or pagefile-backed page is never faulted into the stopped target.
class SectionFileReader final : public ByteReader
{
  public:
    SectionFileReader(ResourceMemory &memory, const ResourceLayout &layout) : memory_(memory), layout_(layout)
    {
    }
    std::wstring Error;
    bool Initialize(const ResourceMapping &mapping)
    {
        const auto control = memory_.Bytes(mapping.ControlArea, layout_.Extent({L"image"}));
        if (!control)
        {
            Error = memory_.Error;
            return false;
        }
        // This target uses 512-byte image sectors and 4-KiB data-file sectors.
        const uint64_t sectorSize = layout_.Value(*control, L"image") != 0 ? 512 : 4096;
        std::set<uint64_t> seen;
        auto next = mapping.Subsection;
        while (next != 0 && memory_.Check())
        {
            if (seen.size() >= 96 || !seen.insert(next).second)
            {
                Error = L"ResourceSubsectionCycleOrLimit";
                return false;
            }
            const auto bytes = memory_.Bytes(next, layout_.Extent({L"control", L"pteBase", L"next", L"sector", L"sectorHigh", L"sectors", L"tail", L"ptes", L"unusedPtes"}));
            if (!bytes)
            {
                Error = memory_.Error;
                return false;
            }
            Segment segment;
            if (layout_.Value(*bytes, L"sectorHigh") != 0)
            {
                Error = L"ResourceFileSizeLimit";
                return false;
            }
            segment.Offset = layout_.Value(*bytes, L"sector") * sectorSize;
            segment.Size = layout_.Value(*bytes, L"sectors") * sectorSize + layout_.Value(*bytes, L"tail");
            segment.Pte = layout_.Value(*bytes, L"pteBase");
            const auto count = layout_.Value(*bytes, L"ptes");
            const auto unused = layout_.Value(*bytes, L"unusedPtes");
            if (layout_.Value(*bytes, L"control") != mapping.ControlArea || segment.Size == 0 || count == 0 || count > 16384 ||
                unused > count || layout_.Value(*bytes, L"tail") >= sectorSize || segment.Size > (count - unused) * 4096 ||
                !Contains(64 * 1024 * 1024, segment.Offset, segment.Size) ||
                !memory_.Architecture.KernelPointer(segment.Pte) || segment.Pte % 8 != 0 ||
                (segment.Size + 4095) / 4096 > count)
            {
                Error = L"ResourceSubsectionInvalid";
                return false;
            }
            size_ = (std::max)(size_, segment.Offset + segment.Size);
            segments_.push_back(segment);
            next = layout_.Value(*bytes, L"next");
        }
        std::sort(segments_.begin(), segments_.end(), [](const Segment &a, const Segment &b)
        {
            return a.Offset < b.Offset;
        });
        for (size_t i = 1; i < segments_.size(); ++i)
        {
            if (segments_[i - 1].Offset + segments_[i - 1].Size > segments_[i].Offset)
            {
                Error = L"ResourceSubsectionsOverlap";
                return false;
            }
        }
        return !segments_.empty() && !memory_.Budget.Stopped;
    }
    uint64_t Size() const override
    {
        return size_;
    }
    bool Read(uint64_t offset, std::span<unsigned char> output) override
    {
        Error.clear();
        if (output.empty() || output.size() > 65536 || !Contains(size_, offset, output.size()) || !memory_.Check())
        {
            Error = L"ResourceFileReadBounds";
            return false;
        }
        size_t done = 0;
        while (done < output.size())
        {
            const auto position = offset + done;
            const auto segment = std::find_if(segments_.begin(), segments_.end(), [&](const Segment &item)
            {
                return position >= item.Offset && position - item.Offset < item.Size;
            });
            if (segment == segments_.end())
            {
                Error = L"ResourceFileRangeUnmapped";
                return false;
            }
            const auto relative = position - segment->Offset;
            const auto pteAddress = segment->Pte + (relative / 4096) * 8;
            auto found = pages_.find(pteAddress);
            if (found == pages_.end())
            {
                if (pages_.size() >= 256)
                {
                    Error = L"ResourceFilePageLimit";
                    return false;
                }
                const auto pte = memory_.Bytes(pteAddress, 8);
                if (!pte)
                {
                    Error = memory_.Error;
                    return false;
                }
                const auto value = WfpInteger(*pte, 0, 8);
                const bool valid = layout_.Value(*pte, L"valid") != 0;
                if (!valid && (layout_.Value(*pte, L"transition") == 0 || layout_.Value(*pte, L"prototype") != 0))
                {
                    Error = L"ResourcePageNotResident";
                    return false;
                }
                const auto pfn = layout_.Value(*pte, valid ? L"hardwarePfn" : L"transitionPfn");
                if (pfn == 0 || pfn > (UINT64_MAX >> 12))
                {
                    Error = L"ResourcePageFrameInvalid";
                    return false;
                }
                const auto page = memory_.Bytes(pfn << 12, 4096, AddressSpace::Physical);
                const auto after = page ? memory_.Bytes(pteAddress, 8) : std::nullopt;
                if (!page || !after || WfpInteger(*after, 0, 8) != value)
                {
                    Error = page && after ? L"ResourcePageChanged" : memory_.Error;
                    return false;
                }
                found = pages_.emplace(pteAddress, *page).first;
            }
            const auto inPage = size_t(relative & 4095);
            const auto count = (std::min)({output.size() - done, 4096 - inPage, size_t(segment->Size - relative)});
            std::copy_n(found->second.begin() + inPage, count, output.begin() + done);
            done += count;
        }
        return true;
    }
  private:
    struct Segment
    {
        uint64_t Offset = 0;
        uint64_t Size = 0;
        uint64_t Pte = 0;
    };
    ResourceMemory &memory_;
    const ResourceLayout &layout_;
    uint64_t size_ = 0;
    std::vector<Segment> segments_;
    std::map<uint64_t, std::vector<unsigned char>> pages_;
};
} // namespace kncore
