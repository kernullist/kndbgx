#pragma once

#include "ObjectRead.h"
#include "ServiceTable.h"
#include <array>

namespace kncore
{
class NamespaceReadMeter final : public TargetReader
{
  public:
    explicit NamespaceReadMeter(TargetReader &reader) : reader_(reader)
    {
    }
    ReadResult Read(AddressSpace space, uint64_t address, size_t length) override
    {
        ++Requests;
        Bytes += length;
        const auto start = std::chrono::steady_clock::now();
        auto result = reader_.Read(space, address, length);
        Elapsed += std::chrono::steady_clock::now() - start;
        return result;
    }
    uint64_t Requests = 0;
    uint64_t Bytes = 0;
    std::chrono::steady_clock::duration Elapsed{};

  private:
    TargetReader &reader_;
};

inline void StartNamespaceTraversal(WalkBudget &budget, std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now())
{
    // Serial KD needs more time than an in-process reader. All directories share this bound.
    budget.StartTraversal(now, std::chrono::seconds(120));
}

struct NamespaceLayout
{
    std::optional<FieldInfo> Buckets, Next, Object, Body, Type, Mask, Parent, Length, Maximum, Buffer;
    uint32_t NameInfoSize = 0;

    bool Valid() const
    {
        const auto field = [](const std::optional<FieldInfo> &value, uint32_t size, FieldKind kind, uint32_t extent)
        {
            return value && value->Size == size && value->Kind == kind && !value->BitOffset && !value->BitWidth && value->ValidFor(extent);
        };
        return Buckets && Buckets->Kind == FieldKind::Array && Buckets->ElementSize == 8u && Buckets->ArrayCount &&
               *Buckets->ArrayCount <= 512 && Buckets->ValidFor(8192) && !Buckets->BitOffset && !Buckets->BitWidth &&
               field(Next, 8, FieldKind::Pointer, 256) && field(Object, 8, FieldKind::Pointer, 256) && Body && Body->Offset == 0x30 &&
               Body->Kind == FieldKind::Composite && !Body->BitOffset && !Body->BitWidth &&
               field(Type, 1, FieldKind::Unsigned, Body->Offset) && Type->Offset == 0x18 &&
               field(Mask, 1, FieldKind::Unsigned, Body->Offset) && Mask->Offset == 0x1a && NameInfoSize > 0 && NameInfoSize <= 256 &&
               field(Parent, 8, FieldKind::Pointer, NameInfoSize) && field(Length, 2, FieldKind::Unsigned, NameInfoSize) &&
               field(Maximum, 2, FieldKind::Unsigned, NameInfoSize) && field(Buffer, 8, FieldKind::Pointer, NameInfoSize);
    }
};

inline bool KernelReadRange(const TargetArchitecture &architecture, uint64_t address, uint64_t size)
{
    return size != 0 && ValidRange(address, size) && architecture.KernelPointer(address) && architecture.KernelPointer(address + size - 1);
}

struct NamespaceNamePart
{
    uint64_t Parent = 0;
    std::wstring Name;
};

inline std::optional<NamespaceNamePart> ReadNamespaceNamePart(TargetReader &reader, const TargetArchitecture &architecture,
    const NamespaceLayout &layout, uint64_t header, unsigned char offset, std::optional<uint64_t> expectedParent = {},
    WalkBudget *budget = nullptr)
{
    if (offset < layout.NameInfoSize || header < offset || !KernelReadRange(architecture, header - offset, layout.NameInfoSize) ||
        (budget && !CheckWalkDeadline(*budget)))
    {
        return {};
    }
    const auto extent =
        std::max({layout.Parent->Offset + 8, layout.Length->Offset + 2, layout.Maximum->Offset + 2, layout.Buffer->Offset + 8});
    const auto block = reader.Read(AddressSpace::Virtual, header - offset, extent);
    if (budget && !CheckWalkDeadline(*budget))
    {
        return {};
    }
    const auto directory = BlockValue(block, layout.Parent->Offset, 8);
    const auto length = BlockValue(block, layout.Length->Offset, 2);
    const auto maximum = BlockValue(block, layout.Maximum->Offset, 2);
    const auto buffer = BlockValue(block, layout.Buffer->Offset, 8);
    if (!directory || (expectedParent && *directory != *expectedParent) || !KernelReadRange(architecture, *directory, 1) ||
        *directory % 8 != 0 || !length || !maximum || !buffer || *length == 0 || *length > *maximum || *length > 2048 ||
        *length % 2 != 0 || !KernelReadRange(architecture, *buffer, *length))
    {
        return {};
    }
    const auto text = reader.Read(AddressSpace::Virtual, *buffer, static_cast<size_t>(*length));
    if ((budget && !CheckWalkDeadline(*budget)) || !ExactBytes(text, static_cast<size_t>(*length)))
    {
        return {};
    }
    std::wstring result(static_cast<size_t>(*length / 2), L'\0');
    std::memcpy(result.data(), text.Bytes.data(), static_cast<size_t>(*length));
    for (size_t i = 0; i < result.size(); ++i)
    {
        const auto unit = result[i];
        if (unit == 0 || unit == L'\\' || (unit >= 0xdc00 && unit <= 0xdfff))
        {
            return {};
        }
        if (unit >= 0xd800 && unit <= 0xdbff)
        {
            if (++i >= result.size() || result[i] < 0xdc00 || result[i] > 0xdfff)
            {
                return {};
            }
        }
    }
    return NamespaceNamePart{*directory, std::move(result)};
}

inline bool ReadNamespaceName(TargetReader &reader, const TargetArchitecture &architecture, const NamespaceLayout &layout, uint64_t header,
                              uint64_t parent, unsigned char offset, std::wstring *name)
{
    const auto part = ReadNamespaceNamePart(reader, architecture, layout, header, offset, parent);
    if (part && name)
    {
        *name = part->Name;
        return true;
    }
    return false;
}

template <typename Visitor>
void WalkNamedNamespace(TargetReader &reader, const TargetArchitecture &architecture, const NamespaceLayout &layout, uint64_t root,
                        uint64_t cookieAddress, uint64_t offsetsAddress, unsigned directoryType, unsigned selectedType, unsigned maxDepth,
                        WalkBudget &budget, Visitor visitor)
{
    uint8_t cookie = 0;
    std::array<uint8_t, 4> offsets{};
    if (budget.Cancelled && budget.Cancelled())
    {
        budget.Stop(Status::Cancelled, L"Cancelled");
        return;
    }
    if (!layout.Valid() || maxDepth > 32 || directoryType > 255 || selectedType > 255 || !KernelReadRange(architecture, root, 1) ||
        !KernelReadRange(architecture, cookieAddress, 1) || !KernelReadRange(architecture, offsetsAddress, 4) ||
        !reader.ReadExact(AddressSpace::Virtual, cookieAddress, &cookie) ||
        !reader.ReadExact(AddressSpace::Virtual, offsetsAddress, &offsets))
    {
        budget.Stop(Status::Unavailable, L"NamespaceLayoutOrDecoderUnavailable");
        return;
    }
    const auto rootRaw = ReadField(reader, root - layout.Body->Offset, layout.Type);
    if (!rootRaw || static_cast<uint8_t>(*rootRaw ^ cookie ^ ((root - layout.Body->Offset) >> 8)) != directoryType)
    {
        budget.Stop(Status::Unavailable, L"ObjectCookieDecodeNotCorroboratedByRootType");
        return;
    }
    struct Directory
    {
        uint64_t Body;
        unsigned Depth;
        std::wstring Path;
    };
    std::vector<Directory> pending{{root, 0, L"\\"}};
    std::set<uint64_t> directories;
    bool depthLimited = false;
    uint64_t namesRead = 0;
    uint64_t filtered = 0;
    const auto entrySize = std::max(layout.Next->Offset + 8, layout.Object->Offset + 8);
    const auto begin = std::chrono::steady_clock::now();
    StartNamespaceTraversal(budget, begin);
    const auto headerStart = std::min(layout.Type->Offset, layout.Mask->Offset);
    const auto headerBytes = std::max(layout.Type->Offset, layout.Mask->Offset) + 1 - headerStart;
    while (!pending.empty() && CheckWalkDeadline(budget))
    {
        const auto current = pending.back();
        pending.pop_back();
        if (!directories.insert(current.Body).second)
        {
            budget.Stop(Status::Partial, L"RepeatedDirectory");
            break;
        }
        if (!KernelReadRange(architecture, current.Body, uint64_t(layout.Buckets->Offset) + layout.Buckets->Size))
        {
            budget.Stop(Status::Partial, L"InvalidDirectoryAddress");
            break;
        }
        const auto buckets = reader.Read(AddressSpace::Virtual, current.Body + layout.Buckets->Offset, layout.Buckets->Size);
        for (unsigned bucket = 0; bucket < *layout.Buckets->ArrayCount && CheckWalkDeadline(budget); ++bucket)
        {
            const auto first = BlockValue(buckets, bucket * 8, 8);
            if (!first)
            {
                ++budget.Report.Collected.Unreadable;
                continue;
            }
            uint64_t node = *first;
            while (node != 0 && CheckWalkDeadline(budget))
            {
                if (!KernelReadRange(architecture, node, entrySize) || !budget.Consume(node, architecture))
                {
                    if (!budget.Stopped)
                    {
                        budget.Stop(Status::Partial, L"InvalidDirectoryEntry");
                    }
                    break;
                }
                const auto entry = reader.Read(AddressSpace::Virtual, node, entrySize);
                const auto next = BlockValue(entry, layout.Next->Offset, 8);
                const auto body = BlockValue(entry, layout.Object->Offset, 8);
                if (!next || !body || *body < layout.Body->Offset || *body % 8 != 0 ||
                    !KernelReadRange(architecture, *body - layout.Body->Offset, layout.Body->Offset))
                {
                    ++budget.Report.Collected.Unreadable;
                    break;
                }
                node = *next;
                ++budget.Report.Collected.Read;
                const auto headerAddress = *body - layout.Body->Offset;
                const auto header = reader.Read(AddressSpace::Virtual, headerAddress + headerStart, headerBytes);
                const auto rawType = BlockValue(header, layout.Type->Offset - headerStart, 1);
                if (!rawType)
                {
                    ++budget.Report.Collected.Unreadable;
                    continue;
                }
                const auto type = static_cast<uint8_t>(*rawType ^ cookie ^ (headerAddress >> 8));
                ++budget.Report.Collected.Decoded;
                if (type != directoryType && type != selectedType)
                {
                    ++filtered;
                    continue;
                }
                const auto mask = BlockValue(header, layout.Mask->Offset - headerStart, 1);
                std::wstring name;
                ++namesRead;
                const bool named = mask && (*mask & 2) &&
                                   ReadNamespaceName(reader, architecture, layout, headerAddress, current.Body, offsets[*mask & 3], &name);
                const auto path = named && !current.Path.empty() ? current.Path + (current.Path == L"\\" ? L"" : L"\\") + name : L"";
                if (path.empty())
                {
                    ++budget.Report.Collected.Unknown;
                }
                if (!CheckWalkDeadline(budget))
                {
                    break;
                }
                if (type == directoryType)
                {
                    if (current.Depth < maxDepth)
                    {
                        pending.push_back({*body, current.Depth + 1, path});
                    }
                    else
                    {
                        depthLimited = true;
                    }
                }
                else if (!visitor(*body, type, current.Depth, path))
                {
                    if (CheckWalkDeadline(budget))
                    {
                        budget.Stop(Status::Partial, L"VisitorStopped");
                    }
                }
            }
        }
    }
    uint8_t finalCookie = 0;
    std::array<uint8_t, 4> finalOffsets{};
    if (CheckWalkDeadline(budget))
    {
        const bool stable = reader.ReadExact(AddressSpace::Virtual, cookieAddress, &finalCookie) && finalCookie == cookie &&
                            reader.ReadExact(AddressSpace::Virtual, offsetsAddress, &finalOffsets) && finalOffsets == offsets;
        if (CheckWalkDeadline(budget) && !stable)
        {
            budget.Stop(Status::StaleContext, L"NamespaceDecoderChanged");
        }
    }
    if (CheckWalkDeadline(budget) && (depthLimited || budget.Report.Collected.Unknown || budget.Report.Collected.Unreadable))
    {
        budget.Stop(Status::Partial, depthLimited ? L"DepthLimit" : L"NamespaceFieldsUnavailable");
    }
    budget.Report.Analysis = knjson::Value::MakeObject();
    budget.Report.Analysis.Set(L"directoriesVisited", knjson::Value(std::to_wstring(directories.size())));
    budget.Report.Analysis.Set(L"namesRead", knjson::Value(std::to_wstring(namesRead)));
    budget.Report.Analysis.Set(L"objectsFilteredBeforeNameRead", knjson::Value(std::to_wstring(filtered)));
    budget.Report.Analysis.Set(L"traversalLimitMs", knjson::Value(L"120000"));
    budget.Report.Analysis.Set(
        L"traversalElapsedMs",
        knjson::Value(
            std::to_wstring(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count())));
    budget.Complete();
}
} // namespace kncore
