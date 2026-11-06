#pragma once

#include "CollectorRead.h"

namespace kncore
{
struct HandleTableLayout
{
    std::optional<FieldInfo> TableCode;
    std::optional<FieldInfo> NextHandle;
    std::optional<FieldInfo> ObjectBits;
    std::optional<FieldInfo> AccessBits;
    uint32_t EntrySize = 0;
    uint32_t BodyOffset = 0;
    bool CidTable = false;

    bool Valid() const
    {
        return TableCode && TableCode->Size == 8 && !TableCode->BitOffset && !TableCode->BitWidth &&
               NextHandle && NextHandle->Size == 4 && !NextHandle->BitOffset && !NextHandle->BitWidth &&
               EntrySize == 16 && (CidTable ? BodyOffset == 0 : BodyOffset >= 16 && BodyOffset <= 256 && BodyOffset % 16 == 0) &&
               ObjectBits && ObjectBits->ValidFor(EntrySize) && ObjectBits->Size == 8 &&
               ObjectBits->BitOffset && ObjectBits->BitWidth == 44u &&
               AccessBits && AccessBits->ValidFor(EntrySize) && AccessBits->BitOffset && AccessBits->BitWidth &&
               *AccessBits->BitWidth <= 32 && (AccessBits->Size == 4 || AccessBits->Size == 8);
    }
};

struct TargetHandleEntry
{
    uint64_t Handle = 0;
    uint64_t Object = 0;
    uint32_t Access = 0;
};

inline uint64_t HandleEntryField(std::span<const unsigned char> entry, const FieldInfo &field)
{
    uint64_t value = 0;
    std::memcpy(&value, entry.data() + field.Offset, field.Size);
    return (value >> *field.BitOffset) & ((uint64_t(1) << *field.BitWidth) - 1);
}

template <typename Visitor>
bool WalkTargetHandleTable(TargetReader &reader, uint64_t table, const HandleTableLayout &layout,
                           const TargetArchitecture &architecture, WalkBudget &budget, Visitor visitor)
{
    if (budget.Stopped)
    {
        return false;
    }
    if (!layout.Valid() || architecture.PointerBytes != 8 || !architecture.KernelPointer(table))
    {
        return budget.Stop(Status::Unavailable, L"HandleTableLayoutUnavailable");
    }
    const auto check = [&](bool enforceNodeBudget = true)
    {
        if (!budget.Stopped && budget.Cancelled && budget.Cancelled())
        {
            budget.Stop(Status::Cancelled, L"Cancelled");
        }
        if (!budget.Stopped && (std::chrono::steady_clock::now() >= budget.Deadline ||
                                (enforceNodeBudget && budget.Report.Collected.Visited >= budget.MaxNodes)))
        {
            budget.Stop(Status::Partial, L"HandleTableBudget");
        }
        return !budget.Stopped;
    };
    budget.StartTraversal();
    const auto readExact = [&](uint64_t address, size_t length, Status missing, const wchar_t *reason) -> std::optional<ReadResult>
    {
        if (!check())
        {
            return {};
        }
        auto bytes = reader.Read(AddressSpace::Virtual, address, length);
        const bool terminal = bytes.State != Status::Success && bytes.State != Status::Partial && bytes.State != Status::Unavailable;
        // An expired cooperative budget must not hide a completed engine failure.
        if (!terminal && !check())
        {
            return {};
        }
        if (!ExactBytes(bytes, length))
        {
            ++budget.Report.Collected.Unreadable;
            budget.Report.Error = bytes.Error;
            budget.Stop(terminal ? bytes.State : missing, reason);
            return {};
        }
        return bytes;
    };
    const auto fieldValue = [&](const FieldInfo &field) -> std::optional<uint64_t>
    {
        if (!ValidRange(table, static_cast<uint64_t>(field.Offset) + field.Size))
        {
            budget.Stop(Status::Unavailable, L"HandleTableHeaderRangeInvalid");
            return {};
        }
        const auto bytes = readExact(table + field.Offset, field.Size, Status::Unavailable, L"HandleTableHeaderUnreadable");
        if (!bytes)
        {
            return {};
        }
        uint64_t value = 0;
        std::memcpy(&value, bytes->Bytes.data(), field.Size);
        return value;
    };
    const auto code = fieldValue(*layout.TableCode);
    if (!code)
    {
        return false;
    }
    const auto next = fieldValue(*layout.NextHandle);
    if (!next)
    {
        return false;
    }
    if (*next % 4 != 0 || *next > 4 * 1024 * 1024 || (*code & 3) > 2)
    {
        return budget.Stop(Status::Unavailable, L"HandleTableBoundsUnavailable");
    }
    const auto levels = static_cast<unsigned>(*code & 3);
    const uint64_t root = *code & ~uint64_t(3);
    const uint64_t count = *next / 4;
    uint64_t capacity = 4096 / layout.EntrySize;
    for (unsigned level = 0; level < levels; ++level)
    {
        capacity *= 512;
    }
    if (count == 0 || count > capacity || !architecture.KernelPointer(root) || root % 4096 != 0)
    {
        return budget.Stop(Status::Unavailable, L"HandleTableRootInvalid");
    }
    budget.Report.Collected.Expected += count - 1;
    std::set<uint64_t> pages;
    std::function<bool(uint64_t, unsigned, uint64_t, uint64_t)> visitPage;
    visitPage = [&](uint64_t page, unsigned level, uint64_t first, uint64_t slots)
    {
        if (!check())
        {
            return false;
        }
        if (!architecture.KernelPointer(page) || page % 4096 != 0 || !ValidRange(page, 4096) || !pages.insert(page).second)
        {
            return budget.Stop(Status::Partial, L"HandleTablePageInvalidOrRepeated");
        }
        const auto bytes = readExact(page, 4096, Status::Partial, L"HandleTablePageUnreadable");
        if (!bytes)
        {
            return false;
        }
        if (level != 0)
        {
            const uint64_t childSlots = slots / 512;
            const uint64_t children = (std::min)(uint64_t(512), (count - first + childSlots - 1) / childSlots);
            for (uint64_t i = 0; i < children; ++i)
            {
                uint64_t child = 0;
                std::memcpy(&child, bytes->Bytes.data() + i * 8, 8);
                if (!visitPage(child, level - 1, first + i * childSlots, childSlots))
                {
                    return false;
                }
            }
        }
        else
        {
            const uint64_t end = (std::min)(count, first + slots);
            for (uint64_t index = first; index < end; ++index)
            {
                if (index == 0)
                {
                    continue;
                }
                if (!check())
                {
                    return false;
                }
                ++budget.Report.Collected.Visited;
                ++budget.Report.Collected.Read;
                const std::span entry(bytes->Bytes.data() + (index - first) * layout.EntrySize, layout.EntrySize);
                const uint64_t objectBits = HandleEntryField(entry, *layout.ObjectBits);
                if (objectBits == 0)
                {
                    continue;
                }
                // CID entries encode bodies; process handles encode headers. Both retain bits 4..47.
                const uint64_t lower = objectBits << 4;
                if ((lower & (uint64_t(1) << 47)) == 0)
                {
                    ++budget.Report.Collected.Unknown;
                    continue;
                }
                const uint64_t header = lower | 0xffff000000000000ull;
                if (!ValidRange(header, layout.BodyOffset + 1) || !architecture.KernelPointer(header + layout.BodyOffset))
                {
                    ++budget.Report.Collected.Unknown;
                    continue;
                }
                ++budget.Report.Collected.Decoded;
                TargetHandleEntry decoded{index * 4, header + layout.BodyOffset,
                                          static_cast<uint32_t>(HandleEntryField(entry, *layout.AccessBits))};
                if (!visitor(decoded) || !check(false))
                {
                    if (!budget.Stopped)
                    {
                        budget.Stop(Status::Partial, L"HandleTableVisitorStopped");
                    }
                    return false;
                }
            }
        }
        return true;
    };
    return visitPage(root, levels, 0, capacity);
}
} // namespace kncore
