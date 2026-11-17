#pragma once

#include "CollectorRead.h"
#include <array>
#include <string_view>

namespace kncore
{
struct PoolDisplayOptions
{
    explicit PoolDisplayOptions(bool payload) : Summary(!payload), Permissions(payload)
    {
    }
    bool Summary;
    bool Permissions;
    bool Full = false;

    bool Apply(std::wstring_view option)
    {
        if (option == L"summary" || option == L"big" || option == L"find")
        {
            Summary = option == L"summary";
            explicitMode_ = true;
        }
        else if (option == L"/wx" || option == L"/full")
        {
            Permissions = true;
            Full = Full || option == L"/full";
            if (!explicitMode_)
            {
                Summary = false;
            }
        }
        else
        {
            return false;
        }
        return true;
    }

  private:
    bool explicitMode_ = false;
};

struct BigPoolEntry
{
    uint64_t Address = 0;
    uint64_t Size = 0;
    std::array<unsigned char, 4> Tag = {};
    bool NonPaged = false;
    bool NonPagedKnown = false;
};

inline bool ParseBigPool64(std::span<const unsigned char> bytes, std::vector<BigPoolEntry> &entries)
{
    entries.clear();
    uint32_t count = 0;
    if (bytes.size() < 8)
    {
        return false;
    }
    std::memcpy(&count, bytes.data(), 4);
    if (count > (bytes.size() - 8) / 24 || count > 4000000)
    {
        return false;
    }
    for (size_t i = 0; i < count; ++i)
    {
        BigPoolEntry entry;
        const auto *raw = bytes.data() + 8 + i * 24;
        std::memcpy(&entry.Address, raw, 8);
        std::memcpy(&entry.Size, raw + 8, 8);
        std::memcpy(entry.Tag.data(), raw + 16, 4);
        entry.NonPaged = (entry.Address & 1) != 0;
        entry.NonPagedKnown = true;
        entry.Address &= ~uint64_t(1);
        if (entry.Size == 0 || !ValidRange(entry.Address, entry.Size))
        {
            entries.clear();
            return false;
        }
        entries.push_back(entry);
    }
    return true;
}

inline uint64_t PoolPageCount(const BigPoolEntry &entry)
{
    return (entry.Size - 1) / 4096 + 1 + (((entry.Size - 1) % 4096 + (entry.Address & 4095)) >= 4096 ? 1 : 0);
}

// Offsets from the matched kernel PDB's _POOL_TRACKER_BIG_PAGES type.
// NumberOfBytes is a byte count, and Va bit zero marks a freed allocation.
// This table has a different contract from SYSTEM_BIGPOOL_ENTRY above.
struct PoolTableLayout
{
    unsigned EntrySize = 0;
    unsigned VaOffset = 0;
    unsigned TagOffset = 0;
    unsigned SizeOffset = 0;
    unsigned SizeBytes = 0;
};

constexpr unsigned kPoolMaxTableEntries = 4000000;

inline bool ValidPoolStorageRange(const TargetArchitecture &architecture, uint64_t address, uint64_t bytes)
{
    return architecture.KernelPointer(address) && ValidRange(address, bytes) &&
           architecture.KernelPointer(address + bytes - 1);
}

inline std::optional<uint64_t> ReadPoolTableGlobal(TargetReader &reader, const TargetArchitecture &architecture,
                                                  uint64_t address, const std::optional<FieldInfo> &field, unsigned bytes)
{
    if ((bytes != 4 && bytes != 8) || !field || field->Offset != 0 || field->Size != bytes ||
        field->BitOffset || field->BitWidth || address % bytes != 0 || !ValidPoolStorageRange(architecture, address, bytes))
    {
        return {};
    }
    return ReadField(reader, address, field);
}

inline bool ValidPoolTableLayout(const PoolTableLayout &layout)
{
    const auto fits = [&](unsigned offset, unsigned size)
    {
        return offset <= layout.EntrySize && size <= layout.EntrySize - offset;
    };
    return (layout.SizeBytes == 4 || layout.SizeBytes == 8) && layout.EntrySize >= 24 && layout.EntrySize <= 1024 &&
           fits(layout.VaOffset, 8) && fits(layout.TagOffset, 4) && fits(layout.SizeOffset, layout.SizeBytes);
}

inline bool ValidPoolTableStorage(const TargetArchitecture &architecture, uint64_t address, uint64_t count,
                                  const PoolTableLayout &layout)
{
    // Count and entry-size bounds keep the product below UINT64_MAX.
    return ValidPoolTableLayout(layout) && count != 0 && count <= kPoolMaxTableEntries && address % 8 == 0 &&
           ValidPoolStorageRange(architecture, address, count * static_cast<uint64_t>(layout.EntrySize));
}

enum class PoolTableEntryKind
{
    Entry,
    Free,
    Invalid
};

inline PoolTableEntryKind DecodePoolTableEntry64(const unsigned char *raw, const PoolTableLayout &layout, BigPoolEntry &entry)
{
    entry = BigPoolEntry{};
    if (raw == nullptr || !ValidPoolTableLayout(layout))
    {
        return PoolTableEntryKind::Invalid;
    }
    uint64_t va = 0;
    std::memcpy(&va, raw + layout.VaOffset, 8);
    if (va == 0 || (va & 1) != 0)
    {
        return PoolTableEntryKind::Free;
    }
    uint64_t bytes = 0;
    std::memcpy(&bytes, raw + layout.SizeOffset, layout.SizeBytes);
    if ((va >> 47) != 0x1ffff || (va & 4095) != 0 || !ValidRange(va, bytes) ||
        ((va + bytes - 1) >> 47) != 0x1ffff)
    {
        return PoolTableEntryKind::Invalid;
    }
    entry.Address = va;
    entry.Size = bytes;
    std::memcpy(entry.Tag.data(), raw + layout.TagOffset, 4);
    // PoolFlags/PoolType encoding varies by kernel. Without a verified
    // interpretation, the caller must retain an unknown pool class.
    return PoolTableEntryKind::Entry;
}
} // namespace kncore
