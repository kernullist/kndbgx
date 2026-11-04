#pragma once

// x64 page table walker (PML4 and PML5/LA57 aware).
//
// Reads page table entries through the session physical-read primitive and
// reports every traversed entry plus effective permissions, mirroring the
// kn-live-dbg vtop information density.

#include <windows.h>

#include <string>
#include "../core/Result.h"
#include "../core/Architecture.h"

namespace knengine
{
// CR4.LA57 is bit 12. Bit 23 is CR4.CET; mixing them mis-classifies
// every CET-enabled 4-level system as 5-level paging.
const int kCr4La57Bit = 12;

inline bool Cr4HasLa57(ULONG64 cr4)
{
    return ((cr4 >> kCr4La57Bit) & 1ULL) != 0;
}

// Pure x64 index extraction used by the walker and covered by the
// driver-free self-test. out[0] is the topmost level index.
void ComputeOrderedIndices(ULONG64 virtualAddress, bool la57Active, unsigned int out[5]);

class DbgSession;

bool DetectLa57(DbgSession &session);

struct PageWalkResult
{
    bool Ok;
    std::wstring Error;

    ULONG64 VirtualAddress;
    ULONG64 DirectoryTableBase;
    bool La57Active;
    bool PhysicalWidthVerified = false;
    unsigned PhysicalAddressBits = 52;

    // Raw entry values and the physical address of each entry's slot.
    // Index 0 is the top level (PML5E when La57Active, else PML4E).
    static const int kMaxLevels = 5;
    ULONG64 EntryValue[kMaxLevels];
    ULONG64 EntrySlotPhysical[kMaxLevels];
    int LevelCount; // number of populated entries

    bool Present;
    bool LargePage;          // 2 MB or 1 GB leaf above the PTE level
    int LargePageLevel;      // -1 when not large; index into arrays
    ULONG PageSize;          // 0x1000 / 0x200000 / 0x40000000
    ULONG64 PhysicalAddress; // final translated PA (page base | offset)
    ULONG OffsetInPage;
    ULONG ContiguousBytes; // bytes translatable before next boundary

    bool EffectiveWritable;   // R/W ANDed across every traversed entry
    bool EffectiveExecutable; // NX bit ORed across every traversed entry

    PageWalkResult();
};

inline knjson::Value PageWalkObservation(const PageWalkResult &walk)
{
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"PageTranslation"));
    row.Set(L"va", knjson::Value(kncore::Hex(walk.VirtualAddress)));
    row.Set(L"dtb", knjson::Value(kncore::Hex(walk.DirectoryTableBase)));
    row.Set(L"pa", walk.Ok ? knjson::Value(kncore::Hex(walk.PhysicalAddress)) : knjson::Value());
    row.Set(L"pageSize", walk.Ok ? knjson::Value(kncore::Hex(walk.PageSize)) : knjson::Value());
    row.Set(L"writable", walk.Ok ? knjson::Value(walk.EffectiveWritable) : knjson::Value());
    row.Set(L"executable", walk.Ok ? knjson::Value(walk.EffectiveExecutable) : knjson::Value());
    row.Set(L"error", walk.Error.empty() ? knjson::Value() : knjson::Value(walk.Error));
    auto entries = knjson::Value::MakeArray();
    for (int index = 0; index < walk.LevelCount && index < PageWalkResult::kMaxLevels; ++index)
    {
        auto entry = knjson::Value::MakeObject();
        entry.Set(L"level", knjson::Value(std::to_wstring((walk.La57Active ? 5 : 4) - index)));
        entry.Set(L"address", knjson::Value(kncore::Hex(walk.EntrySlotPhysical[index])));
        entry.Set(L"addressSpace", knjson::Value(L"physical"));
        entry.Set(L"value", knjson::Value(kncore::Hex(walk.EntryValue[index])));
        entries.Push(entry);
    }
    row.Set(L"entries", entries);
    return row;
}

// Walks `va` starting from `directoryTableBase` (a raw CR3 value; PCID
// and flag bits are masked internally). `la57Active` selects 5-level
// paging (CR4.LA57). Returns false with Error set on unreadable tables
// or non-present mappings.
bool WalkVirtualToPhysical(DbgSession &session, ULONG64 virtualAddress, ULONG64 directoryTableBase, bool la57Active,
                           PageWalkResult *result);

bool WalkPageTables(kncore::TargetReader &reader, const kncore::TargetArchitecture &architecture, uint64_t virtualAddress,
                    uint64_t directoryTableBase, PageWalkResult *result);
} // namespace knengine
