#include "PageWalk.h"

#include "EngineCore.h"

namespace knengine
{
namespace
{
// Physical address bits on x64 MMU translation entries.
const ULONG64 kPhysMask = 0x000FFFFFFFFFF000ULL;
} // namespace

void ComputeOrderedIndices(ULONG64 virtualAddress, bool la57Active, unsigned int out[5])
{
    const unsigned int pml4 = static_cast<unsigned int>((virtualAddress >> 39) & 0x1FF);
    const unsigned int pdpt = static_cast<unsigned int>((virtualAddress >> 30) & 0x1FF);
    const unsigned int pd = static_cast<unsigned int>((virtualAddress >> 21) & 0x1FF);
    const unsigned int pt = static_cast<unsigned int>((virtualAddress >> 12) & 0x1FF);

    if (la57Active)
    {
        out[0] = static_cast<unsigned int>((virtualAddress >> 48) & 0x1FF);
        out[1] = pml4;
        out[2] = pdpt;
        out[3] = pd;
        out[4] = pt;
    }
    else
    {
        out[0] = pml4;
        out[1] = pdpt;
        out[2] = pd;
        out[3] = pt;
        out[4] = 0;
    }
}

PageWalkResult::PageWalkResult()
{
    Ok = false;
    Error.clear();
    VirtualAddress = 0;
    DirectoryTableBase = 0;
    La57Active = false;

    for (int i = 0; i < kMaxLevels; ++i)
    {
        EntryValue[i] = 0;
        EntrySlotPhysical[i] = 0;
    }

    LevelCount = 0;
    Present = false;
    LargePage = false;
    LargePageLevel = -1;
    PageSize = 0x1000;
    PhysicalAddress = 0;
    OffsetInPage = 0;
    ContiguousBytes = 0x1000;
    EffectiveWritable = false;
    EffectiveExecutable = true;
}

bool WalkPageTables(kncore::TargetReader &reader, const kncore::TargetArchitecture &architecture, uint64_t virtualAddress,
                    uint64_t directoryTableBase, PageWalkResult *result)
{
    bool ok = false;
    PageWalkResult walk;

    do
    {
        if (result == nullptr)
        {
            break;
        }

        walk.VirtualAddress = virtualAddress;
        walk.DirectoryTableBase = directoryTableBase;
        walk.La57Active = architecture.VirtualAddressBits == 57u;
        walk.PhysicalWidthVerified = architecture.PhysicalAddressBits.has_value();
        walk.PhysicalAddressBits = architecture.PhysicalAddressBits.value_or(52);
        if (architecture.Machine != IMAGE_FILE_MACHINE_AMD64 || architecture.PointerBytes != 8 || !architecture.VirtualAddressBits ||
            (*architecture.VirtualAddressBits != 48 && *architecture.VirtualAddressBits != 57) || walk.PhysicalAddressBits < 32 ||
            walk.PhysicalAddressBits > 52)
        {
            walk.Error = L"Unsupported or unknown paging architecture";
            break;
        }
        const ULONG64 physicalMask = ((1ULL << walk.PhysicalAddressBits) - 1) & ~0xfffULL;
        if ((directoryTableBase & kPhysMask & ~physicalMask) != 0)
        {
            walk.Error = L"Directory table base exceeds target physical width";
            break;
        }

        // Canonicality check:
        // 4-level paging: bits 63..47 must be sign extension of bit 47.
        // 5-level paging (LA57): bits 63..56 must be sign extension of bit 56.
        if (!architecture.Canonical(virtualAddress))
        {
            walk.Error = L"non-canonical virtual address";
            break;
        }

        // CR3: PCID in bits 11..0 on PCIDE systems. Mask to the
        // physical table base. LA57 is CR4 bit 12, not a CR3 flag.
        ULONG64 tablePhysical = directoryTableBase & kPhysMask;

        if (tablePhysical == 0)
        {
            walk.Error = L"directory table base is zero";
            break;
        }

        unsigned int orderedIndices[PageWalkResult::kMaxLevels] = {};
        ComputeOrderedIndices(virtualAddress, walk.La57Active, orderedIndices);

        // Level metadata per depth. Depth 0 = leaf PTE.
        struct LevelInfo
        {
            int shift; // VA shift covered by entries AT this depth
            ULONG64 pageSize;
        };
        const LevelInfo levelInfo[5] = {
            {12, 0x1000},     // PTE (depth 0)
            {21, 0x200000},   // PDE (depth 1)
            {30, 0x40000000}, // PDPTE (depth 2)
            {39, 0},          // PML4E (depth 3)
            {48, 0}           // PML5E (depth 4)
        };

        // Traversal order: top-down. Depth 0 is the leaf PTE.
        const int topDepth = walk.La57Active ? 4 : 3;

        walk.Present = true;
        walk.EffectiveWritable = true;
        walk.EffectiveExecutable = true;
        int populated = 0;
        int currentDepth = topDepth;

        for (int i = 0; i <= topDepth; ++i)
        {
            const ULONG64 entrySlot = tablePhysical + static_cast<ULONG64>(orderedIndices[i]) * 8ULL;

            ULONG64 entryValue = 0;
            if (!reader.ReadExact(kncore::AddressSpace::Physical, entrySlot, &entryValue))
            {
                walk.Error = L"failed to read page table entry";
                walk.Present = false;
                break;
            }

            walk.EntrySlotPhysical[populated] = entrySlot;
            walk.EntryValue[populated] = entryValue;
            ++populated;

            if ((entryValue & 0x1ULL) == 0)
            {
                // Not present at this level.
                walk.Present = false;
                walk.Error = L"mapping not present";
                break;
            }
            if ((entryValue & kPhysMask & ~physicalMask) != 0)
            {
                walk.Error = L"Entry exceeds target physical width";
                break;
            }
            if (currentDepth >= 3 && (entryValue & 0x80ULL) != 0)
            {
                walk.Error = L"Reserved large-page bit at non-leaf upper level";
                break;
            }

            if ((entryValue & 0x2ULL) == 0)
            {
                walk.EffectiveWritable = false;
            }

            if ((entryValue & 0x8000000000000000ULL) != 0)
            {
                walk.EffectiveExecutable = false;
            }

            // Large page check applies to depths above the PTE level:
            // depth 2 = PDPTE (1 GB), depth 1 = PDE (2 MB).
            if (currentDepth == 2 || currentDepth == 1)
            {
                if ((entryValue & 0x80ULL) != 0)
                {
                    const int shift = levelInfo[currentDepth].shift;
                    const ULONG64 offsetMask = (1ULL << shift) - 1;
                    if ((entryValue & offsetMask & kPhysMask & ~(1ULL << 12)) != 0)
                    {
                        walk.Error = L"Reserved large-page alignment bits";
                        break;
                    }
                    const ULONG64 pageBase = entryValue & ~offsetMask & kPhysMask;

                    walk.LargePage = true;
                    walk.LargePageLevel = populated - 1;
                    walk.PageSize = static_cast<ULONG>(levelInfo[currentDepth].pageSize);
                    walk.PhysicalAddress = pageBase | (virtualAddress & offsetMask);
                    walk.OffsetInPage = static_cast<ULONG>(virtualAddress & offsetMask);
                    walk.ContiguousBytes = static_cast<ULONG>(static_cast<ULONG64>(walk.PageSize) - walk.OffsetInPage);
                    ok = true;
                    break;
                }
            }

            if (currentDepth == 0)
            {
                walk.PageSize = 0x1000;
                walk.PhysicalAddress = (entryValue & kPhysMask) | (virtualAddress & 0xFFFULL);
                walk.OffsetInPage = static_cast<ULONG>(virtualAddress & 0xFFFULL);
                walk.ContiguousBytes = static_cast<ULONG>(0x1000 - walk.OffsetInPage);
                ok = true;
                break;
            }

            // Descend into the next table.
            tablePhysical = entryValue & kPhysMask;
            --currentDepth;
        }

        walk.LevelCount = populated;
        walk.Ok = ok;
    } while (false);

    if (result != nullptr)
    {
        *result = walk;
    }

    return result != nullptr && result->Ok;
}

bool DetectLa57(DbgSession &session)
{
    ULONG64 cr4 = 0;
    return session.ReadRegisterHex(L"cr4", &cr4) && Cr4HasLa57(cr4);
}

bool WalkVirtualToPhysical(DbgSession &session, ULONG64 address, ULONG64 dtb, bool la57, PageWalkResult *result)
{
    SessionStatus status = {};
    session.QueryStatus(&status);
    ULONG64 cr4 = 0;
    if (result == nullptr)
    {
        return false;
    }
    if (status.Architecture != IMAGE_FILE_MACHINE_AMD64 || !session.ReadRegisterHex(L"cr4", &cr4) || Cr4HasLa57(cr4) != la57)
    {
        *result = {};
        result->VirtualAddress = address;
        result->DirectoryTableBase = dtb;
        result->La57Active = la57;
        result->Error = L"Paging mode unavailable or changed; x64 and current CR4 required";
        return false;
    }
    const kncore::TargetArchitecture architecture{IMAGE_FILE_MACHINE_AMD64, 8, la57 ? 57u : 48u, {}};
    return WalkPageTables(session, architecture, address, dtb, result);
}
} // namespace knengine
