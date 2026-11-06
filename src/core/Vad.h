#pragma once

#include "CollectorRead.h"

namespace kncore
{
struct VadLayout
{
    std::optional<FieldInfo> Node;
    std::optional<FieldInfo> Left;
    std::optional<FieldInfo> Right;
    std::optional<FieldInfo> Start;
    std::optional<FieldInfo> End;
    std::optional<FieldInfo> StartHigh;
    std::optional<FieldInfo> EndHigh;
    std::optional<FieldInfo> Protection;
    bool NoHighFields = false;
};

struct VadRow
{
    uint64_t Object = 0;
    std::optional<uint64_t> Start;
    std::optional<uint64_t> End;
    std::optional<uint64_t> ProtectionIndex;
    std::optional<uint64_t> PageProtection;
};

inline bool ValidProtectionTable(std::span<const uint32_t> table)
{
    constexpr uint32_t base[] = {1, 2, 0x10, 0x20, 4, 8, 0x40, 0x80};
    constexpr uint32_t modifiers[] = {0, 0x200, 0x100, 0x400};
    if (table.size() != 32)
    {
        return false;
    }
    for (size_t i = 0; i < table.size(); ++i)
    {
        const uint32_t expected = (i & 7) == 0 ? 1 : base[i & 7] | modifiers[i >> 3];
        if (table[i] != expected)
        {
            return false;
        }
    }
    return true;
}

inline std::optional<bool> ExecutableProtection(std::optional<uint64_t> pageProtection)
{
    if (!pageProtection)
    {
        return {};
    }
    const uint64_t base = *pageProtection & 0xff;
    if (base != 1 && base != 2 && base != 4 && base != 8 && base != 0x10 && base != 0x20 && base != 0x40 && base != 0x80)
    {
        return {};
    }
    return (base & 0xf0) != 0;
}

// The _MMVAD protection index encodes an architectural base access right
// plus modifier bits (Windows Internals; the target's MmProtectToValue maps
// an index to the actual PAGE_* mask): base 0..7, +8 no-cache, +0x10 guard,
// +0x18 write-combine. Used for display when the target table is
// unavailable; the raw index is always shown alongside.
inline std::wstring StandardProtectionName(uint64_t index)
{
    static const wchar_t *base[8] = {L"NoAccess",  L"ReadOnly",  L"Execute",          L"ExecuteRead",
                                    L"ReadWrite", L"WriteCopy", L"ExecuteReadWrite", L"ExecuteWriteCopy"};
    if (index >= 32)
    {
        return {};
    }
    std::wstring name = base[index & 7];
    if ((index & 7) == 0)
    {
        // MmProtectToValue maps every no-access variant to PAGE_NOACCESS.
        return name;
    }
    if ((index & 0x18) == 0x18)
    {
        name += L"+WriteCombine";
    }
    else
    {
        if ((index & 0x8) != 0)
        {
            name += L"+NoCache";
        }
        if ((index & 0x10) != 0)
        {
            name += L"+Guard";
        }
    }
    return name;
}

inline VadRow ReadVad(TargetReader &reader, uint64_t object, const VadLayout &layout, const std::vector<uint32_t> &protectionTable)
{
    VadRow row;
    row.Object = object;
    const auto start = ReadField(reader, object, layout.Start);
    const auto end = ReadField(reader, object, layout.End);
    const auto highStart = layout.NoHighFields ? std::optional<uint64_t>(0) : ReadField(reader, object, layout.StartHigh);
    const auto highEnd = layout.NoHighFields ? std::optional<uint64_t>(0) : ReadField(reader, object, layout.EndHigh);
    if (start && end && highStart && highEnd && *start <= UINT32_MAX && *end <= UINT32_MAX && *highStart <= 255 && *highEnd <= 255)
    {
        const uint64_t first = *start | (*highStart << 32);
        const uint64_t last = *end | (*highEnd << 32);
        if (first <= last && last < (UINT64_MAX >> 12))
        {
            row.Start = first << 12;
            row.End = ((last + 1) << 12) - 1;
        }
    }
    if (layout.Protection && layout.Protection->BitOffset && layout.Protection->BitWidth)
    {
        row.ProtectionIndex = ReadField(reader, object, layout.Protection);
    }
    if (row.ProtectionIndex && *row.ProtectionIndex < protectionTable.size())
    {
        row.PageProtection = protectionTable[static_cast<size_t>(*row.ProtectionIndex)];
    }
    return row;
}

template <typename Visitor>
void WalkVadTree(TargetReader &reader, uint64_t root, const VadLayout &layout, const TargetArchitecture &architecture,
                 const std::vector<uint32_t> &protectionTable, WalkBudget &budget, Visitor visitor)
{
    if (!layout.Node || !layout.Left || !layout.Right || layout.Left->Size != architecture.PointerBytes ||
        layout.Right->Size != architecture.PointerBytes)
    {
        budget.Stop(Status::Unavailable, L"VadTreeLayoutUnavailable");
        return;
    }
    std::vector<uint64_t> stack;
    if (root != 0)
    {
        stack.push_back(root);
    }
    while (!stack.empty())
    {
        const uint64_t node = stack.back();
        stack.pop_back();
        if (!architecture.KernelPointer(node) || !budget.Consume(node, architecture))
        {
            if (!budget.Stopped)
            {
                budget.Stop(Status::Partial, L"InvalidVadNode");
            }
            break;
        }
        const auto left = ReadField(reader, node, layout.Left);
        const auto right = ReadField(reader, node, layout.Right);
        for (const auto child : {right, left})
        {
            if (!child)
            {
                ++budget.Report.Collected.Unreadable;
            }
            else if (*child != 0)
            {
                stack.push_back(*child);
            }
        }
        if (node < layout.Node->Offset || !architecture.KernelPointer(node - layout.Node->Offset))
        {
            budget.Stop(Status::Partial, L"InvalidVadContainer");
            break;
        }
        const auto row = ReadVad(reader, node - layout.Node->Offset, layout, protectionTable);
        ++budget.Report.Collected.Read;
        if (!row.Start || !row.End || !ExecutableProtection(row.PageProtection).has_value())
        {
            ++budget.Report.Collected.Unknown;
        }
        else
        {
            ++budget.Report.Collected.Decoded;
        }
        if (!visitor(row))
        {
            budget.Stop(Status::Partial, L"VadVisitorStopped");
            break;
        }
    }
    if (!budget.Stopped && (budget.Report.Collected.Unknown != 0 || budget.Report.Collected.Unreadable != 0))
    {
        budget.Stop(Status::Partial, L"VadFieldsOrLinksUnavailable");
    }
    budget.Complete();
}
} // namespace kncore
