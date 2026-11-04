#pragma once

#include <cstdint>
#include <optional>

namespace kncore
{
struct TargetArchitecture
{
    uint32_t Machine = 0;
    unsigned PointerBytes = 0;
    std::optional<unsigned> VirtualAddressBits;
    std::optional<unsigned> PhysicalAddressBits;

    bool Canonical(uint64_t address) const
    {
        if (Machine == 0x14c && PointerBytes == 4)
        {
            return address <= UINT32_MAX;
        }
        if (Machine != 0x8664 || PointerBytes != 8 || !VirtualAddressBits || (*VirtualAddressBits != 48 && *VirtualAddressBits != 57))
        {
            return false;
        }
        const unsigned bits = *VirtualAddressBits;
        const uint64_t mask = UINT64_MAX << (bits - 1);
        return (address & mask) == 0 || (address & mask) == mask;
    }

    bool KernelPointer(uint64_t address) const
    {
        return Machine == 0x8664 && Canonical(address) && (address >> 63) != 0;
    }
};
} // namespace kncore
