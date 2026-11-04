#pragma once

#include "BinaryFormats.h"
#include <array>
#include <optional>

namespace kncore
{
inline std::optional<uint64_t> PeFileOffset(const PeImage &image, uint64_t rva, uint64_t size)
{
    if (size == 0 || !Contains(image.ImageSize, rva, size))
    {
        return {};
    }
    std::optional<uint64_t> offset;
    if (rva < image.HeadersSize)
    {
        if (!Contains(image.HeadersSize, rva, size))
        {
            return {};
        }
        offset = rva;
    }
    for (const auto &section : image.Sections)
    {
        const uint64_t extent = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
        if (extent != 0 && rva < uint64_t(section.VirtualAddress) + extent && section.VirtualAddress < rva + size)
        {
            // Any intersecting mapping must cover the entire read and be uniquely file-backed.
            if (offset || rva < section.VirtualAddress || !Contains(section.SizeOfRawData, rva - section.VirtualAddress, size))
            {
                return {};
            }
            offset = uint64_t(section.PointerToRawData) + rva - section.VirtualAddress;
        }
    }
    return offset;
}

inline std::optional<std::array<unsigned char, 20>> CodeViewIdentity(ByteReader &reader, const PeImage &image, bool mapped,
                                                                     bool *complete = nullptr)
{
    if (complete != nullptr)
    {
        *complete = true;
    }
    const auto incomplete = [complete]() -> std::optional<std::array<unsigned char, 20>>
    {
        if (complete != nullptr)
        {
            *complete = false;
        }
        return {};
    };
    const auto directory = image.DebugDirectory;
    if (directory.Size == 0 && directory.VirtualAddress == 0)
    {
        return {};
    }
    if (directory.VirtualAddress == 0 || directory.Size == 0 || directory.Size % sizeof(IMAGE_DEBUG_DIRECTORY) != 0 ||
        directory.Size > 64 * sizeof(IMAGE_DEBUG_DIRECTORY) || !Contains(image.ImageSize, directory.VirtualAddress, directory.Size))
    {
        return incomplete();
    }
    const auto offset =
        mapped ? std::optional<uint64_t>(directory.VirtualAddress) : PeFileOffset(image, directory.VirtualAddress, directory.Size);
    if (!offset)
    {
        return incomplete();
    }
    std::optional<std::array<unsigned char, 20>> found;
    for (uint32_t index = 0; index < directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY); ++index)
    {
        IMAGE_DEBUG_DIRECTORY entry = {};
        if (!reader.ReadObject(*offset + index * sizeof(entry), &entry))
        {
            return incomplete();
        }
        if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW)
        {
            continue;
        }
        std::array<unsigned char, 24> record;
        const uint64_t recordOffset = mapped ? entry.AddressOfRawData : entry.PointerToRawData;
        if (entry.SizeOfData < record.size() || !Contains(reader.Size(), recordOffset, entry.SizeOfData) ||
            !reader.Read(recordOffset, record) || std::memcmp(record.data(), "RSDS", 4) != 0)
        {
            return incomplete();
        }
        std::array<unsigned char, 20> identity;
        std::copy(record.begin() + 4, record.end(), identity.begin());
        if (found && *found != identity)
        {
            return incomplete();
        }
        found = identity;
    }
    return found;
}

inline bool SamePeIdentity(const PeImage &a, const PeImage &b, const std::optional<std::array<unsigned char, 20>> &aPdb,
                           const std::optional<std::array<unsigned char, 20>> &bPdb)
{
    return a.File.Machine == b.File.Machine && a.ImageSize == b.ImageSize && a.File.TimeDateStamp == b.File.TimeDateStamp && aPdb && bPdb &&
           *aPdb == *bPdb;
}
} // namespace kncore
