#pragma once

#include "BinaryFormats.h"
#include "CollectorRead.h"

namespace kncore
{
struct MappedPeHeaders
{
    Status State = Status::Unavailable;
    PeImage Image;
    ReadResult LastRead;
    std::wstring Message;
};

inline MappedPeHeaders ReadMappedPeHeaders(TargetReader &reader, uint64_t base, uint32_t imageSize)
{
    MappedPeHeaders result;
    const auto read = [&](uint64_t offset, size_t length)
    {
        result.LastRead = reader.Read(AddressSpace::Virtual, base + offset, length);
        const bool complete = ExactBytes(result.LastRead, length);
        if (!complete)
        {
            result.State = result.LastRead.State == Status::Success ? Status::InternalFault : result.LastRead.State;
            result.Message = L"PE header read failed";
        }
        return complete;
    };
    do
    {
        if (!ValidRange(base, imageSize) || imageSize < sizeof(IMAGE_DOS_HEADER))
        {
            result.Message = L"invalid module range";
            break;
        }
        if (!read(0, sizeof(IMAGE_DOS_HEADER)))
        {
            break;
        }
        IMAGE_DOS_HEADER dos = {};
        Load(result.LastRead.Bytes, 0, &dos);
        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < sizeof(IMAGE_DOS_HEADER))
        {
            result.Message = L"invalid DOS header";
            break;
        }
        const uint64_t nt = static_cast<uint32_t>(dos.e_lfanew);
        constexpr size_t fixedSize = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        if (!Contains(imageSize, nt, fixedSize))
        {
            result.Message = L"NT header outside module";
            break;
        }
        if (!Contains(65536, nt, fixedSize))
        {
            result.State = Status::Unsupported;
            result.Message = L"PE headers exceed the 64 KiB limit";
            break;
        }
        if (!read(nt, fixedSize))
        {
            break;
        }
        DWORD signature = 0;
        IMAGE_FILE_HEADER file = {};
        Load(result.LastRead.Bytes, 0, &signature);
        Load(result.LastRead.Bytes, sizeof(DWORD), &file);
        if (signature != IMAGE_NT_SIGNATURE || file.NumberOfSections == 0 || file.NumberOfSections > 96)
        {
            result.Message = L"invalid PE signature or section count";
            break;
        }
        const uint64_t headers =
            nt + fixedSize + file.SizeOfOptionalHeader + uint64_t(file.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
        if (headers > imageSize)
        {
            result.Message = L"PE headers outside module";
            break;
        }
        if (headers > 65536)
        {
            result.State = Status::Unsupported;
            result.Message = L"PE headers exceed the 64 KiB limit";
            break;
        }
        if (!read(0, static_cast<size_t>(headers)))
        {
            break;
        }
        const auto parsed = ParsePeHeaders(result.LastRead.Bytes, &result.Image);
        if (!parsed || result.Image.ImageSize != imageSize)
        {
            result.Message = parsed ? L"PE image size does not match the module" : parsed.Error;
            break;
        }
        result.State = Status::Success;
    } while (false);
    return result;
}
} // namespace kncore
