#pragma once

#include <windows.h>
#include <dbghelp.h>
#include <algorithm>
#include <cstring>
#include <span>
#include <string>
#include <vector>
#include "Input.h"

namespace kncore
{
static_assert(offsetof(IMAGE_DOS_HEADER, e_lfanew) == 0x3c);
static_assert(sizeof(MINIDUMP_MODULE) == 108);

enum class BinaryStatus
{
    Complete,
    Truncated,
    Invalid,
    Unsupported,
    BudgetExceeded
};

struct BinaryResult
{
    BinaryStatus Status = BinaryStatus::Invalid;
    std::wstring Error;
    explicit operator bool() const
    {
        return Status == BinaryStatus::Complete;
    }
};

inline bool Contains(uint64_t size, uint64_t offset, uint64_t length)
{
    return offset <= size && length <= size - offset;
}

template <typename T> bool Load(std::span<const unsigned char> bytes, size_t offset, T *out)
{
    const bool ok = out != nullptr && Contains(bytes.size(), offset, sizeof(T));
    if (ok)
    {
        std::memcpy(out, bytes.data() + offset, sizeof(T));
    }
    return ok;
}

struct PeImage
{
    IMAGE_FILE_HEADER File = {};
    bool Is64 = false;
    uint32_t ImageSize = 0;
    uint32_t HeadersSize = 0;
    uint32_t EntryRva = 0;
    IMAGE_DATA_DIRECTORY ResourceDirectory = {};
    IMAGE_DATA_DIRECTORY DebugDirectory = {};
    std::vector<IMAGE_SECTION_HEADER> Sections;
};

inline BinaryResult ParsePeHeaders(std::span<const unsigned char> bytes, PeImage *out, uint64_t diskFileSize = 0)
{
    BinaryResult result;
    do
    {
        IMAGE_DOS_HEADER dos = {};
        if (out == nullptr || !Load(bytes, 0, &dos))
        {
            result = {BinaryStatus::Truncated, L"DOS header unavailable"};
            break;
        }
        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < sizeof(IMAGE_DOS_HEADER))
        {
            result.Error = L"invalid DOS signature or e_lfanew";
            break;
        }
        const size_t nt = static_cast<size_t>(dos.e_lfanew);
        DWORD signature = 0;
        PeImage image;
        if (!Load(bytes, nt, &signature) || !Load(bytes, nt + sizeof(DWORD), &image.File))
        {
            result = {BinaryStatus::Truncated, L"NT header unavailable"};
            break;
        }
        if (signature != IMAGE_NT_SIGNATURE || image.File.NumberOfSections == 0 || image.File.NumberOfSections > 96)
        {
            result.Error = L"invalid PE signature or section count";
            break;
        }
        const size_t optional = nt + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        WORD magic = 0;
        if (!Contains(bytes.size(), optional, image.File.SizeOfOptionalHeader) || !Load(bytes, optional, &magic))
        {
            result = {BinaryStatus::Truncated, L"optional header unavailable"};
            break;
        }
        uint32_t directories = 0;
        size_t minimum = 0;
        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            minimum = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
            image.Is64 = true;
            Load(bytes, optional + offsetof(IMAGE_OPTIONAL_HEADER64, NumberOfRvaAndSizes), &directories);
        }
        else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            minimum = offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
            Load(bytes, optional + offsetof(IMAGE_OPTIONAL_HEADER32, NumberOfRvaAndSizes), &directories);
        }
        else
        {
            result = {BinaryStatus::Unsupported, L"unsupported optional header magic"};
            break;
        }
        if (image.File.SizeOfOptionalHeader < minimum || directories > 16 ||
            directories * sizeof(IMAGE_DATA_DIRECTORY) > image.File.SizeOfOptionalHeader - minimum)
        {
            result.Error = L"invalid optional header size or directory count";
            break;
        }
        Load(bytes, optional + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfImage), &image.ImageSize);
        Load(bytes, optional + offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfHeaders), &image.HeadersSize);
        Load(bytes, optional + offsetof(IMAGE_OPTIONAL_HEADER32, AddressOfEntryPoint), &image.EntryRva);
        if (directories > IMAGE_DIRECTORY_ENTRY_RESOURCE)
        {
            Load(bytes, optional + minimum + IMAGE_DIRECTORY_ENTRY_RESOURCE * sizeof(IMAGE_DATA_DIRECTORY), &image.ResourceDirectory);
        }
        if (directories > IMAGE_DIRECTORY_ENTRY_DEBUG)
        {
            Load(bytes, optional + minimum + IMAGE_DIRECTORY_ENTRY_DEBUG * sizeof(IMAGE_DATA_DIRECTORY), &image.DebugDirectory);
        }
        const size_t table = optional + image.File.SizeOfOptionalHeader;
        const size_t tableSize = image.File.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
        if (!Contains(bytes.size(), table, tableSize))
        {
            result = {BinaryStatus::Truncated, L"section table unavailable"};
            break;
        }
        if (image.ImageSize == 0 || image.HeadersSize > image.ImageSize || !Contains(image.HeadersSize, table, tableSize) ||
            image.EntryRva >= image.ImageSize)
        {
            result.Error = L"invalid image/header/entry bounds";
            break;
        }
        bool valid = true;
        for (size_t i = 0; i < image.File.NumberOfSections; ++i)
        {
            IMAGE_SECTION_HEADER section = {};
            Load(bytes, table + i * sizeof(section), &section);
            if (!Contains(image.ImageSize, section.VirtualAddress, std::max(section.Misc.VirtualSize, section.SizeOfRawData)) ||
                (diskFileSize != 0 && !Contains(diskFileSize, section.PointerToRawData, section.SizeOfRawData)))
            {
                valid = false;
                break;
            }
            image.Sections.push_back(section);
        }
        if (!valid)
        {
            result.Error = L"section outside image or file";
            break;
        }
        *out = std::move(image);
        result.Status = BinaryStatus::Complete;
    } while (false);
    return result;
}

class ByteReader
{
  public:
    virtual ~ByteReader() = default;
    virtual uint64_t Size() const = 0;
    virtual bool Read(uint64_t offset, std::span<unsigned char> destination) = 0;

    template <typename T> bool ReadObject(uint64_t offset, T *value)
    {
        T temporary = {};
        const bool ok = value != nullptr && Contains(Size(), offset, sizeof(T)) &&
                        Read(offset, std::span(reinterpret_cast<unsigned char *>(&temporary), sizeof(T)));
        if (ok)
        {
            *value = temporary;
        }
        return ok;
    }
};

class SpanReader final : public ByteReader
{
  public:
    explicit SpanReader(std::span<const unsigned char> bytes) : bytes_(bytes)
    {
    }
    uint64_t Size() const override
    {
        return bytes_.size();
    }
    bool Read(uint64_t offset, std::span<unsigned char> destination) override
    {
        const bool ok = Contains(bytes_.size(), offset, destination.size());
        if (ok && !destination.empty())
        {
            std::memcpy(destination.data(), bytes_.data() + static_cast<size_t>(offset), destination.size());
        }
        return ok;
    }

  private:
    std::span<const unsigned char> bytes_;
};

struct DumpModule
{
    MINIDUMP_MODULE Record = {};
    std::wstring Name;
};

struct DumpMetadata
{
    bool Minidump = false;
    bool SystemAvailable = false;
    bool ExceptionAvailable = false;
    bool ModuleListAvailable = false;
    WORD Architecture = 0xffff;
    DWORD Build = 0;
    DWORD Processors = 0;
    ULONG64 DirectoryTableBase = 0;
    DWORD ExceptionCode = 0;
    ULONG64 ExceptionAddress = 0;
    std::vector<DumpModule> Modules;
};

inline bool ReadDumpString(ByteReader &reader, RVA rva, std::wstring *out)
{
    ULONG32 byteCount = 0;
    if (out == nullptr || rva == 0 || !reader.ReadObject(rva, &byteCount) || (byteCount % 2) != 0 || byteCount > 32768 ||
        !Contains(reader.Size(), uint64_t(rva) + sizeof(byteCount), byteCount))
    {
        return false;
    }
    std::wstring text(byteCount / sizeof(wchar_t), L'\0');
    const bool ok = reader.Read(uint64_t(rva) + sizeof(byteCount), std::span(reinterpret_cast<unsigned char *>(text.data()), byteCount)) &&
                    ValidUtf16(text, false);
    if (ok)
    {
        *out = std::move(text);
    }
    return ok;
}

inline BinaryResult ParseDumpMetadata(ByteReader &reader, DumpMetadata *out)
{
    BinaryResult result;
    do
    {
        DWORD signature = 0;
        if (out == nullptr || !reader.ReadObject(0, &signature))
        {
            result = {BinaryStatus::Truncated, L"dump signature unavailable"};
            break;
        }
        DumpMetadata metadata;
        if (signature == 0x45474150)
        {
            DWORD valid = 0;
            if (!reader.ReadObject(4, &valid))
            {
                result = {BinaryStatus::Truncated, L"kernel dump signature unavailable"};
                break;
            }
            const bool x64 = valid == 0x34365544;
            if (!x64 && valid != 0x504d5544)
            {
                result.Error = L"invalid kernel dump signature";
                break;
            }
            DWORD machine = 0;
            const uint64_t minimumHeader = x64 ? 0x2000 : 0x1000;
            DWORD dtb32 = 0;
            bool validFields = reader.Size() >= minimumHeader && reader.ReadObject(12, &metadata.Build) &&
                               reader.ReadObject(x64 ? 0x30 : 0x20, &machine) &&
                               reader.ReadObject(x64 ? 0x34 : 0x24, &metadata.Processors) &&
                               reader.ReadObject(x64 ? 0x38 : 0x28, &metadata.ExceptionCode);
            if (x64)
            {
                validFields = validFields && reader.ReadObject(0x10, &metadata.DirectoryTableBase);
            }
            else
            {
                validFields = validFields && reader.ReadObject(0x10, &dtb32);
                metadata.DirectoryTableBase = dtb32;
            }
            if (!validFields)
            {
                result = {BinaryStatus::Truncated, L"kernel dump header unavailable"};
                break;
            }
            if (machine != static_cast<DWORD>(x64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386))
            {
                result = {BinaryStatus::Unsupported, L"unsupported kernel dump machine"};
                break;
            }
            metadata.Architecture = x64 ? PROCESSOR_ARCHITECTURE_AMD64 : PROCESSOR_ARCHITECTURE_INTEL;
            metadata.SystemAvailable = true;
            *out = std::move(metadata);
            result.Status = BinaryStatus::Complete;
            break;
        }
        MINIDUMP_HEADER header = {};
        if (!reader.ReadObject(0, &header))
        {
            result = {BinaryStatus::Truncated, L"minidump header unavailable"};
            break;
        }
        if (header.Signature != MINIDUMP_SIGNATURE || (header.Version & 0xffff) != MINIDUMP_VERSION)
        {
            result.Error = L"invalid minidump signature or version";
            break;
        }
        if (header.NumberOfStreams > 4096)
        {
            result = {BinaryStatus::BudgetExceeded, L"stream count exceeds metadata budget"};
            break;
        }
        if (!Contains(reader.Size(), header.StreamDirectoryRva, uint64_t(header.NumberOfStreams) * sizeof(MINIDUMP_DIRECTORY)))
        {
            result = {BinaryStatus::Truncated, L"stream directory outside file"};
            break;
        }
        metadata.Minidump = true;
        bool valid = true;
        bool seenModules = false;
        bool seenSystem = false;
        bool seenException = false;
        size_t totalNameUnits = 0;
        for (DWORD i = 0; i < header.NumberOfStreams; ++i)
        {
            MINIDUMP_DIRECTORY directory = {};
            if (!reader.ReadObject(uint64_t(header.StreamDirectoryRva) + uint64_t(i) * sizeof(directory), &directory) ||
                !Contains(reader.Size(), directory.Location.Rva, directory.Location.DataSize))
            {
                valid = false;
                break;
            }
            const uint64_t rva = directory.Location.Rva;
            const uint64_t size = directory.Location.DataSize;
            if (directory.StreamType == ModuleListStream)
            {
                ULONG32 count = 0;
                if (seenModules || size < sizeof(count) || !reader.ReadObject(rva, &count) || count > 100000 ||
                    uint64_t(count) * sizeof(MINIDUMP_MODULE) > size - sizeof(count))
                {
                    valid = false;
                    break;
                }
                seenModules = true;
                metadata.ModuleListAvailable = true;
                for (ULONG32 m = 0; m < count; ++m)
                {
                    DumpModule module;
                    if (!reader.ReadObject(rva + sizeof(count) + uint64_t(m) * sizeof(MINIDUMP_MODULE), &module.Record) ||
                        !ReadDumpString(reader, module.Record.ModuleNameRva, &module.Name) ||
                        !ValidRange(module.Record.BaseOfImage, module.Record.SizeOfImage) ||
                        !Contains(reader.Size(), module.Record.CvRecord.Rva, module.Record.CvRecord.DataSize) ||
                        !Contains(reader.Size(), module.Record.MiscRecord.Rva, module.Record.MiscRecord.DataSize))
                    {
                        valid = false;
                        break;
                    }
                    totalNameUnits += module.Name.size();
                    if (totalNameUnits > 1024 * 1024)
                    {
                        valid = false;
                        break;
                    }
                    metadata.Modules.push_back(std::move(module));
                }
            }
            else if (directory.StreamType == SystemInfoStream)
            {
                MINIDUMP_SYSTEM_INFO system = {};
                if (seenSystem || size < sizeof(system) || !reader.ReadObject(rva, &system))
                {
                    valid = false;
                    break;
                }
                seenSystem = true;
                metadata.SystemAvailable = true;
                metadata.Architecture = system.ProcessorArchitecture;
                metadata.Build = system.BuildNumber;
                metadata.Processors = system.NumberOfProcessors;
            }
            else if (directory.StreamType == ExceptionStream)
            {
                MINIDUMP_EXCEPTION_STREAM exception = {};
                if (seenException || size < sizeof(exception) || !reader.ReadObject(rva, &exception) ||
                    exception.ExceptionRecord.NumberParameters > EXCEPTION_MAXIMUM_PARAMETERS ||
                    !Contains(reader.Size(), exception.ThreadContext.Rva, exception.ThreadContext.DataSize))
                {
                    valid = false;
                    break;
                }
                seenException = true;
                metadata.ExceptionAvailable = true;
                metadata.ExceptionCode = exception.ExceptionRecord.ExceptionCode;
                metadata.ExceptionAddress = exception.ExceptionRecord.ExceptionAddress;
            }
            if (!valid)
            {
                break;
            }
        }
        if (!valid)
        {
            result.Error = L"invalid, duplicate, truncated or excessive metadata stream";
            break;
        }
        *out = std::move(metadata);
        result.Status = BinaryStatus::Complete;
    } while (false);
    return result;
}
} // namespace kncore
