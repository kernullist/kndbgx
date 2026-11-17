#pragma once

#include "PeIdentity.h"
#include "../util/Text.h"
#include <map>
#include <set>

namespace kncore
{
struct IndirectResource
{
    std::wstring Module;
    uint32_t Id = 0;
};

inline std::optional<IndirectResource> ParseIndirectResource(const std::wstring &text)
{
    const auto comma = text.find(L',');
    if (text.size() > 512 || text.empty() || text[0] != L'@' || comma == std::wstring::npos || comma < 2 ||
        comma + 2 >= text.size() || text[comma + 1] != L'-')
    {
        return {};
    }
    IndirectResource result;
    for (size_t i = 1; i < comma; ++i)
    {
        auto c = text[i];
        if (c >= L'A' && c <= L'Z')
        {
            c += L'a' - L'A';
        }
        if (!((c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9') || c == L'.' || c == L'_' || c == L'-'))
        {
            return {};
        }
        result.Module += c;
    }
    if ((!result.Module.ends_with(L".dll") && !result.Module.ends_with(L".exe")) || result.Module.find(L"..") != std::wstring::npos)
    {
        return {};
    }
    const auto end = text.find(L';', comma + 2);
    const auto digits = text.substr(comma + 2, end == std::wstring::npos ? end : end - comma - 2);
    uint64_t id = 0;
    if (digits.empty() || !std::all_of(digits.begin(), digits.end(), [](wchar_t c)
    {
        return c >= L'0' && c <= L'9';
    }) || !ParseUnsigned(digits, 10, &id) || id == 0 || id > 65535)
    {
        return {};
    }
    if (end != std::wstring::npos)
    {
        const auto version = text.substr(end + 1);
        if (version.size() < 2 || version[0] != L'v' || !std::all_of(version.begin() + 1, version.end(), [](wchar_t c)
        {
            return c >= L'0' && c <= L'9';
        }))
        {
            return {};
        }
    }
    result.Id = static_cast<uint32_t>(id);
    return result;
}

inline bool ResourceUtf16(std::span<const unsigned char> bytes, std::wstring &text, bool terminated = false)
{
    if (bytes.size() % 2 != 0 || bytes.size() > 8192 || (terminated && bytes.size() < 2))
    {
        return false;
    }
    text.clear();
    bool high = false;
    for (size_t i = 0; i < bytes.size(); i += 2)
    {
        const auto c = wchar_t(bytes[i] | (uint16_t(bytes[i + 1]) << 8));
        if (terminated && i + 2 == bytes.size())
        {
            return c == 0 && !high;
        }
        const bool low = c >= 0xdc00 && c <= 0xdfff;
        if (c == 0 || low != high)
        {
            return false;
        }
        high = c >= 0xd800 && c <= 0xdbff;
        text += c;
    }
    return !high;
}

struct MuiConfiguration
{
    uint32_t Type = 0;
    std::array<unsigned char, 32> Checksums = {};
    std::wstring Language;
};

// The reader supplies target image or file bytes; no host resource loader is used.
class PeResources
{
  public:
    explicit PeResources(ByteReader &reader, bool image = false) : reader_(reader), image_(image)
    {
    }
    std::wstring Error = L"ResourceUnavailable";
    PeImage Image;

    bool Initialize()
    {
        IMAGE_DOS_HEADER dos = {};
        IMAGE_FILE_HEADER file = {};
        if (!reader_.ReadObject(0, &dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 64 || dos.e_lfanew > 65536 ||
            !reader_.ReadObject(uint64_t(dos.e_lfanew) + 4, &file) || file.NumberOfSections == 0 || file.NumberOfSections > 96)
        {
            return Fail(L"ResourcePeHeaderUnavailable");
        }
        const auto size = size_t(dos.e_lfanew) + 24 + file.SizeOfOptionalHeader + size_t(file.NumberOfSections) * 40;
        if (size > 65536 || size > reader_.Size())
        {
            return Fail(L"ResourcePeHeaderBounds");
        }
        std::vector<unsigned char> headers(size);
        if (!reader_.Read(0, headers) || !ParsePeHeaders(headers, &Image, image_ ? 0 : reader_.Size()))
        {
            return Fail(L"ResourcePeHeaderInvalid");
        }
        const auto directory = Image.ResourceDirectory;
        if (directory.VirtualAddress == 0 || directory.Size < 16 || directory.Size > 4 * 1024 * 1024 ||
            !Contains(Image.ImageSize, directory.VirtualAddress, directory.Size))
        {
            return Fail(L"ResourceDirectoryUnavailable");
        }
        return true;
    }

    std::optional<MuiConfiguration> Mui()
    {
        const auto data = Find(L"MUI", 0, 1);
        if (!data)
        {
            return {};
        }
        auto bytes = Rva(data->Rva, data->Size);
        uint32_t signature = 0, size = 0, version = 0, type = 0, languageOffset = 0, languageSize = 0;
        if (!bytes || bytes->size() < 132 || !Load(*bytes, 0, &signature) || !Load(*bytes, 4, &size) ||
            !Load(*bytes, 8, &version) || !Load(*bytes, 16, &type) || signature != 0xfecdfecd || size != bytes->size() ||
            version != 0x10000 || (type != 0x11 && type != 0x12))
        {
            Fail(L"ResourceMuiConfigurationInvalid");
            return {};
        }
        MuiConfiguration result;
        result.Type = type;
        std::copy_n(bytes->begin() + 28, result.Checksums.size(), result.Checksums.begin());
        if (std::all_of(result.Checksums.begin(), result.Checksums.end(), [](unsigned char c)
        {
            return c == 0;
        }))
        {
            Fail(L"ResourceMuiChecksumAbsent");
            return {};
        }
        Load(*bytes, type == 0x12 ? 116 : 124, &languageOffset);
        Load(*bytes, type == 0x12 ? 120 : 128, &languageSize);
        if (languageOffset < 132 || languageSize > 128 || !Contains(bytes->size(), languageOffset, languageSize) ||
            !ResourceUtf16(std::span(*bytes).subspan(languageOffset, languageSize), result.Language, true) || result.Language.empty() ||
            !std::all_of(result.Language.begin(), result.Language.end(), [](wchar_t c)
            {
                return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') || c == L'-';
            }))
        {
            Fail(L"ResourceMuiLanguageInvalid");
            return {};
        }
        return result;
    }

    std::optional<std::wstring> String(uint32_t id, uint32_t &language)
    {
        if (id > 65535)
        {
            Fail(L"ResourceStringIdInvalid");
            return {};
        }
        const auto data = Find(L"", 6, id / 16 + 1);
        if (!data)
        {
            return {};
        }
        const auto bytes = Rva(data->Rva, data->Size);
        if (!bytes)
        {
            return {};
        }
        size_t offset = 0;
        std::optional<std::wstring> found;
        for (uint32_t slot = 0; slot < 16; ++slot)
        {
            uint16_t length = 0;
            if (!Load(*bytes, offset, &length) || length > 2048 || !Contains(bytes->size(), offset + 2, size_t(length) * 2))
            {
                Fail(L"ResourceStringBlockInvalid");
                return {};
            }
            offset += 2;
            if (slot == id % 16)
            {
                std::wstring text;
                const auto payload = std::span(*bytes).subspan(offset, size_t(length) * 2);
                // Some target string tables include one trailing NUL in the length.
                const bool terminated = payload.size() >= 2 && payload[payload.size() - 2] == 0 && payload.back() == 0;
                if (!ResourceUtf16(payload, text, terminated))
                {
                    Fail(L"ResourceStringInvalidUtf16");
                    return {};
                }
                found = std::move(text);
            }
            offset += size_t(length) * 2;
        }
        if (offset != bytes->size())
        {
            Fail(L"ResourceStringBlockTrailingData");
            return {};
        }
        language = data->Language;
        if (found && found->empty())
        {
            Fail(L"ResourceStringEmptyOrAbsent");
            return {};
        }
        return found;
    }

  private:
    struct Entry
    {
        uint32_t Id = 0;
        std::wstring Name;
        bool Named = false;
        bool Directory = false;
        uint32_t Offset = 0;
    };
    struct Data
    {
        uint32_t Rva = 0;
        uint32_t Size = 0;
        uint32_t Language = 0;
    };
    ByteReader &reader_;
    bool image_;

    bool Fail(const wchar_t *error)
    {
        Error = error;
        return false;
    }
    std::optional<std::vector<unsigned char>> Rva(uint32_t rva, uint32_t size)
    {
        if (size == 0 || size > 65536 || !Contains(Image.ImageSize, rva, size))
        {
            Fail(L"ResourceDataBounds");
            return {};
        }
        const auto offset = image_ ? std::optional<uint64_t>(rva) : PeFileOffset(Image, rva, size);
        std::vector<unsigned char> bytes(size);
        if (!offset || !Contains(reader_.Size(), *offset, size) || !reader_.Read(*offset, bytes))
        {
            Fail(L"ResourceDataUnreadable");
            return {};
        }
        return bytes;
    }
    std::optional<std::vector<unsigned char>> DirectoryBytes(uint32_t offset, uint32_t size)
    {
        if (!Contains(Image.ResourceDirectory.Size, offset, size))
        {
            Fail(L"ResourceDirectoryBounds");
            return {};
        }
        return Rva(Image.ResourceDirectory.VirtualAddress + offset, size);
    }
    std::optional<std::vector<Entry>> Directory(uint32_t offset)
    {
        const auto header = DirectoryBytes(offset, 16);
        uint16_t named = 0, ids = 0;
        if (!header || !Load(*header, 12, &named) || !Load(*header, 14, &ids) || uint32_t(named) + ids > 4096)
        {
            Fail(L"ResourceDirectoryCountInvalid");
            return {};
        }
        std::vector<Entry> entries;
        if (named + ids == 0)
        {
            return entries;
        }
        const auto bytes = DirectoryBytes(offset + 16, (uint32_t(named) + ids) * 8);
        if (!bytes)
        {
            return {};
        }
        for (size_t i = 0; i < size_t(named) + ids; ++i)
        {
            uint32_t name = 0, next = 0;
            Load(*bytes, i * 8, &name);
            Load(*bytes, i * 8 + 4, &next);
            Entry entry{name & 0x7fffffff, {}, (name >> 31) != 0, (next >> 31) != 0, next & 0x7fffffff};
            if (entry.Named != (i < named))
            {
                Fail(L"ResourceDirectoryNameOrder");
                return {};
            }
            if (entry.Named)
            {
                const auto lengthBytes = DirectoryBytes(entry.Id, 2);
                uint16_t length = 0;
                if (!lengthBytes || !Load(*lengthBytes, 0, &length) || length == 0 || length > 128)
                {
                    Fail(L"ResourceDirectoryNameInvalid");
                    return {};
                }
                const auto nameBytes = DirectoryBytes(entry.Id + 2, uint32_t(length) * 2);
                if (!nameBytes || !ResourceUtf16(*nameBytes, entry.Name))
                {
                    Fail(L"ResourceDirectoryNameInvalid");
                    return {};
                }
            }
            entries.push_back(std::move(entry));
        }
        return entries;
    }
    std::optional<Data> Find(const std::wstring &typeName, uint32_t typeId, uint32_t id)
    {
        uint32_t offset = 0;
        std::set<uint32_t> visited;
        for (unsigned level = 0; level < 3; ++level)
        {
            if (!visited.insert(offset).second)
            {
                Fail(L"ResourceDirectoryCycle");
                return {};
            }
            const auto entries = Directory(offset);
            if (!entries)
            {
                return {};
            }
            std::optional<Entry> found;
            for (const auto &entry : *entries)
            {
                const bool match = level == 0 ? (typeName.empty() ? !entry.Named && entry.Id == typeId : entry.Named && entry.Name == typeName) :
                                   level == 1 ? !entry.Named && entry.Id == id : !entry.Named && entry.Id <= 65535;
                if (match)
                {
                    if (found)
                    {
                        Fail(level == 2 ? L"ResourceLanguageAmbiguous" : L"ResourceDirectoryDuplicate");
                        return {};
                    }
                    found = entry;
                }
            }
            if (!found || found->Directory != (level < 2))
            {
                Fail(found ? L"ResourceDirectoryShapeInvalid" : level == 0 ? L"ResourceTypeNotFound" : L"ResourceNotFound");
                return {};
            }
            offset = found->Offset;
            if (level == 2)
            {
                const auto bytes = DirectoryBytes(offset, 16);
                Data data;
                uint32_t reserved = 0;
                if (!bytes || !Load(*bytes, 0, &data.Rva) || !Load(*bytes, 4, &data.Size) || !Load(*bytes, 12, &reserved) ||
                    reserved != 0 || data.Rva < Image.ResourceDirectory.VirtualAddress ||
                    !Contains(Image.ResourceDirectory.Size, data.Rva - Image.ResourceDirectory.VirtualAddress, data.Size))
                {
                    Fail(L"ResourceLeafBounds");
                    return {};
                }
                data.Language = found->Id;
                return data;
            }
        }
        return {};
    }
};
} // namespace kncore
