#pragma once

#include "BfeRegression.h"
#include "../core/BfeResources.h"

namespace knself
{
inline std::vector<unsigned char> ResourcePeFixture(bool mui = true, bool terminatedString = false)
{
    std::vector<unsigned char> bytes(4096);
    const auto put = [&](size_t offset, uint64_t value, size_t size)
    {
        for (size_t i = 0; i < size; ++i)
        {
            bytes[offset + i] = static_cast<unsigned char>(value >> (i * 8));
        }
    };
    const auto wide = [&](size_t offset, const std::wstring &text)
    {
        for (size_t i = 0; i < text.size(); ++i)
        {
            put(offset + i * 2, text[i], 2);
        }
    };
    put(0, IMAGE_DOS_SIGNATURE, 2);
    put(0x3c, 0x80, 4);
    put(0x80, IMAGE_NT_SIGNATURE, 4);
    put(0x84, IMAGE_FILE_MACHINE_AMD64, 2);
    put(0x86, 1, 2);
    put(0x94, 0xf0, 2);
    put(0x98, IMAGE_NT_OPTIONAL_HDR64_MAGIC, 2);
    put(0x98 + 56, 0x3000, 4);
    put(0x98 + 60, 0x400, 4);
    put(0x98 + 108, 16, 4);
    put(0x98 + 112 + 16, 0x2000, 4);
    put(0x98 + 112 + 20, 0x800, 4);
    put(0x188 + 8, 0x800, 4);
    put(0x188 + 12, 0x2000, 4);
    put(0x188 + 16, 0x800, 4);
    put(0x188 + 20, 0x400, 4);
    put(0x400 + 12, 1, 2);
    put(0x400 + 14, mui ? 1 : 0, 2);
    put(0x410, 0x80000100, 4);
    put(0x414, 0x80000030, 4);
    put(0x418, 6, 4);
    put(0x41c, 0x80000050, 4);
    for (const auto offset : {0x430u, 0x450u, 0x470u, 0x490u})
    {
        put(offset + 14, 1, 2);
    }
    put(0x440, 1, 4);
    put(0x444, 0x80000070, 4);
    put(0x460, 76, 4);
    put(0x464, 0x80000090, 4);
    put(0x480, 0x409, 4);
    put(0x484, 0xb0, 4);
    put(0x4a0, 0x412, 4);
    put(0x4a4, 0xc0, 4);
    put(0x4b0, 0x2200, 4);
    put(0x4b4, 0xb0, 4);
    put(0x4c0, 0x2400, 4);
    put(0x500, 3, 2);
    wide(0x502, L"MUI");
    put(0x600, 0xfecdfecd, 4);
    put(0x604, 0xb0, 4);
    put(0x608, 0x10000, 4);
    put(0x610, mui ? 0x12 : 0x11, 4);
    for (size_t i = 0; i < 32; ++i)
    {
        bytes[0x61c + i] = static_cast<unsigned char>(i + 1);
    }
    put(mui ? 0x674 : 0x67c, 0xa0, 4);
    put(mui ? 0x678 : 0x680, 12, 4);
    wide(0x6a0, mui ? L"ko-KR" : L"en-US");
    std::wstring text = L"Target \ud55c\uad6d\uc5b4 " + std::wstring{wchar_t(0xd83d), wchar_t(0xde00)};
    if (terminatedString)
    {
        text += wchar_t(0);
    }
    size_t cursor = 0x800;
    for (unsigned slot = 0; slot < 16; ++slot)
    {
        put(cursor, slot == 9 ? text.size() : 0, 2);
        cursor += 2;
        if (slot == 9)
        {
            wide(cursor, text);
            cursor += text.size() * 2;
        }
    }
    put(0x4c4, cursor - 0x800, 4);
    return bytes;
}

inline kncore::ResourceLayout ResourceLayoutFixture()
{
    kncore::ResourceLayout layout;
    const auto field = [&](const wchar_t *name, uint32_t offset, uint32_t size, int bit = -1, uint32_t width = 0)
    {
        kncore::FieldInfo info;
        info.Offset = offset;
        info.Size = size;
        info.Kind = kncore::FieldKind::Unsigned;
        if (bit >= 0)
        {
            info.BitOffset = static_cast<uint32_t>(bit);
            info.BitWidth = width;
        }
        layout.Add(name, info, size, bit >= 0);
    };
    field(L"control", 0, 8);
    field(L"pteBase", 8, 8);
    field(L"next", 16, 8);
    field(L"sectorHigh", 0x20, 4, 6, 10);
    field(L"tail", 0x20, 4, 20, 12);
    field(L"sector", 0x24, 4);
    field(L"sectors", 0x28, 4);
    field(L"ptes", 0x2c, 4);
    field(L"unusedPtes", 0x34, 4);
    field(L"image", 0x38, 4, 5, 1);
    field(L"valid", 0, 8, 0, 1);
    field(L"hardwarePfn", 0, 8, 12, 40);
    field(L"transitionPfn", 0, 8, 12, 40);
    field(L"transition", 0, 8, 11, 1);
    field(L"prototype", 0, 8, 10, 1);
    field(L"root", 0x80, 8);
    field(L"left", 0, 8);
    field(L"right", 8, 8);
    field(L"start", 0x18, 4);
    field(L"startHigh", 0x20, 1);
    field(L"private", 0x30, 4, 19, 1);
    field(L"subsection", 0x50, 8);
    field(L"filePointer", 0x40, 8);
    field(L"refCount", 0, 8, 0, 4);
    field(L"fileName", 0x58, 16);
    return layout;
}

template <typename Check> void RunResourceRegression(Check check)
{
    using namespace kncore;
    const auto parsed = ParseIndirectResource(L"@BFE.dll,-1209;v2");
    check(parsed && parsed->Module == L"bfe.dll" && parsed->Id == 1209, "resource.indirect-id-and-version");
    for (const auto text : {L"@bfe.dll,0", L"@bfe.dll,-65536", L"@../bfe.dll,-1", L"@C:\\bfe.dll,-1", L"@bfe.dll,-0",
                            L"@{package?name}", L"@bfe.dll,-12x", L"@bfe.dll,-12;v", L"@bfe.dll,-184467440737095516160"})
    {
        check(!ParseIndirectResource(text), "resource.unsupported-reference-not-reinterpreted");
    }
    {
        const auto bytes = ResourcePeFixture();
        SpanReader reader(bytes);
        PeResources resources(reader);
        uint32_t language = 0;
        check(resources.Initialize(), "resource.pe-file-rva-to-raw-offset");
        const auto mui = resources.Mui();
        const auto value = resources.String(1209, language);
        check(mui && mui->Type == 0x12 && mui->Language == L"ko-KR" && language == 0x412 && value && ValidUtf16(*value) &&
              value->find(L"\ud55c\uad6d\uc5b4") != std::wstring::npos, "resource.target-language-and-utf16-pair");
        check(!resources.String(5013, language) && resources.Error == L"ResourceNotFound", "resource.missing-block-is-not-a-string");
        check(!resources.String(1208, language) && resources.Error == L"ResourceStringEmptyOrAbsent", "resource.empty-slot-does-not-erase-reference");
    }
    {
        auto bytes = ResourcePeFixture(true, true);
        SpanReader reader(bytes);
        PeResources resources(reader);
        uint32_t language = 0;
        check(resources.Initialize() && resources.String(1209, language) &&
              resources.String(1209, language)->find(wchar_t(0)) == std::wstring::npos,
              "resource.optional-trailing-nul-is-display-terminator");
        bytes[0x814] = 0;
        bytes[0x815] = 0;
        check(!resources.String(1209, language) && resources.Error == L"ResourceStringInvalidUtf16",
              "resource.embedded-nul-is-not-silently-truncated");
    }
    for (unsigned mutation = 0; mutation < 6; ++mutation)
    {
        auto bytes = ResourcePeFixture();
        if (mutation == 0)
        {
            bytes[0x464] = 0;
        }
        else if (mutation == 1)
        {
            bytes[0x49e] = 2;
            std::memcpy(bytes.data() + 0x4a8, bytes.data() + 0x4a0, 8);
        }
        else if (mutation == 2)
        {
            bytes[0x812] = 0xff;
            bytes[0x813] = 0xff;
        }
        else if (mutation == 3)
        {
            bytes[0x814] = 0;
            bytes[0x815] = 0xdc;
        }
        else if (mutation == 4)
        {
            bytes[0x4c3] = 0x80;
        }
        else
        {
            bytes.resize(0x820);
        }
        SpanReader reader(bytes);
        PeResources resources(reader);
        uint32_t language = 0;
        check(!resources.Initialize() || !resources.String(1209, language), "resource.rejects-cycle-duplicate-truncation-and-invalid-text");
    }
    constexpr uint64_t subsection = 0xffff800000010000, control = 0xffff800000020000, ptes = 0xffff800000030000;
    const TargetArchitecture architecture{0x8664, 8, 48, {}};
    const auto layout = ResourceLayoutFixture();
    const auto fileMemory = [&]()
    {
        ByteFixture memory;
        memory.Text(subsection, {}, 0x38);
        memory.Text(control, {}, 0x40);
        memory.Put(subsection, control);
        memory.Put(subsection + 8, ptes);
        memory.Put(subsection + 0x28, 2, 4);
        memory.Put(subsection + 0x2c, 2, 4);
        memory.Put(ptes, 0x10001);
        memory.Put(ptes + 8, 0x20800);
        memory.Text(0x10000, {}, 4096);
        memory.Text(0x20000, {}, 4096);
        memory.Put(0x10ffc, 0x44332211, 4);
        memory.Put(0x20000, 0x88776655, 4);
        return memory;
    };
    const ResourceMapping mapping{0, 0, subsection, control, 0, L"\\Windows\\System32\\fixture.dll.mui", L"fixture.dll.mui"};
    {
        auto memory = fileMemory();
        WalkBudget budget;
        ResourceMemory target(memory, architecture, budget);
        SectionFileReader file(target, layout);
        std::array<unsigned char, 8> bytes = {};
        check(file.Initialize(mapping) && file.Size() == 8192 && file.Read(4092, bytes) &&
              WfpInteger(bytes, 0, 8) == 0x8877665544332211ULL, "resource.valid-and-standby-pages-cross-boundary");
        const auto reads = memory.Reads;
        check(file.Read(4092, bytes) && memory.Reads == reads, "resource.section-pages-cached-within-collection");
        check(!file.Read(file.Size(), bytes) && !file.Error.empty() && file.Read(4092, bytes) && file.Error.empty(),
              "resource.successful-read-clears-earlier-failure-detail");
        memory.Put(control + 0x38, 0x20, 4);
        memory.Put(subsection + 0x28, 16, 4);
        SectionFileReader image(target, layout);
        check(image.Initialize(mapping) && image.Size() == 8192, "resource.image-sector-unit-differs-from-data-file");
    }
    for (unsigned mutation = 0; mutation < 4; ++mutation)
    {
        auto memory = fileMemory();
        if (mutation == 0)
        {
            memory.Put(ptes + 8, 0x20400);
        }
        else if (mutation == 1)
        {
            memory.Put(subsection + 16, subsection);
        }
        else if (mutation == 2)
        {
            memory.Put(subsection, control + 16);
        }
        else
        {
            memory.Put(subsection + 0x34, 2, 4);
        }
        WalkBudget budget;
        ResourceMemory target(memory, architecture, budget);
        SectionFileReader file(target, layout);
        std::array<unsigned char, 8> bytes = {};
        check(!file.Initialize(mapping) || !file.Read(4092, bytes), "resource.refuses-nonresident-or-inconsistent-section");
    }
    for (const auto state : {Status::Cancelled, Status::StaleContext, Status::InternalFault})
    {
        WfpTerminalReader memory;
        memory.State = state;
        WalkBudget budget;
        ResourceMemory target(memory, architecture, budget);
        SectionFileReader file(target, layout);
        check(!file.Initialize(mapping) && budget.Report.State == state && budget.Stopped && memory.Reads == 1,
              "resource.terminal-read-status-preserved");
    }
    {
        auto memory = fileMemory();
        WalkBudget budget;
        ResourceMemory target(memory, architecture, budget);
        SectionFileReader file(target, layout);
        const bool initialized = file.Initialize(mapping);
        const auto before = memory.Reads;
        memory.BeforeRead = [&]()
        {
            if (memory.Reads == before + 3)
            {
                memory.Put(ptes, 0x30001);
            }
        };
        std::array<unsigned char, 4> bytes = {};
        check(initialized && !file.Read(0, bytes) && file.Error == L"ResourcePageChanged",
              "resource.changed-prototype-pte-rejects-copied-page");
    }
    for (unsigned mutation = 0; mutation < 6; ++mutation)
    {
        ByteFixture memory;
        const auto mapFile = [&](uint64_t sub, uint64_t area, uint64_t pte, uint64_t physical, const std::vector<unsigned char> &bytes)
        {
            memory.Text(sub, {}, 0x38);
            memory.Text(area, {}, 0x40);
            memory.Put(sub, area);
            memory.Put(sub + 8, pte);
            memory.Put(sub + 0x28, 1, 4);
            memory.Put(sub + 0x2c, 1, 4);
            memory.Put(pte, physical | 0x800);
            for (size_t i = 0; i < bytes.size(); ++i)
            {
                memory.Put(physical + i, bytes[i], 1);
            }
        };
        auto base = ResourcePeFixture(false);
        auto mui = ResourcePeFixture(true);
        if (mutation == 1)
        {
            mui[0x61c] ^= 1;
        }
        else if (mutation == 2)
        {
            mui[0x674] = 0xff;
        }
        else if (mutation == 5)
        {
            mui[0x4a0] = 9;
        }
        mapFile(subsection, control, ptes, 0x10000, base);
        mapFile(subsection + 0x100, control + 0x100, ptes + 0x100, 0x20000, mui);
        std::vector<ResourceMapping> files{
            {1, 0x100000, subsection, control, 0, L"\\Windows\\System32\\bfe.dll", L"bfe.dll"},
            {1, 0x200000, subsection + 0x100, control + 0x100, 0, L"\\Windows\\System32\\ko-KR\\bfe.dll.mui", L"bfe.dll.mui"}};
        if (mutation == 3)
        {
            files.pop_back();
        }
        else if (mutation == 4)
        {
            files.push_back(files[0]);
        }
        WalkBudget budget;
        ResourceMemory target(memory, architecture, budget);
        BfeResourceResolver resolver(target, layout, files);
        const auto result = resolver.Resolve(L"@bfe.dll,-1209");
        if (mutation == 0)
        {
            check(result.Get(L"state").AsString(L"") == L"Resolved" && result.Get(L"language").AsString(L"") == L"ko-KR" &&
                  result.Get(L"value").AsString(L"").starts_with(L"Target "), "resource.matching-target-mui-pair-resolves");
            const auto reads = memory.Reads;
            check(resolver.Resolve(L"@bfe.dll,-1209").Write() == result.Write() && memory.Reads == reads,
                  "resource.repeated-reference-uses-command-cache");
            constexpr uint64_t process = 0xffff800000040000, vad = 0xffff800000050000;
            constexpr uint64_t object = 0xffff800000060000, buffer = 0xffff800000070000;
            for (size_t i = 0; i < files.size(); ++i)
            {
                const auto delta = i * 0x1000;
                memory.Put(process + delta + 0x80, vad + delta);
                memory.Text(vad + delta, {}, 0x58);
                memory.Put(vad + delta + 0x18, 0x100 + i, 4);
                memory.Put(vad + delta + 0x50, files[i].Subsection);
                memory.Put(files[i].ControlArea + 0x40, (object + delta) | 3);
                memory.Text(object + delta + 0x58, {}, 16);
                memory.Put(object + delta + 0x58, files[i].Path.size() * 2, 2);
                memory.Put(object + delta + 0x5a, files[i].Path.size() * 2 + 2, 2);
                memory.Put(object + delta + 0x60, buffer + delta);
                for (size_t j = 0; j < files[i].Path.size(); ++j)
                {
                    memory.Put(buffer + delta + j * 2, files[i].Path[j], 2);
                }
            }
            for (unsigned variant = 0; variant < 3; ++variant)
            {
                auto targetBytes = memory;
                if (variant != 0)
                {
                    targetBytes.Put(process + 0x1080, 0);
                }
                if (variant == 1)
                {
                    targetBytes.Put(vad + 8, vad + 0x2000);
                }
                WalkBudget resolutionBudget;
                ResourceMemory resolutionMemory(targetBytes, architecture, resolutionBudget);
                BfeRecord record;
                record.Type = 0;
                record.Key = L"fixture-provider";
                record.Row = knjson::Value::MakeObject();
                record.Row.Set(L"name", knjson::Value(L"@bfe.dll,-1209"));
                record.Row.Set(L"nameState", knjson::Value(L"IndirectResource"));
                std::vector<BfeRecord> records{record};
                auto analysis = knjson::Value::MakeObject();
                ResolveBfeResources(resolutionMemory, layout, {process, process + 0x1000}, records, analysis);
                const auto &row = records[0].Row;
                check(row.Get(L"nameRaw").AsString(L"") == L"@bfe.dll,-1209", "resource.raw-reference-preserved");
                if (variant == 0)
                {
                    auto joined = knjson::Value::MakeObject();
                    joined.Set(L"providerKey", knjson::Value(record.Key));
                    BfeJoinReference(joined, records, 0, L"providerKey", L"provider", true);
                    check(row.Get(L"name").AsString(L"").starts_with(L"Target ") &&
                          joined.Get(L"providerNameRaw").AsString(L"") == L"@bfe.dll,-1209" &&
                          joined.Get(L"providerNameResource").Get(L"state").AsString(L"") == L"Resolved" &&
                          analysis.Get(L"resourceResolved").AsString(L"") == L"1",
                          "resource.base-and-mui-in-different-processes-resolve-and-join");
                }
                else
                {
                    check(row.Get(L"name").AsString(L"") == L"@bfe.dll,-1209" &&
                          row.Get(L"nameResource").Get(L"state").AsString(L"") ==
                              (variant == 1 ? L"ResourceDiscoveryIncomplete" : L"ResourceMuiNotMapped") &&
                          resolutionBudget.Report.State == Status::Partial,
                          "resource.incomplete-vad-scan-does-not-claim-absence");
                }
            }
        }
        else
        {
            check(result.Get(L"state").AsString(L"") != L"Resolved" && result.Get(L"value").IsNull(),
                  "resource.mismatch-malformed-missing-and-ambiguous-mui-not-guessed");
        }
    }
}
} // namespace knself
