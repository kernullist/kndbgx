#pragma once

#include "../core/BinaryFormats.h"
#include "../util/Json.h"
#include "../util/Text.h"
#include <clocale>
#include <limits>
#include <random>
#include <stdexcept>

namespace knself
{
using CheckFn = void (*)(bool, const char *);

template <typename T> void StoreFixture(std::vector<unsigned char> &bytes, size_t offset, const T &value)
{
    if (!kncore::Contains(bytes.size(), offset, sizeof(value)))
    {
        throw std::out_of_range("fixture bounds");
    }
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

inline std::vector<unsigned char> PeFixture(bool x64)
{
    std::vector<unsigned char> bytes(1024);
    IMAGE_DOS_HEADER dos = {};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    StoreFixture(bytes, 0, dos);
    StoreFixture(bytes, 0x80, DWORD(IMAGE_NT_SIGNATURE));
    IMAGE_FILE_HEADER file = {};
    file.Machine = x64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
    file.NumberOfSections = 1;
    file.SizeOfOptionalHeader = x64 ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32);
    StoreFixture(bytes, 0x84, file);
    if (x64)
    {
        IMAGE_OPTIONAL_HEADER64 optional = {};
        optional.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        optional.SizeOfImage = 0x3000;
        optional.SizeOfHeaders = 0x400;
        optional.AddressOfEntryPoint = 0x1000;
        optional.NumberOfRvaAndSizes = 16;
        StoreFixture(bytes, 0x98, optional);
    }
    else
    {
        IMAGE_OPTIONAL_HEADER32 optional = {};
        optional.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        optional.SizeOfImage = 0x3000;
        optional.SizeOfHeaders = 0x400;
        optional.AddressOfEntryPoint = 0x1000;
        optional.NumberOfRvaAndSizes = 16;
        StoreFixture(bytes, 0x98, optional);
    }
    IMAGE_SECTION_HEADER section = {};
    section.VirtualAddress = 0x1000;
    section.Misc.VirtualSize = 0x1000;
    section.SizeOfRawData = 0x200;
    section.PointerToRawData = 0x400;
    section.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    StoreFixture(bytes, 0x98 + file.SizeOfOptionalHeader, section);
    return bytes;
}

inline std::vector<unsigned char> DumpFixture()
{
    std::vector<unsigned char> bytes(512);
    MINIDUMP_HEADER header = {};
    header.Signature = MINIDUMP_SIGNATURE;
    header.Version = MINIDUMP_VERSION;
    header.NumberOfStreams = 1;
    header.StreamDirectoryRva = sizeof(header);
    StoreFixture(bytes, 0, header);
    MINIDUMP_DIRECTORY directory = {};
    directory.StreamType = ModuleListStream;
    directory.Location.Rva = 0x40;
    directory.Location.DataSize = sizeof(ULONG32) + 2 * sizeof(MINIDUMP_MODULE);
    StoreFixture(bytes, header.StreamDirectoryRva, directory);
    StoreFixture(bytes, 0x40, ULONG32(2));
    for (ULONG32 i = 0; i < 2; ++i)
    {
        MINIDUMP_MODULE module = {};
        module.BaseOfImage = 0x10000000ULL + i * 0x10000;
        module.SizeOfImage = 0x2000;
        module.ModuleNameRva = 0x180 + i * 16;
        StoreFixture(bytes, 0x44 + i * sizeof(module), module);
        StoreFixture(bytes, module.ModuleNameRva, ULONG32(2));
        StoreFixture(bytes, module.ModuleNameRva + 4, wchar_t(L'A' + i));
    }
    return bytes;
}

inline void RunPureRegression(CheckFn check)
{
    const std::wstring scalar = L"A\U0001f600B";
    check(knutil::Utf16PrefixUnits(scalar, 2) == 1 && knutil::Utf16PrefixUnits(scalar, 3) == 3 &&
              knutil::Utf16PrefixUnits(scalar, 100) == 4 && knutil::Utf16PrefixUnits(scalar, 0) == 0 &&
              kncore::ValidUtf16(scalar.substr(0, knutil::Utf16PrefixUnits(scalar, 2))),
          "review.console-budget-never-splits-utf16-scalar");
    knjson::Value parsed;
    bool rejects = true;
    for (const std::wstring text :
         {L"\"unfinished", L"\"raw\nnewline\"", L"+1", L"01", L".5", L"1.", L"1e", L"1e+", L"1e999", L"1e-999", L"NaN", L"Infinity",
          L"[1,]", L"{\"a\":null,\"a\":1}", L"\"\\ud800\"", L"\"\\udc00\"", L"\"\\ud800a\"", L"\"\\x41\""})
    {
        rejects = rejects && !knjson::Parse(text, &parsed);
    }
    check(rejects, "T-JSON-01 rejects malformed grammar and duplicate keys");
    check(!knjson::Parse(std::wstring(33, L'[') + L"0" + std::wstring(33, L']'), &parsed), "T-JSON-01 depth budget");
    knjson::ParseLimits tiny;
    tiny.MaxStringUnits = 3;
    tiny.MaxNodes = 3;
    tiny.MaxInputUnits = 32;
    check(!knjson::Parse(L"\"abcd\"", &parsed, tiny) && !knjson::Parse(L"[1,2,3]", &parsed, tiny) &&
              !knjson::Parse(std::wstring(33, L' '), &parsed, tiny),
          "T-JSON-01 allocation budgets");
    const double precise = 1.23456789012345;
    check(knjson::Parse(knjson::Value(precise).Write(), &parsed) && parsed.AsDouble(0) == precise, "T-JSON-01 round-trip precision");
    bool nonfiniteRejected = false;
    try
    {
        knjson::Value(std::numeric_limits<double>::infinity()).Write();
    }
    catch (const std::domain_error &)
    {
        nonfiniteRejected = true;
    }
    check(nonfiniteRejected, "T-JSON-01 nonfinite serialization fails");
    bool surrogateRejected = false;
    try
    {
        knjson::Value(std::wstring(1, wchar_t(0xD800))).Write();
    }
    catch (const std::domain_error &)
    {
        surrogateRejected = true;
    }
    check(surrogateRejected, "T-JSON-01 unpaired output surrogate fails");
    bool escapedBudgetRejected = false;
    try
    {
        knjson::Value(std::wstring((16 * 1024 * 1024) / 6 + 1, wchar_t(1))).Write();
    }
    catch (const std::length_error &)
    {
        escapedBudgetRejected = true;
    }
    check(escapedBudgetRejected, "review.json-single-escaped-string-budget");
    auto original = knjson::Value::MakeArray();
    original.Push(knjson::Value(1.0));
    auto changed = original;
    changed.Push(original);
    original.Push(original);
    check(changed.Write() == L"[1,[1]]" && original.Write() == L"[1,[1]]", "T-JSON-01 copied result values do not alias or cycle");
    const char *locale = std::setlocale(LC_NUMERIC, nullptr);
    const std::string savedLocale = locale != nullptr ? locale : "C";
    std::setlocale(LC_NUMERIC, "German");
    check(knjson::Value(3.5).Write() == L"3.5" && knjson::Parse(L"3.5", &parsed), "T-JSON-01 locale independent");
    std::setlocale(LC_NUMERIC, savedLocale.c_str());
    check(knjson::Parse(L"\"0xffffffffffffffff\"", &parsed) && parsed.AsString(L"") == L"0xffffffffffffffff",
          "T-JSON-01 exact address string");

    std::vector<std::wstring> tokens;
    check(knutil::Tokenize(L"dump-analyze \"C:\\My Dumps\\\ud14c\uc2a4\ud2b8.dmp\"", &tokens) && tokens.size() == 2 &&
              tokens[1] == L"C:\\My Dumps\\\ud14c\uc2a4\ud2b8.dmp",
          "T-PARSE-01 quoted Unicode path");
    check(knutil::Tokenize(L"cmd \"\" tail", &tokens) && tokens.size() == 3 && tokens[1].empty(), "T-PARSE-01 empty quoted argument");
    check(!knutil::Tokenize(L"cmd \"unfinished", &tokens) && tokens.empty(), "T-PARSE-01 unmatched quote");
    check(!knutil::Tokenize(L"db 0\neb 0 ff", &tokens) && tokens.empty(), "T-PARSE-01 multiline command rejected");
    unsigned long long reg = 0;
    check(!knutil::ParseWindbgHex(L"cr3 = unavailable", &reg) && !knutil::ParseWindbgHex(L"cr3 = access denied 1234", &reg) &&
              !knutil::ParseWindbgHex(L"no registers 1234", &reg) && !knutil::ParseWindbgHex(L"cr3 = 1234 garbage", &reg) &&
              knutil::ParseWindbgHex(L"cr3 = 0", &reg) && reg == 0,
          "T-PARSE-01 error text is not a register value");
    uint64_t number = 0;
    check(kncore::ParseUnsigned(L"ffffffffffffffff", 16, &number) && number == UINT64_MAX &&
              !kncore::ParseUnsigned(L"10000000000000000", 16, &number) && !kncore::ParseUnsigned(L"10tail", 16, &number) &&
              !kncore::ParseUnsigned(L"-1", 16, &number),
          "T-PARSE-01 complete numeric input");
    std::vector<unsigned char> planned;
    const std::vector<uint64_t> tooWide = {1, 256};
    const std::vector<uint64_t> validValues = {0x12, 0x34};
    check(!kncore::PlanValues(0, 1, tooWide, &planned) && planned.empty() && !kncore::PlanValues(UINT64_MAX, 1, validValues, &planned) &&
              planned.empty() && kncore::PlanValues(0, 1, validValues, &planned) && planned == std::vector<unsigned char>({0x12, 0x34}),
          "T-PLAN-01 pure values validate before bytes");

    bool fills = true;
    for (const size_t patternSize : {1, 2, 3, 5, 7, 16, 4095, 4096, 4097})
    {
        std::vector<unsigned char> pattern(patternSize);
        for (size_t i = 0; i < pattern.size(); ++i)
        {
            pattern[i] = static_cast<unsigned char>((i * 13) % 251);
        }
        for (const size_t chunkSize : {1, 7, 4096, 4097})
        {
            std::vector<unsigned char> actual(16385);
            for (size_t offset = 0; offset < actual.size(); offset += chunkSize)
            {
                fills = fills &&
                        kncore::FillChunk(pattern, offset, std::span(actual).subspan(offset, std::min(chunkSize, actual.size() - offset)));
            }
            for (size_t i = 0; i < actual.size(); ++i)
            {
                fills = fills && actual[i] == pattern[i % pattern.size()];
            }
        }
    }
    check(fills && !kncore::FillChunk({}, 0, planned), "T-FILL-01 product planner phase and empty pattern");

    kncore::PeImage pe;
    for (const bool x64 : {false, true})
    {
        auto bytes = PeFixture(x64);
        check(bool(kncore::ParsePeHeaders(bytes, &pe)) && pe.Is64 == x64 && pe.Sections.size() == 1,
              x64 ? "T-PE-01 PE32+ fixture" : "T-PE-01 PE32 fixture");
        check(!kncore::ParsePeHeaders(std::span(bytes).first(63), &pe) && !kncore::ParsePeHeaders(std::span(bytes).first(0x90), &pe) &&
                  !kncore::ParsePeHeaders(std::span(bytes).first(0x180), &pe),
              "T-PE-01 truncated headers");
        StoreFixture(bytes, 0x3c, LONG(-1));
        check(!kncore::ParsePeHeaders(bytes, &pe), "T-PE-01 invalid e_lfanew");
    }
    auto excessive = PeFixture(true);
    StoreFixture(excessive, 0x86, WORD(65535));
    check(!kncore::ParsePeHeaders(excessive, &pe), "T-PE-01 excessive sections");
    excessive = PeFixture(true);
    StoreFixture(excessive, 0x94, WORD(2));
    check(!kncore::ParsePeHeaders(excessive, &pe), "T-PE-01 short optional header");
    auto dump = DumpFixture();
    kncore::SpanReader reader(dump);
    kncore::DumpMetadata metadata;
    check(bool(kncore::ParseDumpMetadata(reader, &metadata)) && metadata.Modules.size() == 2 && metadata.Modules[1].Name == L"B" &&
              metadata.Modules[1].Record.BaseOfImage == 0x10010000,
          "T-DUMP-01 full SDK module stride");
    auto malformedName = DumpFixture();
    StoreFixture(malformedName, 0x184, wchar_t(0xd800));
    kncore::SpanReader malformedNameReader(malformedName);
    check(!kncore::ParseDumpMetadata(malformedNameReader, &metadata), "review.dump-unpaired-surrogate-name-rejected");
    StoreFixture(dump, 0x40, ULONG32(UINT32_MAX));
    check(!kncore::ParseDumpMetadata(reader, &metadata), "T-DUMP-01 count overflow");
    dump = DumpFixture();
    StoreFixture(dump, sizeof(MINIDUMP_HEADER) + 8, ULONG32(0xfffffff0));
    kncore::SpanReader badRva(dump);
    check(!kncore::ParseDumpMetadata(badRva, &metadata), "T-DUMP-01 stream outside file");
    std::vector<unsigned char> minimal(sizeof(MINIDUMP_HEADER));
    MINIDUMP_HEADER header = {};
    header.Signature = MINIDUMP_SIGNATURE;
    header.Version = MINIDUMP_VERSION;
    StoreFixture(minimal, 0, header);
    kncore::SpanReader small(minimal);
    check(bool(kncore::ParseDumpMetadata(small, &metadata)), "T-DUMP-01 minimal valid dump");

    std::mt19937 random(0x4b4e4458);
    bool stable = true;
    for (size_t iteration = 0; iteration < 2000; ++iteration)
    {
        std::wstring input;
        for (size_t i = 0, count = random() % 256; i < count; ++i)
        {
            input.push_back(static_cast<wchar_t>(random() % 128));
        }
        if (knjson::Parse(input, &parsed))
        {
            knjson::Value again;
            stable = stable && knjson::Parse(parsed.Write(), &again) && again.Write() == parsed.Write();
        }
        auto mutated = PeFixture((iteration % 2) == 0);
        mutated[random() % mutated.size()] = static_cast<unsigned char>(random());
        kncore::ParsePeHeaders(std::span(mutated).first(random() % mutated.size()), &pe);
    }
    check(stable, "T-JSON-01 deterministic malformed corpus round-trip");
}
} // namespace knself
