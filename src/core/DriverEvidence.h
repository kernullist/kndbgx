#pragma once

#include "PeIdentity.h"
#include "KernelAnalysis.h"
#include <cmath>
#include <map>

namespace kncore
{
inline std::optional<std::wstring> PeAscii(std::span<const unsigned char> bytes, const PeImage &image, uint64_t rva)
{
    std::wstring value;
    for (unsigned i = 0; i < 256; ++i)
    {
        if (!Contains(image.ImageSize, rva, uint64_t(i) + 1))
        {
            return {};
        }
        const auto offset = PeFileOffset(image, rva + i, 1);
        if (!offset || *offset >= bytes.size())
        {
            return {};
        }
        const auto byte = bytes[static_cast<size_t>(*offset)];
        if (byte == 0)
        {
            return value.empty() ? std::nullopt : std::optional<std::wstring>(value);
        }
        if (byte < 32 || byte > 126)
        {
            return {};
        }
        value.push_back(byte);
    }
    return {};
}

inline Result AuditDriverPe(std::span<const unsigned char> bytes, const std::function<bool()> &cancelled = {})
{
    Result result;
    result.Source = L"host-file:PE";
    result.Consistency = L"immutable-file-buffer";
    if (cancelled && cancelled())
    {
        result.State = Status::Cancelled;
        result.Collected.StopReason = L"Cancelled";
        return result;
    }
    PeImage pe;
    const auto parsed = ParsePeHeaders(bytes, &pe, bytes.size());
    if (!parsed || pe.HeadersSize > bytes.size())
    {
        result.State = Status::InvalidInput;
        result.Error.Message = L"Invalid or incomplete PE headers: " + parsed.Error;
        return result;
    }
    IMAGE_DOS_HEADER dos = {};
    Load(bytes, 0, &dos);
    const uint64_t optional = uint64_t(dos.e_lfanew) + 4 + sizeof(IMAGE_FILE_HEADER);
    WORD characteristics = 0;
    WORD subsystem = 0;
    DWORD directoryCount = 0;
    Load(bytes, optional + offsetof(IMAGE_OPTIONAL_HEADER64, DllCharacteristics), &characteristics);
    Load(bytes, optional + offsetof(IMAGE_OPTIONAL_HEADER64, Subsystem), &subsystem);
    Load(bytes,
         optional +
             (pe.Is64 ? offsetof(IMAGE_OPTIONAL_HEADER64, NumberOfRvaAndSizes) : offsetof(IMAGE_OPTIONAL_HEADER32, NumberOfRvaAndSizes)),
         &directoryCount);
    const uint64_t directories =
        optional + (pe.Is64 ? offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) : offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory));
    auto directory = [&](unsigned index)
    {
        IMAGE_DATA_DIRECTORY value = {};
        if (index < directoryCount)
        {
            Load(bytes, directories + uint64_t(index) * sizeof(value), &value);
        }
        return value;
    };
    auto image = knjson::Value::MakeObject();
    image.Set(L"kind", knjson::Value(L"DriverImage"));
    image.Set(L"machine", knjson::Value(Hex(pe.File.Machine)));
    image.Set(L"is64", knjson::Value(pe.Is64));
    image.Set(L"subsystem", knjson::Value(Hex(subsystem)));
    image.Set(L"nativeSubsystem", knjson::Value(subsystem == IMAGE_SUBSYSTEM_NATIVE));
    image.Set(L"imageSize", knjson::Value(std::to_wstring(pe.ImageSize)));
    image.Set(L"entryRva", knjson::Value(Hex(pe.EntryRva)));
    image.Set(L"timestamp", knjson::Value(Hex(pe.File.TimeDateStamp)));
    image.Set(L"nxCompatible", knjson::Value((characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0));
    image.Set(L"dynamicBase", knjson::Value((characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0));
    image.Set(L"highEntropyVa", knjson::Value((characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0));
    image.Set(L"guardCfDeclared", knjson::Value((characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0));
    image.Set(L"forceIntegrity", knjson::Value((characteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) != 0));
    image.Set(L"relocationsStripped", knjson::Value((pe.File.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0));
    const auto config = directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    if (config.Size != 0 || config.VirtualAddress != 0)
    {
        const auto offset = PeFileOffset(pe, config.VirtualAddress, config.Size);
        DWORD declared = 0;
        if (config.VirtualAddress == 0 || !offset || !Contains(bytes.size(), *offset, config.Size) || config.Size < 4 ||
            !Load(bytes, *offset, &declared) || declared < 4 || declared > config.Size)
        {
            ++result.Collected.Unknown;
            image.Set(L"loadConfigValid", knjson::Value(false));
        }
        else
        {
            image.Set(L"loadConfigValid", knjson::Value(true));
            auto field = [&](const wchar_t *name, size_t position, unsigned width)
            {
                uint64_t value = 0;
                if (Contains(declared, position, width))
                {
                    std::memcpy(&value, bytes.data() + *offset + position, width);
                    image.Set(name, knjson::Value(Hex(value)));
                }
                else
                {
                    image.Set(name, knjson::Value());
                }
            };
            field(L"securityCookieVa",
                  pe.Is64 ? offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie)
                          : offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, SecurityCookie),
                  pe.Is64 ? 8 : 4);
            field(L"guardFlags",
                  pe.Is64 ? offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardFlags) : offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardFlags), 4);
            field(L"guardCfFunctionCount",
                  pe.Is64 ? offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFFunctionCount)
                          : offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardCFFunctionCount),
                  pe.Is64 ? 8 : 4);
            field(L"guardEhContinuationCount",
                  pe.Is64 ? offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardEHContinuationCount)
                          : offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, GuardEHContinuationCount),
                  pe.Is64 ? 8 : 4);
        }
    }
    const auto security = directory(IMAGE_DIRECTORY_ENTRY_SECURITY);
    image.Set(L"certificateTablePresent", knjson::Value(security.VirtualAddress != 0 || security.Size != 0));
    image.Set(L"certificateTableBoundsValid",
              knjson::Value(security.VirtualAddress != 0 && security.Size >= 8 && (security.VirtualAddress & 7) == 0 &&
                            Contains(bytes.size(), security.VirtualAddress, security.Size)));
    if ((security.VirtualAddress != 0 || security.Size != 0) && !image.Get(L"certificateTableBoundsValid").AsBool(false))
    {
        ++result.Collected.Unknown;
    }
    SpanReader reader(bytes);
    bool debugComplete = false;
    const auto pdb = CodeViewIdentity(reader, pe, false, &debugComplete);
    image.Set(L"debugMetadataComplete", knjson::Value(debugComplete));
    if (!debugComplete)
    {
        ++result.Collected.Unknown;
    }
    if (pdb)
    {
        auto identity = knjson::Value::MakeArray();
        for (const auto byte : *pdb)
        {
            identity.Push(knjson::Value(double(byte)));
        }
        image.Set(L"codeViewGuidAgeBytes", identity);
    }
    else
    {
        image.Set(L"codeViewGuidAgeBytes", knjson::Value());
    }
    for (size_t i = 0; i < pe.Sections.size(); ++i)
    {
        const auto &left = pe.Sections[i];
        const uint64_t leftSize = std::max(left.Misc.VirtualSize, left.SizeOfRawData);
        if ((leftSize != 0 && left.VirtualAddress < pe.HeadersSize) || (left.SizeOfRawData != 0 && left.PointerToRawData < pe.HeadersSize))
        {
            ++result.Collected.Unknown;
        }
        for (size_t j = i + 1; j < pe.Sections.size(); ++j)
        {
            const auto &right = pe.Sections[j];
            const uint64_t rightSize = std::max(right.Misc.VirtualSize, right.SizeOfRawData);
            const bool virtualOverlap = leftSize != 0 && rightSize != 0 &&
                                        left.VirtualAddress < uint64_t(right.VirtualAddress) + rightSize &&
                                        right.VirtualAddress < uint64_t(left.VirtualAddress) + leftSize;
            const bool rawOverlap = left.SizeOfRawData != 0 && right.SizeOfRawData != 0 &&
                                    left.PointerToRawData < uint64_t(right.PointerToRawData) + right.SizeOfRawData &&
                                    right.PointerToRawData < uint64_t(left.PointerToRawData) + left.SizeOfRawData;
            if (virtualOverlap || rawOverlap)
            {
                ++result.Collected.Unknown;
            }
        }
    }
    bool kasan = false;
    auto sections = knjson::Value::MakeArray();
    for (const auto &section : pe.Sections)
    {
        std::wstring name;
        for (const unsigned char ch : section.Name)
        {
            if (ch == 0)
            {
                break;
            }
            name.push_back(ch >= 32 && ch < 127 ? ch : L'?');
        }
        kasan = kasan || name == L"KASAN";
        const bool executable = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        const bool writable = (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"PeSection"));
        row.Set(L"name", knjson::Value(name));
        row.Set(L"rva", knjson::Value(Hex(section.VirtualAddress)));
        row.Set(L"virtualBytes", knjson::Value(std::to_wstring(section.Misc.VirtualSize)));
        row.Set(L"fileBytes", knjson::Value(std::to_wstring(section.SizeOfRawData)));
        row.Set(L"readable", knjson::Value((section.Characteristics & IMAGE_SCN_MEM_READ) != 0));
        row.Set(L"writable", knjson::Value(writable));
        row.Set(L"executable", knjson::Value(executable));
        sections.Push(row);
        if (executable && writable)
        {
            auto finding = knjson::Value::MakeObject();
            finding.Set(L"rule", knjson::Value(L"PE.WritableExecutableSection"));
            finding.Set(L"section", knjson::Value(name));
            finding.Set(L"severity", knjson::Value(L"review"));
            finding.Set(L"message", knjson::Value(L"Writable executable image section; investigate compatibility and runtime mappings"));
            result.Findings.Push(finding);
        }
    }
    image.Set(L"kasanSectionPresent", knjson::Value(kasan));
    result.Rows.Push(image);
    for (const auto &row : sections.Items())
    {
        result.Rows.Push(row);
    }
    const auto imports = directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (imports.VirtualAddress != 0 || imports.Size != 0)
    {
        bool terminated = false;
        const auto table = PeFileOffset(pe, imports.VirtualAddress, imports.Size);
        if (imports.VirtualAddress == 0 || imports.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR) ||
            !Contains(pe.ImageSize, imports.VirtualAddress, imports.Size) || !table || !Contains(bytes.size(), *table, imports.Size))
        {
            ++result.Collected.Unknown;
        }
        else
        {
            for (unsigned i = 0; i < 256 && uint64_t(i + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR) <= imports.Size; ++i)
            {
                if (cancelled && cancelled())
                {
                    result.State = Status::Cancelled;
                    break;
                }
                IMAGE_IMPORT_DESCRIPTOR descriptor = {};
                Load(bytes, *table + uint64_t(i) * sizeof(descriptor), &descriptor);
                if (descriptor.OriginalFirstThunk == 0 && descriptor.TimeDateStamp == 0 && descriptor.ForwarderChain == 0 &&
                    descriptor.Name == 0 && descriptor.FirstThunk == 0)
                {
                    terminated = true;
                    break;
                }
                const auto module = PeAscii(bytes, pe, descriptor.Name);
                uint64_t thunkRva = descriptor.OriginalFirstThunk != 0 ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
                bool thunkTerminated = false;
                if (descriptor.Name == 0 || !module || thunkRva == 0)
                {
                    ++result.Collected.Unknown;
                    continue;
                }
                for (unsigned j = 0; j < 4096 && result.Rows.Items().size() < 8192; ++j)
                {
                    const unsigned width = pe.Is64 ? 8 : 4;
                    const auto offset = PeFileOffset(pe, thunkRva + uint64_t(j) * width, width);
                    uint64_t thunk = 0;
                    if (!offset || !Contains(bytes.size(), *offset, width))
                    {
                        break;
                    }
                    std::memcpy(&thunk, bytes.data() + *offset, width);
                    if (thunk == 0)
                    {
                        thunkTerminated = true;
                        break;
                    }
                    const uint64_t flag = pe.Is64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;
                    auto row = knjson::Value::MakeObject();
                    row.Set(L"kind", knjson::Value(L"PeImport"));
                    row.Set(L"module", knjson::Value(*module));
                    row.Set(L"lookupValue", knjson::Value(Hex(thunk)));
                    const uint64_t iatRva = uint64_t(descriptor.FirstThunk) + uint64_t(j) * width;
                    const auto iatOffset = PeFileOffset(pe, iatRva, width);
                    const bool iatValid = descriptor.FirstThunk != 0 && Contains(pe.ImageSize, iatRva, width) && iatOffset &&
                                          Contains(bytes.size(), *iatOffset, width);
                    row.Set(L"iatRva", iatValid ? knjson::Value(Hex(iatRva)) : knjson::Value());
                    if (!iatValid)
                    {
                        ++result.Collected.Unknown;
                    }
                    if ((thunk & flag) != 0)
                    {
                        const bool ordinalValid = (thunk & ~(flag | uint64_t(0xffff))) == 0;
                        row.Set(L"ordinal", ordinalValid ? knjson::Value(std::to_wstring(thunk & 0xffff)) : knjson::Value());
                        if (!ordinalValid)
                        {
                            ++result.Collected.Unknown;
                        }
                    }
                    else
                    {
                        const auto hint = PeFileOffset(pe, thunk, sizeof(WORD));
                        const auto name = thunk <= 0x7fffffff && hint && Contains(bytes.size(), *hint, sizeof(WORD))
                                              ? PeAscii(bytes, pe, thunk + 2)
                                              : std::nullopt;
                        row.Set(L"name", name ? knjson::Value(*name) : knjson::Value());
                        if (!name)
                        {
                            ++result.Collected.Unknown;
                        }
                    }
                    result.Rows.Push(row);
                }
                if (!thunkTerminated)
                {
                    ++result.Collected.Unknown;
                }
            }
            if (!terminated)
            {
                ++result.Collected.Unknown;
            }
        }
    }
    const auto delay = directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
    if (delay.Size != 0 || delay.VirtualAddress != 0)
    {
        ++result.Collected.Unknown;
        result.Limitations.Push(knjson::Value(L"Delay imports are present and are not enumerated"));
    }
    result.Collected.Visited = result.Rows.Items().size();
    result.Collected.Decoded = result.Collected.Visited;
    result.Collected.Complete = result.Collected.Unknown == 0 && result.State != Status::Cancelled;
    result.Collected.StopReason = result.Collected.Complete ? L"DeclaredPeMetadataDecoded" : L"PartialPeMetadata";
    if (!result.Collected.Complete && result.State == Status::Success)
    {
        result.State = Status::Partial;
    }
    result.Limitations.Push(
        knjson::Value(L"PE declarations do not prove runtime protection, HVCI compatibility, vulnerability status or driver trust"));
    return result;
}

inline bool JsonIndex(const knjson::Value &value, size_t bound, size_t &index)
{
    const double number = value.AsDouble(-1);
    const bool valid = value.IsNumber() && std::isfinite(number) && number >= 0 && std::floor(number) == number && number < double(bound);
    if (valid)
    {
        index = static_cast<size_t>(number);
    }
    return valid;
}

inline std::optional<std::wstring> SarifMessage(const knjson::Value &message, const knjson::Value &rule, const knjson::Value &component)
{
    auto text = message.Get(L"text").IsString() ? message.Get(L"text") : message.Get(L"markdown");
    if (!text.IsString())
    {
        const auto id = message.Get(L"id").AsString(L"");
        const auto &local = rule.Get(L"messageStrings").Get(id);
        const auto &global = component.Get(L"globalMessageStrings").Get(id);
        const auto &format = local.IsObject() ? local : global;
        text = format.Get(L"text").IsString() ? format.Get(L"text") : format.Get(L"markdown");
    }
    if (!text.IsString())
    {
        return {};
    }
    const auto source = text.AsString(L"");
    if (source.size() > 2048)
    {
        return {};
    }
    const auto &args = message.Get(L"arguments");
    if ((!args.IsNull() && !args.IsArray()) || args.Items().size() > 64)
    {
        return {};
    }
    std::wstring rendered;
    for (size_t i = 0; i < source.size(); ++i)
    {
        if ((source[i] == L'{' || source[i] == L'}') && i + 1 < source.size() && source[i] == source[i + 1])
        {
            rendered.push_back(source[i++]);
        }
        else if (source[i] == L'{')
        {
            const auto end = source.find(L'}', i + 1);
            uint64_t index = 0;
            const auto token = end == std::wstring::npos ? std::wstring_view() : std::wstring_view(source).substr(i + 1, end - i - 1);
            if (token.empty() ||
                !std::all_of(token.begin(), token.end(),
                             [](wchar_t c)
                             {
                                 return c >= L'0' && c <= L'9';
                             }) ||
                !ParseUnsigned(token, 10, &index) || index >= args.Items().size() || !args.Items()[static_cast<size_t>(index)].IsString())
            {
                return {};
            }
            const auto argument = args.Items()[static_cast<size_t>(index)].AsString(L"");
            if (argument.size() > 2048 - rendered.size())
            {
                return {};
            }
            rendered += argument;
            i = end;
        }
        else if (source[i] == L'}')
        {
            return {};
        }
        else
        {
            rendered.push_back(source[i]);
        }
        if (rendered.size() > 2048)
        {
            return {};
        }
    }
    return rendered;
}

inline bool SarifLevelKnown(const std::wstring &level)
{
    return level == L"none" || level == L"note" || level == L"warning" || level == L"error";
}

struct SarifInvocationLevels
{
    bool Valid = true;
    std::map<size_t, std::wstring> Levels;
};

inline std::vector<SarifInvocationLevels> SarifOverrides(const knjson::Value &invocations, const knjson::Value &rules,
                                                         const std::map<std::wstring, size_t> &ruleLookup)
{
    std::vector<SarifInvocationLevels> result;
    for (const auto &invocation : invocations.Items())
    {
        SarifInvocationLevels resolved;
        const auto &overrides = invocation.Get(L"ruleConfigurationOverrides");
        resolved.Valid = invocation.IsObject() && (overrides.IsNull() || overrides.IsArray());
        for (const auto &entry : overrides.Items())
        {
            const auto &level = entry.Get(L"configuration").Get(L"level");
            if (level.IsNull())
            {
                continue;
            }
            const auto &descriptor = entry.Get(L"descriptor");
            const auto &reference = descriptor.Get(L"index");
            const auto &id = descriptor.Get(L"id");
            size_t index = 0;
            bool known = JsonIndex(reference, rules.Items().size(), index);
            if (reference.IsNull() && id.IsString())
            {
                const auto found = ruleLookup.find(id.AsString(L""));
                known = found != ruleLookup.end() && found->second != SIZE_MAX;
                if (known)
                {
                    index = found->second;
                }
            }
            if (!known || !descriptor.Get(L"toolComponent").IsNull() || !level.IsString() || !SarifLevelKnown(level.AsString(L"")) ||
                (!id.IsNull() && (!id.IsString() || id.AsString(L"") != rules.Items()[index].Get(L"id").AsString(L""))) ||
                !resolved.Levels.emplace(index, level.AsString(L"")).second)
            {
                resolved.Valid = false;
            }
        }
        result.push_back(std::move(resolved));
    }
    return result;
}

inline Result ImportSarif(const knjson::Value &document, const std::function<bool()> &cancelled = {})
{
    Result result;
    result.Source = L"host-file:SARIF";
    result.Consistency = L"immutable-file-buffer";
    auto label = [&result](const std::wstring &text)
    {
        size_t size = std::min<size_t>(text.size(), 512);
        if (size < text.size())
        {
            ++result.Collected.Unknown;
            if (size > 0 && text[size - 1] >= 0xd800 && text[size - 1] <= 0xdbff)
            {
                --size;
            }
        }
        return knjson::Value(text.substr(0, size));
    };
    const auto &runs = document.Get(L"runs");
    if (!document.IsObject() || document.Get(L"version").AsString(L"") != L"2.1.0" || !runs.IsArray() || runs.Items().size() > 64)
    {
        result.State = Status::InvalidInput;
        result.Error.Message = L"Expected SARIF 2.1.0 with at most 64 inline runs";
        return result;
    }
    for (size_t r = 0; r < runs.Items().size(); ++r)
    {
        const auto &run = runs.Items()[r];
        const auto &driver = run.Get(L"tool").Get(L"driver");
        const auto &items = run.Get(L"results");
        if (cancelled && cancelled())
        {
            result.State = Status::Cancelled;
            break;
        }
        if (!run.IsObject() || driver.Get(L"name").AsString(L"").empty())
        {
            ++result.Collected.Unknown;
            continue;
        }
        if (!run.Get(L"externalPropertyFileReferences").IsNull())
        {
            ++result.Collected.Unknown;
            result.Limitations.Push(knjson::Value(L"External SARIF properties were not loaded"));
        }
        auto runRow = knjson::Value::MakeObject();
        runRow.Set(L"kind", knjson::Value(L"SarifRun"));
        runRow.Set(L"runIndex", knjson::Value(std::to_wstring(r)));
        runRow.Set(L"tool", driver.Get(L"name"));
        runRow.Set(L"version", driver.Get(L"semanticVersion").IsString() ? driver.Get(L"semanticVersion") : driver.Get(L"version"));
        runRow.Set(L"invocations", run.Get(L"invocations"));
        runRow.Set(L"originalUriBaseIds", run.Get(L"originalUriBaseIds"));
        runRow.Set(L"artifacts", run.Get(L"artifacts"));
        runRow.Set(L"toolMetadata", run.Get(L"tool"));
        runRow.Set(L"externalPropertyFileReferences", run.Get(L"externalPropertyFileReferences"));
        runRow.Set(L"resultsAvailable", knjson::Value(items.IsArray()));
        result.Rows.Push(runRow);
        if (!items.IsArray())
        {
            ++result.Collected.Unknown;
            continue;
        }
        std::map<std::wstring, size_t> ruleLookup;
        const auto &rules = driver.Get(L"rules");
        for (size_t index = 0; index < rules.Items().size(); ++index)
        {
            const auto id = rules.Items()[index].Get(L"id").AsString(L"");
            if (!id.empty() && !ruleLookup.emplace(id, index).second)
            {
                ++result.Collected.Unknown;
                ruleLookup[id] = SIZE_MAX;
            }
        }
        const auto overrides = SarifOverrides(run.Get(L"invocations"), rules, ruleLookup);
        for (const auto &invocation : overrides)
        {
            if (!invocation.Valid)
            {
                ++result.Collected.Unknown;
            }
        }
        result.Collected.Expected += items.Items().size();
        for (const auto &item : items.Items())
        {
            if (cancelled && cancelled())
            {
                result.State = Status::Cancelled;
                break;
            }
            if (result.Collected.Visited >= 4096)
            {
                ++result.Collected.Unknown;
                break;
            }
            ++result.Collected.Visited;
            if (!item.IsObject() || !item.Get(L"message").IsObject())
            {
                ++result.Collected.Unknown;
                continue;
            }
            auto row = knjson::Value::MakeObject();
            row.Set(L"kind", knjson::Value(L"StaticFinding"));
            row.Set(L"runIndex", knjson::Value(std::to_wstring(r)));
            row.Set(L"tool", label(driver.Get(L"name").AsString(L"")));
            knjson::Value rule;
            size_t index = 0;
            std::optional<size_t> resolvedRuleIndex;
            const bool componentReference = !item.Get(L"rule").Get(L"toolComponent").IsNull();
            const auto &ruleIndex = item.Get(L"ruleIndex").IsNull() ? item.Get(L"rule").Get(L"index") : item.Get(L"ruleIndex");
            if (!componentReference && JsonIndex(ruleIndex, rules.Items().size(), index))
            {
                rule = rules.Items()[index];
                resolvedRuleIndex = index;
            }
            else if (!componentReference && !ruleIndex.IsNull())
            {
                ++result.Collected.Unknown;
            }
            const auto ruleId = item.Get(L"ruleId").AsString(item.Get(L"rule").Get(L"id").AsString(rule.Get(L"id").AsString(L"")));
            if (!rule.IsNull() && rule.Get(L"id").AsString(L"") != ruleId)
            {
                rule = {};
                resolvedRuleIndex.reset();
                ++result.Collected.Unknown;
            }
            if (!componentReference && rule.IsNull() && !ruleId.empty())
            {
                const auto found = ruleLookup.find(ruleId);
                if (found != ruleLookup.end() && found->second != SIZE_MAX)
                {
                    rule = rules.Items()[found->second];
                    resolvedRuleIndex = found->second;
                }
            }
            row.Set(L"ruleId", label(ruleId));
            row.Set(L"ruleIndex", ruleIndex);
            const auto &kind = item.Get(L"kind");
            const auto resultKind = kind.AsString(L"fail");
            const bool kindKnown = (kind.IsNull() || kind.IsString()) &&
                                   (resultKind == L"fail" || resultKind == L"pass" || resultKind == L"open" ||
                                    resultKind == L"informational" || resultKind == L"notApplicable" || resultKind == L"review");
            row.Set(L"resultKind", label(resultKind));
            if (kindKnown && resultKind != L"fail")
            {
                row.Set(L"kind", knjson::Value(L"StaticResult"));
            }
            std::wstring level = L"unknown";
            const auto &explicitLevel = item.Get(L"level");
            if (kindKnown && !explicitLevel.IsNull())
            {
                if (explicitLevel.IsString() && SarifLevelKnown(explicitLevel.AsString(L"")) &&
                    (resultKind == L"fail" || explicitLevel.AsString(L"") == L"none"))
                {
                    level = explicitLevel.AsString(L"");
                }
            }
            else if (kindKnown && resultKind != L"fail")
            {
                level = L"none";
            }
            else if (kindKnown && !componentReference)
            {
                const auto &defaultLevel = rule.Get(L"defaultConfiguration").Get(L"level");
                level = defaultLevel.IsNull() ? L"warning" : defaultLevel.AsString(L"unknown");
                if (!SarifLevelKnown(level))
                {
                    level = L"unknown";
                }
                const auto &invocationIndex = item.Get(L"provenance").Get(L"invocationIndex");
                if (!invocationIndex.IsNull() && (!invocationIndex.IsNumber() || invocationIndex.AsDouble(-2) != -1))
                {
                    size_t invocation = 0;
                    if (!JsonIndex(invocationIndex, overrides.size(), invocation) || !overrides[invocation].Valid)
                    {
                        level = L"unknown";
                    }
                    else if (resolvedRuleIndex)
                    {
                        const auto found = overrides[invocation].Levels.find(*resolvedRuleIndex);
                        if (found != overrides[invocation].Levels.end())
                        {
                            level = found->second;
                        }
                    }
                }
            }
            row.Set(L"level", label(level));
            if (!SarifLevelKnown(level))
            {
                ++result.Collected.Unknown;
            }
            const auto &message = item.Get(L"message");
            const auto rendered = SarifMessage(message, rule, componentReference ? knjson::Value() : driver);
            row.Set(L"message", rendered ? knjson::Value(*rendered) : knjson::Value());
            row.Set(L"messageId", message.Get(L"id"));
            row.Set(L"baselineState", item.Get(L"baselineState"));
            row.Set(L"suppressions", item.Get(L"suppressions"));
            row.Set(L"locations", item.Get(L"locations"));
            row.Set(L"rawResult", item);
            if (!rendered)
            {
                ++result.Collected.Unknown;
            }
            if (componentReference)
            {
                ++result.Collected.Unknown;
                row.Set(L"ruleResolution", knjson::Value(L"External or extension tool component; original descriptor included"));
            }
            result.Rows.Push(row);
            ++result.Collected.Decoded;
        }
        if (result.State == Status::Cancelled || result.Collected.Visited >= 4096)
        {
            if (r + 1 < runs.Items().size())
            {
                ++result.Collected.Unknown;
            }
            break;
        }
    }
    result.Collected.Complete =
        result.State == Status::Success && result.Collected.Unknown == 0 && result.Collected.Visited == result.Collected.Expected;
    result.Collected.StopReason = result.Collected.Complete ? L"InlineSarifImported" : L"PartialSarifImport";
    if (!result.Collected.Complete && result.State == Status::Success)
    {
        result.State = Status::Partial;
    }
    result.Limitations.Push(knjson::Value(
        L"Imported analyzer results have not been independently verified. URIs are included as text; no external content is fetched."));
    return result;
}
} // namespace kncore
