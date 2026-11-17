#pragma once

#include "BfeRead.h"
#include "MappedResources.h"

namespace kncore
{
class BfeResourceResolver
{
  public:
    BfeResourceResolver(ResourceMemory &memory, const ResourceLayout &layout, const std::vector<ResourceMapping> &mappings)
        : memory_(memory)
    {
        for (const auto &mapping : mappings)
        {
            auto source = std::make_unique<Source>();
            source->Mapping = mapping;
            source->File = std::make_unique<SectionFileReader>(memory, layout);
            source->Pe = std::make_unique<PeResources>(*source->File);
            source->Ready = source->File->Initialize(mapping) && source->Pe->Initialize();
            if (source->Ready)
            {
                source->Mui = source->Pe->Mui();
                source->Ready = source->Mui.has_value() || source->Pe->Error == L"ResourceNotFound";
            }
            sources_.push_back(std::move(source));
        }
    }

    knjson::Value Resolve(const std::wstring &raw)
    {
        if (const auto found = cache_.find(raw); found != cache_.end())
        {
            return found->second;
        }
        auto result = knjson::Value::MakeObject();
        result.Set(L"state", knjson::Value(L"UnsupportedIndirectSyntax"));
        const auto reference = ParseIndirectResource(raw);
        if (!reference)
        {
            return result;
        }
        result.Set(L"module", knjson::Value(reference->Module));
        result.Set(L"id", knjson::Value(std::to_wstring(reference->Id)));
        if (cache_.size() >= 1024 || !memory_.Check())
        {
            result.Set(L"state", knjson::Value(cache_.size() >= 1024 ? L"ResourceReferenceLimit" : L"ResourceReadStopped"));
            return result;
        }
        result.Set(L"state", knjson::Value(L"ResourceModuleNotMapped"));
        if (std::count_if(sources_.begin(), sources_.end(), [&](const auto &source)
        {
            return source->Mapping.Name == reference->Module;
        }) > 1)
        {
            result.Set(L"state", knjson::Value(L"ResourceModuleAmbiguous"));
            return result;
        }
        Source *selected = nullptr;
        std::optional<std::wstring> value;
        uint32_t language = 0;
        for (const auto &base : sources_)
        {
            if (base->Mapping.Name != reference->Module)
            {
                continue;
            }
            if (!base->Ready)
            {
                result.Set(L"state", knjson::Value(base->File->Error.empty() ? base->Pe->Error : base->File->Error));
                continue;
            }
            if (base->Mui && base->Mui->Type != 0x11)
            {
                result.Set(L"state", knjson::Value(L"ResourceModuleTypeMismatch"));
                continue;
            }
            if (!base->Mui)
            {
                const auto direct = base->Pe->String(reference->Id, language);
                if (direct)
                {
                    selected = base.get();
                    value = direct;
                    break;
                }
                result.Set(L"state", knjson::Value(base->Pe->Error));
                continue;
            }
            result.Set(L"state", knjson::Value(L"ResourceMuiNotMapped"));
            for (const auto &mui : sources_)
            {
                if (mui->Mapping.Name != reference->Module + L".mui")
                {
                    continue;
                }
                if (!mui->Ready || !mui->Mui || mui->Mui->Type != 0x12 || mui->Mui->Checksums != base->Mui->Checksums)
                {
                    result.Set(L"state", knjson::Value(L"ResourceMuiMismatchOrUnavailable"));
                    continue;
                }
                uint32_t candidateLanguage = 0;
                const auto candidate = mui->Pe->String(reference->Id, candidateLanguage);
                if (!candidate)
                {
                    result.Set(L"state", knjson::Value(mui->File->Error.empty() ? mui->Pe->Error : mui->File->Error));
                    continue;
                }
                const auto locale = LocaleNameToLCID(mui->Mui->Language.c_str(), 0);
                if (locale == 0 || LANGIDFROMLCID(locale) != candidateLanguage)
                {
                    result.Set(L"state", knjson::Value(L"ResourceLanguageMismatch"));
                    continue;
                }
                if (selected && (language != candidateLanguage || value != candidate || selected->Mui->Language != mui->Mui->Language))
                {
                    result.Set(L"state", knjson::Value(L"ResourceLanguageOrValueAmbiguous"));
                    return result;
                }
                selected = mui.get();
                value = candidate;
                language = candidateLanguage;
            }
        }
        if (selected && value && memory_.Check())
        {
            result.Set(L"state", knjson::Value(L"Resolved"));
            result.Set(L"value", knjson::Value(*value));
            result.Set(L"source", knjson::Value(L"TargetSectionPhysical"));
            result.Set(L"languageId", knjson::Value(Hex(language)));
            result.Set(L"language", selected->Mui ? knjson::Value(selected->Mui->Language) : knjson::Value());
            result.Set(L"file", knjson::Value(selected->Mapping.Path));
            result.Set(L"process", knjson::Value(Hex(selected->Mapping.Process)));
            result.Set(L"mapping", knjson::Value(Hex(selected->Mapping.Address)));
        }
        cache_.emplace(raw, result);
        return result;
    }

  private:
    struct Source
    {
        ResourceMapping Mapping;
        std::unique_ptr<SectionFileReader> File;
        std::unique_ptr<PeResources> Pe;
        std::optional<MuiConfiguration> Mui;
        bool Ready = false;
    };
    ResourceMemory &memory_;
    std::vector<std::unique_ptr<Source>> sources_;
    std::map<std::wstring, knjson::Value> cache_;
};

inline void ResolveBfeResources(ResourceMemory &memory, const ResourceLayout &layout, const std::vector<uint64_t> &processes,
                                std::vector<BfeRecord> &records, knjson::Value &analysis)
{
    std::set<std::wstring> wanted;
    std::set<std::wstring> references;
    for (const auto &record : records)
    {
        for (const auto field : {L"name", L"description"})
        {
            const auto raw = record.Row.Get(field).AsString(L"");
            if (!raw.empty() && raw[0] == L'@')
            {
                references.insert(raw);
                if (const auto parsed = ParseIndirectResource(raw))
                {
                    wanted.insert(parsed->Module);
                    wanted.insert(parsed->Module + L".mui");
                }
            }
        }
    }
    ResourceMappingCatalog catalog(memory, layout);
    size_t scanned = 0;
    if (!processes.empty() && !wanted.empty())
    {
        catalog.Scan(processes.front(), wanted);
        ++scanned;
    }
    BfeResourceResolver resolver(memory, layout, catalog.Mappings);
    std::map<std::wstring, knjson::Value> resolved;
    std::set<std::wstring> fallbackNames;
    for (const auto &raw : references)
    {
        auto value = resolver.Resolve(raw);
        const auto state = value.Get(L"state").AsString(L"");
        if (state == L"ResourceModuleNotMapped" || state == L"ResourceMuiNotMapped")
        {
            if (const auto parsed = ParseIndirectResource(raw))
            {
                fallbackNames.insert(parsed->Module);
                fallbackNames.insert(parsed->Module + L".mui");
            }
        }
        resolved.emplace(raw, std::move(value));
    }
    size_t mappings = catalog.Mappings.size();
    if (!fallbackNames.empty() && !memory.Budget.Stopped)
    {
        WalkBudget fallbackBudget;
        fallbackBudget.Cancelled = memory.Budget.Cancelled;
        fallbackBudget.StartTraversal(std::chrono::steady_clock::now(), std::chrono::seconds(60));
        ResourceMemory fallbackMemory(memory.Reader, memory.Architecture, fallbackBudget);
        ResourceMappingCatalog fallback(fallbackMemory, layout);
        auto missing = fallbackNames;
        std::vector<ResourceMapping> combined;
        std::set<uint64_t> controlAreas;
        for (const auto &mapping : catalog.Mappings)
        {
            if (fallbackNames.contains(mapping.Name))
            {
                combined.push_back(mapping);
                controlAreas.insert(mapping.ControlArea);
                missing.erase(mapping.Name);
            }
        }
        for (size_t i = 1; i < processes.size() && !missing.empty() && fallbackMemory.Check(); ++i)
        {
            fallback.Scan(processes[i], fallbackNames);
            ++scanned;
            for (const auto &mapping : fallback.Mappings)
            {
                missing.erase(mapping.Name);
            }
        }
        mappings += fallback.Mappings.size();
        catalog.Complete = catalog.Complete && fallback.Complete && !fallbackBudget.Stopped;
        for (const auto &mapping : fallback.Mappings)
        {
            if (controlAreas.insert(mapping.ControlArea).second)
            {
                combined.push_back(mapping);
            }
        }
        if (WfpTerminalRead(fallbackBudget.Report.State))
        {
            memory.Budget.Stop(fallbackBudget.Report.State, L"ResourceReadStopped");
        }
        BfeResourceResolver retry(memory, layout, combined);
        for (auto &[raw, value] : resolved)
        {
            const auto state = value.Get(L"state").AsString(L"");
            if (state == L"ResourceModuleNotMapped" || state == L"ResourceMuiNotMapped")
            {
                value = retry.Resolve(raw);
                const auto retryState = value.Get(L"state").AsString(L"");
                if (!catalog.Complete && (retryState == L"ResourceModuleNotMapped" || retryState == L"ResourceMuiNotMapped"))
                {
                    value.Set(L"state", knjson::Value(L"ResourceDiscoveryIncomplete"));
                }
            }
        }
    }
    if (!catalog.Complete)
    {
        for (auto &[raw, value] : resolved)
        {
            const auto state = value.Get(L"state").AsString(L"");
            if (state == L"ResourceModuleNotMapped" || state == L"ResourceMuiNotMapped")
            {
                value.Set(L"state", knjson::Value(L"ResourceDiscoveryIncomplete"));
            }
        }
    }
    size_t successful = 0;
    for (const auto &[raw, value] : resolved)
    {
        successful += value.Get(L"state").AsString(L"") == L"Resolved";
    }
    if (!WfpTerminalRead(memory.Budget.Report.State))
    {
        auto staged = records;
        size_t units = 0;
        for (auto &record : staged)
        {
            for (const auto field : {L"name", L"description"})
            {
                const auto raw = record.Row.Get(field).AsString(L"");
                if (const auto found = resolved.find(raw); found != resolved.end())
                {
                    auto metadata = knjson::Value::MakeObject();
                    for (const auto &[key, value] : found->second.Fields())
                    {
                        if (key != L"value")
                        {
                            metadata.Set(key, value);
                        }
                    }
                    record.Row.Set(std::wstring(field) + L"Raw", knjson::Value(raw));
                    record.Row.Set(std::wstring(field) + L"Resource", metadata);
                    if (found->second.Get(L"state").AsString(L"") == L"Resolved")
                    {
                        record.Row.Set(field, found->second.Get(L"value"));
                        record.Row.Set(std::wstring(field) + L"State", knjson::Value(L"ResolvedResource"));
                    }
                }
            }
            units += record.Row.Write().size();
        }
        if (units <= 2 * 1024 * 1024)
        {
            records = std::move(staged);
        }
        else
        {
            successful = 0;
            memory.Budget.Stop(Status::Partial, L"BfeResourceOutputBudget");
        }
    }
    analysis.Set(L"resourceReferences", knjson::Value(std::to_wstring(references.size())));
    analysis.Set(L"resourceResolved", knjson::Value(std::to_wstring(successful)));
    analysis.Set(L"resourceUnresolved", knjson::Value(std::to_wstring(references.size() - successful)));
    analysis.Set(L"resourceMappings", knjson::Value(std::to_wstring(mappings)));
    analysis.Set(L"resourceProcessesScanned", knjson::Value(std::to_wstring(scanned)));
    analysis.Set(L"resourceCatalogComplete", knjson::Value(catalog.Complete));
    if (!memory.Budget.Stopped && successful != references.size())
    {
        memory.Budget.Stop(Status::Partial, L"BfeResourceUnavailable");
    }
}
} // namespace kncore
