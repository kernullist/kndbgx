#pragma once

#include "Result.h"
#include <map>
#include <string_view>

namespace kncore
{
inline std::wstring ModuleAddressLabel(std::wstring_view module, uint64_t offset)
{
    return std::wstring(module) + (offset == 0 ? L"" : L"+" + Hex(offset));
}

inline bool SymbolNameCanBind(std::wstring_view name)
{
    const auto qualifier = name.find(L'!');
    return qualifier != std::wstring_view::npos && qualifier != 0 && qualifier + 1 < name.size() &&
           name.find(L" <PERF> ") == std::wstring_view::npos;
}

inline bool ExactSymbolBinding(uint64_t address, uint64_t displacement, uint64_t symbolStart, uint64_t moduleBase,
                               uint64_t moduleSize)
{
    return ValidRange(moduleBase, moduleSize) && address >= moduleBase && address - moduleBase < moduleSize &&
           symbolStart >= moduleBase && symbolStart - moduleBase < moduleSize && displacement <= address &&
           address - displacement == symbolStart;
}

// Keep this cache local to one result; symbol reloads and target changes must retry.
class SymbolAddressCache
{
  public:
    template <typename Resolve> std::optional<uint64_t> Get(uint64_t moduleBase, const std::wstring &name, Resolve resolve)
    {
        auto [entry, inserted] = values_.try_emplace(std::make_pair(moduleBase, name));
        if (inserted)
        {
            entry->second = resolve();
        }
        return entry->second;
    }

  private:
    std::map<std::pair<uint64_t, std::wstring>, std::optional<uint64_t>> values_;
};

inline bool HasObservationValue(const knjson::Value &value, size_t depth = 0)
{
    if (depth > 8 || value.IsNull())
    {
        return false;
    }
    if (value.IsObject())
    {
        for (const auto &[name, child] : value.Fields())
        {
            if (name != L"kind" && name != L"interpretation" && HasObservationValue(child, depth + 1))
            {
                return true;
            }
        }
        return false;
    }
    if (value.IsArray())
    {
        for (const auto &child : value.Items())
        {
            if (HasObservationValue(child, depth + 1))
            {
                return true;
            }
        }
        return false;
    }
    return !value.IsString() || !value.AsString(L"").empty();
}

inline void SeparateResultDiagnostics(Result &report)
{
    auto observations = knjson::Value::MakeArray();
    auto diagnostics = report.Analysis.Get(L"diagnostics");
    if (!diagnostics.IsArray())
    {
        diagnostics = knjson::Value::MakeArray();
    }
    for (const auto &row : report.Rows.Items())
    {
        const auto kind = row.Get(L"kind").AsString(L"");
        if (kind == L"CoverageGap" || kind == L"CallbackTable" || kind == L"RawSymbolObservation")
        {
            diagnostics.Push(row);
        }
        else if (!HasObservationValue(row))
        {
            auto diagnostic = knjson::Value::MakeObject();
            diagnostic.Set(L"kind", knjson::Value(L"EmptyObservation"));
            diagnostic.Set(L"reason", knjson::Value(L"Collector returned a record without observation fields"));
            diagnostic.Set(L"record", row);
            diagnostics.Push(diagnostic);
            ++report.Collected.Unknown;
            report.Collected.Complete = false;
            if (report.State == Status::Success)
            {
                report.State = Status::Partial;
                report.Collected.StopReason = L"EmptyObservation";
            }
        }
        else
        {
            observations.Push(row);
        }
    }
    report.Rows = observations;
    if (!diagnostics.Items().empty())
    {
        if (!report.Analysis.IsObject())
        {
            report.Analysis = knjson::Value::MakeObject();
        }
        report.Analysis.Set(L"diagnostics", diagnostics);
    }
}

inline bool DisplaySymbolField(std::wstring_view field)
{
    return field == L"symbol" || field == L"symbolSource" || field == L"symbolAddress" || field == L"symbolField" ||
           field == L"symbolDisplacement" || field.ends_with(L"Symbol") || field.ends_with(L"SymbolSource") ||
           field.ends_with(L"SymbolDisplacement");
}
} // namespace kncore
