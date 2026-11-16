#pragma once

#include "ResultStore.h"
#include "ResultAddress.h"

namespace kncore
{
// Generation strings and optional context fields retain their wire types.
inline bool MatchesStamp(const SessionStamp &stamp, const knjson::Value &candidate)
{
    const auto expected = stamp.ToJson();
    if (!candidate.IsObject() || candidate.Fields().size() != expected.Fields().size())
    {
        return false;
    }
    for (const auto &[key, value] : expected.Fields())
    {
        if (value.IsObject())
        {
            const auto &context = candidate.Get(key);
            if (!context.IsObject() || context.Fields().size() != value.Fields().size())
            {
                return false;
            }
            for (const auto &[field, scalar] : value.Fields())
            {
                const auto found = std::find_if(context.Fields().begin(), context.Fields().end(),
                                                [&](const auto &entry)
                                                {
                                                    return entry.first == field;
                                                });
                if (found == context.Fields().end() || found->second.Write() != scalar.Write())
                {
                    return false;
                }
            }
        }
        else if (candidate.Get(key).Write() != value.Write())
        {
            return false;
        }
    }
    return true;
}

struct ResultAddress
{
    uint64_t Address = 0;
    std::wstring Space;
};

inline std::optional<ResultAddress> BoundResultAddress(const StoredResult &source, const knjson::Value &parameters,
                                                       const SessionStamp &current)
{
    if (source.Id != parameters.Get(L"resultId").AsString(L"") || source.Data.Stamp != current || !current.Context.Complete() ||
        !MatchesStamp(source.Data.Stamp, parameters.Get(L"expectedStamp")))
    {
        return std::nullopt;
    }
    const auto collection = parameters.Get(L"collection").AsString(L"");
    if (collection != L"rows" && collection != L"findings")
    {
        return std::nullopt;
    }
    const auto &rows = collection == L"rows" ? source.Data.Rows.Items() : source.Data.Findings.Items();
    uint64_t index = 0;
    if (!ParseUnsigned(parameters.Get(L"index").AsString(L""), 10, &index) || index >= rows.size())
    {
        return std::nullopt;
    }
    const auto &row = rows[static_cast<size_t>(index)];
    const auto fieldEntry = std::find_if(parameters.Fields().begin(), parameters.Fields().end(),
        [](const auto &entry)
        {
            return entry.first == L"field";
        });
    if (fieldEntry != parameters.Fields().end() && !fieldEntry->second.IsString())
    {
        return std::nullopt;
    }
    const auto field = fieldEntry == parameters.Fields().end() ? L"address" : fieldEntry->second.AsString(L"");
    auto path = parameters.Get(L"path");
    const auto pathEntry = std::find_if(parameters.Fields().begin(), parameters.Fields().end(), [](const auto &entry)
    {
        return entry.first == L"path";
    });
    if (pathEntry != parameters.Fields().end())
    {
        if (fieldEntry != parameters.Fields().end() || !path.IsArray() || path.Items().empty() || path.Items().size() > 4 ||
            !std::all_of(path.Items().begin(), path.Items().end(), [](const auto &part)
            {
                return part.IsString() && AddressPathPart(part.AsString(L""));
            }))
        {
            return std::nullopt;
        }
    }
    else
    {
        const auto space = row.Get(L"addressSpace").AsString(L"");
        const auto kind = row.Get(L"kind").AsString(L"");
        const bool callback = (field == L"routine" && RoutineRecordKind(kind)) ||
                              ((field == L"preRoutine" || field == L"postRoutine") && kind == L"ObjectCallbackRegistration");
        if ((field != L"address" && !callback) || (callback && !space.empty() && space != L"virtual"))
        {
            return std::nullopt;
        }
        path = knjson::Value::MakeArray();
        path.Push(knjson::Value(field));
    }
    const auto descriptors = ResultAddressFields(row, &source.Data);
    for (const auto &descriptor : descriptors.Items())
    {
        if (descriptor.Get(L"path").Write() != path.Write())
        {
            continue;
        }
        uint64_t address = 0;
        const auto raw = AddressPathValue(row, path).AsString(L"");
        const auto space = descriptor.Get(L"space").AsString(L"");
        uint64_t process = 0;
        if (row.Get(L"historical").AsBool(false) || (!row.Get(L"target").IsNull() && !MatchesStamp(current, row.Get(L"target"))) ||
            !(raw.starts_with(L"0x") || raw.starts_with(L"0X")) || raw.size() > 18 || !ParseUnsigned(raw, 16, &address) ||
            (address == 0 && !descriptor.Get(L"allowZero").AsBool(false)))
        {
            return std::nullopt;
        }
        const auto offsetEntry = std::find_if(parameters.Fields().begin(), parameters.Fields().end(), [](const auto &entry)
        {
            return entry.first == L"byteOffset";
        });
        if (offsetEntry != parameters.Fields().end())
        {
            uint64_t offset = 0;
            if (!offsetEntry->second.IsString() || !ParseUnsigned(offsetEntry->second.AsString(L""), 10, &offset) ||
                row.Get(L"kind").AsString(L"") != L"MemoryBytes" || path.Items().size() != 1 ||
                path.Items()[0].AsString(L"") != L"address" || !row.Get(L"bytes").IsArray() ||
                row.Get(L"bytes").Items().size() != 16 || offset >= 16 || address > UINT64_MAX - offset)
            {
                return std::nullopt;
            }
            address += offset;
        }
        const bool userPointer = current.Context.EffectiveArchitecture == 0x14c ? address < 0x100000000ULL : address < 0x8000000000000000ULL;
        if (space == L"virtual" && userPointer && descriptor.Get(L"process").IsString() &&
            (!ParseUnsigned(descriptor.Get(L"process").AsString(L""), 16, &process) || process == 0 || process != current.Context.ImplicitProcess))
        {
            return std::nullopt;
        }
        return ResultAddress{address, space};
    }
    return std::nullopt;
}

inline std::optional<std::wstring> BoundResultCommand(const StoredResult &source, const knjson::Value &parameters,
                                                      const SessionStamp &current)
{
    const auto location = BoundResultAddress(source, parameters, current);
    if (!location)
    {
        return std::nullopt;
    }
    const auto action = parameters.Get(L"action").AsString(L"");
    if (action == L"navigate")
    {
        return std::wstring(L"navigate ") + (location->Space == L"physical" ? L"pa " : L"va ") + Hex(location->Address);
    }
    if (location->Space == L"virtual" && (action == L"disassemble" || action == L"source"))
    {
        return std::wstring(action == L"source" ? L"source " : L"u ") + Hex(location->Address);
    }
    return std::nullopt;
}
} // namespace kncore
