#pragma once

#include "Result.h"
#include "ResultPresentation.h"
#include "Input.h"
#include <map>
#include <set>
#include <optional>
#include <algorithm>

namespace kncore
{
struct Snapshot
{
    knjson::Value Metadata = knjson::Value::MakeObject();
    std::map<std::wstring, knjson::Value> Collections;
};

inline bool SnapshotLeaf(const std::wstring &name)
{
    return !name.empty() && name.size() <= 64 && name.find(L"..") == std::wstring::npos &&
           std::all_of(name.begin(), name.end(),
                       [](wchar_t c)
                       {
                           return (c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9') || c == L'-' || c == L'.';
                       }) &&
           name.front() != L'.' && name.back() != L'.';
}

inline bool ValidCollection(const knjson::Value &value)
{
    const auto state = value.Get(L"status").AsString(L"");
    const std::set<std::wstring> states = {L"Success",   L"Partial",      L"Unavailable", L"Unsupported", L"InvalidInput",
                                           L"Cancelled", L"StaleContext", L"EngineError", L"IOError",     L"InternalFault"};
    return value.IsObject() && value.Get(L"schema").AsString(L"") == L"kndbgx.result.v2" && states.contains(state) &&
           value.Get(L"rows").IsArray() && value.Get(L"rows").Items().size() <= 100000 &&
           std::all_of(value.Get(L"rows").Items().begin(), value.Get(L"rows").Items().end(),
                       [](const auto &row)
                       {
                           return row.IsObject();
                       }) &&
           value.Get(L"coverage").Get(L"complete").IsBool();
}

inline bool ValidSnapshot(const Snapshot &snapshot)
{
    if (snapshot.Metadata.Get(L"schema").AsString(L"") != L"kndbgx.snapshot.v2" ||
        snapshot.Metadata.Get(L"target").Get(L"sessionId").AsString(L"").empty() ||
        snapshot.Metadata.Get(L"target").Get(L"targetGeneration").AsString(L"").empty() || snapshot.Collections.empty() ||
        snapshot.Collections.size() > 32)
    {
        return false;
    }
    size_t totalRows = 0;
    for (const auto &[name, collection] : snapshot.Collections)
    {
        if (!SnapshotLeaf(name) || !ValidCollection(collection))
        {
            return false;
        }
        const auto count = collection.Get(L"rows").Items().size();
        if (count > 100000 - totalRows)
        {
            return false;
        }
        totalRows += count;
    }
    return true;
}

inline std::wstring SnapshotRecordKind(const knjson::Value &row)
{
    const auto kind = row.Get(L"kind").AsString(L"");
    const auto family = row.Get(L"family").AsString(L"");
    // Semantic row labels do not change the identity of existing routine observations.
    return (kind == L"RegistryHive" && family == L"Hive.GetCellRoutine") ||
           (kind == L"KernelTimer" && family == L"Timer.Dpc") ||
           (kind == L"QueuedDpc" && family == L"Dpc.DeferredRoutine") ? L"RoutineObservation" : kind;
}

inline std::wstring SnapshotKey(const knjson::Value &row, bool crossSession)
{
    const auto text = [&](const wchar_t *field)
    {
        return row.Get(field).AsString(L"");
    };
    const auto kind = SnapshotRecordKind(row);
    if (!row.IsObject() || kind.empty())
    {
        return {};
    }
    const auto key = [&](std::initializer_list<std::wstring> parts)
    {
        auto tuple = knjson::Value::MakeArray();
        tuple.Push(knjson::Value(kind));
        for (const auto &part : parts)
        {
            tuple.Push(knjson::Value(part));
        }
        return tuple.Write();
    };
    if (kind == L"Win32kProcessPolicy" || kind == L"Win32kServicePolicy")
    {
        if (crossSession || text(L"eprocess").empty() || text(L"pid").empty() || text(L"createTime").empty() ||
            (kind == L"Win32kServicePolicy" && text(L"index").empty()))
        {
            return {};
        }
        return key({text(L"pid"), text(L"createTime"), text(L"eprocess"), text(L"sessionId"), text(L"sessionState"), text(L"index")});
    }
    if (kind == L"Process")
    {
        return crossSession || text(L"pid").empty() || text(L"createTime").empty() || text(L"eprocess").empty()
                   ? L""
                   : key({text(L"pid"), text(L"createTime"), text(L"eprocess")});
    }
    if (kind == L"Module")
    {
        return text(L"moduleIdentity").empty() ? L"" : key({text(L"moduleIdentity")});
    }
    if (kind == L"UnloadedDriver")
    {
        uint64_t start = 0;
        uint64_t end = 0;
        uint64_t time = 0;
        auto name = text(L"name");
        if (crossSession || !row.Get(L"identityComplete").AsBool(false) || name.empty() ||
            !ParseUnsigned(text(L"StartAddress"), 16, &start) || !ParseUnsigned(text(L"EndAddress"), 16, &end) ||
            !ParseUnsigned(text(L"CurrentTime"), 16, &time) || start == 0 || start >= end || time == 0)
        {
            return {};
        }
        for (auto &character : name)
        {
            if (character >= L'A' && character <= L'Z')
            {
                character += L'a' - L'A';
            }
        }
        return key({name, Hex(start), Hex(end), Hex(time)});
    }
    if (!crossSession && !text(L"objectKey").empty())
    {
        return key({text(L"objectKey")});
    }
    if (kind == L"IdtGate" && !text(L"cpu").empty() && !text(L"vector").empty())
    {
        return key({text(L"cpu"), text(L"vector")});
    }
    if (kind == L"RoutineObservation" &&
        (text(L"family") == L"ShadowSSDT" || text(L"family") == L"FilteredShadowSSDT") && !text(L"sessionId").empty())
    {
        // Windows session IDs and their bindings do not identify the same session on another target.
        return crossSession || text(L"sessionState").empty() || text(L"index").empty()
            ? L"" : key({text(L"family"), text(L"sessionId"), text(L"sessionState"), text(L"index")});
    }
    if (!text(L"family").empty() && !text(L"index").empty())
    {
        return key({text(L"family"), text(L"index")});
    }
    if (!text(L"register").empty() && !text(L"cpu").empty())
    {
        return key({text(L"cpu"), text(L"register")});
    }
    if (!crossSession && !text(L"family").empty() && !text(L"slot").empty())
    {
        return key({text(L"family"), text(L"slot")});
    }
    return {};
}

inline knjson::Value ComparableRow(const knjson::Value &row, bool crossSession = false)
{
    auto normalized = knjson::Value::MakeObject();
    const bool module = row.Get(L"kind").AsString(L"") == L"Module";
    const bool routine = row.Get(L"routine").IsString() && row.Get(L"routine").AsString(L"") != Hex(0);
    const bool relocatedRoutine = crossSession && routine && !row.Get(L"moduleIdentity").AsString(L"").empty() &&
                                  !row.Get(L"rva").AsString(L"").empty() &&
                                  row.Get(L"moduleIdentityKind").AsString(L"") == L"MatchedPdbImage";
    for (const auto &[name, value] : row.Fields())
    {
        if (name == L"kind")
        {
            normalized.Set(name, knjson::Value(SnapshotRecordKind(row)));
            continue;
        }
        if (DisplaySymbolField(name))
        {
            // Host symbol availability is presentation, not target memory state.
            continue;
        }
        if (row.Get(L"kind").AsString(L"") == L"UnloadedDriver" &&
            (name == L"index" || name == L"record" || name == L"ringNextIndex"))
        {
            // Ring position is storage metadata, not unload event identity.
            continue;
        }
        if (name == L"majorName" &&
            (row.Get(L"family").AsString(L"") == L"Minifilter.PreOperation" ||
             row.Get(L"family").AsString(L"") == L"Minifilter.PostOperation"))
        {
            // The decoded label does not change the observed operation code.
            continue;
        }
        if (row.Get(L"kind").AsString(L"") == L"ObjectCallbackRegistration")
        {
            if (name == L"pre" || name == L"post")
            {
                auto nested = ComparableRow(value, crossSession);
                if (crossSession)
                {
                    nested.Set(L"slot", knjson::Value());
                }
                normalized.Set(name, nested);
                continue;
            }
            if (crossSession && (name == L"preRoutine" || name == L"postRoutine" || name == L"slot" || name == L"listEntry"))
            {
                normalized.Set(name, knjson::Value());
                continue;
            }
        }
        if ((module && (name == L"base" || name == L"path")) || (relocatedRoutine && (name == L"routine" || name == L"slot")))
        {
            continue;
        }
        if (crossSession && routine && (name == L"routine" || name == L"slot"))
        {
            // A path, timestamp and size do not establish the same image across targets.
            normalized.Set(name, knjson::Value());
            continue;
        }
        normalized.Set(name, value);
    }
    return normalized;
}

inline bool SameKnownValue(const knjson::Value &a, const knjson::Value &b, bool &unknown, size_t depth = 0)
{
    if (a.IsNull() || b.IsNull() || depth > 32)
    {
        unknown = true;
        return true;
    }
    if (a.GetType() != b.GetType())
    {
        return false;
    }
    bool same = true;
    if (a.IsObject())
    {
        std::set<std::wstring> fields;
        for (const auto &field : a.Fields())
        {
            fields.insert(field.first);
        }
        for (const auto &field : b.Fields())
        {
            fields.insert(field.first);
        }
        for (const auto &key : fields)
        {
            same = SameKnownValue(a.Get(key), b.Get(key), unknown, depth + 1) && same;
        }
    }
    else if (a.IsArray())
    {
        same = a.Items().size() == b.Items().size();
        for (size_t i = 0; i < std::min(a.Items().size(), b.Items().size()); ++i)
        {
            same = SameKnownValue(a.Items()[i], b.Items()[i], unknown, depth + 1) && same;
        }
    }
    else
    {
        same = a.Write() == b.Write();
    }
    return same;
}

inline Result DiffSnapshots(const Snapshot &before, const Snapshot &after, bool crossSession = false)
{
    Result result;
    result.CommandId = L"!diff";
    result.Source = L"SnapshotArtifacts";
    result.Consistency = L"immutable-import";
    if (!ValidSnapshot(before) || !ValidSnapshot(after))
    {
        result.State = Status::InvalidInput;
        result.Error.Message = L"Invalid snapshot v2 schema";
        return result;
    }
    if ((before.Metadata.Get(L"targetStable").IsBool() && !before.Metadata.Get(L"targetStable").AsBool(false)) ||
        (after.Metadata.Get(L"targetStable").IsBool() && !after.Metadata.Get(L"targetStable").AsBool(false)))
    {
        result.State = Status::StaleContext;
        result.Error.Message = L"A snapshot crossed target generations during collection";
        return result;
    }
    const auto &aTarget = before.Metadata.Get(L"target");
    const auto &bTarget = after.Metadata.Get(L"target");
    const bool sameTarget = aTarget.Get(L"sessionId").AsString(L"") == bTarget.Get(L"sessionId").AsString(L"") &&
                            aTarget.Get(L"targetGeneration").AsString(L"") == bTarget.Get(L"targetGeneration").AsString(L"");
    if (!sameTarget && !crossSession)
    {
        result.State = Status::Unavailable;
        result.Error.Message =
            L"Different target/session identities; explicit /cross-session is required for identity-normalized comparison";
        return result;
    }
    std::set<std::wstring> collectors;
    for (const auto &pair : before.Collections)
    {
        collectors.insert(pair.first);
    }
    for (const auto &pair : after.Collections)
    {
        collectors.insert(pair.first);
    }
    bool inputsComplete = true;
    bool inputIdentitiesKnown = true;
    auto inputCollections = knjson::Value::MakeArray();
    for (const auto &collector : collectors)
    {
        const auto a = before.Collections.find(collector);
        const auto b = after.Collections.find(collector);
        const knjson::Value empty;
        const auto &old = a != before.Collections.end() ? a->second : empty;
        const auto &now = b != after.Collections.end() ? b->second : empty;
        const bool complete = old.Get(L"status").AsString(L"") == L"Success" && now.Get(L"status").AsString(L"") == L"Success" &&
                              old.Get(L"coverage").Get(L"complete").AsBool(false) && now.Get(L"coverage").Get(L"complete").AsBool(false) &&
                              old.Get(L"coverage").Get(L"unknownEntries").AsString(L"") == L"0" &&
                              now.Get(L"coverage").Get(L"unknownEntries").AsString(L"") == L"0" &&
                              old.Get(L"coverage").Get(L"unreadableEntries").AsString(L"") == L"0" &&
                              now.Get(L"coverage").Get(L"unreadableEntries").AsString(L"") == L"0";
        inputsComplete = inputsComplete && complete;
        auto input = knjson::Value::MakeObject();
        input.Set(L"collector", knjson::Value(collector));
        const auto metadata = [](const knjson::Value &collection)
        {
            if (collection.IsNull())
            {
                return collection;
            }
            auto value = collection;
            value.Set(L"rowCount", knjson::Value(std::to_wstring(collection.Get(L"rows").Items().size())));
            value.Set(L"findingCount", knjson::Value(std::to_wstring(collection.Get(L"findings").Items().size())));
            value.Set(L"rows", knjson::Value::MakeArray());
            value.Set(L"findings", knjson::Value::MakeArray());
            return value;
        };
        input.Set(L"before", metadata(old));
        input.Set(L"after", metadata(now));
        input.Set(L"coverageComplete", knjson::Value(complete));
        std::map<std::wstring, std::pair<std::vector<knjson::Value>, std::vector<knjson::Value>>> objects;
        size_t unidentified = 0;
        bool entryOnlyShadow = false;
        bool sessionShadow = false;
        for (unsigned side = 0; side < 2; ++side)
        {
            const auto &rows = side == 0 ? old.Get(L"rows") : now.Get(L"rows");
            for (const auto &row : rows.Items())
            {
                if (row.Get(L"kind").AsString(L"") == L"RoutineObservation" && row.Get(L"family").AsString(L"") == L"ShadowSSDT")
                {
                    entryOnlyShadow |= row.Get(L"sessionId").AsString(L"").empty();
                    sessionShadow |= !row.Get(L"sessionId").AsString(L"").empty();
                }
                auto key = SnapshotKey(row, crossSession);
                if (key.empty())
                {
                    key = L"UnknownIdentity:" + std::to_wstring(++unidentified);
                }
                auto &entry = objects[key];
                (side == 0 ? entry.first : entry.second).push_back(row);
            }
        }
        // Entry-thunk snapshots cannot establish additions/removals of session implementation bindings.
        const bool identitiesKnown = unidentified == 0 && !(entryOnlyShadow && sessionShadow);
        inputIdentitiesKnown = inputIdentitiesKnown && identitiesKnown;
        input.Set(L"identitiesKnown", knjson::Value(identitiesKnown));
        inputCollections.Push(input);
        if (objects.empty() && !complete)
        {
            objects[L"UnknownCoverage"] = {};
        }
        for (const auto &[key, versions] : objects)
        {
            ++result.Collected.Visited;
            const auto &first = versions.first;
            const auto &second = versions.second;
            std::wstring state;
            bool unknownFields = false;
            bool knownChanged = false;
            if (key.starts_with(L"Unknown") || first.size() > 1 || second.size() > 1)
            {
                state = L"Unknown";
            }
            else if (first.empty() || second.empty())
            {
                // An unidentified row on either side could be this missing object.
                state = !complete || !identitiesKnown ? L"Unknown" : first.empty() ? L"Added" : L"Removed";
            }
            else
            {
                const bool equal =
                    SameKnownValue(ComparableRow(first[0], crossSession), ComparableRow(second[0], crossSession), unknownFields);
                knownChanged = !equal;
                state = !equal ? L"Changed" : unknownFields ? L"Unknown" : L"Unchanged";
            }
            auto row = knjson::Value::MakeObject();
            knownChanged = knownChanged || state == L"Added" || state == L"Removed";
            row.Set(L"kind", knjson::Value(L"SnapshotDifference"));
            row.Set(L"collector", knjson::Value(collector));
            row.Set(L"key", knjson::Value(key));
            row.Set(L"state", knjson::Value(state));
            row.Set(L"knownChanged", knjson::Value(knownChanged));
            row.Set(L"unknownFields", knjson::Value(unknownFields));
            row.Set(L"beforeCount", knjson::Value(std::to_wstring(first.size())));
            row.Set(L"afterCount", knjson::Value(std::to_wstring(second.size())));
            row.Set(L"before", first.size() == 1 ? first[0] : knjson::Value());
            row.Set(L"after", second.size() == 1 ? second[0] : knjson::Value());
            result.Rows.Push(row);
            result.Collected.Unknown += state == L"Unknown" || unknownFields ? 1 : 0;
        }
    }
    result.Analysis = knjson::Value::MakeObject();
    result.Analysis.Set(L"comparisonComplete", knjson::Value(true));
    result.Analysis.Set(L"inputCoverageComplete", knjson::Value(inputsComplete));
    result.Analysis.Set(L"inputIdentitiesKnown", knjson::Value(inputIdentitiesKnown));
    result.Analysis.Set(L"inputCollections", inputCollections);
    result.Collected.Complete = inputsComplete && inputIdentitiesKnown && result.Collected.Unknown == 0;
    result.Collected.Expected = result.Collected.Visited;
    result.Collected.Decoded = result.Collected.Visited;
    result.Collected.Classified = result.Collected.Visited - result.Collected.Unknown;
    result.State = result.Collected.Complete ? Status::Success : Status::Partial;
    result.Collected.StopReason = !inputsComplete                 ? L"InputCoverageIncomplete"
                                  : !inputIdentitiesKnown         ? L"InputIdentityUnknown"
                                  : result.Collected.Unknown != 0 ? L"UnknownComparisonFields"
                                                                  : L"EndOfSnapshotComparison";
    return result;
}
} // namespace kncore
