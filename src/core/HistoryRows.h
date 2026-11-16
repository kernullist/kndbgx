#pragma once

#include "Result.h"

namespace kncore
{
// Keep collection metadata separate so every visible row is an actual record.
inline bool AppendHistoryCollection(Result &combined, const Result &child, size_t maxRows = 65536)
{
    if (!combined.Analysis.IsObject())
    {
        combined.Analysis = knjson::Value::MakeObject();
    }
    auto collections = combined.Analysis.Get(L"collections");
    if (!collections.IsArray())
    {
        collections = knjson::Value::MakeArray();
    }
    auto metadata = child.ToJson();
    metadata.Set(L"rows", knjson::Value::MakeArray());
    metadata.Set(L"recordCount", knjson::Value(std::to_wstring(child.Rows.Items().size())));
    collections.Push(metadata);
    combined.Analysis.Set(L"collections", collections);
    auto diagnostics = combined.Analysis.Get(L"diagnostics");
    if (!diagnostics.IsArray())
    {
        diagnostics = knjson::Value::MakeArray();
    }
    for (auto diagnostic : child.Analysis.Get(L"diagnostics").Items())
    {
        diagnostic.Set(L"sourceCommand", knjson::Value(child.CommandId));
        diagnostics.Push(diagnostic);
    }
    combined.Analysis.Set(L"diagnostics", diagnostics);
    for (const auto &finding : child.Findings.Items())
    {
        combined.Findings.Push(finding);
    }
    for (const auto &limitation : child.Limitations.Items())
    {
        combined.Limitations.Push(limitation);
    }
    combined.Collected.Visited += child.Collected.Visited;
    combined.Collected.Read += child.Collected.Read;
    combined.Collected.Decoded += child.Collected.Decoded;
    combined.Collected.Classified += child.Collected.Classified;
    combined.Collected.Unknown += child.Collected.Unknown;
    combined.Collected.Unreadable += child.Collected.Unreadable;
    bool truncated = false;
    for (auto row : child.Rows.Items())
    {
        if (combined.Rows.Items().size() >= maxRows)
        {
            truncated = true;
            break;
        }
        row.Set(L"sourceCommand", knjson::Value(child.CommandId));
        combined.Rows.Push(row);
    }
    const bool terminal = child.State == Status::Cancelled || child.State == Status::StaleContext || child.State == Status::InternalFault;
    if (terminal || truncated || child.State != Status::Success || !child.Collected.Complete)
    {
        combined.State = terminal ? child.State : Status::Partial;
        combined.Collected.Complete = false;
        combined.Collected.StopReason = truncated ? L"CompositeRowLimit" : L"ChildCollectionIncomplete";
    }
    return !terminal && !truncated;
}
} // namespace kncore
