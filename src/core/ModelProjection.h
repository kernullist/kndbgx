#pragma once

#include "ResultPage.h"

namespace kncore
{
// Arrays become Items.rN properties in the host adapter. Values retain their JSON types.
inline knjson::Value ProjectResult(const StoredResult &stored, size_t offset, const SessionStamp &current, size_t findingOffset = 0)
{
    auto metadata = stored.Data;
    metadata.Rows = knjson::Value::MakeArray();
    metadata.Findings = knjson::Value::MakeArray();
    auto metadataValue = metadata.ToJson();
    size_t metadataBytes = 0;
    const bool inlineMetadata = metadataValue.WriteStream(
        [&](std::wstring_view fragment)
        {
            const size_t bytes = knutil::WideToUtf8(std::wstring(fragment)).size();
            if (bytes > 65536 - metadataBytes)
            {
                return false;
            }
            metadataBytes += bytes;
            return true;
        });
    if (!inlineMetadata)
    {
        metadataValue = knjson::Value::MakeObject();
        metadataValue.Set(L"kind", knjson::Value(L"MetadataReference"));
        metadataValue.Set(L"resultId", knjson::Value(stored.Id));
        metadataValue.Set(L"status", knjson::Value(StatusName(stored.Data.State)));
        metadataValue.Set(L"reason", knjson::Value(L"Metadata exceeds page budget; export this result to inspect the complete metadata"));
    }
    auto result = knjson::Value::MakeObject();
    result.Set(L"Schema", knjson::Value(L"kndbgx.model.v1"));
    result.Set(L"ResultId", knjson::Value(stored.Id));
    result.Set(L"HistoricalAtPublication", knjson::Value(stored.Data.Stamp != current));
    result.Set(L"View", knjson::Value(L"Stored result; compare Metadata.target with the current debugger session before reuse"));
    result.Set(L"Metadata", metadataValue);
    result.Set(L"MetadataDelivery", knjson::Value(inlineMetadata ? L"Complete" : L"Referenced"));
    result.Set(L"RowCount", knjson::Value(std::to_wstring(stored.Data.Rows.Items().size())));
    result.Set(L"Offset", knjson::Value(std::to_wstring(offset)));
    const auto rows = PageRecords(stored, L"rows", offset, 2 * 1024 * 1024);
    const auto findings = PageRecords(stored, L"findings", findingOffset, 2 * 1024 * 1024);
    result.Set(L"Rows", rows.Records);
    result.Set(L"Next", knjson::Value(std::to_wstring(rows.Next)));
    result.Set(L"PageComplete", knjson::Value(rows.Valid && rows.Next == rows.Total));
    result.Set(L"RowsDelivery", knjson::Value(rows.Delivery()));
    result.Set(L"FindingCount", knjson::Value(std::to_wstring(findings.Total)));
    result.Set(L"FindingOffset", knjson::Value(std::to_wstring(findingOffset)));
    result.Set(L"Findings", findings.Records);
    result.Set(L"NextFinding", knjson::Value(std::to_wstring(findings.Next)));
    result.Set(L"FindingPageComplete", knjson::Value(findings.Valid && findings.Next == findings.Total));
    result.Set(L"FindingsDelivery", knjson::Value(findings.Delivery()));
    result.Set(L"PageByteUnit", knjson::Value(L"UTF-8 JSON array bytes"));
    result.Set(L"Paging", knjson::Value(L"result-read <id> [row-offset] [finding-offset]; export to inspect referenced records"));
    return result;
}
} // namespace kncore
