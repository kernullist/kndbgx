#pragma once

#include "ResultStore.h"
#include "../util/Text.h"

namespace kncore
{
struct RecordPage
{
    knjson::Value Records = knjson::Value::MakeArray();
    size_t Offset = 0;
    size_t Next = 0;
    size_t Total = 0;
    size_t PayloadBytes = 2;
    size_t Referenced = 0;
    bool Valid = false;
    const wchar_t *Delivery() const
    {
        return !Valid ? L"Unavailable" : Total == 0 ? L"Empty" : Referenced != 0 ? L"Referenced" : Next == Total ? L"Complete" : L"Paged";
    }
};

// The byte budget covers the UTF-8 JSON array, including brackets and commas.
inline RecordPage PageRecords(const StoredResult &stored, const std::wstring &collection, size_t offset, size_t byteBudget = 24000,
                              size_t recordBudget = 128)
{
    RecordPage page;
    page.Offset = offset;
    page.Next = offset;
    if ((collection != L"rows" && collection != L"findings") || byteBudget < 512 || byteBudget > 2 * 1024 * 1024 || recordBudget == 0 ||
        recordBudget > 128)
    {
        return page;
    }
    const auto &records = collection == L"rows" ? stored.Data.Rows.Items() : stored.Data.Findings.Items();
    page.Total = records.size();
    if (offset > records.size())
    {
        return page;
    }
    while (page.Next < records.size() && page.Records.Items().size() < recordBudget)
    {
        auto record = records[page.Next];
        size_t bytes = knutil::WideToUtf8(record.Write()).size();
        const bool referenced = bytes > byteBudget - 2;
        if (referenced)
        {
            record = knjson::Value::MakeObject();
            record.Set(L"kind", knjson::Value(L"RecordReference"));
            record.Set(L"resultId", knjson::Value(stored.Id));
            record.Set(L"collection", knjson::Value(collection));
            record.Set(L"index", knjson::Value(std::to_wstring(page.Next)));
            record.Set(L"serializedUtf8Bytes", knjson::Value(std::to_wstring(bytes)));
            record.Set(L"reason", knjson::Value(L"Record exceeds page budget; export this result to inspect the complete record"));
            bytes = knutil::WideToUtf8(record.Write()).size();
            if (bytes > byteBudget - 2)
            {
                return page;
            }
        }
        const size_t separator = page.Records.Items().empty() ? 0 : 1;
        if (bytes + separator > byteBudget - page.PayloadBytes)
        {
            break;
        }
        page.PayloadBytes += bytes + separator;
        page.Records.Push(record);
        page.Referenced += referenced ? 1 : 0;
        ++page.Next;
    }
    page.Valid = page.Next == page.Total || page.Next > page.Offset;
    return page;
}
} // namespace kncore
