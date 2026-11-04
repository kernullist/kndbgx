#pragma once

#include "../util/Json.h"
#include <set>
#include <algorithm>

namespace kncore
{
inline bool ParseHashCatalog(const std::wstring &text, knjson::Value &metadata, std::set<std::wstring> &hashes)
{
    hashes.clear();
    if (!knjson::Parse(text, &metadata) || metadata.Get(L"schema").AsString(L"") != L"kndbgx.hash-catalog.v1" ||
        metadata.Get(L"source").AsString(L"").empty() || metadata.Get(L"version").AsString(L"").empty() ||
        !metadata.Get(L"sha256").IsArray() || metadata.Get(L"sha256").Items().size() > 100000)
    {
        return false;
    }
    for (const auto &item : metadata.Get(L"sha256").Items())
    {
        const auto digest = item.AsString(L"");
        if (digest.size() != 64 ||
            std::any_of(digest.begin(), digest.end(),
                        [](wchar_t c)
                        {
                            return !((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'));
                        }) ||
            !hashes.insert(digest).second)
        {
            hashes.clear();
            return false;
        }
    }
    return true;
}
} // namespace kncore
