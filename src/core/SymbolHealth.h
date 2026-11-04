#pragma once

#include "Result.h"
#include <algorithm>

namespace kncore
{
struct SymbolModuleKey
{
    uint64_t Base = 0;
    uint64_t Size = 0;
    uint64_t Timestamp = 0;
    uint64_t Checksum = 0;
    bool operator==(const SymbolModuleKey &) const = default;

    knjson::Value ToJson() const
    {
        auto result = knjson::Value::MakeObject();
        result.Set(L"base", knjson::Value(Hex(Base)));
        result.Set(L"size", knjson::Value(std::to_wstring(Size)));
        result.Set(L"timestamp", knjson::Value(std::to_wstring(Timestamp)));
        result.Set(L"checksum", knjson::Value(std::to_wstring(Checksum)));
        return result;
    }
};

inline std::optional<SymbolModuleKey> ParseSymbolModuleKey(const knjson::Value &value)
{
    SymbolModuleKey key;
    if (!value.IsObject() || value.Fields().size() != 4 || !value.Get(L"base").IsString() ||
        !value.Get(L"size").IsString() || !value.Get(L"timestamp").IsString() || !value.Get(L"checksum").IsString() ||
        !ParseUnsigned(value.Get(L"base").AsString(L""), 16, &key.Base) || key.Base == 0 ||
        !ParseUnsigned(value.Get(L"size").AsString(L""), 10, &key.Size) || key.Size == 0 || key.Size > UINT32_MAX ||
        !ParseUnsigned(value.Get(L"timestamp").AsString(L""), 10, &key.Timestamp) || key.Timestamp > UINT32_MAX ||
        !ParseUnsigned(value.Get(L"checksum").AsString(L""), 10, &key.Checksum) || key.Checksum > UINT32_MAX ||
        !ValidRange(key.Base, key.Size))
    {
        return {};
    }
    return key;
}

inline bool SymbolIdentifier(const std::wstring &value, size_t limit, bool module = false)
{
    return !value.empty() && value.size() <= limit && std::all_of(value.begin(), value.end(), [&](wchar_t letter)
    {
        return (letter >= L'a' && letter <= L'z') || (letter >= L'A' && letter <= L'Z') ||
               (letter >= L'0' && letter <= L'9') || letter == L'_' || (module && (letter == L'.' || letter == L'-'));
    });
}

inline const wchar_t *SymbolImageMatch(bool metadataValid, bool pdbLoaded, bool pdbIdentityPresent, bool unmatched)
{
    return !metadataValid ? L"Unknown" : unmatched ? L"Mismatched" : pdbLoaded && pdbIdentityPresent ? L"Matched" : L"Unknown";
}
} // namespace kncore
