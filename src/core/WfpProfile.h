#pragma once

#include "CallbackLayout.h"

namespace kncore
{
inline constexpr wchar_t WfpProfileId[] = L"WFP-28000.2952-NETIO-DE265633-FWPKCLNT-EACE892D";

inline bool WfpProfileIdentity(const ModuleIdentity &identity, std::wstring_view module)
{
    if (module == L"nt")
    {
        return CallbackProfile28000Identity(identity);
    }
    if (!identity.Matched || identity.Machine != 0x8664 || identity.PdbAge != 1 ||
        identity.Base == 0 || !ValidRange(identity.Base, identity.ImageSize))
    {
        return false;
    }
    if (module == L"NETIO")
    {
        return identity.Timestamp == 0x3bce0554 && identity.ImageSize == 0xbc000 &&
               _wcsicmp(identity.PdbGuid.c_str(), L"{DE265633-63BA-3A8B-E44C-0496BB5EAE44}") == 0;
    }
    if (module == L"fwpkclnt")
    {
        return identity.Timestamp == 0xfc07e3f8 && identity.ImageSize == 0x8b000 &&
               _wcsicmp(identity.PdbGuid.c_str(), L"{EACE892D-E775-C77A-413A-BDE50BC0A90B}") == 0;
    }
    return false;
}

inline std::span<const CallbackCodeWindow> WfpProfileWindows(std::wstring_view module)
{
    if (module == L"NETIO")
    {
        static const std::array<CallbackCodeWindow, 11> windows = {{
            {L"FeGetWfpGlobalPtr", 0x64740, 0x0, L"488b0551530300c3"},
            {L"FeEnumLayer", 0x7980, 0x4e, L"663bb980010000"},
            {L"FeGetRefCalloutEx", 0x70b0, 0x9c, L"488b15452909003bba980100007328488b82a0010000488d0c7f48c1e1054803c14889068b500440f6c50174060fb6480c0bd185d2750a"},
            {L"FeRegisterCalloutEntry", 0x3ec18, 0x9f, L"44893b8d6801896b044183ff030f85f20000004c897328"},
            {L"FeRegisterCalloutEntry", 0x3ec18, 0xb6, L"488b4424604c8bb42488000000488943188b4424708943308a44247888434e4c896b204d85f60f85cb000000837b50000fb78424900000006689434c"},
            {L"FeRegisterCalloutEntry", 0x3ec18, 0x1a4, L"4c897310"},
            {L"FeRegisterCalloutEntry", 0x3ec18, 0x1bc, L"4c897340"},
            {L"FeAddCalloutEntry", 0x3eb50, 0x5f, L"c644110c01"},
            {L"AddFilterToFilterHashtable", 0x59f0, 0x89, L"896f1c488bd7488977204c897728488b050a4009008b8890010000894f18488b0dfa3f09004c8b4710488b8988010000"},
            {L"KfdFindFilterById", 0x5c10, 0x42, L"488b4c2450488b4118488907"},
            {L"AddFilterToIndex", 0x4d46c, 0x68, L"6644896730"}}};
        return windows;
    }
    if (module == L"fwpkclnt")
    {
        static const std::array<CallbackCodeWindow, 3> windows = {{
            {L"FwppCalloutFindById", 0x67c6c, 0x0, L"3b0d661cfeff73138bc1488d0c80488b055f1cfeff488d04c8c3"},
            {L"FwppCalloutAlloc", 0x67c94, 0x45, L"0f10450083492001897910"},
            {L"FwppCalloutRegister", 0x679d4, 0xf8, L"894314834b2004"}}};
        return windows;
    }
    if (module == L"nt")
    {
        static const std::array<CallbackCodeWindow, 2> windows = {{
            {L"RtlLookupEntryHashTable", 0x428e60, 0x52, L"4d8b43204533d241817b088000000077588bca48c1e1044903c8"},
            {L"RtlLookupEntryHashTable", 0x428e60, 0xbb, L"8d8280000000ba010000000fbdc8d3e233d08d41f94d8b04c0eb8d"}}};
        return windows;
    }
    return {};
}

template <typename Resolve>
const wchar_t *VerifyWfpProfile(TargetReader &reader, const ModuleIdentity &identity, std::wstring_view module, Resolve resolve)
{
    if (!WfpProfileIdentity(identity, module))
    {
        return L"NoMatchingWfpProfile";
    }
    const auto root = module == L"NETIO" ? L"gWfpGlobal" : L"gFwppCallouts";
    if (module != L"nt" && resolve(root) != identity.Base + (module == L"NETIO" ? 0x99a98 : 0x498a0))
    {
        return L"WfpRootSymbolMismatch";
    }
    for (const auto &window : WfpProfileWindows(module))
    {
        if (resolve(window.Symbol) != identity.Base + window.SymbolRva)
        {
            return L"WfpCodeSymbolMismatch";
        }
        const auto size = std::wcslen(window.Bytes) / 2;
        const auto rva = uint64_t(window.SymbolRva) + window.Offset;
        if (size == 0 || size > 256 || rva >= identity.ImageSize || size > identity.ImageSize - rva)
        {
            return L"WfpCodeRangeInvalid";
        }
        const auto bytes = reader.Read(AddressSpace::Virtual, identity.Base + rva, size);
        if (!ExactBytes(bytes, size))
        {
            return L"WfpCodeUnavailable";
        }
        constexpr wchar_t digits[] = L"0123456789abcdef";
        for (size_t i = 0; i < size; ++i)
        {
            if (window.Bytes[2 * i] != digits[bytes.Bytes[i] >> 4] || window.Bytes[2 * i + 1] != digits[bytes.Bytes[i] & 15])
            {
                return L"WfpCodeMismatch";
            }
        }
    }
    return L"Verified";
}
} // namespace kncore
