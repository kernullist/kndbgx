#pragma once

#include "CallbackLayout.h"

namespace kncore
{
inline constexpr wchar_t KernelSymbolProfileId[] = L"NT-26100.8655-symbols-PDB-11D7FE79-age1";

enum class KernelLayoutFamily
{
    ObjectTypes,
    ObjectNames,
    VadProtection,
    HostSilo,
    Nmi,
    Unloaded,
    Firmware
};

inline std::span<const CallbackCodeWindow> KernelProfileWindows(KernelLayoutFamily family)
{
    // Exact image and target code corroboration; no instruction-pattern searches.
    static const std::array<CallbackCodeWindow, 1> objectTypes = {
        {{L"ObGetObjectType", 0x9b3340, 0, L"488d41d00fb649e848c1e8080fb6c04833c10fb60d332b61004833c1488d0ddd346100488b04c1c3"}}};
    static const std::array<CallbackCodeWindow, 2> objectNames = {
        {{L"ObQueryNameInfo", 0x9b90e0, 0, L"488d41d00fb649eaf6c102750433c0c3"},
         {L"ObQueryNameInfo", 0x9b90e0, 0x11, L"83e103488d15856155000fb60c11482bc1c3"}}};
    static const std::array<CallbackCodeWindow, 1> protection = {
        {{L"MmProtectToValue", 0x14320, 0,
          L"0100000002000000100000002000000004000000080000004000000080000000010000000202000010020000200200000402000008020000400200008002000"
          L"0010000000201000010010000200100000401000008010000400100008001000001000000020400001004000020040000040400000804000040040000800400"
          L"00"}}};
    static const std::array<CallbackCodeWindow, 4> silo = {
        {{L"PsGetServerSiloGlobals", 0x3d1f40, 0, L"4885c97509488d05f4c9bf00c3"},
         {L"PsGetServerSiloGlobals", 0x3d1f40, 0xe, L"488b81e0050000c3"},
         {L"EtwpFreeLoggerContext", 0xa4b660, 0x289, L"488b85c802000033d2488bcb4ac704f801000000"},
         {L"EtwpGetLoggerTimeStamp", 0x360f80, 4, L"488b41184885c0742d4883e8010f840d0100004883e8010f841e0100004883f8010f850d010000"}}};
    static const std::array<CallbackCodeWindow, 4> nmi = {
        {{L"KeRegisterNmiCallback", 0x5ad680, 0xf, L"488bfa488bf1ba2000000041b84b4e4d498d4a20e8485a5c00488bd833c0"},
         {L"KeRegisterNmiCallback", 0x5ad680, 0x39,
          L"4889730848897b1048895b18e80680c6ff488b15ff919900488d0df09199004889138ad048891dec919900"},
         {L"KiProcessNMI", 0x5b47c0, 0x92, L"488b1d77209900418aff4885db7420488b4308408ad7488b4b10"},
         {L"KiProcessNMI", 0x5b47c0, 0xb1, L"488b1b400af84885db75e5"}}};
    static const std::array<CallbackCodeWindow, 4> unloaded = {
        {{L"MiRememberUnloadedDriver", 0xab0cbc, 0x2f,
          L"4c8b0d5e4544004d85c97529bad0070000418d4e4041b84d6d4454e8e56c75ff4889053e4544004c8bc84885c00f84a0000000eb0b8b052245440083f832720"
          L"9418bc6890514454400488d1480498d1cd1"},
         {L"MiRememberUnloadedDriver", 0xab0cbc, 0x9b, L"48894308"},
         {L"MiRememberUnloadedDriver", 0xab0cbc, 0xc6, L"66890349b90800000080f7ffff0fb7470266894302488d042e4889431848897310"},
         {L"MiRememberUnloadedDriver", 0xab0cbc, 0xf5, L"482bca48894b20ff058a444400"}}};
    static const std::array<CallbackCodeWindow, 2> firmware = {
        {{L"ExpRegisterFirmwareTableInformationHandler", 0x7b5d40, 0xde, L"ba28000000b90001000041b841524654e8bdd23b00488bc84885c0744e"},
         {L"ExpRegisterFirmwareTableInformationHandler", 0x7b5d40, 0xfb,
          L"8b06488d79188901488b460848894108488b46104889411048897f0848893f488b4910e87df3b7ff488b052e8e7400483928751348892f48894708488938488"
          L"93d188e7400"}}};
    switch (family)
    {
    case KernelLayoutFamily::ObjectTypes:
        return objectTypes;
    case KernelLayoutFamily::ObjectNames:
        return objectNames;
    case KernelLayoutFamily::VadProtection:
        return protection;
    case KernelLayoutFamily::HostSilo:
        return silo;
    case KernelLayoutFamily::Nmi:
        return nmi;
    case KernelLayoutFamily::Unloaded:
        return unloaded;
    case KernelLayoutFamily::Firmware:
        return firmware;
    }
    return {};
}

inline std::span<const std::pair<const wchar_t *, uint32_t>> KernelProfileSymbols(KernelLayoutFamily family)
{
    static const std::pair<const wchar_t *, uint32_t> types[] = {{L"ObTypeIndexTable", 0xfc6840}, {L"ObHeaderCookie", 0xfc5e8c}};
    static const std::pair<const wchar_t *, uint32_t> names[] = {{L"ObpInfoMaskToOffset", 0xf0f280}};
    static const std::pair<const wchar_t *, uint32_t> protection[] = {{L"MmProtectToValue", 0x14320}};
    static const std::pair<const wchar_t *, uint32_t> silo[] = {{L"PspHostSiloGlobals", 0xfce940}};
    static const std::pair<const wchar_t *, uint32_t> nmi[] = {{L"KiNmiCallbackListHead", 0xf468d0}};
    static const std::pair<const wchar_t *, uint32_t> unloaded[] = {{L"MmUnloadedDrivers", 0xef5250}, {L"MmLastUnloadedDriver", 0xef5248}};
    static const std::pair<const wchar_t *, uint32_t> firmware[] = {{L"ExpFirmwareTableProviderListHead", 0xefec90}};
    switch (family)
    {
    case KernelLayoutFamily::ObjectTypes:
        return types;
    case KernelLayoutFamily::ObjectNames:
        return names;
    case KernelLayoutFamily::VadProtection:
        return protection;
    case KernelLayoutFamily::HostSilo:
        return silo;
    case KernelLayoutFamily::Nmi:
        return nmi;
    case KernelLayoutFamily::Unloaded:
        return unloaded;
    case KernelLayoutFamily::Firmware:
        return firmware;
    }
    return {};
}

template <typename Resolve>
const wchar_t *VerifyKernelProfile(TargetReader &reader, const ModuleIdentity &identity, KernelLayoutFamily family, Resolve resolve)
{
    if (!CallbackProfileIdentity(identity) || KernelProfileWindows(family).empty())
    {
        return L"NoMatchingKernelProfile";
    }
    for (const auto &[name, rva] : KernelProfileSymbols(family))
    {
        if (rva >= identity.ImageSize || resolve(name) != identity.Base + rva)
        {
            return L"KernelProfileSymbolMismatch";
        }
    }
    for (const auto &window : KernelProfileWindows(family))
    {
        const size_t digits = std::wcslen(window.Bytes);
        const size_t count = digits / 2;
        const uint64_t rva = uint64_t(window.SymbolRva) + window.Offset;
        if (digits % 2 != 0 || count == 0 || count > 256 || rva >= identity.ImageSize || count > identity.ImageSize - rva ||
            resolve(window.Symbol) != identity.Base + window.SymbolRva)
        {
            return L"KernelProfileWindowInvalid";
        }
        const auto read = reader.Read(AddressSpace::Virtual, identity.Base + rva, count);
        if (!ExactBytes(read, count))
        {
            return L"KernelProfileBytesUnavailable";
        }
        constexpr wchar_t hex[] = L"0123456789abcdef";
        for (size_t i = 0; i < count; ++i)
        {
            if (window.Bytes[i * 2] != hex[read.Bytes[i] >> 4] || window.Bytes[i * 2 + 1] != hex[read.Bytes[i] & 15])
            {
                return L"KernelProfileBytesMismatch";
            }
        }
    }
    return L"Verified";
}

inline bool ProfilePointerStorageAllowed(const std::optional<FieldInfo> &shape, bool publicOnly, uint32_t pointerBytes)
{
    return shape ? shape->Kind == FieldKind::Pointer && shape->Offset == 0 && shape->Size == pointerBytes &&
                       shape->ValidFor(pointerBytes) && !shape->BitOffset && !shape->BitWidth
                 : publicOnly;
}

inline FieldInfo KernelProfileField(uint32_t offset, uint32_t size)
{
    FieldInfo field;
    field.Offset = offset;
    field.Size = size;
    field.Source = KernelSymbolProfileId;
    return field;
}

inline bool ApplyKernelProfileField(std::optional<FieldInfo> &field, uint32_t offset, uint32_t size)
{
    const bool compatible = !field || (field->Offset == offset && field->Size == size && !field->BitOffset && !field->BitWidth);
    if (compatible && !field)
    {
        field = KernelProfileField(offset, size);
    }
    return compatible;
}
} // namespace kncore
