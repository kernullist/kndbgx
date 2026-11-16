#pragma once

#include "CallbackLayout.h"

namespace kncore
{
inline constexpr wchar_t KernelSymbolProfileId[] = L"NT-26100.8655-symbols-PDB-11D7FE79-age1";
inline constexpr wchar_t PiddbProfileId[] = L"NT-28000.2952-PiDDB-PDB-4660396C-age1";
inline constexpr wchar_t KernelSymbolProfile28000Id[] = L"NT-28000.2952-symbols-PDB-4660396C-age1";
inline constexpr wchar_t CiHashProfileId[] = L"CI-28000.2952-hash-cache-PDB-F660C9DA-age1";
inline constexpr wchar_t Win32kServiceProfileId[] = L"WIN32K-28000.2952-services-PDB-2414214E-age1";

inline bool Win32kServiceProfileIdentity(const ModuleIdentity &identity)
{
    return identity.Matched && identity.Machine == 0x8664 && identity.PdbAge == 1 && identity.Timestamp == 0xeaa9257b &&
           identity.ImageSize == 0xca000 &&
           _wcsicmp(identity.PdbGuid.c_str(), L"{2414214E-C1ED-F9F3-CE5F-1595CCD37B1B}") == 0 &&
           identity.Base != 0 && ValidRange(identity.Base, identity.ImageSize);
}

inline bool CiHashProfileIdentity(const ModuleIdentity &identity)
{
    return identity.Matched && identity.Machine == 0x8664 && identity.PdbAge == 1 && identity.Timestamp == 0x773f58da &&
           identity.ImageSize == 0x11c000 &&
           _wcsicmp(identity.PdbGuid.c_str(), L"{F660C9DA-4538-E0B7-62AA-C762F4FA8CDB}") == 0 &&
           identity.Base != 0 && ValidRange(identity.Base, identity.ImageSize);
}

inline const wchar_t *KernelProfileName(const ModuleIdentity &identity)
{
    return CiHashProfileIdentity(identity) ? CiHashProfileId :
           CallbackProfile28000Identity(identity) ? KernelSymbolProfile28000Id : KernelSymbolProfileId;
}

enum class KernelLayoutFamily
{
    ObjectTypes,
    ObjectNames,
    VadProtection,
    HostSilo,
    Nmi,
    Unloaded,
    Firmware,
    Piddb,
    CiHash,
    TimerDpc,
    ShadowService,
    Win32kService,
    AlpcPorts,
    FilteredService,
    Win32kDispatch
};

inline std::span<const CallbackCodeWindow> KernelProfileWindows(KernelLayoutFamily family, bool build28000 = false)
{
    if (family == KernelLayoutFamily::Win32kDispatch)
    {
        static const std::array<CallbackCodeWindow, 8> dispatch = {{
            {L"W32GetSessionStateForSession", 0x5e50, 0, L"83f901720f488b05443e0800ffc9488b04c8c3cc8bc1488d0d6b3e0800488b04c1c3"},
            {L"W32GetSessionState", 0x3330, 0x2a, L"83f80172158d48ff488b0537690800488b04c8"},
            {L"W32GetSessionState", 0x3330, 0x44, L"8bc8488d055b690800488b04c8"},
            {L"W32GetMaxSessionCount", 0x167b0, 0x27, L"8b1d03350700"},
            {L"W32GetMaxSessionCount", 0x167b0, 0x4e, L"8d43014883c4205bc3"},
            {L"W32SessionInitialize", 0x57b8, 0x4d8, L"488b050940080048833cf000"},
            {L"SysEntryGetW32pServiceTableFilter", 0x1c5a0, 0, L"488d05896d0800c3"},
            {L"SysEntryGetW32pServiceLimitFilter", 0x18850, 0, L"8b051ec80800c3"}}};
        return dispatch;
    }
    if (family == KernelLayoutFamily::Win32kService)
    {
        static const std::array<CallbackCodeWindow, 2> services = {{
            {L"SysEntryGetW32pServiceTable", 0x1c590, 0, L"488d05694a0800c3"},
            {L"SysEntryGetW32pServiceLimit", 0x1c580, 0, L"8b05be670800c3"}}};
        return services;
    }
    if (family == KernelLayoutFamily::CiHash)
    {
        // Cross-image calls can be relocated by the loader and are excluded.
        static const std::array<CallbackCodeWindow, 5> ciHash = {{
            {L"I_PEUpdateHashCache", 0x95888, 0x107, L"498b1e4885db742f488d4b1841b814000000498bd54c8b156dd8fbff"},
            {L"I_PEUpdateHashCache", 0x95888, 0x128, L"4883f8140f84e2000000488b1bebd34c8d35ca960500"},
            {L"I_PEUpdateHashCache", 0x95888, 0x14b, L"410fb717b9020100004883c25241b850454155"},
            {L"I_PEUpdateHashCache", 0x95888, 0x172,
             L"410f104500498bd70f114618418b4d10894e28488d4e08410f1004240f11462c418b44241089463c410fb7076683c0026689460a410fb707668901488d464848894610"},
            {L"I_PEUpdateHashCache", 0x95888, 0x1c1, L"897e40c7464400000000498b06488906498936ff4500"}}};
        return ciHash;
    }
    if (build28000 && family != KernelLayoutFamily::Piddb)
    {
        static const std::array<CallbackCodeWindow, 3> filtered = {{
            {L"KeAddSystemServiceTable", 0xb5fde0, 0x32, L"488d05e71646008d4aff48c1e1054c89140144894401104c894c0118"},
            {L"KiSystemServiceRepeat", 0x749a88, 0xe, L"f74378800000007413f743780000200074074c8d1d517a87004d8bd3"},
            {L"KiSystemServiceRepeat", 0x749a88, 0x35, L"4d8b143a4d631c82498bc349c1fb044d03d3"}}};
        static const std::array<CallbackCodeWindow, 12> alpc = {{
            {L"AlpcpInitializePort", 0xa324c0, 0x2c, L"488bd9"},
            {L"AlpcpInitializePort", 0xa324c0, 0xab, L"8b81a0010000"},
            {L"AlpcpInitializePort", 0xa324c0, 0xbc, L"8d0c1233c883e10633c8"},
            {L"AlpcpInitializePort", 0xa324c0, 0x12c, L"488b0555214e00488d0d46214e00483908"},
            {L"AlpcpInitializePort", 0xa324c0, 0x160, L"4889430848890b4889184883c8ff48891d13214e00"},
            {L"AlpcpDestroyPort", 0xa33314, 0x13, L"488bd9"},
            {L"AlpcpDestroyPort", 0xa33314, 0x4a, L"488b1348395a087558488b4308483918754f48891048894208"},
            {L"AlpcpCreateClientPort", 0x922240, 0x4a0, L"ba02000000488bcfe8d3fd1000"},
            {L"AlpcpAcceptConnectPort", 0xa31860, 0x40e, L"4533c0418d5003498bcfe843080000"},
            {L"AlpcpCreateConnectionPort", 0xa30660, 0xc6, L"be01000000"},
            {L"AlpcpCreateConnectionPort", 0xa30660, 0xf2, L"8bd6488b5c2460488bcbe85f1d0000"},
            {L"AlpcpCreatePort", 0xa31760, 0x1e, L"488b15a3f55800"}}};
        static const std::array<CallbackCodeWindow, 8> timer = {{
            {L"KeSetTimerEx", 0x34fdc0, 0x2f, L"488b15b212c700498bef48332d9815c7008bca480fcd4833ef448af048d3cd4833ea"},
            {L"KeSetTimerEx", 0x34fdc0, 0xe4, L"48896f30"},
            {L"KiTimerWaitTest", 0x350c90, 0x1c, L"488b6a30488bf1488b0dee03c7004d8be0448a3a4833e948d3c54180e77f4833ea"},
            {L"KiTimerWaitTest", 0x350c90, 0x4c, L"480fcd48332db206c700"},
            {L"KeSetTimerEx", 0x34fdc0, 0x27, L"488bf9"},
            {L"KeSetTimerEx", 0x34fdc0, 0x19, L"4d8bf9"},
            {L"KeInitializeDpc", 0x48af10, 0, L"33c0c701130100004889413848894110488951184c894120c3"},
            {L"KeInitializeThreadedDpc", 0x53fe10, 0, L"33c0c7011a0100004889413848894110488951184c894120c3"}}};
        static const std::array<CallbackCodeWindow, 1> types = {{
            {L"ObGetObjectType", 0xa75d90, 0, L"488d41d00fb649e848c1e8080fb6c04833c10fb60de7b154004833c1488d0dadbb5400488b04c1c3"}}};
        static const std::array<CallbackCodeWindow, 2> names = {{
            {L"ObQueryNameInfo", 0xa7c290, 0, L"488d41d00fb649eaf6c102750433c0c3"},
            {L"ObQueryNameInfo", 0xa7c290, 0x11, L"83e103488d15358349000fb60c11482bc1c3"}}};
        static const std::array<CallbackCodeWindow, 3> shadow = {{
            {L"KeAddSystemServiceTable", 0xb5fde0, 0xda, L"4c89151f154600448905281546004c890d29154600"},
            {L"KeAddSystemServiceTable", 0xb5fde0, 0xf4, L"4c8b1505154600488d05fe144600448b0d5f5139008b3d01154600"},
            {L"KeAddSystemServiceTable", 0xb5fde0, 0x119, L"4d8bda496313448d4301488bc24d8d5b0448c1f804418bd8428b0c10"}}};
        static const std::array<CallbackCodeWindow, 5> silo = {{
            {L"PsGetServerSiloGlobals", 0x2baea0, 0, L"4885c97509488d0594ead000"},
            {L"PsGetServerSiloGlobals", 0x2baea0, 0xe, L"488b81e0050000c3"},
            {L"EtwpFreeLoggerContext", 0x93cfa0, 0x294, L"488b85c802000033d2488bcb4ac704f801000000"},
            {L"EtwpGetLoggerTimeStamp", 0x2fcd60, 0x10, L"488b41184885c00f85bb000000"},
            {L"EtwpGetLoggerTimeStamp", 0x2fcd60, 0xd8, L"4883e801742f4883e8010f842a0300004883f8010f8519030000"}}};
        static const std::array<CallbackCodeWindow, 4> nmi = {{
            {L"KeRegisterNmiCallback", 0x5f4d30, 0xf, L"488bfa488bf1ba2000000041b84b4e4d498d4a20e8d8666300488bd8"},
            {L"KeRegisterNmiCallback", 0x5f4d30, 0x39,
             L"4889730848897b1048895b18e8e663c2ff488b15ef679500488d0de06795004889138ad048891ddc679500"},
            {L"KiProcessNMI", 0x5fb830, 0x92, L"488b1da7fc9400418aff4885db7420488b4308408ad7488b4b10"},
            {L"KiProcessNMI", 0x5fb830, 0xb1, L"488b1b400af84885db75e5"}}};
        static const std::array<CallbackCodeWindow, 4> unloaded = {{
            {L"MiRememberUnloadedDriver", 0x9a4200, 0x2a,
             L"488b0d2f5c55004885c90f84a50000008b05285c550083f8320f83ca000000488d1480488d3cd1"},
            {L"MiRememberUnloadedDriver", 0x9a4200, 0x7a, L"48894708"},
            {L"MiRememberUnloadedDriver", 0x9a4200, 0xb0,
             L"0fb706488d4c24406689074c03f50fb746026689470248896f104c897718e8bdd68aff48894720ff058b5b5500"},
            {L"MiRememberUnloadedDriver", 0x9a4200, 0xe8, L"bad0070000448bc8b94000000041b84d6d4454e8e0a59dff488905595b5500"}}};
        static const std::array<CallbackCodeWindow, 2> firmware = {{
            {L"ExpRegisterFirmwareTableInformationHandler", 0x839120, 0xe1, L"ba38000000b90001000041b841524654e81a223f00488bc84885c07459"},
            {L"ExpRegisterFirmwareTableInformationHandler", 0x839120, 0xfe,
             L"8b06488d79188901488b460848894108488b461048894110488d412848897f0848893f48894008488900488b4910e82f07b2ff488b05f0a66c00483928751348892f4889470848893848893ddaa66c00"}}};
        switch (family)
        {
        case KernelLayoutFamily::FilteredService:
            return filtered;
        case KernelLayoutFamily::AlpcPorts:
            return alpc;
        case KernelLayoutFamily::ObjectTypes:
            return types;
        case KernelLayoutFamily::ObjectNames:
            return names;
        case KernelLayoutFamily::TimerDpc:
            return timer;
        case KernelLayoutFamily::ShadowService:
            return shadow;
        case KernelLayoutFamily::HostSilo:
            return silo;
        case KernelLayoutFamily::Nmi:
            return nmi;
        case KernelLayoutFamily::Unloaded:
            return unloaded;
        case KernelLayoutFamily::Firmware:
            return firmware;
        default:
            return {};
        }
    }
    // Reviewed insertion, comparison and lookup code establishes the private payload.
    static const std::array<CallbackCodeWindow, 6> piddb = {{
        {L"RtlInsertElementGenericTableFullAvl", 0x41a3b0, 0xbf, L"4c8bc6488d4f20498bd7e802103300"},
        {L"PiCompareDDBCacheEntries", 0xb1f990, 0xf,
         L"450fb74810488bfa0fb75210498bd84d8b4018488bf149d1e9488b4f1848d1eac644242001e88700deff"},
        {L"PiCompareDDBCacheEntries", 0xb1f990, 0x46, L"8b43208b4f203bc1"},
        {L"PiUpdateDriverDBCache", 0xb2e66c, 0x104, L"4533c9488d55c0488d0d029d4a00458d4138e809b68eff"},
        {L"PiUpdateDriverDBCache", 0xb2e66c, 0x1bd, L"448965e4f30f7f45e8418b47088945e0"},
        {L"PiLookupInDDBCache", 0x918554, 0x12a, L"8b58244885ed7490"}}};
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
    case KernelLayoutFamily::Piddb:
        return piddb;
    case KernelLayoutFamily::CiHash:
    case KernelLayoutFamily::TimerDpc:
    case KernelLayoutFamily::ShadowService:
    case KernelLayoutFamily::Win32kService:
    case KernelLayoutFamily::AlpcPorts:
    case KernelLayoutFamily::FilteredService:
    case KernelLayoutFamily::Win32kDispatch:
        return {};
    }
    return {};
}

inline std::span<const std::pair<const wchar_t *, uint32_t>> KernelProfileSymbols(KernelLayoutFamily family, bool build28000 = false)
{
    if (family == KernelLayoutFamily::Win32kDispatch)
    {
        static const std::pair<const wchar_t *, uint32_t> dispatch[] = {
            {L"gSessionGlobalSlots", 0x89ca0}, {L"gLowSessionGlobalSlots", 0x89cd8}, {L"gAvailableSlots", 0x89ce0},
            {L"W32pServiceTableFilter", 0xa3330}, {L"W32pServiceLimitFilter", 0xa5074}, {L"W32pArgumentTableFilter", 0xa5078}};
        return dispatch;
    }
    if (family == KernelLayoutFamily::Win32kService)
    {
        static const std::pair<const wchar_t *, uint32_t> services[] = {
            {L"W32pServiceTable", 0xa1000}, {L"W32pServiceLimit", 0xa2d44}};
        return services;
    }
    static const std::pair<const wchar_t *, uint32_t> ciHash[] = {{L"g_KernelHashBucketList", 0xef090}};
    if (family == KernelLayoutFamily::CiHash)
    {
        return ciHash;
    }
    if (build28000 && family != KernelLayoutFamily::Piddb)
    {
        static const std::pair<const wchar_t *, uint32_t> filtered[] = {{L"KeServiceDescriptorTableFilter", 0xfc1500}};
        static const std::pair<const wchar_t *, uint32_t> alpc[] = {{L"AlpcpPortList", 0xf14740}, {L"AlpcPortObjectType", 0xfc0d28}};
        static const std::pair<const wchar_t *, uint32_t> types[] = {{L"ObTypeIndexTable", 0xfc1960}, {L"ObHeaderCookie", 0xfc0f90}};
        static const std::pair<const wchar_t *, uint32_t> names[] = {{L"ObpInfoMaskToOffset", 0xf145e0}};
        static const std::pair<const wchar_t *, uint32_t> timer[] = {{L"KiWaitNever", 0xfc10a8}, {L"KiWaitAlways", 0xfc1398}};
        static const std::pair<const wchar_t *, uint32_t> shadow[] = {{L"KeServiceDescriptorTableShadow", 0xfc13c0}};
        static const std::pair<const wchar_t *, uint32_t> silo[] = {{L"PspHostSiloGlobals", 0xfc9940}};
        static const std::pair<const wchar_t *, uint32_t> nmi[] = {{L"KiNmiCallbackListHead", 0xf4b570}};
        static const std::pair<const wchar_t *, uint32_t> unloaded[] = {{L"MmUnloadedDrivers", 0xef9e60}, {L"MmLastUnloadedDriver", 0xef9e68}};
        static const std::pair<const wchar_t *, uint32_t> firmware[] = {{L"ExpFirmwareTableProviderListHead", 0xf03940}};
        switch (family)
        {
        case KernelLayoutFamily::FilteredService:
            return filtered;
        case KernelLayoutFamily::AlpcPorts:
            return alpc;
        case KernelLayoutFamily::ObjectTypes:
            return types;
        case KernelLayoutFamily::ObjectNames:
            return names;
        case KernelLayoutFamily::TimerDpc:
            return timer;
        case KernelLayoutFamily::ShadowService:
            return shadow;
        case KernelLayoutFamily::HostSilo:
            return silo;
        case KernelLayoutFamily::Nmi:
            return nmi;
        case KernelLayoutFamily::Unloaded:
            return unloaded;
        case KernelLayoutFamily::Firmware:
            return firmware;
        default:
            return {};
        }
    }
    static const std::pair<const wchar_t *, uint32_t> types[] = {{L"ObTypeIndexTable", 0xfc6840}, {L"ObHeaderCookie", 0xfc5e8c}};
    static const std::pair<const wchar_t *, uint32_t> names[] = {{L"ObpInfoMaskToOffset", 0xf0f280}};
    static const std::pair<const wchar_t *, uint32_t> protection[] = {{L"MmProtectToValue", 0x14320}};
    static const std::pair<const wchar_t *, uint32_t> silo[] = {{L"PspHostSiloGlobals", 0xfce940}};
    static const std::pair<const wchar_t *, uint32_t> nmi[] = {{L"KiNmiCallbackListHead", 0xf468d0}};
    static const std::pair<const wchar_t *, uint32_t> unloaded[] = {{L"MmUnloadedDrivers", 0xef5250}, {L"MmLastUnloadedDriver", 0xef5248}};
    static const std::pair<const wchar_t *, uint32_t> firmware[] = {{L"ExpFirmwareTableProviderListHead", 0xefec90}};
    static const std::pair<const wchar_t *, uint32_t> piddb[] = {{L"PiDDBCacheTable", 0xfd8480}};
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
    case KernelLayoutFamily::Piddb:
        return piddb;
    case KernelLayoutFamily::CiHash:
        return ciHash;
    case KernelLayoutFamily::TimerDpc:
    case KernelLayoutFamily::ShadowService:
    case KernelLayoutFamily::Win32kService:
    case KernelLayoutFamily::AlpcPorts:
    case KernelLayoutFamily::FilteredService:
    case KernelLayoutFamily::Win32kDispatch:
        return {};
    }
    return {};
}

template <typename Resolve>
const wchar_t *VerifyKernelProfile(TargetReader &reader, const ModuleIdentity &identity, KernelLayoutFamily family, Resolve resolve)
{
    const bool build28000 = CallbackProfile28000Identity(identity);
    const bool matched = (family == KernelLayoutFamily::Win32kService || family == KernelLayoutFamily::Win32kDispatch) ? Win32kServiceProfileIdentity(identity) :
                         family == KernelLayoutFamily::CiHash ? CiHashProfileIdentity(identity) :
                         family == KernelLayoutFamily::Piddb ? build28000 : CallbackProfileIdentity(identity);
    if (!matched || KernelProfileWindows(family, build28000).empty())
    {
        return L"NoMatchingKernelProfile";
    }
    for (const auto &[name, rva] : KernelProfileSymbols(family, build28000))
    {
        if (rva >= identity.ImageSize || resolve(name) != identity.Base + rva)
        {
            return L"KernelProfileSymbolMismatch";
        }
    }
    for (const auto &window : KernelProfileWindows(family, build28000))
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
