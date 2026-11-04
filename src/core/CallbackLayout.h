#pragma once

#include "CollectorRead.h"
#include <array>
#include <cwchar>
#include <string_view>

namespace kncore
{
inline constexpr wchar_t CallbackProfileId[] = L"NT-26100.8655-callbacks-PDB-11D7FE79-age1";
inline constexpr wchar_t CallbackProfile28000Id[] = L"NT-28000.2952-callbacks-PDB-4660396C-age1";

enum class CallbackFamily
{
    Process,
    Thread,
    Image,
    Object,
    Registry
};

struct CallbackCodeWindow
{
    const wchar_t *Symbol;
    uint32_t SymbolRva;
    uint32_t Offset;
    const wchar_t *Bytes;
};

inline bool CallbackProfile28000Identity(const ModuleIdentity &identity)
{
    return identity.Matched && identity.Machine == 0x8664 && identity.PdbAge == 1 && identity.Timestamp == 0xe1a9f520 &&
           identity.ImageSize == 0x1459000 &&
           _wcsicmp(identity.PdbGuid.c_str(), L"{4660396C-2030-4C03-9AF4-5FC6B15ADF98}") == 0 &&
           identity.Base != 0 && ValidRange(identity.Base, identity.ImageSize);
}

inline const wchar_t *CallbackProfileName(const ModuleIdentity &identity)
{
    return CallbackProfile28000Identity(identity) ? CallbackProfile28000Id : CallbackProfileId;
}

inline bool CallbackProfileIdentity(const ModuleIdentity &identity)
{
    return CallbackProfile28000Identity(identity) ||
           (identity.Matched && identity.Machine == 0x8664 && identity.PdbAge == 1 && identity.Timestamp == 0x90b083da &&
           identity.ImageSize == 0x1450000 &&
           _wcsicmp(identity.PdbGuid.c_str(), L"{11D7FE79-CC24-5612-0555-03EE86BB0E3E}") == 0 &&
           identity.Base != 0 && ValidRange(identity.Base, identity.ImageSize));
}

inline std::span<const CallbackCodeWindow> CallbackProfileWindows(CallbackFamily family, bool build28000 = false)
{
    if (build28000)
    {
        // Reviewed against the stopped 28000.2952 target and its matched public PDB.
        static const std::array<CallbackCodeWindow, 3> process28000 = {{
            {L"ExAllocateCallBack", 0xb47a04, 0x10, L"ba18000000"},
            {L"ExAllocateCallBack", 0xb47a04, 0x28, L"488978084889581048c70000000000"},
            {L"PspSetCreateProcessNotifyRoutine", 0xb41da0, 0x38,
             L"4c8d2da1853c0083c8ff660185e4010000904533ff4183ff40733a4e8d24fd000000004d03e5498bcc"}}};
        static const std::array<CallbackCodeWindow, 3> thread28000 = {{
            process28000[0], process28000[1],
            {L"PspSetCreateThreadNotifyRoutine", 0x806978, 0x22, L"83fb40735e488d0dda3b70004533c0488d0cd9488bd7"}}};
        static const std::array<CallbackCodeWindow, 3> image28000 = {{
            process28000[0], process28000[1],
            {L"PsSetLoadImageNotifyRoutineEx", 0xb478d0, 0x31, L"83ff4073658bc7488d0d71283c004533c0488bd6488d0cc1"}}};
        static const std::array<CallbackCodeWindow, 2> object28000 = {{
            {L"ObRegisterCallbacks", 0xa808c0, 0x15a,
             L"458bc7488d572049c1e0064903d0498954382848891249895c38588b442e08418944383049897c3838488b042e488b0849894c3840488b442e104989443848488b442e184989443850"},
            {L"ObRegisterCallbacks", 0xa808c0, 0x1d4, L"8bc34103dd48c1e00644096c3834"}}};
        static const std::array<CallbackCodeWindow, 5> registry28000 = {{
            {L"CmpRegisterCallbackInternal", 0x9f8adc, 0x3c, L"ba5000000041b8434d6362b900010000"},
            {L"CmpRegisterCallbackInternal", 0x9f8adc, 0x67,
             L"4889400841b8434d63614889004883c040488940084889008b431433d083e201c743100000000033d048896b208953144c8973280fb7076689433266894330"},
            {L"CmpInsertCallbackInListByAltitude", 0x9f8c14, 0x25,
             L"488b05f83750004c8d3d0938500048ffc0488905e737500048894618488b3df4375000"},
            {L"CmpInsertCallbackInListByAltitude", 0x9f8c14, 0x76, L"48890e4889460848897108488930f0ff05b5714f00"},
            {L"CmpEnumerateCallback", 0x9f8cf0, 0x48, L"483bca74178b411085c07905488b09ebeff0ff4110488b792848890e"}}};
        switch (family)
        {
        case CallbackFamily::Process:
            return process28000;
        case CallbackFamily::Thread:
            return thread28000;
        case CallbackFamily::Image:
            return image28000;
        case CallbackFamily::Object:
            return object28000;
        case CallbackFamily::Registry:
            return registry28000;
        }
        return {};
    }
    // These windows corroborate the allocation, loop bounds, strides and field stores.
    static const std::array<CallbackCodeWindow, 3> process = {{
        {L"ExAllocateCallBack", 0xa86500, 0x10, L"ba18000000"},
        {L"ExAllocateCallBack", 0xa86500, 0x28, L"488320004889780848895810"},
        {L"PspSetCreateProcessNotifyRoutine", 0xa8cf1c, 0x38,
         L"4c8d2de584470083c8ff660185e4010000904533f64183fe4073384e8d24f5000000004d03e5498bcce89ec681ff488bf84885c0741883e3fe4c397808"}}};
    static const std::array<CallbackCodeWindow, 3> thread = {{
        process[0], process[1],
        {L"PspSetCreateThreadNotifyRoutine", 0x77a578, 0x22, L"83fb40735e488d0d9aac78004533c0488d0cd9488bd7"}}};
    static const std::array<CallbackCodeWindow, 3> image = {{
        process[0], process[1],
        {L"PsSetLoadImageNotifyRoutineEx", 0xa863c0, 0x31, L"83ff4073658bc7488d0d41f247004533c0488bd6488d0cc1"}}};
    static const std::array<CallbackCodeWindow, 2> object = {{
        {L"ObRegisterCallbacks", 0x9cf0a0, 0x145,
         L"8bd548c1e2064883c2204803d74889520848891248895a388b460889421048897a18488b06488b0848894a20488b461048894228488b461848894230"},
        {L"ObRegisterCallbacks", 0x9cf0a0, 0x102, L"8bc34103dc48c1e0064409643834"}}};
    static const std::array<CallbackCodeWindow, 5> registry = {{
        {L"CmpRegisterCallbackInternal", 0x96e90c, 0x23,
         L"4c8bf1498943e8498d4bd8418af1498bf8488beae81853a8ffba5000000041b8434d6362b900010000e893472000"},
        {L"CmpRegisterCallbackInternal", 0x96e90c, 0x67,
         L"4889400841b8434d63614889004883c040488940084889008b431433d083e201c743100000000033d048896b208953144c8973280fb70766894332668943300fb717e836472000488943384885c0745c440fb707488bc8488b5708e86df9d4ff"},
        {L"CmpInsertCallbackInListByAltitude", 0x96ea44, 0x25,
         L"488b05588e58004c8d3d698e580048ffc0488905478e580048894618488b3d548e5800"},
        {L"CmpInsertCallbackInListByAltitude", 0x96ea44, 0x76, L"48890e4889460848897108488930f0ff05bd0e5800"},
        {L"CmpEnumerateCallback", 0x7d2080, 0x54, L"493bc974178b411085c07905488b09ebeff0ff4110488b792848890e"}}};
    switch (family)
    {
    case CallbackFamily::Process:
        return process;
    case CallbackFamily::Thread:
        return thread;
    case CallbackFamily::Image:
        return image;
    case CallbackFamily::Object:
        return object;
    case CallbackFamily::Registry:
        return registry;
    }
    return {};
}

inline const wchar_t *NotifyTableName(CallbackFamily family)
{
    switch (family)
    {
    case CallbackFamily::Process:
        return L"PspCreateProcessNotifyRoutine";
    case CallbackFamily::Thread:
        return L"PspCreateThreadNotifyRoutine";
    case CallbackFamily::Image:
        return L"PspLoadImageNotifyRoutine";
    default:
        return L"";
    }
}

inline uint32_t NotifyTableRva(CallbackFamily family, bool build28000 = false)
{
    switch (family)
    {
    case CallbackFamily::Process:
        return build28000 ? 0xf0a380 : 0xf05440;
    case CallbackFamily::Thread:
        return build28000 ? 0xf0a580 : 0xf05240;
    case CallbackFamily::Image:
        return build28000 ? 0xf0a180 : 0xf05640;
    default:
        return 0;
    }
}

template <typename Resolve>
const wchar_t *VerifyCallbackProfile(TargetReader &reader, const ModuleIdentity &identity, CallbackFamily family, Resolve resolve)
{
    const wchar_t *reason = L"Verified";
    do
    {
        const bool build28000 = CallbackProfile28000Identity(identity);
        const auto windows = CallbackProfileWindows(family, build28000);
        if (!CallbackProfileIdentity(identity) || windows.empty())
        {
            reason = L"NoMatchingCallbackProfile";
            break;
        }
        if (family == CallbackFamily::Registry &&
            (resolve(L"CallbackListHead") != identity.Base + (build28000 ? 0xefc450 : 0xef78e0) ||
             resolve(L"CmpCallBackCount") != identity.Base + (build28000 ? 0xeefe54 : 0xeef98c)))
        {
            reason = L"RegistryCallbackSymbolMismatch";
            break;
        }
        if (family != CallbackFamily::Object && family != CallbackFamily::Registry &&
            resolve(NotifyTableName(family)) != identity.Base + NotifyTableRva(family, build28000))
        {
            reason = L"CallbackTableSymbolMismatch";
            break;
        }
        for (const auto &window : windows)
        {
            if (resolve(window.Symbol) != identity.Base + window.SymbolRva)
            {
                reason = L"CallbackCodeSymbolMismatch";
                break;
            }
            const auto count = std::wcslen(window.Bytes) / 2;
            const uint64_t rva = static_cast<uint64_t>(window.SymbolRva) + window.Offset;
            if (count == 0 || count > 256 || rva >= identity.ImageSize || count > identity.ImageSize - rva)
            {
                reason = L"CallbackCodeRangeInvalid";
                break;
            }
            const auto read = reader.Read(AddressSpace::Virtual, identity.Base + rva, count);
            if (!ExactBytes(read, count))
            {
                reason = L"CallbackCodeUnavailable";
                break;
            }
            constexpr wchar_t digits[] = L"0123456789abcdef";
            bool matches = true;
            for (size_t i = 0; i < count; ++i)
            {
                if (window.Bytes[i * 2] != digits[read.Bytes[i] >> 4] || window.Bytes[i * 2 + 1] != digits[read.Bytes[i] & 15])
                {
                    matches = false;
                    break;
                }
            }
            if (!matches)
            {
                reason = L"CallbackCodeMismatch";
                break;
            }
        }
    } while (false);
    return reason;
}

inline FieldInfo CallbackProfileField(uint32_t offset, uint32_t size, const wchar_t *source = CallbackProfileId)
{
    FieldInfo field;
    field.Offset = offset;
    field.Size = size;
    field.Source = source;
    return field;
}

inline FieldInfo CallbackProfileTable(const wchar_t *source = CallbackProfileId)
{
    auto field = CallbackProfileField(0, 64 * 8, source);
    field.Kind = FieldKind::Array;
    field.ArrayCount = 64;
    field.ElementSize = 8;
    return field;
}

inline bool ApplyObjectCallbackProfile(std::optional<FieldInfo> &links, std::optional<FieldInfo> &operations,
                                       std::optional<FieldInfo> &pre, std::optional<FieldInfo> &post,
                                       const wchar_t *source = CallbackProfileId)
{
    const auto agrees = [](const std::optional<FieldInfo> &field, uint32_t offset, uint32_t size)
    {
        return !field || (field->Offset == offset && field->Size == size && !field->BitOffset && !field->BitWidth);
    };
    const bool compatible = agrees(links, 0, 16) && agrees(operations, 0x10, 4) && agrees(pre, 0x28, 8) && agrees(post, 0x30, 8);
    if (compatible)
    {
        if (!links)
        {
            links = CallbackProfileField(0, 16, source);
        }
        if (!operations)
        {
            operations = CallbackProfileField(0x10, 4, source);
        }
        if (!pre)
        {
            pre = CallbackProfileField(0x28, 8, source);
        }
        if (!post)
        {
            post = CallbackProfileField(0x30, 8, source);
        }
    }
    return compatible;
}

inline bool NotifyTableValid(const std::optional<FieldInfo> &table, uint64_t address)
{
    return table && table->Kind == FieldKind::Array && table->Offset == 0 && table->ValidFor(table->Size) &&
           table->ElementSize == 8u && table->ArrayCount && *table->ArrayCount <= 4096 && address % 8 == 0 &&
           ValidRange(address, table->Size);
}

struct NotifyCallbackObservation
{
    std::optional<uint64_t> Raw;
    std::optional<uint64_t> Block;
    std::optional<uint64_t> Routine;
    std::optional<uint64_t> Context;
    bool Unreadable = false;
    const wchar_t *Reason = L"Decoded";
};

inline NotifyCallbackObservation ReadNotifyCallback(TargetReader &reader, const TargetArchitecture &architecture, uint64_t slot,
                                                    const std::optional<FieldInfo> &references,
                                                    const std::optional<FieldInfo> &function,
                                                    const std::optional<FieldInfo> &context = std::nullopt)
{
    NotifyCallbackObservation result;
    do
    {
        if (architecture.PointerBytes != 8 || !architecture.KernelPointer(slot) || slot % 8 != 0 || !ValidRange(slot, 8))
        {
            result.Reason = L"InvalidCallbackSlot";
            break;
        }
        result.Raw = ReadField(reader, slot, CallbackProfileField(0, 8));
        if (!result.Raw)
        {
            result.Unreadable = true;
            result.Reason = L"UnreadableSlot";
            break;
        }
        if (*result.Raw == 0)
        {
            result.Reason = L"EmptySlot";
            break;
        }
        if (!references || references->Size != 8 || !references->ValidFor(8) || references->BitOffset != 0u ||
            !references->BitWidth || *references->BitWidth >= 8 || !function || function->Size != 8 ||
            function->BitOffset || function->BitWidth)
        {
            result.Reason = L"CallbackBlockLayoutUnavailable";
            break;
        }
        result.Block = *result.Raw & ~((uint64_t(1) << *references->BitWidth) - 1);
        if (!architecture.KernelPointer(*result.Block))
        {
            result.Reason = L"InvalidCallbackBlock";
            break;
        }
        result.Routine = ReadField(reader, *result.Block, function);
        if (context && context->Size == 8 && !context->BitOffset && !context->BitWidth)
        {
            result.Context = ReadField(reader, *result.Block, context);
            result.Unreadable = !result.Context;
        }
        if (!result.Routine)
        {
            result.Unreadable = true;
            result.Reason = L"UnreadableRoutine";
        }
        else if (*result.Routine == 0 || !architecture.KernelPointer(*result.Routine))
        {
            result.Reason = L"InvalidNotifyRoutine";
        }
    } while (false);
    return result;
}

struct RegistryCallbackObservation
{
    std::optional<uint64_t> Routine;
    std::optional<uint64_t> Context;
    std::optional<uint64_t> Cookie;
    std::optional<uint32_t> References;
    std::optional<uint32_t> Flags;
    bool Unreadable = false;
};

inline RegistryCallbackObservation ReadProfiledRegistryCallback(TargetReader &reader, const TargetArchitecture &architecture,
                                                               uint64_t entry)
{
    RegistryCallbackObservation result;
    if (architecture.PointerBytes == 8 && architecture.KernelPointer(entry) && entry % 8 == 0 && ValidRange(entry, 0x50))
    {
        const auto read = reader.Read(AddressSpace::Virtual, entry, 0x50);
        if (ExactBytes(read, 0x50))
        {
            uint32_t references = 0;
            uint64_t cookie = 0;
            uint64_t context = 0;
            uint64_t routine = 0;
            std::memcpy(&references, read.Bytes.data() + 0x10, sizeof(references));
            uint32_t flags = 0;
            std::memcpy(&flags, read.Bytes.data() + 0x14, sizeof(flags));
            std::memcpy(&cookie, read.Bytes.data() + 0x18, sizeof(cookie));
            std::memcpy(&context, read.Bytes.data() + 0x20, sizeof(context));
            std::memcpy(&routine, read.Bytes.data() + 0x28, sizeof(routine));
            result.References = references;
            result.Flags = flags;
            result.Cookie = cookie;
            result.Context = context;
            result.Routine = routine;
        }
        else
        {
            result.Unreadable = true;
        }
    }
    return result;
}
} // namespace kncore
