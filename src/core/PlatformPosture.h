#pragma once

#include "Result.h"
#include <array>
#include <optional>

namespace kncore
{
inline constexpr uint32_t CodeIntegrityKnownOptions = 0x3fff;

struct CodeIntegrityState
{
    bool QueryAvailable = false;
    bool Known = false;
    uint32_t NtStatus = 0xc000007a;
    uint32_t ReturnedLength = 0;
    uint32_t StructureLength = 0;
    uint32_t Options = 0;
};

inline CodeIntegrityState DecodeCodeIntegrityReply(bool available, uint32_t status, uint32_t returned, uint32_t length, uint32_t options)
{
    CodeIntegrityState state;
    state.QueryAvailable = available;
    state.NtStatus = status;
    state.ReturnedLength = returned;
    state.StructureLength = length;
    state.Known = available && (status & 0x80000000U) == 0 && returned == 8 && length == 8;
    if (state.Known)
    {
        state.Options = options;
    }
    return state;
}

inline Result CodeIntegrityReport(const CodeIntegrityState &state)
{
    Result report;
    report.Source = L"HostSystemCodeIntegrity";
    report.Consistency = L"host-nonatomic";
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"HostCodeIntegrity"));
    row.Set(L"source", knjson::Value(L"NtQuerySystemInformation(SystemCodeIntegrityInformation=103)"));
    row.Set(L"scope", knjson::Value(L"DebuggerHost"));
    row.Set(L"queryAvailable", knjson::Value(state.QueryAvailable));
    row.Set(L"known", knjson::Value(state.Known));
    row.Set(L"ntStatus", knjson::Value(Hex(state.NtStatus)));
    row.Set(L"returnedLength", knjson::Value(std::to_wstring(state.ReturnedLength)));
    row.Set(L"structureLength", knjson::Value(std::to_wstring(state.StructureLength)));
    row.Set(L"raw", state.Known ? knjson::Value(Hex(state.Options)) : knjson::Value());
    const uint32_t unknown = state.Options & ~CodeIntegrityKnownOptions;
    row.Set(L"unknownOptions", state.Known ? knjson::Value(Hex(unknown)) : knjson::Value());
    const std::pair<const wchar_t *, uint32_t> flags[] = {
        {L"codeIntegrityEnabled", 0x1}, {L"testSign", 0x2},           {L"umciEnabled", 0x4},         {L"umciAuditMode", 0x8},
        {L"umciExclusionPaths", 0x10},  {L"testBuild", 0x20},         {L"preproductionBuild", 0x40}, {L"debugMode", 0x80},
        {L"flightBuild", 0x100},        {L"flightingEnabled", 0x200}, {L"hvciEnabled", 0x400},       {L"hvciAuditMode", 0x800},
        {L"hvciStrictMode", 0x1000},    {L"hvciIumEnabled", 0x2000}};
    for (const auto &[name, mask] : flags)
    {
        row.Set(name, state.Known ? knjson::Value((state.Options & mask) != 0) : knjson::Value());
    }
    report.Rows.Push(row);
    report.Collected.Expected = 1;
    report.Collected.Visited = state.QueryAvailable ? 1 : 0;
    report.Collected.Read = state.Known ? 1 : 0;
    report.Collected.Decoded = state.Known ? 1 : 0;
    report.Collected.Unknown = !state.Known || unknown != 0 ? 1 : 0;
    report.Collected.Complete = report.Collected.Unknown == 0;
    report.Collected.StopReason = !state.Known   ? L"CodeIntegrityQueryUnavailable"
                                  : unknown != 0 ? L"UnknownCodeIntegrityOptions"
                                                 : L"CodeIntegrityQueryComplete";
    report.State = !state.Known ? Status::Unavailable : unknown != 0 ? Status::Partial : Status::Success;
    if (!state.Known)
    {
        report.Error = {L"NTSTATUS", state.NtStatus, L"NtQuerySystemInformation",
                        L"Code integrity query failed or returned an incompatible structure; values remain unknown"};
    }
    report.Limitations.Push(knjson::Value(L"Public system-information flags describe the debugger host at query time, not a remote "
                                          L"target or dump. Private ci!g_CiOptions uses a different representation. Current flags do not "
                                          L"establish enforcement history or system integrity."));
    return report;
}

struct HypervisorCpuid
{
    std::optional<uint32_t> MaximumBasicLeaf;
    std::wstring CpuVendor;
    std::optional<bool> Present;
    std::optional<uint32_t> MaximumHypervisorLeaf;
    std::wstring HypervisorVendor;
    std::optional<uint32_t> Interface;
    std::optional<std::array<uint32_t, 4>> HardwareFeatures;
    std::wstring HardwareStatus = L"DiscoveryUnavailable";
    bool Complete = false;
};

inline std::wstring CpuidSignature(uint32_t first, uint32_t second, uint32_t third)
{
    std::wstring text;
    constexpr wchar_t digits[] = L"0123456789abcdef";
    for (const uint32_t word : {first, second, third})
    {
        for (unsigned shift = 0; shift < 32; shift += 8)
        {
            const auto byte = static_cast<unsigned char>(word >> shift);
            if (byte >= 0x20 && byte <= 0x7e)
            {
                text += static_cast<wchar_t>(byte);
            }
            else
            {
                text += L"\\x";
                text += digits[byte >> 4];
                text += digits[byte & 15];
            }
        }
    }
    return text;
}

template <typename Query> HypervisorCpuid QueryHypervisorCpuid(Query query)
{
    HypervisorCpuid result;
    std::array<uint32_t, 4> registers = {};
    do
    {
        if (!query(0, registers))
        {
            break;
        }
        result.MaximumBasicLeaf = registers[0];
        result.CpuVendor = CpuidSignature(registers[1], registers[3], registers[2]);
        if (*result.MaximumBasicLeaf < 1 || !query(1, registers))
        {
            break;
        }
        result.Present = (registers[2] & 0x80000000U) != 0;
        if (!*result.Present)
        {
            result.Complete = true;
            result.HardwareStatus = L"HypervisorNotAdvertised";
            break;
        }
        if (!query(0x40000000, registers))
        {
            break;
        }
        result.MaximumHypervisorLeaf = registers[0];
        result.HypervisorVendor = CpuidSignature(registers[1], registers[2], registers[3]);
        // This interface defines the base hypervisor leaf range only.
        if (*result.MaximumHypervisorLeaf < 0x40000001 || *result.MaximumHypervisorLeaf > 0x400000ff)
        {
            result.HardwareStatus = L"InvalidHypervisorLeafRange";
            break;
        }
        if (!query(0x40000001, registers))
        {
            break;
        }
        result.Interface = registers[0];
        if (*result.Interface != 0x31237648)
        {
            result.HardwareStatus = L"InterfaceUnsupported";
            result.Complete = true;
            break;
        }
        if (*result.MaximumHypervisorLeaf < 0x40000006)
        {
            result.HardwareStatus = L"LeafUnavailable";
            result.Complete = true;
            break;
        }
        if (!query(0x40000006, registers))
        {
            result.HardwareStatus = L"HardwareQueryUnavailable";
            break;
        }
        result.HardwareFeatures = registers;
        result.HardwareStatus = L"Available";
        result.Complete = true;
    } while (false);
    return result;
}

inline knjson::Value HypervisorCpuidRow(const HypervisorCpuid &state)
{
    auto row = knjson::Value::MakeObject();
    const auto number = [](const std::optional<uint32_t> &value)
    {
        return value ? knjson::Value(Hex(*value)) : knjson::Value();
    };
    row.Set(L"kind", knjson::Value(L"HostCpuObservation"));
    row.Set(L"source", knjson::Value(L"DebuggerHostCpuid"));
    row.Set(L"scope", knjson::Value(L"DebuggerHost"));
    row.Set(L"cpuVendor", state.MaximumBasicLeaf ? knjson::Value(state.CpuVendor) : knjson::Value());
    row.Set(L"maximumBasicLeaf", number(state.MaximumBasicLeaf));
    row.Set(L"hypervisorBit", state.Present ? knjson::Value(*state.Present) : knjson::Value());
    row.Set(L"hypervisorVendor", state.MaximumHypervisorLeaf ? knjson::Value(state.HypervisorVendor) : knjson::Value());
    row.Set(L"maximumHypervisorLeaf", number(state.MaximumHypervisorLeaf));
    row.Set(L"interfaceSignature", number(state.Interface));
    row.Set(L"microsoftInterface", state.Interface ? knjson::Value(*state.Interface == 0x31237648) : knjson::Value());
    row.Set(L"hardwareFeaturesAvailable", knjson::Value(state.HardwareFeatures.has_value()));
    row.Set(L"hardwareFeaturesStatus", knjson::Value(state.HardwareStatus));
    row.Set(L"hardwareFeatures", state.HardwareFeatures ? knjson::Value(Hex((*state.HardwareFeatures)[0])) : knjson::Value());
    auto raw = knjson::Value();
    if (state.HardwareFeatures)
    {
        raw = knjson::Value::MakeObject();
        const wchar_t *names[] = {L"eax", L"ebx", L"ecx", L"edx"};
        for (size_t index = 0; index < 4; ++index)
        {
            raw.Set(names[index], knjson::Value(Hex((*state.HardwareFeatures)[index])));
        }
    }
    row.Set(L"hardwareRegisters", raw);
    row.Set(L"discoveryComplete", knjson::Value(state.Complete));
    return row;
}
} // namespace kncore
