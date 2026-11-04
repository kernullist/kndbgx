#pragma once

#include "Result.h"
#include <array>
#include <algorithm>
#include <optional>
#include <cwchar>

namespace kncore
{
inline knjson::Value DecodeIoctl(uint32_t code)
{
    static constexpr const wchar_t *methods[] = {L"METHOD_BUFFERED", L"METHOD_IN_DIRECT", L"METHOD_OUT_DIRECT", L"METHOD_NEITHER"};
    static constexpr const wchar_t *access[] = {L"FILE_ANY_ACCESS", L"FILE_READ_ACCESS", L"FILE_WRITE_ACCESS",
                                                L"FILE_READ_ACCESS | FILE_WRITE_ACCESS"};
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"Ioctl"));
    row.Set(L"code", knjson::Value(Hex(code)));
    row.Set(L"deviceType", knjson::Value(Hex(code >> 16)));
    row.Set(L"function", knjson::Value(Hex((code >> 2) & 0xfff)));
    row.Set(L"method", knjson::Value(methods[code & 3]));
    row.Set(L"access", knjson::Value(access[(code >> 14) & 3]));
    row.Set(L"vendorDevice", knjson::Value((code & 0x80000000u) != 0));
    row.Set(L"vendorFunction", knjson::Value((code & 0x2000u) != 0));
    row.Set(L"review", knjson::Value((code & 3) == 3 ? L"Inspect caller context, probing, lifetime and exception handling for user buffers"
                                                     : L"Inspect actual dispatch validation and buffer lengths"));
    return row;
}

inline knjson::Value DecodeNtStatus(uint32_t code)
{
    static constexpr const wchar_t *severity[] = {L"Success", L"Informational", L"Warning", L"Error"};
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"NtStatus"));
    row.Set(L"code", knjson::Value(Hex(code)));
    row.Set(L"severity", knjson::Value(severity[code >> 30]));
    row.Set(L"ntSuccess", knjson::Value((code & 0x80000000u) == 0));
    row.Set(L"customer", knjson::Value((code & 0x20000000u) != 0));
    row.Set(L"reservedBit", knjson::Value((code & 0x10000000u) != 0));
    row.Set(L"facility", knjson::Value(Hex((code >> 16) & 0xfff)));
    row.Set(L"statusCode", knjson::Value(Hex(code & 0xffff)));
    return row;
}

inline const wchar_t *KasanShadowName(unsigned code)
{
    switch (code)
    {
    case 0x00:
        return L"Addressable";
    case 0x09:
        return L"Paged memory; inspect current IRQL";
    case 0x81:
        return L"Alloca left redzone";
    case 0x82:
        return L"Alloca middle redzone";
    case 0x83:
        return L"Alloca right redzone";
    case 0x84:
        return L"Global right redzone";
    case 0x85:
        return L"Generic invalid memory";
    case 0x86:
        return L"Pool right redzone";
    case 0x87:
        return L"Freed pool";
    case 0x8a:
        return L"Contiguous allocation left redzone";
    case 0x8b:
        return L"Contiguous allocation right redzone";
    case 0x8c:
        return L"Freed lookaside allocation";
    case 0x8d:
        return L"Pool left redzone";
    case 0xf1:
        return L"Stack left redzone";
    case 0xf2:
        return L"Stack middle redzone";
    case 0xf3:
        return L"Stack right redzone";
    case 0xf5:
        return L"Stack use after return";
    case 0xf8:
        return L"Stack use after scope";
    default:
        return code <= 7 ? L"Partially addressable granule" : code < 0x80 ? L"Conditional access" : L"Unknown invalid shadow code";
    }
}

inline knjson::Value DecodeBugcheck(uint32_t code, const std::array<uint64_t, 4> &parameters)
{
    struct Entry
    {
        uint32_t Code;
        const wchar_t *Name;
    };
    static constexpr Entry names[] = {{0xa, L"IRQL_NOT_LESS_OR_EQUAL"},
                                      {0x1e, L"KMODE_EXCEPTION_NOT_HANDLED"},
                                      {0x3b, L"SYSTEM_SERVICE_EXCEPTION"},
                                      {0x50, L"PAGE_FAULT_IN_NONPAGED_AREA"},
                                      {0x7e, L"SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"},
                                      {0x9f, L"DRIVER_POWER_STATE_FAILURE"},
                                      {0xc1, L"SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION"},
                                      {0xc4, L"DRIVER_VERIFIER_DETECTED_VIOLATION"},
                                      {0xc6, L"DRIVER_CAUGHT_MODIFYING_FREED_POOL"},
                                      {0xc9, L"DRIVER_VERIFIER_IOMANAGER_VIOLATION"},
                                      {0xd1, L"DRIVER_IRQL_NOT_LESS_OR_EQUAL"},
                                      {0xd6, L"DRIVER_PAGE_FAULT_BEYOND_END_OF_ALLOCATION"},
                                      {0xe6, L"DRIVER_VERIFIER_DMA_VIOLATION"},
                                      {0x10d, L"WDF_VIOLATION"},
                                      {0x124, L"WHEA_UNCORRECTABLE_ERROR"},
                                      {0x133, L"DPC_WATCHDOG_VIOLATION"},
                                      {0x139, L"KERNEL_SECURITY_CHECK_FAILURE"},
                                      {0x1f2, L"KASAN_ILLEGAL_ACCESS"}};
    const auto found = std::find_if(std::begin(names), std::end(names),
                                    [code](const Entry &entry)
                                    {
                                        return entry.Code == code;
                                    });
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"Bugcheck"));
    row.Set(L"code", knjson::Value(Hex(code)));
    row.Set(L"name", knjson::Value(found == std::end(names) ? L"Unknown; consult the host bugcheck reference" : found->Name));
    auto args = knjson::Value::MakeArray();
    for (const auto value : parameters)
    {
        args.Push(knjson::Value(Hex(value)));
    }
    row.Set(L"parameters", args);
    if (code == 0x1f2)
    {
        row.Set(L"address", knjson::Value(Hex(parameters[0])));
        row.Set(L"accessBytes", knjson::Value(std::to_wstring(parameters[1])));
        row.Set(L"instructionPointer", knjson::Value(Hex(parameters[2])));
        row.Set(L"access", knjson::Value((parameters[3] & 0x100) != 0 ? L"write" : L"read"));
        row.Set(L"shadowByte", knjson::Value(Hex(parameters[3] & 0xff)));
        row.Set(L"shadowMeaning", knjson::Value(KasanShadowName(static_cast<unsigned>(parameters[3] & 0xff))));
        row.Set(L"uninterpretedBits", knjson::Value(Hex(parameters[3] & ~uint64_t(0x1ff))));
    }
    return row;
}

inline const wchar_t *IrpMajorName(unsigned code)
{
    static constexpr const wchar_t *names[] = {L"CREATE",
                                               L"CREATE_NAMED_PIPE",
                                               L"CLOSE",
                                               L"READ",
                                               L"WRITE",
                                               L"QUERY_INFORMATION",
                                               L"SET_INFORMATION",
                                               L"QUERY_EA",
                                               L"SET_EA",
                                               L"FLUSH_BUFFERS",
                                               L"QUERY_VOLUME_INFORMATION",
                                               L"SET_VOLUME_INFORMATION",
                                               L"DIRECTORY_CONTROL",
                                               L"FILE_SYSTEM_CONTROL",
                                               L"DEVICE_CONTROL",
                                               L"INTERNAL_DEVICE_CONTROL",
                                               L"SHUTDOWN",
                                               L"LOCK_CONTROL",
                                               L"CLEANUP",
                                               L"CREATE_MAILSLOT",
                                               L"QUERY_SECURITY",
                                               L"SET_SECURITY",
                                               L"POWER",
                                               L"SYSTEM_CONTROL",
                                               L"DEVICE_CHANGE",
                                               L"QUERY_QUOTA",
                                               L"SET_QUOTA",
                                               L"PNP"};
    return code < std::size(names) ? names[code] : L"UNKNOWN";
}

inline std::wstring MinifilterMajorName(unsigned code)
{
    // FltMgr extends the normal IRP majors with unsigned byte operation IDs.
    const wchar_t *name = IrpMajorName(code);
    switch (code)
    {
    case 0xff:
        name = L"ACQUIRE_FOR_SECTION_SYNCHRONIZATION";
        break;
    case 0xfe:
        name = L"RELEASE_FOR_SECTION_SYNCHRONIZATION";
        break;
    case 0xfd:
        name = L"ACQUIRE_FOR_MOD_WRITE";
        break;
    case 0xfc:
        name = L"RELEASE_FOR_MOD_WRITE";
        break;
    case 0xfb:
        name = L"ACQUIRE_FOR_CC_FLUSH";
        break;
    case 0xfa:
        name = L"RELEASE_FOR_CC_FLUSH";
        break;
    case 0xf9:
        name = L"QUERY_OPEN";
        break;
    case 0xf3:
        name = L"FAST_IO_CHECK_IF_POSSIBLE";
        break;
    case 0xf2:
        name = L"NETWORK_QUERY_OPEN";
        break;
    case 0xf1:
        name = L"MDL_READ";
        break;
    case 0xf0:
        name = L"MDL_READ_COMPLETE";
        break;
    case 0xef:
        name = L"PREPARE_MDL_WRITE";
        break;
    case 0xee:
        name = L"MDL_WRITE_COMPLETE";
        break;
    case 0xed:
        name = L"VOLUME_MOUNT";
        break;
    case 0xec:
        name = L"VOLUME_DISMOUNT";
        break;
    case 0x80:
        name = L"OPERATION_END";
        break;
    }
    return std::wstring(L"IRP_MJ_") + name +
        (std::wcscmp(name, L"UNKNOWN") == 0 ? L" (" + std::to_wstring(code) + L")" : L"");
}

inline bool ValidIrpGeometry(uint64_t address, uint64_t type, uint64_t size, uint64_t headerBytes, uint64_t stackBytes, uint64_t count,
                             uint64_t current)
{
    return type == 6 && headerBytes >= 8 && headerBytes <= 4096 && stackBytes >= 8 && stackBytes <= 4096 && count > 0 && count <= 64 &&
           current > 0 && current <= count + 1 && size >= headerBytes + count * stackBytes && size <= 65535 && size <= UINT64_MAX - address;
}

enum class DiagnosticOperand
{
    None,
    Address,
    Module,
    OptionalModule
};

inline bool DiagnosticTargetMatches(const SessionStamp &expected, const SessionStamp &current)
{
    return expected.SessionId == current.SessionId && expected.TargetGeneration == current.TargetGeneration &&
           expected.StopEpoch == current.StopEpoch;
}
struct DiagnosticRecipe
{
    const wchar_t *Name;
    const wchar_t *Group;
    const wchar_t *Command;
    DiagnosticOperand Operand;
    const wchar_t *Suffix;
    const wchar_t *Description;
    const wchar_t *Reference;
};

inline const std::vector<DiagnosticRecipe> &DiagnosticRecipes()
{
    using O = DiagnosticOperand;
    static const std::vector<DiagnosticRecipe> recipes = {
        {L"net-adapters", L"Network", L"!ndiskd.netadapter", O::None, L" -static -dml 0", L"NDIS network adapters", L"-ndiskd-netadapter"},
        {L"net-adapter", L"Network", L"!ndiskd.netadapter -handle", O::Address, L" -diag -state -bindings -static -dml 0",
         L"Adapter diagnostics and bindings", L"-ndiskd-netadapter"},
        {L"net-drivers", L"Network", L"!ndiskd.minidriver", O::None, L" -static -dml 0", L"NDIS miniport drivers", L"-ndiskd-minidriver"},
        {L"net-driver", L"Network", L"!ndiskd.minidriver -handle", O::Address, L" -handlers -static -dml 0", L"NDIS driver callbacks",
         L"-ndiskd-minidriver"},
        {L"net-oids", L"Network", L"!ndiskd.oid", O::None, L" -static -dml 0", L"Pending NDIS OID requests", L"-ndiskd-oid"},
        {L"net-oid", L"Network", L"!ndiskd.oid -handle", O::Address, L" -static -dml 0", L"NDIS OID request", L"-ndiskd-oid"},
        {L"net-nbl", L"Network", L"!ndiskd.nbl -handle", O::Address, L" -info -static -dml 0", L"NET_BUFFER_LIST metadata", L"-ndiskd-nbl"},
        {L"net-cx", L"Network", L"!ndiskd.cxadapter -handle", O::Address, L" -basic -datapath -static -dml 0",
         L"NetAdapterCx queues and callbacks", L"-ndiskd-cxadapter"},
        {L"storage", L"Storage", L"!storagekd.storadapter", O::None, L"", L"Storport adapters", L"-storagekd-storadapter"},
        {L"storage-adapter", L"Storage", L"!storagekd.storadapter", O::Address, L"", L"Storport adapter and pending requests",
         L"-storagekd-storadapter"},
        {L"usb", L"USB", L"!usb3kd.usb_tree 1", O::None, L"", L"USB controllers, hubs and port status", L"-usb3kd-usb-tree"},
        {L"crash", L"Crash", L"!analyze -v", O::None, L"", L"Host crash analysis", L"-analyze"},
        {L"hang", L"Hang", L"!analyze -hang", O::None, L"", L"Host hang analysis", L"-analyze"},
        {L"locks", L"Hang", L"!kdexts.locks", O::None, L"", L"Executive resources", L"-locks---kdexts-locks-"},
        {L"deadlocks", L"Hang", L"!deadlock", O::None, L"", L"Verifier recorded deadlock data", L"-deadlock"},
        {L"running", L"Hang", L"!running -it", O::None, L"", L"Processor stacks and threads", L"-running"},
        {L"stacks", L"Hang", L"!stacks 2", O::None, L"", L"Kernel thread stacks", L"-stacks"},
        {L"irql", L"Hang", L"!irql", O::None, L"", L"Saved processor IRQL", L"-irql"},
        {L"dpcs", L"Hang", L"!dpcs", O::None, L"", L"Processor DPC queues", L"-dpcs"},
        {L"verifier", L"Verifier", L"!verifier 3", O::OptionalModule, L"", L"Verifier counters and allocations", L"-verifier"},
        {L"iovirp", L"Verifier", L"!iovirp", O::Address, L"", L"Verifier IRP tracking", L"-iovirp"},
        {L"irp", L"IO", L"!irp", O::Address, L" 1", L"Host IRP stack baseline", L"-irp"},
        {L"irpfind", L"IO", L"!irpfind", O::None, L"", L"Pool IRP search; potentially expensive", L"-irpfind"},
        {L"device", L"IO", L"!devobj", O::Address, L"", L"Device object", L"-devobj"},
        {L"devstack", L"IO", L"!devstack", O::Address, L"", L"Device attachment stack", L"-devstack"},
        {L"file", L"IO", L"!fileobj", O::Address, L"", L"File object", L"-fileobj"},
        {L"devnode", L"Power", L"!devnode", O::Address, L"", L"PnP device node", L"-devnode"},
        {L"power", L"Power", L"!poaction", O::None, L"", L"Power action and IRPs", L"-poaction"},
        {L"pnp", L"Power", L"!pnptriage", O::None, L"", L"PnP triage state",
         L"https://learn.microsoft.com/en-us/windows-hardware/test/hlk/testref/"
         L"use-kernel-debugging-to-debug-device-fundamentals-reliability-test-failures"},
        {L"power-triage", L"Power", L"!powertriage", O::None, L"", L"Power IRPs and device stacks", L"-powertriage"},
        {L"blackbox-pnp", L"Power", L"!blackboxpnp", O::None, L"", L"Dump PnP blackbox",
         L"https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/stop-code-error-troubleshooting"},
        {L"blackbox-bsd", L"Crash", L"!blackboxbsd", O::None, L"", L"Boot status blackbox", L"-blackboxbsd"},
        {L"blackbox-ntfs", L"Crash", L"!blackboxntfs", O::None, L"", L"NTFS blackbox; host extension dependent", L"-analyze"},
        {L"whea", L"Crash", L"!whea", O::None, L"", L"WHEA error sources", L"-whea"},
        {L"errrec", L"Crash", L"!errrec", O::Address, L"", L"WHEA error record", L"-errrec"},
        {L"vm", L"Memory", L"!vm 1", O::None, L"", L"Virtual memory summary", L"-vm"},
        {L"memusage", L"Memory", L"!memusage", O::None, L"", L"Physical memory usage", L"-memusage"},
        {L"poolusage", L"Memory", L"!poolused 2", O::None, L"", L"Nonpaged pool usage by tag", L"-poolused"},
        {L"pool", L"Memory", L"!pool", O::Address, L"", L"Pool allocation metadata", L"-pool"},
        {L"pte", L"Memory", L"!pte", O::Address, L"", L"Host page table observation", L"-pte"},
        {L"wdf-driver", L"WDF", L"!wdfkd.wdfdriverinfo", O::Module, L" 0x31", L"Driver objects, contexts and callbacks",
         L"-wdfkd-wdfdriverinfo"},
        {L"wdf-log", L"WDF", L"!wdfkd.wdflogdump", O::Module, L"", L"WDF in-flight recorder", L"-wdfkd-wdflogdump"},
        {L"wdf-device", L"WDF", L"!wdfkd.wdfdevice", O::Address, L"", L"WDF device", L"-wdfkd-wdfdevice"},
        {L"wdf-queues", L"WDF", L"!wdfkd.wdfdevicequeues", O::Address, L"", L"Device queues and requests", L"-wdfkd-wdfdevicequeues"},
        {L"wdf-queue", L"WDF", L"!wdfkd.wdfqueue", O::Address, L"", L"WDF queue", L"-wdfkd-wdfqueue"},
        {L"wdf-request", L"WDF", L"!wdfkd.wdfrequest", O::Address, L"", L"WDF request", L"-wdfkd-wdfrequest"},
        {L"wdf-object", L"WDF", L"!wdfkd.wdfobject", O::Address, L"", L"WDF object and references", L"-wdfkd-wdfobject"},
        {L"wdf-interrupts", L"WDF", L"!wdfkd.wdfdeviceinterrupts", O::Address, L"", L"Device interrupt callbacks",
         L"-wdfkd-wdfdeviceinterrupts"},
        {L"wdf-dma", L"WDF", L"!wdfkd.wdfdmaenabler", O::Address, L"", L"DMA enabler", L"-wdfkd-wdfdmaenabler"},
        {L"wdf-transaction", L"WDF", L"!wdfkd.wdfdmatransaction", O::Address, L"", L"DMA transaction", L"-wdfkd-wdfdmatransaction"},
        {L"wdf-memory", L"WDF", L"!wdfkd.wdfmemory", O::Address, L"", L"WDF memory object", L"-wdfkd-wdfmemory"},
        {L"wdf-lock", L"WDF", L"!wdfkd.wdfspinlock", O::Address, L"", L"WDF spin lock", L"-wdfkd-wdfspinlock"},
        {L"wdf-pool", L"WDF", L"!wdfkd.wdfpoolusage", O::Module, L"", L"WDF allocation usage", L"-wdfkd-wdfpoolusage"}};
    return recipes;
}

inline const DiagnosticRecipe *FindDiagnostic(std::wstring_view name)
{
    const auto &recipes = DiagnosticRecipes();
    const auto found = std::find_if(recipes.begin(), recipes.end(),
                                    [name](const auto &recipe)
                                    {
                                        return name == recipe.Name;
                                    });
    return found == recipes.end() ? nullptr : &*found;
}

inline bool ValidModuleToken(std::wstring_view value)
{
    if (value.empty() || value.size() > 128 || value.front() == L'.' || value.front() == L'-')
    {
        return false;
    }
    return std::all_of(value.begin(), value.end(),
                       [](wchar_t c)
                       {
                           return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') || c == L'_' ||
                                  c == L'-' || c == L'.';
                       });
}

inline std::optional<std::wstring> DiagnosticCommand(const DiagnosticRecipe &recipe, std::wstring operand)
{
    using O = DiagnosticOperand;
    if ((recipe.Operand == O::None && !operand.empty()) ||
        (recipe.Operand != O::None && recipe.Operand != O::OptionalModule && operand.empty()))
    {
        return {};
    }
    if (recipe.Operand == O::Address)
    {
        uint64_t value = 0;
        if (!ParseUnsigned(operand, 16, &value) || value == 0)
        {
            return {};
        }
        operand = Hex(value);
    }
    else if (!operand.empty())
    {
        if (!ValidModuleToken(operand))
        {
            return {};
        }
        if (std::wstring_view(recipe.Group) == L"WDF" && operand.size() > 4 && _wcsicmp(operand.c_str() + operand.size() - 4, L".sys") == 0)
        {
            operand.resize(operand.size() - 4);
        }
    }
    return std::wstring(recipe.Command) + (operand.empty() ? L"" : L" " + operand) + recipe.Suffix;
}
} // namespace kncore
