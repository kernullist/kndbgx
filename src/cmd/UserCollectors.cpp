// M5 user-mode collectors: WFP objects, hypervisor posture, DMA firmware,
// BYOVD catalog hashing and firmware-table provider probing. These run
// entirely in the WinDbg process without kernel memory access.

#include "CollectorSupport.h"
#include "../core/HashCatalog.h"
#include "../core/PeIdentity.h"
#include "../util/FileReader.h"
#include "../util/HostCollectors.h"
#include "../util/CodeIntegrity.h"

#include "../engine/ModuleList.h"

#include <bcrypt.h>
#include <dbgeng.h>
#include <fwpmu.h>
#include <intrin.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <set>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace kncmd
{
namespace
{
std::wstring GuidToText(const GUID &guid)
{
    wchar_t text[64] = L"";
    StringFromGUID2(guid, text, 64);
    return std::wstring(text);
}

} // namespace

// ---- !wfp ----

void ScanWfp(Ctx &ctx)
{
    auto &out = ctx.Out;
    do
    {
        if (!SessionIsLocalLiveKernel(ctx.Session))
        {
            out.Fail(kncore::Status::Unavailable, HostCollectorRefusal(L"wfp"));
            break;
        }
        HANDLE engine = nullptr;
        const DWORD opened = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine);
        if (opened != ERROR_SUCCESS)
        {
            out.Fail(kncore::Status::IOError, L"[wfp.error] engine open failed", {L"Win32", opened, L"FwpmEngineOpen0", L""});
            break;
        }
        const auto close = [](void *handle)
        {
            FwpmEngineClose0(handle);
        };
        std::unique_ptr<void, decltype(close)> engineLease(engine, close);
        std::vector<std::wstring> kinds(ctx.Args.begin() + 1, ctx.Args.end());
        if (kinds.empty())
        {
            kinds.push_back(L"filters");
        }
        out.Details.Source = L"host-wfp";
        out.Details.Consistency = L"enum-handle-snapshot";
        out.Details.Collected.Complete = true;
        size_t displayed = 0;
        for (const auto &kind : kinds)
        {
            const auto visitor = [&](const auto &object)
            {
                const std::wstring name = object.displayData.name != nullptr ? object.displayData.name : L"<unnamed>";
                auto row = knjson::Value::MakeObject();
                row.Set(L"kind", knjson::Value(kind));
                row.Set(L"name", knjson::Value(name));
                using T = std::decay_t<decltype(object)>;
                if constexpr (std::is_same_v<T, FWPM_FILTER0>)
                {
                    row.Set(L"key", knjson::Value(GuidToText(object.filterKey)));
                    row.Set(L"action", knjson::Value(kncore::Hex(object.action.type)));
                }
                else if constexpr (std::is_same_v<T, FWPM_CALLOUT0>)
                {
                    row.Set(L"key", knjson::Value(GuidToText(object.calloutKey)));
                    row.Set(L"layer", knjson::Value(GuidToText(object.applicableLayer)));
                }
                else if constexpr (std::is_same_v<T, FWPM_PROVIDER0>)
                {
                    row.Set(L"key", knjson::Value(GuidToText(object.providerKey)));
                }
                else if constexpr (std::is_same_v<T, FWPM_SUBLAYER0>)
                {
                    row.Set(L"key", knjson::Value(GuidToText(object.subLayerKey)));
                }
                else
                {
                    row.Set(L"key", knjson::Value(GuidToText(object.layerKey)));
                }
                out.Details.Rows.Push(row);
                if (displayed < 100)
                {
                    out.AddLine(L"[wfp." + kind + L"] " + name);
                    ++displayed;
                }
            };
            knutil::EnumerationResult result;
            if (kind == L"filters")
            {
                result = knutil::EnumerateWfp<FWPM_FILTER0>(engine, FwpmFilterCreateEnumHandle0, FwpmFilterEnum0,
                                                            FwpmFilterDestroyEnumHandle0, FwpmFreeMemory0, visitor);
            }
            else if (kind == L"callouts")
            {
                result = knutil::EnumerateWfp<FWPM_CALLOUT0>(engine, FwpmCalloutCreateEnumHandle0, FwpmCalloutEnum0,
                                                             FwpmCalloutDestroyEnumHandle0, FwpmFreeMemory0, visitor);
            }
            else if (kind == L"providers")
            {
                result = knutil::EnumerateWfp<FWPM_PROVIDER0>(engine, FwpmProviderCreateEnumHandle0, FwpmProviderEnum0,
                                                              FwpmProviderDestroyEnumHandle0, FwpmFreeMemory0, visitor);
            }
            else if (kind == L"sublayers")
            {
                result = knutil::EnumerateWfp<FWPM_SUBLAYER0>(engine, FwpmSubLayerCreateEnumHandle0, FwpmSubLayerEnum0,
                                                              FwpmSubLayerDestroyEnumHandle0, FwpmFreeMemory0, visitor);
            }
            else if (kind == L"layers")
            {
                result = knutil::EnumerateWfp<FWPM_LAYER0>(engine, FwpmLayerCreateEnumHandle0, FwpmLayerEnum0, FwpmLayerDestroyEnumHandle0,
                                                           FwpmFreeMemory0, visitor);
            }
            else
            {
                out.Fail(kncore::Status::InvalidInput, L"[wfp.error] unknown collection: " + kind);
                break;
            }
            out.Details.Collected.Expected += result.Coverage.Expected;
            out.Details.Collected.Visited += result.Coverage.Visited;
            out.Details.Collected.Read += result.Coverage.Read;
            out.Details.Collected.Decoded += result.Coverage.Decoded;
            out.Details.Collected.Complete = out.Details.Collected.Complete && result.Coverage.Complete;
            out.Details.Collected.StopReason = result.Coverage.StopReason;
            if (result.State != kncore::Status::Success)
            {
                out.Fail(result.State, L"[wfp.error] incomplete " + kind, {L"Win32", result.Error, L"FwpmEnum", L""});
                break;
            }
        }
        out.AddLine(L"[wfp.summary] collected=" + FmtDec(out.Details.Collected.Read) + L" displayed=" + FmtDec(displayed) + L" complete=" +
                    (out.Details.Collected.Complete ? L"true" : L"false"));
    } while (false);
}

// ---- !ci ----

void ScanCodeIntegrity(Ctx &ctx)
{
    const bool explicitHost = ctx.Args.size() == 2 && _wcsicmp(ctx.Args[1].c_str(), L"/host") == 0;
    const auto stamp = ctx.ExpectedStamp != nullptr ? *ctx.ExpectedStamp : ctx.Session.RefreshStamp();
    if (!explicitHost && !SessionIsLocalLiveKernel(ctx.Session))
    {
        ctx.Out.Fail(kncore::Status::Unsupported,
                     L"Code integrity requires verified local kernel context; use !ci /host to explicitly inspect the debugger host");
        return;
    }
    ctx.Out.Details = kncore::CodeIntegrityReport(knutil::QueryCodeIntegrity());
    ctx.Out.Details.CommandId = L"!ci";
    ctx.Out.Details.Analysis = knjson::Value::MakeObject();
    ctx.Out.Details.Analysis.Set(L"targetCorrelation", knjson::Value(explicitHost ? L"NotRequested" : L"VerifiedLocalKernel"));
    for (const auto &row : ctx.Out.Details.Rows.Items())
    {
        ctx.Out.AddLine(row.Write());
    }
    if (!explicitHost && ctx.Session.RefreshStamp() != stamp)
    {
        ctx.Out.Fail(kncore::Status::StaleContext, L"Local kernel context changed during code integrity collection");
        ctx.Out.Details.Analysis.Set(L"targetCorrelation", knjson::Value(L"ContextChanged"));
    }
    else if (ctx.Out.Details.State == kncore::Status::Unavailable)
    {
        ctx.Out.AddLine(ctx.Out.Details.Error.Message);
    }
}

// ---- !hv ----

void ScanHv(Ctx &ctx)
{
    auto &report = ctx.Out.Details;
    report.Source = L"HostCpuid+TargetRegisters";
    report.Consistency = L"cross-source-nonatomic";
    const auto cpuid = kncore::QueryHypervisorCpuid([](uint32_t leaf, std::array<uint32_t, 4> &values)
    {
        int registers[4] = {};
        __cpuidex(registers, static_cast<int>(leaf), 0);
        for (size_t index = 0; index < 4; ++index)
        {
            values[index] = static_cast<uint32_t>(registers[index]);
        }
        return true;
    });
    const auto host = kncore::HypervisorCpuidRow(cpuid);
    if (!cpuid.Complete)
    {
        ++report.Collected.Unknown;
    }
    report.Rows.Push(host);
    ctx.Out.AddLine(host.Write());
    ULONG64 cr4 = 0;
    const bool known = ctx.Session.ReadRegisterHex(L"cr4", &cr4);
    auto target = knjson::Value::MakeObject();
    target.Set(L"kind", knjson::Value(L"TargetControlRegister"));
    target.Set(L"source", knjson::Value(L"DebuggeeRegister"));
    target.Set(L"scope", knjson::Value(L"Debuggee"));
    target.Set(L"cr4", known ? knjson::Value(kncore::Hex(cr4)) : knjson::Value());
    target.Set(L"bit13", known ? knjson::Value((cr4 & (1 << 13)) != 0) : knjson::Value());
    report.Rows.Push(target);
    ctx.Out.AddLine(target.Write());
    if (!known)
    {
        ++report.Collected.Unknown;
    }
    report.Collected.Complete = report.Collected.Unknown == 0;
    report.Collected.Expected = 2;
    report.Collected.Visited = 2;
    report.Collected.Read = (cpuid.MaximumBasicLeaf ? 1 : 0) + (known ? 1 : 0);
    report.Collected.Decoded = (cpuid.Complete ? 1 : 0) + (known ? 1 : 0);
    report.Collected.StopReason = report.Collected.Complete ? L"PostureObservationComplete" : L"PostureObservationIncomplete";
    report.State = report.Collected.Complete ? kncore::Status::Success : kncore::Status::Partial;
    report.Limitations.Push(knjson::Value(L"Host CPUID is not remote target CPUID. CR4 bit 13 is VMXE on Intel; vendor-specific "
                                          L"interpretation and VBS/protection state are not inferred."));
    report.Limitations.Push(knjson::Value(L"Hypervisor hardware features require the vendor-neutral Hv#1 interface and leaf "
                                          L"0x40000006. A missing or incompatible leaf remains null, not a zero capability mask."));
}

// ---- !dma ----

void ScanDma(Ctx &ctx)
{
    CmdText &out = ctx.Out;

    do
    {
        if (!SessionIsLocalLiveKernel(ctx.Session))
        {
            out.Fail(kncore::Status::Unavailable, HostCollectorRefusal(L"dma"));
            break;
        }

        struct FirmwareTable
        {
            const wchar_t *Label;
            unsigned long Signature;
        };

        FirmwareTable tables[] = {
            {L"DMAR (Intel VT-d)", 'RAMD'},
            {L"IVRS (AMD-Vi)", 'SRVI'},
        };

        for (const FirmwareTable &table : tables)
        {
            const auto observed = knutil::QueryAcpi(table.Signature, GetSystemFirmwareTable, GetLastError);
            auto row = knjson::Value::MakeObject();
            row.Set(L"table", knjson::Value(table.Label));
            row.Set(L"bytes", knjson::Value(std::to_wstring(observed.Bytes)));
            row.Set(L"error", knjson::Value(kncore::Hex(observed.Error)));
            row.Set(L"available", knjson::Value(observed.Bytes != 0));
            out.Details.Rows.Push(row);
            out.Details.Source = L"host-firmware";
            if (observed.Bytes == 0)
            {
                out.Fail(kncore::Status::Partial, L"[dma.firmware] query unavailable: " + std::wstring(table.Label),
                         {L"Win32", observed.Error, L"GetSystemFirmwareTable", L""});
            }
            else
            {
                out.AddLine(L"[dma.firmware] " + std::wstring(table.Label) + L" observed size=" + FmtDec(observed.Bytes));
            }
        }

        out.AddLine(L"[dma.note] firmware data alone cannot confirm that DMA protection is active");
    } while (false);
}

// ---- !byovd ----

void ScanByovd(Ctx &ctx)
{
    if (!SessionIsLocalLiveKernel(ctx.Session))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, HostCollectorRefusal(L"byovd"));
        return;
    }
    wchar_t path[32768] = {};
    const DWORD expanded = ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\kndbgx\\data\\byovd-sha256.json", path, _countof(path));
    if (expanded == 0 || expanded > _countof(path))
    {
        ctx.Out.Fail(kncore::Status::IOError, L"Catalog path cannot be expanded");
        return;
    }
    knutil::FileReader file(path);
    if (!file.IsOpen() || file.Size() == 0 || file.Size() > 8 * 1024 * 1024)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Versioned catalog unavailable: " + std::wstring(path));
        return;
    }
    std::vector<unsigned char> bytes(static_cast<size_t>(file.Size()));
    if (!file.Read(0, bytes))
    {
        ctx.Out.Fail(kncore::Status::IOError, L"Catalog read failed");
        return;
    }
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<const char *>(bytes.data()),
                                           static_cast<int>(bytes.size()), nullptr, 0);
    std::wstring text(static_cast<size_t>(std::max(0, length)), L'\0');
    if (length > 0)
    {
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<const char *>(bytes.data()), static_cast<int>(bytes.size()),
                            text.data(), length);
    }
    knjson::Value catalog;
    std::set<std::wstring> hashes;
    if (length == 0 || !kncore::ParseHashCatalog(text, catalog, hashes))
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"Catalog schema/source/version/digests invalid");
        return;
    }
    ctx.Out.Details.Source = L"HostFiles:Sha256Catalog";
    auto metadata = knjson::Value::MakeObject();
    metadata.Set(L"kind", knjson::Value(L"HashCatalog"));
    metadata.Set(L"source", catalog.Get(L"source"));
    metadata.Set(L"version", catalog.Get(L"version"));
    metadata.Set(L"count", knjson::Value(std::to_wstring(hashes.size())));
    metadata.Set(L"catalogSha256", knjson::Value(knutil::Sha256File(path).Digest));
    ctx.Out.Details.Rows.Push(metadata);
    ctx.Out.AddLine(metadata.Write());
    if (ctx.Args.size() > 1)
    {
        ctx.Out.Details.Collected.Complete = true;
        return;
    }
    std::vector<knengine::KernelModuleInfo> modules;
    if (!knengine::EnumerateKernelModules(ctx.Session, &modules))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Module enumeration unavailable");
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    ctx.Out.Details.Collected.Expected = modules.size();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    for (const auto &module : modules)
    {
        if (ctx.Session.Cancelled() || std::chrono::steady_clock::now() >= deadline)
        {
            ctx.Out.Fail(ctx.Session.Cancelled() ? kncore::Status::Cancelled : kncore::Status::Partial,
                         L"Hash collection cancelled or budget exhausted");
            break;
        }
        ++ctx.Out.Details.Collected.Visited;
        knutil::FileReader imageFile(module.ImageName);
        const auto identity = layout.Identity(module.ModuleName.c_str());
        std::vector<unsigned char> header(static_cast<size_t>(std::min<uint64_t>(65536, imageFile.Size())));
        kncore::PeImage pe;
        bool matches = imageFile.IsOpen() && imageFile.Read(0, header) && bool(kncore::ParsePeHeaders(header, &pe, imageFile.Size())) &&
                       identity && pe.File.TimeDateStamp == identity->Timestamp && pe.ImageSize == identity->ImageSize &&
                       pe.File.Machine == identity->Machine;
        const auto cv = matches ? kncore::CodeViewIdentity(imageFile, pe, false) : std::nullopt;
        if (cv && identity)
        {
            GUID guid = {};
            uint32_t age = 0;
            std::memcpy(&guid, cv->data(), 16);
            std::memcpy(&age, cv->data() + 16, 4);
            matches = age == identity->PdbAge && _wcsicmp(GuidToText(guid).c_str(), identity->PdbGuid.c_str()) == 0;
        }
        else
        {
            matches = false;
        }
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"ModuleFileCatalogObservation"));
        row.Set(L"module", knjson::Value(module.ModuleName));
        row.Set(L"path", knjson::Value(module.ImageName));
        row.Set(L"imageIdentityMatches", knjson::Value(matches));
        const auto hash = matches ? knutil::Sha256File(module.ImageName,
                                                       [&]() -> DWORD
                                                       {
                                                           return ctx.Session.Cancelled()                        ? ERROR_CANCELLED
                                                                  : std::chrono::steady_clock::now() >= deadline ? ERROR_TIMEOUT
                                                                                                                 : ERROR_SUCCESS;
                                                       })
                                  : knutil::HashResult();
        row.Set(L"sha256", hash.State == kncore::Status::Success ? knjson::Value(hash.Digest) : knjson::Value());
        row.Set(L"catalogMatch", hash.State == kncore::Status::Success ? knjson::Value(hashes.contains(hash.Digest)) : knjson::Value());
        ctx.Out.Details.Rows.Push(row);
        ctx.Out.AddLine(row.Write());
        if (hash.State == kncore::Status::Success)
        {
            ++ctx.Out.Details.Collected.Read;
        }
        else
        {
            ++ctx.Out.Details.Collected.Unknown;
        }
    }
    ctx.Out.Details.Collected.Complete = ctx.Out.Details.State == kncore::Status::Success && ctx.Out.Details.Collected.Unknown == 0;
    if (ctx.Out.Details.State == kncore::Status::Success && !ctx.Out.Details.Collected.Complete)
    {
        ctx.Out.Details.State = kncore::Status::Partial;
    }
    ctx.Out.Details.Limitations.Push(
        knjson::Value(L"File hash matches the supplied catalog; this does not establish exploitability or check the loaded image. "
                      L"The identity and hash checks use read-only file handles that prevent file replacement."));
}

// ---- !fwtable ----

void ScanFwtable(Ctx &ctx)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:FirmwareProviders"))
    {
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    const auto head = SymbolAddress(ctx.Session, layout, L"nt", L"ExpFirmwareTableProviderListHead");
    auto links = layout.Field(L"nt", L"_SYSTEM_FIRMWARE_TABLE_HANDLER", L"FirmwareTableProviderList");
    auto callback = layout.Field(L"nt", L"_SYSTEM_FIRMWARE_TABLE_HANDLER", L"FirmwareTableHandler");
    auto signature = layout.Field(L"nt", L"_SYSTEM_FIRMWARE_TABLE_HANDLER", L"ProviderSignature");
    bool compatible = true;
    if ((!links || !callback || !signature) && layout.VerifyProfile(kncore::KernelLayoutFamily::Firmware))
    {
        compatible = layout.CanProfileField(L"nt", L"_SYSTEM_FIRMWARE_TABLE_HANDLER", L"FirmwareTableProviderList") &&
                     layout.CanProfileField(L"nt", L"_SYSTEM_FIRMWARE_TABLE_HANDLER", L"FirmwareTableHandler") &&
                     layout.CanProfileField(L"nt", L"_SYSTEM_FIRMWARE_TABLE_HANDLER", L"ProviderSignature") &&
                     kncore::ApplyKernelProfileField(links, 0x18, 16) && kncore::ApplyKernelProfileField(callback, 8, 8) &&
                     kncore::ApplyKernelProfileField(signature, 0, 4);
        budget.Report.LayoutProfile = kncore::KernelSymbolProfileId;
    }
    if (!compatible || !head || !links || links->Size != 16 || !callback || callback->Size != 8)
    {
        UnknownScope(ctx, budget, L"FirmwareProviders",
                     L"Named provider record/link layout unavailable; byte-pattern guesses are not used");
    }
    else
    {
        const auto owners = knengine::CollectOwnershipIndex(ctx.Session);
        kncore::WalkList(ctx.Session, *head, architecture, budget,
                         [&](uint64_t node)
                         {
                             if (node < links->Offset)
                             {
                                 return kncore::VisitDecision::Failed;
                             }
                             const auto record = node - links->Offset;
                             auto row = kncore::RoutineObservation(budget.Report, architecture, owners, L"FirmwareProvider", node,
                                                                   kncore::ReadField(ctx.Session, record, callback));
                             const auto provider = kncore::ReadField(ctx.Session, record, signature);
                             row.Set(L"signature", kncore::OptionalNumber(provider, true));
                             if (!provider)
                             {
                                 ++budget.Report.Collected.Unknown;
                             }
                             EmitRow(ctx, budget, row);
                             return kncore::VisitDecision::Continue;
                         });
    }
    FinishCollection(ctx, budget);
}
} // namespace kncmd
