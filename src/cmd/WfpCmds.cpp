#include "CollectorSupport.h"
#include "../core/WfpProfile.h"
#include "../core/WfpRead.h"
#include "../core/BfeRead.h"
#include "../engine/ContextGuard.h"

namespace kncmd
{
namespace
{
void CollectBfeMetadata(Ctx &ctx, const kncore::TargetArchitecture &architecture, kncore::WalkBudget &budget,
                        std::vector<kncore::BfeRecord> &records, knjson::Value &analysis)
{
    using namespace kncore;
    knengine::ContextGuard restore(ctx.Session);
    knengine::LayoutResolver layout(ctx.Session);
    uint64_t process = 0;
    uint64_t module = 0;
    uint64_t pid = 0;
    uint64_t candidates = 0;
    bool profileVerified = false;
    do
    {
        if (!restore.Valid())
        {
            budget.Stop(Status::Unavailable, L"BfeContextCaptureFailed");
            break;
        }
        const auto pebField = layout.Field(L"nt", L"_EPROCESS", L"Peb");
        const auto ldrField = layout.Field(L"nt", L"_PEB", L"Ldr");
        const auto listField = layout.Field(L"nt", L"_PEB_LDR_DATA", L"InLoadOrderModuleList");
        const auto linksField = layout.Field(L"nt", L"_LDR_DATA_TABLE_ENTRY", L"InLoadOrderLinks");
        const auto baseField = layout.Field(L"nt", L"_LDR_DATA_TABLE_ENTRY", L"DllBase");
        const auto nameField = layout.Field(L"nt", L"_LDR_DATA_TABLE_ENTRY", L"BaseDllName");
        if (!pebField || pebField->Size != 8 || !ldrField || ldrField->Offset != 0x18 || ldrField->Size != 8 ||
            !listField || listField->Offset != 0x10 || !linksField || linksField->Offset != 0 ||
            !baseField || baseField->Offset != 0x30 || baseField->Size != 8 ||
            !nameField || nameField->Offset != 0x58 || nameField->Size != 16)
        {
            budget.Stop(Status::Unavailable, L"BfeProcessLayoutUnavailable");
            break;
        }
        std::vector<ProcRow> processes;
        CmdText inventory;
        CollectProcesses(ctx.Session, layout, &processes, inventory);
        if (inventory.Details.State != Status::Success || !inventory.Details.Collected.Complete)
        {
            budget.Stop(inventory.Details.State == Status::Cancelled ? Status::Cancelled : Status::Unavailable,
                        L"BfeProcessInventoryIncomplete");
            break;
        }
        const auto translate = [&](uint64_t address) -> std::optional<uint64_t>
        {
            ULONG64 physical = 0;
            return ctx.Session.TranslateVirtual(address, &physical) ? std::optional<uint64_t>(physical) : std::nullopt;
        };
        BfeProcessReader processMemory(ctx.Session, translate);
        BfeReader read(processMemory, budget);
        bool discoveryComplete = true;
        for (const auto &candidate : processes)
        {
            if (_wcsicmp(candidate.Image.c_str(), L"svchost.exe") != 0)
            {
                continue;
            }
            if (!read.Check())
            {
                break;
            }
            ++candidates;
            const auto peb = ReadField(ctx.Session, candidate.Eprocess, pebField);
            if (!peb || *peb == 0 || ctx.Session.SystemObjects()->SetImplicitProcessDataOffset(candidate.Eprocess) != S_OK)
            {
                discoveryComplete = false;
                continue;
            }
            WalkBudget probe;
            probe.Cancelled = budget.Cancelled;
            probe.StartTraversal();
            probe.Deadline = budget.Deadline;
            BfeProcessReader candidateMemory(ctx.Session, translate);
            BfeReader candidateRead(candidateMemory, probe);
            const auto base = FindBfeModule(candidateRead, *peb);
            if (!base)
            {
                if (probe.Report.State == Status::Cancelled)
                {
                    budget.Stop(Status::Cancelled, L"Cancelled");
                    break;
                }
                discoveryComplete = false;
                continue;
            }
            if (*base != 0)
            {
                if (process != 0)
                {
                    budget.Stop(Status::Unavailable, L"BfeProcessAmbiguous");
                    break;
                }
                process = candidate.Eprocess;
                pid = candidate.Pid;
                module = *base;
            }
        }
        if (budget.Stopped)
        {
            break;
        }
        if (process == 0 || !discoveryComplete)
        {
            budget.Stop(Status::Unavailable, discoveryComplete ? L"BfeServiceNotFound" : L"BfeProcessDiscoveryIncomplete");
            break;
        }
        if (ctx.Session.SystemObjects()->SetImplicitProcessDataOffset(process) != S_OK)
        {
            budget.Stop(Status::Unavailable, L"BfeProcessContextFailed");
            break;
        }
        if (!VerifyBfeImage(read, module))
        {
            break;
        }
        profileVerified = true;
        const auto manager = read.Integer(module + 0xf6770);
        if (!manager)
        {
            break;
        }
        for (const auto type : {0u, 2u, 3u, 4u, 5u})
        {
            std::vector<BfeRecord> tableRecords;
            if (!ReadBfeTable(read, architecture, module, *manager, type, tableRecords))
            {
                break;
            }
            records.insert(records.end(), std::make_move_iterator(tableRecords.begin()), std::make_move_iterator(tableRecords.end()));
        }
        if (!budget.Stopped)
        {
            const auto finalManager = read.Integer(module + 0xf6770);
            if (!finalManager || finalManager != manager)
            {
                if (!budget.Stopped)
                {
                    budget.Stop(Status::Partial, L"BfeManagerChanged");
                }
                records.clear();
            }
        }
    } while (false);
    if (!restore.Restore())
    {
        budget.Stop(Status::InternalFault, L"BfeContextRestoreFailed");
    }
    if (!budget.Stopped && budget.Report.Collected.Unknown != 0)
    {
        budget.Stop(Status::Partial, L"BfeTextUnavailable");
    }
    budget.Complete();
    analysis.Set(L"bfeState", knjson::Value(StatusName(budget.Report.State)));
    analysis.Set(L"bfeReason", knjson::Value(budget.Report.Collected.StopReason));
    analysis.Set(L"bfeProfile", profileVerified ? knjson::Value(BfeProfileId) : knjson::Value());
    analysis.Set(L"bfeProcess", process ? knjson::Value(Hex(process)) : knjson::Value());
    analysis.Set(L"bfePid", process ? knjson::Value(std::to_wstring(pid)) : knjson::Value());
    analysis.Set(L"bfeRecords", knjson::Value(std::to_wstring(records.size())));
    analysis.Set(L"bfeProcessCandidates", knjson::Value(std::to_wstring(candidates)));
    ctx.Out.AddLine(L"[wfp.bfe.discovery] candidates=" + std::to_wstring(candidates));
}
} // namespace

void ScanTargetWfp(Ctx &ctx)
{
    using namespace kncore;
    std::set<std::wstring> kinds(ctx.Args.begin() + 1, ctx.Args.end());
    if (kinds.empty())
    {
        kinds.insert(L"filters");
    }
    for (const auto &kind : kinds)
    {
        if (kind != L"filters" && kind != L"callouts" && kind != L"providers" && kind != L"sublayers" && kind != L"layers")
        {
            ctx.Out.Fail(Status::InvalidInput, L"[wfp] Unknown collection.");
            return;
        }
    }
    WalkBudget budget;
    budget.MaxNodes = 131072;
    TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:WFP-NETIO-fwpkclnt"))
    {
        return;
    }
    CollectorWalk walk;
    knengine::LayoutResolver layout(ctx.Session);
    WfpReader read(ctx.Session, architecture, budget);
    uint64_t globalSymbol = 0;
    uint64_t keyRoot = 0;
    do
    {
        for (const auto module : {L"NETIO", L"fwpkclnt", L"nt"})
        {
            const auto identity = layout.Identity(module);
            const auto reason = identity ? VerifyWfpProfile(ctx.Session, *identity, module, [&](const wchar_t *symbol)
            {
                return layout.Address(module, symbol);
            }) : L"WfpModuleIdentityUnavailable";
            if (std::wstring_view(reason) != L"Verified")
            {
                budget.Stop(Status::Unavailable, reason);
                ctx.Out.AddLine(L"[wfp.profile] " + std::wstring(module) + L": " + reason + L"; " + layout.Diagnostic());
                break;
            }
            if (std::wstring_view(module) == L"NETIO")
            {
                globalSymbol = identity->Base + 0x99a98;
            }
            if (std::wstring_view(module) == L"fwpkclnt")
            {
                keyRoot = identity->Base + 0x498a0;
            }
        }
        if (budget.Stopped)
        {
            break;
        }
        budget.Report.LayoutProfile = WfpProfileId;
        budget.Report.Limitations.Push(knjson::Value(L"Filters/callouts are runtime inventory enriched from the target BFE service, not an effective packet verdict. BFE-only filters are counted separately. Provider context remains an opaque target pointer."));
        budget.Report.Limitations.Push(knjson::Value(L"BFE enrichment requires resident user pages in a unique svchost.exe hosting the verified bfe.dll. Indirect resource strings are preserved verbatim, without host localization. Absent and empty descriptions are distinct."));
        budget.Report.Limitations.Push(knjson::Value(L"Callout layer is reported only for a present runtime policy entry; registration-only slots can contain an unassigned zero layer. Condition values are bounded to 4096 bytes, 1024 conditions per filter."));
        const auto global = read.Integer(globalSymbol, 8);
        const auto roots = global ? read.Bytes(*global + 0x178, 0x30) : std::nullopt;
        const auto keyRoots = read.Bytes(keyRoot + 0x38, 0x10);
        if (!roots || !keyRoots)
        {
            break;
        }
        const auto layerCount = static_cast<uint32_t>(WfpInteger(*roots, 8, 2));
        const auto hash = WfpInteger(*roots, 0x10, 8);
        const auto nameSpace = static_cast<uint32_t>(WfpInteger(*roots, 0x18, 4));
        const auto capacity = static_cast<uint32_t>(WfpInteger(*roots, 0x20, 4));
        const auto table = WfpInteger(*roots, 0x28, 8);
        const auto keyCapacity = static_cast<uint32_t>(WfpInteger(*keyRoots, 0, 4));
        const auto keyTable = WfpInteger(*keyRoots, 8, 8);
        if (layerCount == 0 || layerCount > 4096)
        {
            budget.Stop(Status::Partial, L"WfpInvalidLayerCount");
            break;
        }
        std::map<uint32_t, WfpCallout> callouts;
        const bool calloutsComplete = ReadWfpCallouts(read, table, capacity, keyTable, keyCapacity, layerCount, callouts);
        if (kinds.contains(L"callouts"))
        {
            for (const auto &[id, callout] : callouts)
            {
                auto row = knjson::Value::MakeObject();
                row.Set(L"kind", knjson::Value(L"callouts"));
                row.Set(L"source", knjson::Value(L"DebugTargetRuntime"));
                row.Set(L"nameState", knjson::Value(L"NotInRuntimeSchema"));
                row.Set(L"address", knjson::Value(Hex(table + uint64_t(id) * 0x60)));
                WfpSetCalloutFields(row, callout);
                row.Set(L"flags", knjson::Value(Hex(callout.Flags)));
                row.Set(L"registrationFlags", knjson::Value(Hex(callout.KeyFlags)));
                row.Set(L"layerIdRaw", knjson::Value(std::to_wstring(callout.Layer)));
                row.Set(L"layerId", callout.Added ? knjson::Value(std::to_wstring(callout.Layer)) : knjson::Value());
                row.Set(L"layerName", callout.Added ? knjson::Value(WfpLayerName(callout.Layer)) : knjson::Value(L"NotAssigned"));
                if (!read.Retain(row, false))
                {
                    break;
                }
                EmitRow(ctx, budget, row, 0);
                ++budget.Report.Collected.Decoded;
            }
        }
        uint64_t physicalNodes = 0;
        uint64_t otherNodes = 0;
        uint64_t filters = 0;
        if (calloutsComplete && kinds.contains(L"filters"))
        {
            WalkWfpFilters(read, hash, nameSpace, layerCount, [&](const WfpHashEntry &entry)
            {
                knjson::Value row;
                const auto ok = ReadWfpFilter(read, entry, callouts, row);
                if (!row.IsNull() && read.Retain(row, false))
                {
                    EmitRow(ctx, budget, row, 0);
                    ++filters;
                    ++budget.Report.Collected.Decoded;
                }
                return ok && !budget.Stopped;
            }, physicalNodes, otherNodes);
        }
        auto analysis = knjson::Value::MakeObject();
        analysis.Set(L"scope", knjson::Value(L"DebugTargetRuntime"));
        analysis.Set(L"filterCount", kinds.contains(L"filters") ? knjson::Value(std::to_wstring(filters)) : knjson::Value());
        analysis.Set(L"calloutCount", knjson::Value(std::to_wstring(callouts.size())));
        analysis.Set(L"calloutCapacity", knjson::Value(std::to_wstring(capacity)));
        analysis.Set(L"hashNodes", knjson::Value(std::to_wstring(physicalNodes)));
        analysis.Set(L"otherNamespaceNodes", knjson::Value(std::to_wstring(otherNodes)));
        analysis.Set(L"filterNamespace", knjson::Value(std::to_wstring(nameSpace)));
        ctx.Out.AddLine(L"[wfp.runtime] filters=" + (kinds.contains(L"filters") ? std::to_wstring(filters) : L"not-requested") + L" callouts=" + std::to_wstring(callouts.size()) +
                        L" hashNodes=" + std::to_wstring(physicalNodes) + L" otherNamespaces=" + std::to_wstring(otherNodes));
        if (!budget.Stopped)
        {
            const auto finalGlobal = read.Integer(globalSymbol, 8);
            const auto finalRoots = read.Bytes(*global + 0x178, 0x30);
            const auto finalKeys = read.Bytes(keyRoot + 0x38, 0x10);
            if (!finalGlobal || finalGlobal != global || !finalRoots || *finalRoots != *roots || !finalKeys || *finalKeys != *keyRoots)
            {
                if (!budget.Stopped)
                {
                    budget.Stop(Status::Partial, L"WfpRootsChangedDuringRead");
                }
            }
        }
        if (!budget.Stopped)
        {
            WalkBudget bfeBudget;
            bfeBudget.Cancelled = budget.Cancelled;
            bfeBudget.MaxNodes = 65536;
            std::vector<BfeRecord> records;
            CollectBfeMetadata(ctx, architecture, bfeBudget, records, analysis);
            const bool complete = bfeBudget.Report.Collected.Complete;
            budget.Report.Collected.Expected += bfeBudget.Report.Collected.Expected;
            budget.Report.Collected.Visited += bfeBudget.Report.Collected.Visited;
            budget.Report.Collected.Read += bfeBudget.Report.Collected.Read;
            budget.Report.Collected.Decoded += bfeBudget.Report.Collected.Decoded;
            budget.Report.Collected.Unknown += bfeBudget.Report.Collected.Unknown;
            budget.Report.Collected.Unreadable += bfeBudget.Report.Collected.Unreadable;
            if (!analysis.Get(L"bfeProfile").IsNull())
            {
                budget.Report.LayoutProfile += L";" + std::wstring(BfeProfileId);
            }
            auto enriched = knjson::Value::MakeArray();
            uint64_t matched = 0;
            uint64_t managementFilters = 0;
            uint64_t matchedFilters = 0;
            bool mismatch = false;
            read.RowUnits = 0;
            for (auto row : budget.Report.Rows.Items())
            {
                mismatch = !EnrichBfeRow(row, records, complete) || mismatch;
                if (row.Get(L"managementState").AsString(L"") == L"Matched")
                {
                    ++matched;
                    matchedFilters += row.Get(L"kind").AsString(L"") == L"filters";
                }
                if (read.Retain(row, false))
                {
                    enriched.Push(row);
                }
            }
            for (const auto &record : records)
            {
                managementFilters += record.Type == 5;
                if (record.Type <= 3 && kinds.contains(record.Row.Get(L"kind").AsString(L"")))
                {
                    auto row = record.Row;
                    if (record.Type == 2)
                    {
                        BfeJoinReference(row, records, 0, L"providerKey", L"provider", complete);
                    }
                    if (read.Retain(row, false))
                    {
                        enriched.Push(row);
                    }
                }
            }
            budget.Report.Rows = enriched;
            analysis.Set(L"bfeMatchedRows", knjson::Value(std::to_wstring(matched)));
            analysis.Set(L"bfeFilterCount", knjson::Value(std::to_wstring(managementFilters)));
            analysis.Set(L"bfeFiltersWithoutRuntimeMatch", kinds.contains(L"filters") && complete ?
                         knjson::Value(std::to_wstring(managementFilters - matchedFilters)) : knjson::Value());
            if (!complete || mismatch)
            {
                const auto state = bfeBudget.Report.State;
                budget.Stop(state == Status::Cancelled || state == Status::InternalFault ? state : Status::Partial,
                            mismatch ? L"BfeRuntimeIdentityMismatch" : L"BfeMetadataIncomplete");
            }
            ctx.Out.AddLine(L"[wfp.bfe] records=" + std::to_wstring(records.size()) + L" matched=" + std::to_wstring(matched) +
                            L" state=" + StatusName(bfeBudget.Report.State) + L" reason=" + bfeBudget.Report.Collected.StopReason);
        }
        budget.Report.Analysis = analysis;
        size_t displayed = 0;
        for (const auto &row : budget.Report.Rows.Items())
        {
            if (++displayed > 20)
            {
                break;
            }
            ctx.Out.AddLine(row.Write());
        }
    } while (false);
    FinishCollection(ctx, budget);
}
} // namespace kncmd
