#include "CollectorSupport.h"
#include "../core/WfpProfile.h"
#include "../core/WfpRead.h"

namespace kncmd
{

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
        if (kind != L"filters" && kind != L"callouts")
        {
            ctx.Out.Fail(kind == L"providers" || kind == L"sublayers" || kind == L"layers" ? Status::Unsupported : Status::InvalidInput,
                         L"[wfp] Remote/dump runtime collection supports filters and callouts; BFE management collections require local KD.");
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
        budget.Report.Limitations.Push(knjson::Value(L"Target runtime inventory, not BFE management inventory or an effective packet verdict. This collector does not recover BFE display names, filter/provider/sublayer GUIDs or descriptions; provider context remains an opaque target pointer."));
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
                EmitRow(ctx, budget, row, 20);
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
                    EmitRow(ctx, budget, row, 20);
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
        budget.Report.Analysis = analysis;
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
    } while (false);
    FinishCollection(ctx, budget);
}
} // namespace kncmd
