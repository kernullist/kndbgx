#include "CollectorSupport.h"
#include "../core/Win32kPolicy.h"
#include "../util/SnapshotStore.h"

namespace kncmd
{
void ScanWin32kPolicy(Ctx &ctx, const std::wstring &selector)
{
    CollectorWalk collection;
    knengine::LayoutResolver layout(ctx.Session);
    std::vector<ProcRow> processes;
    CmdText inventory;
    if (selector.empty())
    {
        if (!CollectProcesses(ctx.Session, layout, &processes, inventory))
        {
            ReportProcessSelectionFailure(inventory, ctx.Out);
            return;
        }
    }
    else
    {
        ProcRow process;
        if (!ResolveSelectedProcess(ctx, layout, selector, process))
        {
            return;
        }
        processes.push_back(process);
    }
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:Win32kProcessFilterPolicy"))
    {
        return;
    }
    const auto nt = layout.Identity(L"nt");
    const auto image = layout.Identity(L"win32k");
    const auto base = layout.Identity(L"win32kbase");
    const auto descriptorAddress = layout.Address(L"nt", L"KeServiceDescriptorTableFilter");
    std::optional<kncore::ServiceDescriptor> descriptor;
    const auto hash = [](std::span<const unsigned char> bytes)
    {
        return knutil::Sha256Bytes(bytes);
    };
    const auto fieldMatches = [&](const wchar_t *name, uint32_t offset, uint32_t size, kncore::FieldKind kind)
    {
        const auto field = layout.Field(L"nt", L"_EPROCESS", name);
        return field && field->Offset == offset && field->Size == size && field->Kind == kind &&
            !field->BitOffset && !field->BitWidth && field->ValidFor(0x840);
    };
    const bool fields = fieldMatches(L"Win32KFilterSet", 0x6e8, 4, kncore::FieldKind::Unsigned) &&
        fieldMatches(L"MitigationFlags", 0x750, 4, kncore::FieldKind::Unsigned) &&
        fieldMatches(L"Flags3", 0x5fc, 4, kncore::FieldKind::Unsigned) &&
        fieldMatches(L"Session", 0x2e8, 8, kncore::FieldKind::Pointer) &&
        fieldMatches(L"UniqueProcessId", 0x1d0, 8, kncore::FieldKind::Pointer);
    const auto created = layout.Field(L"nt", L"_EPROCESS", L"CreateTime");
    const bool createdMatches = created && created->Offset == 0x1f8 && created->Size == 8 && !created->BitOffset && !created->BitWidth;
    uint32_t limit = 0;
    bool verified = nt && image && base && fields && createdMatches && descriptorAddress &&
        layout.VerifyProfile(kncore::KernelLayoutFamily::FilteredService) &&
        layout.VerifyProfile(kncore::KernelLayoutFamily::Win32kDispatch) &&
        kncore::VerifyWin32kPolicyProfile(ctx.Session, *nt, *image, *base,
            [&](const wchar_t *module, const wchar_t *symbol)
            {
                return layout.Address(module, symbol);
            }, hash) &&
        ctx.Session.ReadExact(kncore::AddressSpace::Virtual, image->Base + 0xa5074, &limit) && limit == 1497;
    if (verified)
    {
        descriptor = kncore::ReadServiceDescriptor(ctx.Session, *descriptorAddress + 32);
        verified = descriptor && kncore::ServiceDescriptorMatches(*descriptor, image->Base + 0xa3330, limit, image->Base + 0xa5078);
    }
    if (!verified)
    {
        UnknownScope(ctx, budget, L"Win32kProcessFilterPolicy", L"Matched NT/win32k/win32kbase identity, PDB fields, filter code, descriptor or extent unavailable");
        FinishCollection(ctx, budget);
        return;
    }
    if (processes.size() > 4096)
    {
        processes.resize(4096);
        UnknownScope(ctx, budget, L"Win32kPolicyProcesses", L"Process policy inventory capped at 4096 records");
    }
    if (selector.empty() && !inventory.Details.Collected.Complete)
    {
        UnknownScope(ctx, budget, L"Win32kPolicyProcesses", L"Process inventory incomplete: " + inventory.Details.Collected.StopReason);
    }
    budget.StartTraversal(std::chrono::steady_clock::now(), std::chrono::seconds(120));
    kncore::NamespaceReadMeter measured(ctx.Session);
    kncore::Win32kPolicySnapshot snapshot;
    snapshot.Capture(measured, architecture, processes, image->Base, nt->Base, base->Base, budget, hash);
    budget.Report.Collected.Expected = processes.size() * (selector.empty() ? 1 : 1497);
    for (const auto &process : processes)
    {
        if (!kncore::CheckWalkDeadline(budget))
        {
            break;
        }
        const auto policy = kncore::ReadWin32kProcessPolicy(snapshot.Memory, architecture, process);
        const auto session = snapshot.Session(policy);
        auto summary = kncore::Win32kPolicyRow(policy, session);
        uint64_t allowed = 0, blocked = 0, audited = 0, unknown = 0, notApplicable = 0;
        for (uint32_t index = 0; index < 1497 && kncore::CheckWalkDeadline(budget); ++index)
        {
            const auto decision = kncore::EvaluateWin32kPolicy(policy, session, index, snapshot.Verified[index]);
            const std::wstring_view value(decision.Value);
            allowed += value == L"Allowed";
            blocked += value == L"Blocked";
            audited += value == L"Audit only";
            unknown += value == L"Unknown";
            notApplicable += value == L"Not applicable";
            if (!selector.empty())
            {
                auto row = summary;
                row.Set(L"kind", knjson::Value(L"Win32kServicePolicy"));
                row.Set(L"serviceName", knjson::Value(kncore::Win32kRoutes[index].Name));
                row.Set(L"serviceId", knjson::Value(kncore::Hex(0x1000 + index)));
                row.Set(L"index", knjson::Value(std::to_wstring(index)));
                row.Set(L"filterDecision", knjson::Value(decision.Value));
                row.Set(L"policyReason", knjson::Value(decision.Reason));
                row.Set(L"filterBit", decision.Bit ? knjson::Value(*decision.Bit) : knjson::Value());
                row.Set(L"entryRoutine", knjson::Value(kncore::Hex(image->Base + 0x2fcc0 + uint64_t(index) * 176)));
                const auto rawReturn = snapshot.Memory.Number(image->Base + 0xa4a94 + index, 1);
                row.Set(L"filteredReturn", snapshot.Verified[index] && rawReturn ?
                    knjson::Value(kncore::Hex(kncore::FilteredServiceReturn(static_cast<uint8_t>(*rawReturn)))) : knjson::Value());
                ++budget.Report.Collected.Visited;
                ++budget.Report.Collected.Read;
                budget.Report.Collected.Decoded += value != L"Unknown";
                budget.Report.Collected.Unknown += value == L"Unknown";
                EmitRow(ctx, budget, row);
            }
        }
        if (selector.empty() && kncore::CheckWalkDeadline(budget))
        {
            summary.Set(L"allowedServices", knjson::Value(std::to_wstring(allowed)));
            summary.Set(L"blockedServices", knjson::Value(std::to_wstring(blocked)));
            summary.Set(L"auditServices", knjson::Value(std::to_wstring(audited)));
            summary.Set(L"unknownServices", knjson::Value(std::to_wstring(unknown)));
            summary.Set(L"notApplicableServices", knjson::Value(std::to_wstring(notApplicable)));
            ++budget.Report.Collected.Visited;
            ++budget.Report.Collected.Read;
            budget.Report.Collected.Decoded += unknown == 0;
            budget.Report.Collected.Unknown += unknown != 0;
            EmitRow(ctx, budget, summary);
        }
    }
    snapshot.Recheck(measured, architecture, budget);
    if (kncore::CheckWalkDeadline(budget))
    {
        kncore::RecheckServiceDescriptor(ctx.Session, *descriptorAddress + 32, *descriptor, budget);
    }
    kncore::RecheckServiceLimit(ctx.Session, image->Base + 0xa5074, limit, budget, L"Win32kPolicyServiceLimitChanged");
    budget.Report.Analysis = knjson::Value::MakeObject();
    budget.Report.Analysis.Set(L"policyTargetReads", knjson::Value(std::to_wstring(measured.Requests)));
    budget.Report.Analysis.Set(L"policyRequestedBytes", knjson::Value(std::to_wstring(measured.Bytes)));
    budget.Report.Limitations.Push(knjson::Value(L"Allowed, Blocked and Audit only describe the selected process's filtered-service policy, "
        L"not syscall success. GUI conversion (win32kDisable/win32kDisableAudit), the calling thread's RestrictedGuiThread bit, "
        L"implementation registration, arguments and other access checks are separate. No syscall is executed and no process context is switched. "
        L"Policy collection is bounded to 4096 processes, 256 session slots and 120 seconds; missing evidence remains Unknown."));
    FinishCollection(ctx, budget);
}
} // namespace kncmd
