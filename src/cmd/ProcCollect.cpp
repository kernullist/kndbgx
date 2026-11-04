#include "ProcCollect.h"
#include <dbgeng.h>
#include "../engine/PageWalk.h"
#include "../engine/ObjectDirectory.h"

namespace kncmd
{
bool KernelArchitecture(knengine::DbgSession &session, kncore::TargetArchitecture *architecture)
{
    knengine::SessionStatus status = {};
    session.QueryStatus(&status);
    ULONG64 cr4 = 0;
    const bool known = architecture != nullptr && status.KernelMode && status.Architecture == IMAGE_FILE_MACHINE_AMD64 &&
                       session.ReadRegisterHex(L"cr4", &cr4);
    if (known)
    {
        *architecture = {IMAGE_FILE_MACHINE_AMD64, 8, knengine::Cr4HasLa57(cr4) ? 57u : 48u, {}};
    }
    return known;
}

kncore::ProcessLayout ResolveProcessLayout(knengine::LayoutResolver &layout)
{
    kncore::ProcessLayout fields;
    fields.Links = layout.Field(L"nt", L"_EPROCESS", L"ActiveProcessLinks");
    if (!fields.Links)
    {
        fields.LinksDiagnostic = layout.Diagnostic();
    }
    fields.Pid = layout.Field(L"nt", L"_EPROCESS", L"UniqueProcessId");
    fields.Image = layout.Field(L"nt", L"_EPROCESS", L"ImageFileName");
    fields.CreateTime = layout.Field(L"nt", L"_EPROCESS", L"CreateTime");
    fields.Dtb = kncore::NestedField(layout.Field(L"nt", L"_EPROCESS", L"Pcb"), layout.Field(L"nt", L"_KPROCESS", L"DirectoryTableBase"));
    const auto identity = layout.Identity(L"nt");
    if (identity)
    {
        fields.Profile = identity->Key();
    }
    return fields;
}

bool CollectProcesses(knengine::DbgSession &session, knengine::LayoutResolver &layout, std::vector<ProcRow> *rows, CmdText &out)
{
    kncore::TargetArchitecture architecture;
    const auto head = layout.Address(L"nt", L"PsActiveProcessHead");
    if (rows == nullptr || !KernelArchitecture(session, &architecture) || !head)
    {
        out.Fail(kncore::Status::Unavailable, L"[proc] target architecture or process list symbol unavailable");
        return false;
    }
    kncore::WalkBudget budget;
    budget.Report.CommandId = out.Details.CommandId;
    budget.Report.Stamp = session.RefreshStamp();
    budget.Report.Source = L"TargetMemory:PsActiveProcessHead";
    knengine::SessionStatus status = {};
    session.QueryStatus(&status);
    budget.Report.Consistency = status.DumpFile ? L"dump" : status.Stopped ? L"stopped" : L"live-nonatomic";
    budget.Cancelled = [&session]()
    {
        return session.Cancelled();
    };
    const auto fields = ResolveProcessLayout(layout);
    kncore::CollectProcessList(session, *head, fields, architecture, budget, *rows);
    if (!(budget.Report.Stamp == session.RefreshStamp()))
    {
        budget.Stop(kncore::Status::StaleContext, L"ProcessCollectionContextChanged");
    }
    out.Details = budget.Report;
    if (out.Details.State != kncore::Status::Success)
    {
        out.AddLine(L"[proc.coverage] " + out.Details.Collected.StopReason);
        if (out.Details.Collected.StopReason == L"ProcessListLayoutUnavailable")
        {
            out.AddLine(L"[proc.layout] " + out.Details.Error.Message);
        }
        if (out.Details.Collected.StopReason == L"NullBeforeListSentinel")
        {
            // Insider builds observed linking PsActiveProcessHead only late
            // in boot: the list head stays zero-linked while boot/system
            // drivers load, and kd's own !process fails the same way.
            out.AddLine(L"[proc] process list head is zero-linked; target may be early in boot, continue and retry");
        }
    }
    return out.Details.State == kncore::Status::Success || out.Details.State == kncore::Status::Partial;
}

bool MatchProcessTarget(const std::vector<ProcRow> &rows, const std::wstring &token, ProcRow *match, bool inventoryComplete)
{
    return kncore::SelectProcess(rows, token, match, inventoryComplete);
}

bool CurrentKernelThread(Ctx &ctx, uint64_t &thread)
{
    ULONG64 address = 0;
    kncore::TargetArchitecture architecture;
    if (!KernelArchitecture(ctx.Session, &architecture) || !EvalAddress(ctx.Session, L"@$thread", &address) ||
        !architecture.KernelPointer(address))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Current ETHREAD unavailable in debugger context");
        return false;
    }
    thread = address;
    return true;
}

void ReportProcessSelectionFailure(const CmdText &inventory, CmdText &out, const std::wstring &unresolvedSelector)
{
    const auto commandId = out.Details.CommandId;
    const auto requestId = out.Details.RequestId;
    if (&inventory != &out)
    {
        out.Details = inventory.Details;
        out.AddLine(inventory.Text());
    }
    out.Details.CommandId = commandId;
    out.Details.RequestId = requestId;
    out.Details.Rows = knjson::Value::MakeArray();
    out.Details.Findings = knjson::Value::MakeArray();
    out.Details.Limitations.Push(knjson::Value(L"Process selection did not complete; requested records were not collected."));
    if (!unresolvedSelector.empty() &&
        (out.Details.State == kncore::Status::Success || out.Details.State == kncore::Status::Partial))
    {
        out.Fail(out.Details.Collected.Complete ? kncore::Status::InvalidInput : kncore::Status::Unavailable,
                 L"Process selector absent, ambiguous, unreadable or not resolved in partial inventory: " + unresolvedSelector,
                 out.Details.Error);
    }
}

bool ResolveSelectedProcess(Ctx &ctx, knengine::LayoutResolver &layout, const std::wstring &selector, ProcRow &target)
{
    if (selector.empty())
    {
        ULONG64 address = 0;
        kncore::TargetArchitecture architecture;
        if (!KernelArchitecture(ctx.Session, &architecture) || !EvalAddress(ctx.Session, L"@$proc", &address) ||
            !architecture.KernelPointer(address) ||
            !kncore::ReadProcess(ctx.Session, address, ResolveProcessLayout(layout), target) || target.Pid > UINT32_MAX)
        {
            ctx.Out.Fail(kncore::Status::Unavailable, L"Current EPROCESS or its matched layout/memory unavailable");
            return false;
        }
        return true;
    }
    // Corroborated object addresses do not require an unrelated full-list walk.
    if (ResolveProcessTarget(ctx.Session, layout, {}, selector, &target, false))
    {
        return true;
    }
    std::vector<ProcRow> rows;
    CmdText list;
    if (!CollectProcesses(ctx.Session, layout, &rows, list))
    {
        ReportProcessSelectionFailure(list, ctx.Out);
        return false;
    }
    if (!ResolveProcessTarget(ctx.Session, layout, rows, selector, &target, list.Details.Collected.Complete))
    {
        ReportProcessSelectionFailure(list, ctx.Out, selector);
        return false;
    }
    if (!list.Details.Collected.Complete)
    {
        ctx.Out.Details.Limitations.Push(knjson::Value(L"Process inventory was partial; selected record was observed."));
    }
    return true;
}

bool ResolveProcessTarget(knengine::DbgSession &session, knengine::LayoutResolver &layout, const std::vector<ProcRow> &rows,
                          const std::wstring &token, ProcRow *match, bool inventoryComplete)
{
    if (MatchProcessTarget(rows, token, match, inventoryComplete))
    {
        return true;
    }
    std::wstring value = token;
    if (kncore::FoldName(value).starts_with(L"eprocess:"))
    {
        value.erase(0, 9);
    }
    uint64_t address = 0;
    kncore::TargetArchitecture architecture;
    if (match == nullptr || !kncore::ParseUnsigned(value, 16, &address) || !KernelArchitecture(session, &architecture) ||
        !architecture.KernelPointer(address))
    {
        return false;
    }
    knengine::ObjectDirectoryWalker objects(session);
    unsigned processType = UINT32_MAX;
    unsigned actualType = UINT32_MAX;
    ProcRow row;
    const bool valid = objects.ResolveTypeIndex(L"Process", &processType) && objects.ObjectTypeIndex(address, &actualType) &&
                       actualType == processType && kncore::ReadProcess(session, address, ResolveProcessLayout(layout), row) &&
                       row.Pid <= UINT32_MAX;
    if (valid)
    {
        *match = row;
    }
    return valid;
}
} // namespace kncmd
