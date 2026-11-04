#pragma once

#include "ProcCollect.h"
#include "../engine/ModuleList.h"
#include "../util/Jsonl.h"
#include "../util/Log.h"
#include "../core/ScannerRules.h"
#include "../core/ResultPresentation.h"
#include "../engine/CpuContext.h"
#include "../engine/SessionWalk.h"
#include <dbgeng.h>

namespace kncmd
{
inline bool CheckCollection(Ctx &ctx, kncore::WalkBudget &budget)
{
    budget.StartTraversal();
    if (!budget.Stopped && ctx.Session.Cancelled())
    {
        budget.Stop(kncore::Status::Cancelled, L"Cancelled");
    }
    if (!budget.Stopped && (std::chrono::steady_clock::now() >= budget.Deadline || budget.Report.Collected.Visited >= budget.MaxNodes ||
                            budget.Report.Rows.Items().size() >= 65536))
    {
        budget.Stop(kncore::Status::Partial, L"CollectionBudget");
    }
    return !budget.Stopped;
}

inline void EmitRow(Ctx &ctx, kncore::WalkBudget &budget, const knjson::Value &row, size_t displayLimit = 256)
{
    budget.Report.Rows.Push(row);
    if (budget.Report.Rows.Items().size() <= displayLimit)
    {
        ctx.Out.AddLine(row.Write());
    }
}

inline void UnknownScope(Ctx &ctx, kncore::WalkBudget &budget, const std::wstring &scope, const std::wstring &reason)
{
    ++budget.Report.Collected.Unknown;
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"CoverageGap"));
    row.Set(L"scope", knjson::Value(scope));
    row.Set(L"reason", knjson::Value(reason));
    EmitRow(ctx, budget, row);
    // Console readers see what is missing and why without opening the
    // structured rows; one bounded line per gap, with the tail summarized.
    if (budget.Report.Collected.Unknown <= 8)
    {
        std::wstring text = L"[gap] " + scope + L": " + reason;
        if (text.size() > 220)
        {
            text.resize(217);
            text += L"...";
        }
        ctx.Out.AddLine(text);
    }
    else if (budget.Report.Collected.Unknown == 9)
    {
        ctx.Out.AddLine(L"[gap] further coverage gaps are recorded in the structured rows only");
    }
}

inline std::optional<uint64_t> SymbolAddress(knengine::DbgSession &, knengine::LayoutResolver &layout, const wchar_t *module,
                                             const wchar_t *name)
{
    return layout.Address(module, name);
}

template <typename Callback> bool EachProcessor(knengine::DbgSession &session, Callback callback)
{
    return knengine::ForEachProcessor(
        session,
        [](ULONG processor, void *context)
        {
            return (*static_cast<Callback *>(context))(processor);
        },
        &callback);
}

// Collector executions resolve layouts and ownership between the begin stamp
// and the first guarded engine operation; concurrent CLI observations in that
// window would otherwise stale-refuse the collection before its own guard
// exists. EnterWalk is reference counted and nests with ContextGuard.
using CollectorWalk = knengine::SessionWalk;

inline bool BeginCollection(Ctx &ctx, kncore::WalkBudget &budget, kncore::TargetArchitecture &architecture, const wchar_t *source)
{
    if (!KernelArchitecture(ctx.Session, &architecture))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Target architecture/CR4 unavailable");
        return false;
    }
    budget.Report.Stamp = ctx.Session.RefreshStamp();
    budget.Report.CommandId = ctx.Out.Details.CommandId;
    budget.Report.Limitations = ctx.Out.Details.Limitations;
    budget.Report.Source = source;
    knengine::SessionStatus status = {};
    ctx.Session.QueryStatus(&status);
    // Any live kernel session (local or remote) reads a running target unless
    // it is explicitly broken in; dumps are always immutable.
    budget.Report.Consistency = status.DumpFile ? L"dump" : status.Stopped ? L"stopped" : L"live-nonatomic";
    budget.Cancelled = [&ctx]()
    {
        return ctx.Session.Cancelled();
    };
    knengine::LayoutResolver layout(ctx.Session);
    if (const auto identity = layout.Identity(L"nt"))
    {
        budget.Report.LayoutProfile = identity->Key();
    }
    return true;
}

inline void FinishCollection(Ctx &ctx, kncore::WalkBudget &budget)
{
    if (ctx.Out.Details.Collected.StopReason == L"OutputBudgetExceeded" && !budget.Stopped)
    {
        budget.Stop(kncore::Status::Partial, L"OutputBudgetExceeded");
    }
    if (!budget.Stopped && (budget.Report.Collected.Unreadable != 0 || budget.Report.Collected.Unknown != 0))
    {
        budget.Stop(kncore::Status::Partial, L"FieldsOrOwnershipUnavailable");
    }
    budget.Complete();
    // Staleness is judged by identity, not raw generation counters: concurrent
    // observations (CLI job polls resolving scope fire register-refresh events)
    // bump stop/context/symbol generations without any real context change —
    // observed live as per-run +1/+1 generation drift with byte-identical
    // identity. Target generation and session identity remain strict.
    const auto endStamp = ctx.Session.RefreshStamp();
    const bool contextChanged = budget.Report.Stamp.SessionId != endStamp.SessionId ||
                                budget.Report.Stamp.TargetGeneration != endStamp.TargetGeneration ||
                                !(budget.Report.Stamp.Context == endStamp.Context);
    if (contextChanged)
    {
        const auto &begin = budget.Report.Stamp;
        knlog::Write(std::wstring(L"FinishCollection: context changed after ") + budget.Report.CommandId + L": target " +
                     std::to_wstring(begin.TargetGeneration) + L"->" + std::to_wstring(endStamp.TargetGeneration) + L", stop " +
                     std::to_wstring(begin.StopEpoch) + L"->" + std::to_wstring(endStamp.StopEpoch) + L", context " +
                     std::to_wstring(begin.ContextGeneration) + L"->" + std::to_wstring(endStamp.ContextGeneration) + L", symbol " +
                     std::to_wstring(begin.SymbolGeneration) + L"->" + std::to_wstring(endStamp.SymbolGeneration) +
                     L", scope-instruction " + kncore::Hex(begin.Context.ScopeInstruction.value_or(0)) + L"->" +
                     kncore::Hex(endStamp.Context.ScopeInstruction.value_or(0)) + L", scope-index " +
                     std::to_wstring(begin.Context.ScopeIndex.value_or(0)) + L"->" +
                     std::to_wstring(endStamp.Context.ScopeIndex.value_or(0)) + L", thread " +
                     std::to_wstring(begin.Context.Thread.value_or(0)) + L"->" + std::to_wstring(endStamp.Context.Thread.value_or(0)) +
                     L", implicit-thread " + std::to_wstring(begin.Context.ImplicitThread.value_or(0)) + L"->" +
                     std::to_wstring(endStamp.Context.ImplicitThread.value_or(0)));
        budget.Stop(kncore::Status::StaleContext, L"CollectionContextChanged");
    }
    if (knengine::Epochs().State() == kncore::SessionState::Faulted)
    {
        budget.Stop(kncore::Status::InternalFault, L"SessionFaultedOrContextRestoreFailed");
    }
    ctx.Out.Details = budget.Report;
    kncore::SeparateResultDiagnostics(ctx.Out.Details);
    AnnotateResultSymbols(ctx.Session, ctx.Out.Details);
    const auto &report = ctx.Out.Details;
    ctx.Out.AddLine(L"[coverage] status=" + std::wstring(kncore::StatusName(report.State)) + L" visited=" +
                    std::to_wstring(report.Collected.Visited) +
                    (report.Collected.Expected ? L" of expected=" + std::to_wstring(report.Collected.Expected) : L"") +
                    L" unknown=" + std::to_wstring(report.Collected.Unknown) + L" unreadable=" +
                    std::to_wstring(report.Collected.Unreadable) + L" reason=" + report.Collected.StopReason);
}

inline std::wstring OwnershipText(const kncore::AddressOwnership &owner)
{
    return owner.Image ? kncore::ModuleAddressLabel(owner.Image->Name, owner.Rva) : owner.Reason;
}

inline void ExportCollected(Ctx &ctx)
{
    std::wstring path;
    std::vector<std::wstring> rest;
    ExtractJsonPath(ctx.Args, 1, &path, &rest);
    if (!path.empty())
    {
        knutil::JsonlWriter writer;
        if (!writer.Open(path) || !writer.WriteLine(ctx.Out.Details.ToJson().Write()) || !writer.Commit(ctx.Out.Details.Collected.Complete))
        {
            ctx.Out.Fail(kncore::Status::IOError, L"Atomic structured export failed: " + path);
        }
    }
}
} // namespace kncmd
