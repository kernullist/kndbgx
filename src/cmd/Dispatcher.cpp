#include "Dispatcher.h"

#include "CmdTypes.h"
#include "WriteGate.h"
#include "CommandSpec.h"
#include "Jobs.h"

#include <cwctype>
#include <dbgeng.h>
#include <exception>

#include "../util/Log.h"
#include "../util/Text.h"
#include "../util/ArtifactWriter.h"
#include "../core/ResultStore.h"
#include "../core/ResultPresentation.h"
#include "../engine/ContextGuard.h"
#include "../engine/SymbolQuery.h"
#include "../util/Token.h"
#include "CollectorSupport.h"

#include <optional>

namespace kncmd
{
namespace
{
void InvokeCppHandler(HandlerFn handler, Ctx *context)
{
    try
    {
        handler(*context);
    }
    catch (const std::exception &)
    {
        context->Out.Fail(kncore::Status::InternalFault, L"[kndbgx] C++ handler exception");
    }
    catch (...)
    {
        context->Out.Fail(kncore::Status::InternalFault, L"[kndbgx] unexpected handler exception");
    }
}

// SEH-safe trampoline: takes only POD arguments so the compiler does
// not require object unwinding inside the __try frame.
unsigned long GuardedRun(HandlerFn handler, Ctx *context)
{
    __try
    {
        InvokeCppHandler(handler, context);
        return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }
}

void EchoToHost(knengine::DbgSession &session, const std::wstring &output)
{
    if (session.IsReady() && !output.empty())
    {
        const size_t limit = knutil::Utf16PrefixUnits(output, 512 * 1024);
        for (size_t offset = 0; offset < limit;)
        {
            const size_t count = knutil::Utf16PrefixUnits(std::wstring_view(output).substr(offset, limit - offset), 2048);
            if (count == 0)
            {
                break;
            }
            const auto text = output.substr(offset, count);
            session.Control()->ControlledOutputWide(DEBUG_OUTCTL_ALL_OTHER_CLIENTS, DEBUG_OUTPUT_NORMAL, L"%s", text.c_str());
            offset += count;
        }
        if (limit < output.size())
        {
            session.Control()->ControlledOutputWide(DEBUG_OUTCTL_ALL_OTHER_CLIENTS, DEBUG_OUTPUT_NORMAL,
                                                    L"\n[output] console display capped; inspect structured results\n");
        }
    }
}
} // namespace

void ExecuteCollector(HandlerFn handler, Ctx &context)
{
    // Command executions resolve layouts, read state and run host diagnostics
    // between stamp captures; their own engine calls fire events (delivered on
    // the session-observer thread) that would otherwise bump generations and
    // stale-refuse the command against itself — observed live as mutations
    // refusing with "planning unavailable" because the plan's stamp re-check
    // races its own read. The counter nests with the guards handlers create.
    // Commands that deliberately change session context or execution state are
    // never wrapped: their changes are real and must keep invalidating. A
    // mutation's explicit post-write ContextChanged is a direct call and
    // unaffected by observation masking. Per-thread ownership lets SEH
    // recovery release abandoned scopes without clobbering another walk.
    const bool internalOperation = context.Request != nullptr && context.Request->Spec != nullptr &&
                                   !HasEffect(context.Request->Spec->Effects, Effect::ExecutionControl) &&
                                   !HasEffect(context.Request->Spec->Effects, Effect::SessionContextChange) &&
                                   !HasEffect(context.Request->Spec->Effects, Effect::OpaqueEngine);
    std::optional<CollectorWalk> collectorWalk;
    if (internalOperation)
    {
        collectorWalk.emplace();
    }
    const unsigned depth = knengine::InternalContextDepth;
    const unsigned symbolDepth = knengine::PassiveSymbolQueryDepth;
    const unsigned walkDepth = knengine::SessionWalkDepth;
    const unsigned long code = GuardedRun(handler, &context);
    const bool balanced = knengine::InternalContextDepth == depth && knengine::PassiveSymbolQueryDepth == symbolDepth &&
                          knengine::SessionWalkDepth == walkDepth;
    // SEH can bypass C++ destructors; preserve the caller's tracking scope.
    knengine::InternalContextDepth = depth;
    knengine::PassiveSymbolQueryDepth = symbolDepth;
    knengine::ReleaseAbandonedSessionWalks(walkDepth);
    if (code != 0)
    {
        context.Session.MarkFault();
        context.Out.Fail(kncore::Status::InternalFault, L"[kndbgx] native fault; session requires review",
                         {L"SEH", code, L"NativeHandler", L""});
    }
    else if (!balanced)
    {
        context.Out.Fail(kncore::Status::InternalFault, L"[kndbgx] unbalanced debugger context tracking; reconnect required");
    }
    if (context.Out.Details.State == kncore::Status::InternalFault)
    {
        context.Session.MarkFault();
    }
}

bool IsNativeCommand(const std::wstring &line)
{
    ParsedCommand parsed;
    ParseCommand(line, &parsed);
    return parsed.Spec != nullptr;
}

static void PrepareResult(Ctx &ctx)
{
    kncore::SeparateResultDiagnostics(ctx.Out.Details);
    const auto *spec = ctx.Request != nullptr ? ctx.Request->Spec : nullptr;
    const auto state = ctx.Out.Details.State;
    if (spec != nullptr && HasEffect(spec->Effects, Effect::TargetRead) && spec->Requires != Capability::None &&
        spec->Handler != WinDbgCommand && state != kncore::Status::InternalFault && state != kncore::Status::StaleContext &&
        state != kncore::Status::Cancelled)
    {
        AnnotateResultSymbols(ctx.Session, ctx.Out.Details);
    }
}

static bool RunCommand(knengine::DbgSession &session, const std::wstring &line, std::wstring *output, kncore::Result *details,
                       const kncore::SessionStamp *expected, const std::function<bool()> &requestCancelled, CommandInput input)
{
    CmdText out;
    ParsedCommand parsed;
    do
    {
        if (!(input == CommandInput::UiConsole ? ParseUiCommand(line, &parsed) : ParseCommand(line, &parsed)))
        {
            out.Fail(parsed.Spec == nullptr && !knutil::Trim(line).empty() ? kncore::Status::Unsupported : kncore::Status::InvalidInput,
                     parsed.Error);
            break;
        }
        const auto &spec = *parsed.Spec;
        out.Details.CommandId = spec.Name;
        if (spec.Handler == WinDbgCommand)
        {
            out.Details.Analysis = knjson::Value::MakeObject();
            out.Details.Analysis.Set(L"hostCommandLine", knjson::Value(parsed.RawArguments));
        }
        if (spec.Support == SupportLevel::Unsupported)
        {
            out.Fail(kncore::Status::Unsupported, std::wstring(L"Unsupported capability: ") + spec.Name);
            break;
        }
        knengine::SessionStatus status = {};
        if (spec.Requires != Capability::None)
        {
            session.QueryStatus(&status);
            if (!status.EngineReady || (spec.Requires != Capability::Engine && !status.TargetPresent))
            {
                out.Fail(kncore::Status::Unavailable, L"Required engine or target is unavailable");
                break;
            }
            if ((spec.Requires == Capability::KernelX64 || spec.Requires == Capability::LocalKernelX64) &&
                (!status.KernelMode || status.Architecture != IMAGE_FILE_MACHINE_AMD64))
            {
                out.Fail(kncore::Status::Unsupported, L"This collector requires an x64 kernel target");
                break;
            }
            const TargetMode modes = EffectiveTargetModes(spec);
            if (modes != TargetMode::Any && status.DumpFile && !HasTargetMode(modes, TargetMode::KernelDump))
            {
                out.Fail(kncore::Status::Unsupported,
                         std::wstring(L"Unsupported in the current session mode: ") + spec.Name +
                             L" requires a live target; the current session is a " +
                             (status.KindText.empty() ? std::wstring(L"dump") : status.KindText) +
                             L" (read-only snapshot). Read-only inspection commands remain available");
                break;
            }
            if (modes != TargetMode::Any && status.KernelMode && !status.DumpFile && !HasTargetMode(modes, TargetMode::LiveKernel))
            {
                out.Fail(kncore::Status::Unsupported, std::wstring(L"Unsupported in the current session mode: ") + spec.Name +
                                                          L" requires a kernel dump target; the current session is live kernel debugging");
                break;
            }
            if (spec.Requires == Capability::LocalKernelX64 && !status.LocalKernel)
            {
                out.Fail(kncore::Status::Unsupported, L"Host-local collection requires verified local kernel context");
                break;
            }
            if (spec.Requires == Capability::StoppedTarget && !status.Stopped)
            {
                out.Fail(kncore::Status::Unavailable, L"Target must be stopped");
                break;
            }
            if (knengine::Epochs().State() == kncore::SessionState::Faulted && HasEffect(spec.Effects, Effect::TargetRead))
            {
                out.Fail(kncore::Status::InternalFault, L"Session faulted; reconnect required");
                break;
            }
        }
        out.Details.Source = spec.Requires == Capability::LocalKernelX64 ? L"host-local"
                             : spec.Requires == Capability::None         ? L"host"
                                                                         : L"target";
        out.Details.Consistency = status.Stopped ? L"StoppedTargetBestEffort" : L"LiveBestEffort";
        const auto stamp = session.RefreshStamp();
        if (expected != nullptr && *expected != stamp)
        {
            out.Fail(kncore::Status::StaleContext, L"Request target changed before dispatch");
            break;
        }
        Ctx ctx = {session, parsed.Arguments, out, &parsed, expected != nullptr ? expected : &stamp, requestCancelled};
        ExecuteCollector(spec.Handler, ctx);
        ExecuteCollector(PrepareResult, ctx);
        if (spec.Handler == WinDbgCommand && out.Details.Source == L"windbg")
        {
            // Also discard state produced by nested extension commands or a fault.
            knengine::Epochs().TargetChanged();
            DiscardChangePlans();
        }
        if (out.Details.CommandId.empty())
        {
            out.Details.CommandId = spec.Name;
        }
    } while (false);
    if (output != nullptr)
    {
        *output = out.Text();
    }
    if (details != nullptr)
    {
        *details = out.Details;
    }
    if (!DetachedCommand(parsed.Spec))
    {
        EchoToHost(session, out.Text());
    }
    return out.Details.State == kncore::Status::Success;
}

bool RunNative(knengine::DbgSession &session, const std::wstring &line, std::wstring *output, kncore::Result *details,
               const kncore::SessionStamp *expected, const std::function<bool()> &requestCancelled)
{
    return RunCommand(session, line, output, details, expected, requestCancelled, CommandInput::Registered);
}

void FinalizeCollection(CommandResult &result, const CommandSpec *spec, const kncore::SessionStamp &current, bool cancelled)
{
    const bool changesContext =
        spec != nullptr && (HasEffect(spec->Effects, Effect::SessionContextChange) || HasEffect(spec->Effects, Effect::TargetMutation) ||
                            HasEffect(spec->Effects, Effect::ExecutionControl) || HasEffect(spec->Effects, Effect::OpaqueEngine));
    const bool failedContext = result.Data.State == kncore::Status::InternalFault || result.Data.State == kncore::Status::StaleContext;
    const bool hasObservations = result.Data.State == kncore::Status::Success || result.Data.State == kncore::Status::Partial;
    const bool correlatedHost = spec != nullptr && spec->Handler == ScanCodeIntegrity &&
                                result.Data.Analysis.Get(L"targetCorrelation").AsString(L"") == L"VerifiedLocalKernel";
    const bool dependsOnTarget = spec != nullptr && (spec->Requires != Capability::None || correlatedHost);
    const bool artifactCommitted =
        spec != nullptr && HasEffect(spec->Effects, Effect::HostFileWrite) && result.Data.Analysis.Get(L"artifactCommitted").AsBool(false);
    if (cancelled && !DetachedCommand(spec) && !failedContext && !artifactCommitted)
    {
        result.Ok = false;
        result.Data.State = kncore::Status::Cancelled;
        result.Data.Collected.Complete = false;
        result.Data.Collected.StopReason = L"Cancelled";
        result.Data.Error.Message = L"Cancelled";
    }
    else if (current != result.Data.Stamp && hasObservations && dependsOnTarget && !changesContext && !DetachedCommand(spec))
    {
        result.Ok = false;
        result.Data.State = kncore::Status::StaleContext;
        result.Data.Collected.Complete = false;
        result.Data.Collected.StopReason = L"ContextChangedDuringCollection";
        result.Data.Error.Message = L"Target, execution, context or symbols changed during collection";
        if (correlatedHost)
        {
            result.Data.Analysis.Set(L"targetCorrelation", knjson::Value(L"ContextChanged"));
        }
    }
    result.Ok = result.Data.State == kncore::Status::Success;
}

void MarkResultNotRetained(CommandResult &result)
{
    result.Ok = false;
    result.ResultId.clear();
    if (result.Data.State == kncore::Status::Success)
    {
        result.Data.State = kncore::Status::Partial;
        result.Data.Collected.StopReason = L"ResultRetentionBudget";
    }
    result.Data.Collected.Complete = false;
    const std::wstring note = L"Result storage limit exceeded; displayed data was not stored";
    result.Error = result.Data.Error.Message.empty() ? result.Error : result.Data.Error.Message;
    result.Error = result.Error.empty() ? note : result.Error + L"; " + note;
    result.Data.Error.Message = result.Error;
    result.Data.Limitations.Push(knjson::Value(note));
}

bool IsResultInspection(const std::wstring &commandId)
{
    return commandId == L"results" || commandId == L"result-read" || commandId == L"model" || commandId == L"job" || commandId == L"jobs" ||
           commandId == L"submit" || commandId == L"cancel" || commandId == L"result-export";
}

CommandResult DispatchCommand(knengine::DbgSession &session, const std::wstring &line, const kncore::SessionStamp *expected,
                              const std::function<bool()> &requestCancelled, CommandInput input)
{
    CommandResult result = {};
    const auto startedStamp = session.RefreshStamp();
    result.Ok = RunCommand(session, line, &result.Output, &result.Data, expected, requestCancelled, input);
    ParsedCommand parsed;
    if (input == CommandInput::UiConsole)
    {
        ParseUiCommand(line, &parsed);
    }
    else
    {
        ParseCommand(line, &parsed);
    }
    const bool host = parsed.Spec != nullptr && parsed.Spec->Handler == WinDbgCommand;
    result.Native = parsed.Spec != nullptr && !host;
    result.Blocked = result.Data.State == kncore::Status::InvalidInput || result.Data.State == kncore::Status::Unsupported;
    result.Data.Stamp = startedStamp;
    const auto *spec = host ? parsed.Spec : FindCommand(result.Data.CommandId);
    const bool cancelled = session.Cancelled();
    FinalizeCollection(result, spec, cancelled ? startedStamp : session.RefreshStamp(), cancelled);
    result.Cls = result.Data.CommandId == L"cls" && result.Ok;
    if (!result.Ok)
    {
        result.Error = result.Data.Error.Message.empty() ? kncore::StatusName(result.Data.State) : result.Data.Error.Message;
    }
    if (!IsResultInspection(result.Data.CommandId))
    {
        const auto retained = kncore::Results().Publish(knutil::NewToken(), result.Data, result.Output);
        if (retained)
        {
            result.ResultId = retained->Id;
        }
        else
        {
            MarkResultNotRetained(result);
        }
    }
    return result;
}
} // namespace kncmd
