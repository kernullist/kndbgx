#include "CommandSpec.h"
#include "BreakpointIdentity.h"
#include "WriteGate.h"
#include "MutationService.h"
#include "../core/DebugAction.h"
#include "../util/ArtifactWriter.h"
#include <dbgeng.h>
#include <wrl/client.h>
#include <bcrypt.h>

namespace kncmd
{
using Microsoft::WRL::ComPtr;
namespace
{
std::wstring ApprovalToken()
{
    unsigned char bytes[32] = {};
    return BCRYPT_SUCCESS(BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) ? kncore::BytesHex(bytes) : L"";
}
void PrepareAction(Ctx &ctx)
{
    const auto &operation = ctx.Args[1];
    const bool run = operation == L"go" || operation == L"step-into" || operation == L"step-over";
    const bool add = operation == L"breakpoint-add";
    const bool existing = operation == L"breakpoint-remove" || operation == L"breakpoint-enable" || operation == L"breakpoint-disable";
    uint64_t operand = 0;
    if ((!run && !add && !existing) || ctx.Args.size() != (run ? 2 : 3) || (add && !EvalAddress(ctx.Session, ctx.Args[2], &operand)) ||
        (existing && (!kncore::ParseUnsigned(ctx.Args[2], 10, &operand) || operand > UINT32_MAX)))
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"debug-plan go|step-into|step-over|breakpoint-add "
                                                   L"<address>|breakpoint-remove|breakpoint-enable|breakpoint-disable <decimal-id>");
        return;
    }
    kncore::DebugAction action{ApprovalToken(),
                               ApprovalToken(),
                               operation,
                               operand,
                               ctx.Session.RefreshStamp(),
                               L"",
                               std::chrono::steady_clock::now() + std::chrono::seconds(60)};
    if (existing)
    {
        IDebugBreakpoint2 *breakpoint = nullptr;
        if (ctx.Session.Control()->GetBreakpointById2(static_cast<ULONG>(operand), &breakpoint) != S_OK ||
            (action.Original = BreakpointIdentity(breakpoint)).empty())
        {
            ctx.Out.Fail(kncore::Status::Unavailable, L"Breakpoint identity unavailable");
            return;
        }
    }
    else if (add)
    {
        const auto read = ctx.Session.Read(kncore::AddressSpace::Virtual, operand, 1);
        if (read.State != kncore::Status::Success)
        {
            ctx.Out.Fail(kncore::Status::Unavailable, L"Breakpoint address must be readable");
            return;
        }
        action.Original = kncore::Hex(read.Bytes[0]);
    }
    if (ctx.Session.RefreshStamp() != action.Stamp || !kncore::ActionPlans().Add(action))
    {
        ctx.Out.Fail(kncore::Status::StaleContext, L"Context changed or action plan capacity reached");
        return;
    }
    ctx.Out.Details.Rows.Push(action.ToJson());
    ctx.Out.AddLine(action.ToJson().Write());
    ctx.Out.AddLine(L"Approve once: debug-approve " + action.Id + L" " + action.Token);
    ctx.Out.Details.Collected.Complete = true;
}

void ApproveAction(Ctx &ctx)
{
    const auto action = kncore::ActionPlans().Consume(ctx.Args[1], ctx.Args[2], ctx.Session.RefreshStamp());
    if (!action)
    {
        ctx.Out.Fail(kncore::Status::StaleContext, L"Action rejected: missing/expired/replayed token or changed context");
        return;
    }
    HRESULT hr = E_FAIL;
    ULONG breakpointId = DEBUG_ANY_ID;
    const auto &operation = action->Operation;
    const auto revalidate = [&]()
    {
        const auto stamp = ctx.Session.RefreshStamp();
        const auto state = kncore::RevalidateDebugAction(*action, stamp, ctx.Session.Cancelled());
        if (state != kncore::Status::Success)
        {
            ctx.Out.Fail(state, L"Action cancelled, expired or context changed before application");
        }
        return state == kncore::Status::Success;
    };
    if (operation == L"go" || operation == L"step-into" || operation == L"step-over")
    {
        if (!revalidate())
        {
            return;
        }
        hr = ctx.Session.Control()->SetExecutionStatus(operation == L"go"          ? DEBUG_STATUS_GO
                                                       : operation == L"step-into" ? DEBUG_STATUS_STEP_INTO
                                                                                   : DEBUG_STATUS_STEP_OVER);
    }
    else if (operation == L"breakpoint-add")
    {
        const auto read = ctx.Session.Read(kncore::AddressSpace::Virtual, action->Operand, 1);
        if (read.State != kncore::Status::Success || kncore::Hex(read.Bytes[0]) != action->Original)
        {
            ctx.Out.Fail(kncore::Status::StaleContext, L"Breakpoint instruction byte changed");
            return;
        }
        IDebugBreakpoint2 *breakpoint = nullptr;
        if (!revalidate())
        {
            return;
        }
        hr = ctx.Session.Control()->AddBreakpoint2(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &breakpoint);
        if (SUCCEEDED(hr))
        {
            hr = breakpoint->SetOffset(action->Operand);
            if (SUCCEEDED(hr))
            {
                hr = breakpoint->AddFlags(DEBUG_BREAKPOINT_ENABLED);
            }
            if (SUCCEEDED(hr))
            {
                hr = breakpoint->GetId(&breakpointId);
            }
            if (FAILED(hr) && FAILED(ctx.Session.Control()->RemoveBreakpoint2(breakpoint)))
            {
                ctx.Out.Details.Limitations.Push(
                    knjson::Value(L"Failed to remove a partially configured breakpoint; inspect host breakpoint list"));
            }
        }
    }
    else
    {
        IDebugBreakpoint2 *breakpoint = nullptr;
        hr = ctx.Session.Control()->GetBreakpointById2(static_cast<ULONG>(action->Operand), &breakpoint);
        if (FAILED(hr) || BreakpointIdentity(breakpoint) != action->Original)
        {
            ctx.Out.Fail(kncore::Status::StaleContext, L"Breakpoint changed or was replaced after planning");
            return;
        }
        if (!revalidate())
        {
            return;
        }
        hr = operation == L"breakpoint-remove"   ? ctx.Session.Control()->RemoveBreakpoint2(breakpoint)
             : operation == L"breakpoint-enable" ? breakpoint->AddFlags(DEBUG_BREAKPOINT_ENABLED)
                                                 : breakpoint->RemoveFlags(DEBUG_BREAKPOINT_ENABLED);
    }
    knengine::Epochs().ExecutionChanged();
    PlanStore().Clear();
    kncore::ActionPlans().Clear();
    if (FAILED(hr))
    {
        ctx.Out.Fail(kncore::Status::EngineError, L"Debugger action failed; no retry performed",
                     {L"HRESULT", static_cast<uint32_t>(hr), operation, L""});
    }
    else
    {
        auto row = action->ToJson();
        row.Set(L"approvalToken", knjson::Value());
        row.Set(L"applied", knjson::Value(true));
        row.Set(L"breakpointId", breakpointId == DEBUG_ANY_ID ? knjson::Value() : knjson::Value(std::to_wstring(breakpointId)));
        ctx.Out.Details.Rows.Push(row);
        ctx.Out.AddLine(row.Write());
        ctx.Out.Details.Collected.Complete = true;
    }
}
} // namespace

void DebugActionCommand(Ctx &ctx)
{
    knengine::SessionStatus status = {};
    ctx.Session.QueryStatus(&status);
    if (status.DumpFile || status.LocalKernel || !status.Stopped || !ctx.Session.RefreshStamp().Context.Complete() ||
        !knengine::SessionObserverReady())
    {
        ctx.Out.Fail(kncore::Status::Unsupported, L"Execution actions require a stopped live user or remote kernel session");
    }
    else if (ctx.Args[0] == L"debug-plan")
    {
        PrepareAction(ctx);
    }
    else
    {
        ApproveAction(ctx);
    }
}
} // namespace kncmd
