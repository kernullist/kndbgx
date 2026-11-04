#include "../util/ResultExport.h"
#include "CommandSpec.h"
#include "BreakpointIdentity.h"
#include "ContextDefaults.h"
#include "../core/Navigation.h"
#include "../core/ResultPresentation.h"
#include "../core/Mutation.h"
#include "../engine/DataModel.h"
#include "../engine/EventInfo.h"
#include "../engine/SymbolQuery.h"
#include "../util/ArtifactWriter.h"
#include <dbgeng.h>
#include <wrl/client.h>

namespace kncmd
{
using Microsoft::WRL::ComPtr;
namespace
{
knjson::Value Context(knengine::DbgSession &session, bool selectedThreadIdentity = false)
{
    auto row = knjson::Value::MakeObject();
    ULONG value = 0;
    auto *system = session.SystemObjects();
    row.Set(selectedThreadIdentity ? L"engineProcessId" : L"processId",
            system->GetCurrentProcessId(&value) == S_OK ? knjson::Value(std::to_wstring(value)) : knjson::Value());
    row.Set(selectedThreadIdentity ? L"engineThreadId" : L"threadId",
            system->GetCurrentThreadId(&value) == S_OK ? knjson::Value(std::to_wstring(value)) : knjson::Value());
    knjson::Value processor;
    ULONG current = 0, count = 0;
    knengine::SessionStatus status = {};
    session.QueryStatus(&status);
    if (status.KernelMode && system->GetCurrentThreadId(&current) == S_OK && session.Control()->GetNumberProcessors(&count) == S_OK &&
        count <= 4096)
    {
        for (ULONG i = 0; i < count; ++i)
        {
            if (system->GetThreadIdByProcessor(i, &value) == S_OK && value == current)
            {
                processor = knjson::Value(std::to_wstring(i));
                break;
            }
        }
    }
    row.Set(L"processor", processor);
    if (selectedThreadIdentity)
    {
        auto identity = knengine::ReadSelectedThreadContext(session, status);
        identity.Set(L"processor", processor);
        row.Set(L"targetContext", identity);
    }
    row.Set(L"target", session.RefreshStamp().ToJson());
    return row;
}

void DescribeAddress(knengine::DbgSession &session, ULONG64 address, knjson::Value &row)
{
    knengine::SymbolQueryScope query;
    wchar_t text[4096] = {};
    ULONG64 displacement = 0;
    auto *symbols = session.Symbols();
    symbols->GetNameByOffsetWide(address, text, _countof(text), nullptr, &displacement);
    ULONG index = 0;
    ULONG64 base = 0;
    const bool module = symbols->GetModuleByOffset(address, 0, &index, &base) == S_OK;
    row.Set(L"moduleBase", module ? knjson::Value(kncore::Hex(base)) : knjson::Value());
    row.Set(L"rva", module ? knjson::Value(kncore::Hex(address - base)) : knjson::Value());
    const bool moduleName =
        module && symbols->GetModuleNameStringWide(DEBUG_MODNAME_MODULE, index, base, text, _countof(text), nullptr) == S_OK;
    row.Set(L"module", moduleName ? knjson::Value(text) : knjson::Value());
    row.Set(L"symbolRva", moduleName ? knjson::Value(kncore::ModuleAddressLabel(text, address - base)) : knjson::Value());
    ULONG line = 0;
    const bool source = symbols->GetLineByOffsetWide(address, &line, text, _countof(text), nullptr, &displacement) == S_OK;
    row.Set(L"sourceFile", source ? knjson::Value(text) : knjson::Value());
    row.Set(L"sourceLine", source ? knjson::Value(std::to_wstring(line)) : knjson::Value());
    row.Set(L"address", knjson::Value(kncore::Hex(address)));
    row.Set(L"addressSpace", knjson::Value(L"virtual"));
    kncore::Result annotation;
    annotation.Rows.Push(row);
    AnnotateResultSymbols(session, annotation);
    row = annotation.Rows.Items()[0];
}

void Add(Ctx &ctx, knjson::Value row)
{
    ctx.Out.Details.Rows.Push(row);
    ctx.Out.AddLine(row.Write());
}

void Stack(Ctx &ctx)
{
    knengine::SymbolQueryScope query;
    uint64_t count = 64;
    if (ctx.Args.size() == 2 && (!kncore::ParseUnsigned(ctx.Args[1], 10, &count) || count == 0 || count > 256))
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"stack [decimal frame count 1..256]");
        return;
    }
    std::vector<DEBUG_STACK_FRAME_EX> frames(static_cast<size_t>(count));
    ComPtr<IDebugControl5> control;
    ULONG filled = 0;
    HRESULT hr = ctx.Session.Client()->QueryInterface(IID_PPV_ARGS(&control));
    if (SUCCEEDED(hr))
    {
        hr = control->GetStackTraceEx(0, 0, 0, frames.data(), static_cast<ULONG>(count), &filled);
    }
    if (FAILED(hr) || filled > frames.size())
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Stack unwind unavailable",
                     {L"HRESULT", static_cast<uint32_t>(hr), L"GetStackTraceEx", L""});
        return;
    }
    const auto context = Context(ctx.Session, true);
    ctx.Out.Details.Analysis = knjson::Value::MakeObject();
    ctx.Out.Details.Analysis.Set(L"stackContext", context);
    for (ULONG i = 0; i < filled && !ctx.Session.Cancelled(); ++i)
    {
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"StackFrame"));
        row.Set(L"index", knjson::Value(std::to_wstring(i)));
        row.Set(L"context", context);
        row.Set(L"addressSpace", knjson::Value(L"virtual"));
        row.Set(L"address", knjson::Value(kncore::Hex(frames[i].InstructionOffset)));
        row.Set(L"stack", knjson::Value(kncore::Hex(frames[i].StackOffset)));
        row.Set(L"return", knjson::Value(kncore::Hex(frames[i].ReturnOffset)));
        row.Set(L"inlineContext", knjson::Value(kncore::Hex(frames[i].InlineFrameContext)));
        DescribeAddress(ctx.Session, frames[i].InstructionOffset, row);
        Add(ctx, row);
    }
    ctx.Out.Details.Collected.Complete = hr == S_OK && filled != 0 && filled < count;
    ctx.Out.Details.Collected.StopReason = filled == count ? L"FrameBudget" : filled == 0 ? L"UnwindUnavailable" : L"EngineUnwindEnded";
    ctx.Out.Details.Limitations.Push(knjson::Value(L"Stack frames come from the engine unwinder; missing metadata can stop the stack walk early"));
}

void Registers(Ctx &ctx)
{
    ComPtr<IDebugRegisters2> registers;
    ULONG count = 0;
    if (FAILED(ctx.Session.Client()->QueryInterface(IID_PPV_ARGS(&registers))) || registers->GetNumberRegisters(&count) != S_OK ||
        count > 4096)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Register enumeration unavailable");
        return;
    }
    const auto context = Context(ctx.Session, true);
    bool complete = true;
    for (ULONG i = 0; i < count && !ctx.Session.Cancelled(); ++i)
    {
        wchar_t name[256] = {};
        DEBUG_REGISTER_DESCRIPTION description = {};
        DEBUG_VALUE value = {};
        const bool described = registers->GetDescriptionWide(i, name, _countof(name), nullptr, &description) == S_OK;
        if (ctx.Args.size() == 2 && (!described || _wcsicmp(name, ctx.Args[1].c_str()) != 0))
        {
            continue;
        }
        const bool read = registers->GetValue(i, &value) == S_OK && value.Type != DEBUG_VALUE_INVALID;
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"Register"));
        row.Set(L"name", described ? knjson::Value(name) : knjson::Value());
        row.Set(L"context", context);
        row.Set(L"type", knjson::Value(std::to_wstring(value.Type)));
        size_t width = 0;
        switch (value.Type)
        {
        case DEBUG_VALUE_INT8:
            width = 1;
            break;
        case DEBUG_VALUE_INT16:
            width = 2;
            break;
        case DEBUG_VALUE_INT32:
        case DEBUG_VALUE_FLOAT32:
            width = 4;
            break;
        case DEBUG_VALUE_INT64:
        case DEBUG_VALUE_FLOAT64:
        case DEBUG_VALUE_VECTOR64:
            width = 8;
            break;
        case DEBUG_VALUE_FLOAT80:
            width = 10;
            break;
        case DEBUG_VALUE_FLOAT82:
            width = 11;
            break;
        case DEBUG_VALUE_FLOAT128:
        case DEBUG_VALUE_VECTOR128:
            width = 16;
            break;
        }
        const auto *bytes = reinterpret_cast<const uint8_t *>(&value);
        row.Set(L"rawBytes", read && width != 0 ? knjson::Value(kncore::BytesHex({bytes, bytes + width})) : knjson::Value());
        const bool scalar = read && value.Type <= DEBUG_VALUE_INT64;
        const uint64_t integer = value.Type == DEBUG_VALUE_INT8    ? value.I8
                                 : value.Type == DEBUG_VALUE_INT16 ? value.I16
                                 : value.Type == DEBUG_VALUE_INT32 ? value.I32
                                                                   : value.I64;
        row.Set(L"value", scalar ? knjson::Value(kncore::Hex(integer)) : knjson::Value());
        complete = complete && read && described && width != 0;
        Add(ctx, row);
    }
    ctx.Out.Details.Collected.Complete = complete && (ctx.Args.size() == 1 || !ctx.Out.Details.Rows.Items().empty());
    ctx.Out.Details.Collected.StopReason = ctx.Out.Details.Collected.Complete ? L"Complete" : L"RegisterUnavailable";
}

void Breakpoints(Ctx &ctx)
{
    ULONG count = 0;
    if (ctx.Session.Control()->GetNumberBreakpoints(&count) != S_OK || count > 4096)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Breakpoint enumeration unavailable");
        return;
    }
    bool complete = true;
    const auto conditions = knengine::ReadBreakpointConditions(ctx.Session.Client());
    for (ULONG i = 0; i < count && !ctx.Session.Cancelled(); ++i)
    {
        IDebugBreakpoint2 *breakpoint = nullptr;
        DEBUG_BREAKPOINT_PARAMETERS parameters = {};
        if (ctx.Session.Control()->GetBreakpointByIndex2(i, &breakpoint) != S_OK || breakpoint->GetParameters(&parameters) != S_OK)
        {
            complete = false;
            ++ctx.Out.Details.Collected.Unreadable;
            continue;
        }
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"Breakpoint"));
        const auto identity = BreakpointIdentity(breakpoint);
        row.Set(L"identity", identity.empty() ? knjson::Value() : knjson::Value(identity));
        row.Set(L"target", ctx.Session.RefreshStamp().ToJson());
        row.Set(L"id", knjson::Value(std::to_wstring(parameters.Id)));
        row.Set(L"addressSpace", knjson::Value(L"virtual"));
        row.Set(L"address",
                (parameters.Flags & DEBUG_BREAKPOINT_DEFERRED) == 0 ? knjson::Value(kncore::Hex(parameters.Offset)) : knjson::Value());
        row.Set(L"enabled", knjson::Value((parameters.Flags & DEBUG_BREAKPOINT_ENABLED) != 0));
        row.Set(L"deferred", knjson::Value((parameters.Flags & DEBUG_BREAKPOINT_DEFERRED) != 0));
        row.Set(L"type", knjson::Value(std::to_wstring(parameters.BreakType)));
        row.Set(L"flags", knjson::Value(kncore::Hex(parameters.Flags)));
        row.Set(L"breakpointType", knjson::Value(parameters.BreakType == DEBUG_BREAKPOINT_CODE ? L"Software / execute" :
                                               parameters.BreakType == DEBUG_BREAKPOINT_DATA ? L"Hardware" : L"Other"));
        row.Set(L"oneShot", knjson::Value((parameters.Flags & DEBUG_BREAKPOINT_ONE_SHOT) != 0));
        row.Set(L"goOnly", knjson::Value((parameters.Flags & DEBUG_BREAKPOINT_GO_ONLY) != 0));
        wchar_t expression[4096] = {};
        const bool expressionRead = breakpoint->GetOffsetExpressionWide(expression, _countof(expression), nullptr) == S_OK;
        row.Set(L"expression", expressionRead ? knjson::Value(expression) : knjson::Value());
        std::wstring trigger = L"Execute";
        if (parameters.BreakType == DEBUG_BREAKPOINT_DATA)
        {
            trigger.clear();
            for (const auto &[flag, name] : {std::pair{DEBUG_BREAK_READ, L"Read"}, std::pair{DEBUG_BREAK_WRITE, L"Write"},
                                            std::pair{DEBUG_BREAK_EXECUTE, L"Execute"}, std::pair{DEBUG_BREAK_IO, L"I/O"}})
            {
                if ((parameters.DataAccessType & flag) != 0)
                {
                    trigger += (trigger.empty() ? L"" : L" / ") + std::wstring(name);
                }
            }
            trigger += L" (" + std::to_wstring(parameters.DataSize) + L" bytes)";
            row.Set(L"dataSize", knjson::Value(std::to_wstring(parameters.DataSize)));
            row.Set(L"dataAccess", knjson::Value(kncore::Hex(parameters.DataAccessType)));
        }
        else if (parameters.BreakType != DEBUG_BREAKPOINT_CODE)
        {
            trigger = L"Type " + std::to_wstring(parameters.BreakType);
        }
        row.Set(L"trigger", knjson::Value(trigger));
        wchar_t command[4096] = {};
        const bool commandRead = breakpoint->GetCommandWide(command, _countof(command), nullptr) == S_OK;
        row.Set(L"command", commandRead ? knjson::Value(command) : knjson::Value());
        const auto condition = conditions.Get(std::to_wstring(parameters.Id));
        row.Set(L"condition", condition);
        row.Set(L"conditionStatus", knjson::Value(condition.IsString() ? L"Read from debugger data model; not evaluated" :
                                                 L"Unavailable from debugger data model; inspect the condition in WinDbg"));
        row.Set(L"matchThreadId",
                parameters.MatchThread == DEBUG_ANY_ID ? knjson::Value() : knjson::Value(std::to_wstring(parameters.MatchThread)));
        row.Set(L"passCount", knjson::Value(std::to_wstring(parameters.PassCount)));
        ULONG currentPass = 0;
        const bool passRead = breakpoint->GetCurrentPassCount(&currentPass) == S_OK;
        row.Set(L"currentPassCount", passRead ? knjson::Value(std::to_wstring(currentPass)) : knjson::Value());
        complete = complete && commandRead && expressionRead && passRead && !identity.empty();
        Add(ctx, row);
    }
    complete = complete && !ctx.Session.Cancelled();
    ctx.Out.Details.Collected.Complete = complete;
    ctx.Out.Details.Collected.StopReason = complete ? L"Complete" : L"BreakpointUnavailable";
}

void LastEvent(Ctx &ctx)
{
    knjson::Value row;
    const auto hr = knengine::ReadLastEvent(ctx.Session.Control(), row);
    if (FAILED(hr))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Last event unavailable",
                     {L"HRESULT", static_cast<uint32_t>(hr), L"GetLastEventInformationWide", L""});
        return;
    }
    row.Set(L"targetContext", knengine::ReadEventContext(ctx.Session, row));
    uint64_t configuredAddress = 0;
    if (kncore::ParseUnsigned(row.Get(L"configuredAddress").AsString(L""), 16, &configuredAddress))
    {
        const auto symbol = AnnotateSymbol(ctx.Session, configuredAddress);
        row.Set(L"configuredSymbol", symbol.empty() ? knjson::Value() : knjson::Value(symbol));
    }
    Add(ctx, row);
    ctx.Out.Details.Analysis = knjson::Value::MakeObject();
    ctx.Out.Details.Analysis.Set(L"lastEvent", row);
    Breakpoints(ctx);
    ctx.Out.Details.Collected.Complete = ctx.Out.Details.Collected.Complete && hr == S_OK;
    if (hr != S_OK)
    {
        ctx.Out.Details.Collected.StopReason = L"EventDataTruncated";
    }
}

void Navigate(Ctx &ctx)
{
    ULONG64 address = 0;
    if ((ctx.Args[1] != L"va" && ctx.Args[1] != L"pa") || !EvalAddress(ctx.Session, ctx.Args[2], &address))
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"navigate va|pa <address>");
        return;
    }
    const auto stamp = ctx.Session.RefreshStamp();
    const bool physical = ctx.Args[1] == L"pa";
    if (ctx.ExpectedStamp != nullptr && *ctx.ExpectedStamp != stamp)
    {
        ctx.Out.Fail(kncore::Status::StaleContext, L"Source result context changed before navigation");
        return;
    }
    const auto read = ctx.Session.Read(physical ? kncore::AddressSpace::Physical : kncore::AddressSpace::Virtual, address, 32);
    auto row = Context(ctx.Session);
    row.Set(L"kind", knjson::Value(L"AddressObservation"));
    row.Set(L"rawBytes", read.State == kncore::Status::Success ? knjson::Value(kncore::BytesHex(read.Bytes)) : knjson::Value());
    row.Set(L"readStatus", knjson::Value(kncore::StatusName(read.State)));
    if (!physical)
    {
        DescribeAddress(ctx.Session, address, row);
    }
    kncore::NavigationPoint point{stamp, physical ? L"physical" : L"virtual", address, {}, row, L""};
    // DbgEng virtual reads use its current process; the manual translation DTB is not applied here.
    row.Set(L"manualDtbApplied", knjson::Value(false));
    point.Observation = row;
    if (ctx.Session.RefreshStamp() != stamp)
    {
        ctx.Out.Fail(kncore::Status::StaleContext, L"Context changed during navigation");
        return;
    }
    kncore::Navigation().Push(point);
    Add(ctx, point.ToJson(stamp));
    ctx.Out.Details.Collected.Complete = read.State == kncore::Status::Success;
    ctx.Out.Details.Collected.StopReason = ctx.Out.Details.Collected.Complete ? L"Complete" : L"BytesUnavailable";
}

void Source(Ctx &ctx)
{
    ULONG64 address = 0;
    if (ctx.Args.size() == 1 && !CurrentInstruction(ctx, address))
    {
        return;
    }
    if (ctx.Args.size() > 1 && !EvalAddress(ctx.Session, ctx.Args[1], &address))
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"Invalid source address");
        return;
    }
    auto row = knjson::Value::MakeObject();
    DescribeAddress(ctx.Session, address, row);
    row.Set(L"address", knjson::Value(kncore::Hex(address)));
    row.Set(L"addressSpace", knjson::Value(L"virtual"));
    Add(ctx, row);
    if (row.Get(L"sourceFile").IsNull())
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Source line metadata unavailable");
        return;
    }
    std::wstring text;
    if (ctx.ExpectedStamp != nullptr && *ctx.ExpectedStamp != ctx.Session.RefreshStamp())
    {
        ctx.Out.Fail(kncore::Status::StaleContext, L"Source result context changed before source listing");
        return;
    }
    const bool complete = ctx.Session.Execute(L"lsa " + kncore::Hex(address), knengine::DbgSession::OutputRouting::CaptureHere, &text);
    ctx.Out.Add(text);
    ctx.Out.Details.Collected.Complete = complete;
    if (!complete)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Cannot display source; file and line information is still available");
    }
}

void Stored(Ctx &ctx)
{
    const auto stamp = ctx.Session.RefreshStamp();
    if (ctx.Args[0] == L"result-export")
    {
        const auto stored = kncore::Results().Find(ctx.Args[1]);
        if (!stored)
        {
            ctx.Out.Fail(kncore::Status::Unavailable, L"Result ID is unknown or has expired");
            return;
        }
        ctx.Out.Details = knutil::ExportStoredResult(*stored, ctx.Args[2], ctx.RequestCancelled);
        for (const auto &row : ctx.Out.Details.Rows.Items())
        {
            ctx.Out.AddLine(row.Write());
        }
        if (ctx.Out.Details.State != kncore::Status::Success)
        {
            ctx.Out.AddLine(ctx.Out.Details.Error.Message);
        }
        return;
    }
    if (ctx.Args[0] == L"results")
    {
        for (const auto &stored : kncore::Results().List())
        {
            auto row = knjson::Value::MakeObject();
            row.Set(L"resultId", knjson::Value(stored->Id));
            row.Set(L"commandId", knjson::Value(stored->Data.CommandId));
            row.Set(L"status", knjson::Value(kncore::StatusName(stored->Data.State)));
            row.Set(L"target", stored->Data.Stamp.ToJson());
            row.Set(L"historical", knjson::Value(stored->Data.Stamp != stamp));
            row.Set(L"rowCount", knjson::Value(std::to_wstring(stored->Data.Rows.Items().size())));
            row.Set(L"findingCount", knjson::Value(std::to_wstring(stored->Data.Findings.Items().size())));
            Add(ctx, row);
        }
    }
    else
    {
        const bool model = ctx.Args[0] == L"model";
        if (model && ctx.Args.size() == 1)
        {
            auto row = knjson::Value::MakeObject();
            row.Set(L"available", knjson::Value(knengine::HasDataModel(ctx.Session.Client())));
            row.Set(L"namespace", knjson::Value(L"Debugger.Models.KNDbgX"));
            row.Set(L"mode", knjson::Value(L"Read-only page copied into the host; viewing it does not read the target"));
            Add(ctx, row);
            ctx.Out.Details.Collected.Complete = true;
            return;
        }
        const size_t idIndex = model ? 2 : 1;
        if ((model && (ctx.Args.size() < 3 || ctx.Args[1] != L"publish")))
        {
            ctx.Out.Fail(kncore::Status::InvalidInput, L"model [publish <result-id> [decimal-offset]]");
            return;
        }
        const auto stored = kncore::Results().Find(ctx.Args[idIndex]);
        uint64_t offset = 0;
        uint64_t findingOffset = 0;
        if (!stored || (ctx.Args.size() > idIndex + 1 && !kncore::ParseUnsigned(ctx.Args[idIndex + 1], 10, &offset)) ||
            (ctx.Args.size() > idIndex + 2 && !kncore::ParseUnsigned(ctx.Args[idIndex + 2], 10, &findingOffset)) ||
            offset > (stored ? stored->Data.Rows.Items().size() : 0) || findingOffset > (stored ? stored->Data.Findings.Items().size() : 0))
        {
            ctx.Out.Fail(kncore::Status::InvalidInput, L"Result or page offset is unavailable");
            return;
        }
        const auto page = kncore::ProjectResult(*stored, static_cast<size_t>(offset), stamp, static_cast<size_t>(findingOffset));
        if (model)
        {
            const HRESULT hr = knengine::PublishDataModel(ctx.Session.Client(), page);
            if (FAILED(hr))
            {
                ctx.Out.Fail(kncore::Status::Unavailable, L"Data Model publication unavailable; use result-read or UI",
                             {L"HRESULT", static_cast<uint32_t>(hr), L"PublishDataModel", L""});
                return;
            }
            ctx.Out.AddLine(L"Result page available in the host: dx -r4 Debugger.Models.KNDbgX");
        }
        Add(ctx, page);
    }
    ctx.Out.Details.Collected.Complete = true;
}
} // namespace

void DebuggerCommand(Ctx &ctx)
{
    const auto &name = ctx.Args[0];
    if (name == L"stack")
    {
        Stack(ctx);
    }
    else if (name == L"registers")
    {
        Registers(ctx);
    }
    else if (name == L"breakpoints")
    {
        Breakpoints(ctx);
    }
    else if (name == L"event")
    {
        LastEvent(ctx);
    }
    else if (name == L"navigate")
    {
        Navigate(ctx);
    }
    else if (name == L"source")
    {
        Source(ctx);
    }
    else if (name == L"history" || name == L"bookmarks")
    {
        ctx.Out.Details.Rows = kncore::Navigation().List(ctx.Session.RefreshStamp(), name == L"bookmarks");
        ctx.Out.AddLine(ctx.Out.Details.Rows.Write());
        ctx.Out.Details.Collected.Complete = true;
    }
    else if (name == L"back" || name == L"forward")
    {
        const auto point = kncore::Navigation().Move(name == L"back" ? -1 : 1);
        if (!point)
        {
            ctx.Out.Fail(kncore::Status::Unavailable, L"No history in that direction");
        }
        else
        {
            Add(ctx, point->ToJson(ctx.Session.RefreshStamp()));
            ctx.Out.Details.Collected.Complete = true;
        }
    }
    else if (name == L"bookmark")
    {
        if (!kncore::Navigation().Bookmark(ctx.Args.size() == 2 ? ctx.Args[1] : L""))
        {
            ctx.Out.Fail(kncore::Status::Unavailable, L"Navigate first; maximum 256 bookmarks and 1024 note characters");
        }
        else
        {
            ctx.Out.AddLine(L"Bookmark saved; export bookmarks from the results list");
            ctx.Out.Details.Collected.Complete = true;
        }
    }
    else
    {
        Stored(ctx);
    }
    ctx.Out.Details.Collected.Visited = ctx.Out.Details.Rows.Items().size();
    ctx.Out.Details.Collected.Decoded = ctx.Out.Details.Collected.Visited;
    if (!ctx.Out.Details.Collected.Complete && ctx.Out.Details.State == kncore::Status::Success)
    {
        ctx.Out.Details.State = kncore::Status::Partial;
    }
}
} // namespace kncmd
