#include "Bridge.h"
#include "../util/ArtifactWriter.h"
#include "../util/ResultExport.h"
#include "../core/Rpc.h"
#include "../core/ResultStore.h"
#include "../core/ResultPage.h"
#include "../core/ResultAction.h"
#include "../core/ProcessAction.h"
#include "../core/MemoryView.h"
#include "../core/DisassemblyView.h"
#include "../core/BreakpointView.h"
#include "../core/DebugAction.h"
#include "../cmd/BreakpointIdentity.h"
#include "../cmd/ProcCollect.h"
#include "../util/Token.h"
#include "../util/Text.h"

#include "../catalog/Catalog.h"
#include "../cmd/Dispatcher.h"
#include "../cmd/WriteGate.h"
#include "../cmd/MutationService.h"
#include "../cmd/Jobs.h"
#include "../engine/EngineCore.h"
#include "../engine/EventInfo.h"
#include "../engine/PageWalk.h"
#include "../engine/SymbolQuery.h"
#include "../engine/SymbolHealth.h"
#include "../util/Log.h"

#include <string>
#include <set>
#include <algorithm>
#include <windows.h>
#include <dbgeng.h>

namespace knbridge
{
namespace
{
knjson::Value InstructionPointer(knengine::DbgSession &session, bool stopped)
{
    Microsoft::WRL::ComPtr<IDebugRegisters> registers;
    ULONG64 address = 0;
    return stopped && SUCCEEDED(session.Client()->QueryInterface(IID_PPV_ARGS(&registers))) &&
                   registers->GetInstructionOffset(&address) == S_OK ? knjson::Value(kncore::Hex(address)) : knjson::Value();
}

knjson::Value MemoryPageTables(knengine::DbgSession &session, const kncore::SessionStamp &stamp,
                               const knjson::Value &read, const std::function<bool()> &cancelled)
{
    uint64_t address = 0;
    uint64_t length = 0;
    if (read.Get(L"addressSpace").AsString(L"") != L"virtual" ||
        !kncore::ParseUnsigned(read.Get(L"address").AsString(L""), 16, &address) ||
        !kncore::ParseUnsigned(read.Get(L"length").AsString(L""), 10, &length) || length > 1024 || !kncore::ValidRange(address, length))
    {
        return {};
    }
    kncore::TargetArchitecture architecture;
    if (!kncmd::KernelArchitecture(session, &architecture))
    {
        return knjson::Value(L"Requires an x64 kernel target with readable CR4");
    }
    // ReadVirtual uses the debugger's implicit process. The vtop override and
    // the processor's CR3 can both refer to a different address space.
    const auto process = stamp.Context.ImplicitProcess.value_or(0);
    Microsoft::WRL::ComPtr<IDebugDataSpaces> spaces;
    USHORT dtbOffset = 0;
    ULONG returned = 0;
    uint64_t dtb = 0;
    if (!architecture.KernelPointer(process) || FAILED(session.Client()->QueryInterface(IID_PPV_ARGS(&spaces))) ||
        spaces->ReadDebuggerData(DEBUG_DATA_OffsetEprocessDirectoryTableBase, &dtbOffset, sizeof(dtbOffset), &returned) != S_OK ||
        returned != sizeof(dtbOffset) || dtbOffset == 0 || !kncore::ValidRange(process, dtbOffset + sizeof(dtb)) ||
        !session.ReadExact(kncore::AddressSpace::Virtual, process + dtbOffset, &dtb) || dtb == 0)
    {
        return knjson::Value(L"Directory table base unavailable for the debugger's selected process");
    }
    auto pages = knjson::Value::MakeArray();
    for (uint64_t offset = 0; offset < length; offset += 0x1000 - ((address + offset) & 0xfff))
    {
        if ((cancelled && cancelled()) || session.Cancelled() || session.RefreshStamp() != stamp)
        {
            return knjson::Value(L"Page table capture interrupted or debugger context changed");
        }
        knengine::PageWalkResult walk;
        knengine::WalkPageTables(session, architecture, (address + offset) & ~0xfffULL, dtb, &walk);
        pages.Push(knengine::PageWalkObservation(walk));
    }
    return session.RefreshStamp() == stamp ? pages : knjson::Value(L"Debugger context changed during page table capture");
}

knjson::Value CurrentProcessResult(knengine::DbgSession &session, const knengine::SessionStatus &status,
                                   const kncore::SessionStamp &stamp)
{
    auto result = knjson::Value::MakeObject();
    result.Set(L"image", knjson::Value());
    result.Set(L"pid", knjson::Value());
    result.Set(L"eprocess", knjson::Value());
    std::wstring reason;
    do
    {
        if (!status.Connected || !status.Stopped)
        {
            reason = status.Connected ? L"Target running" : L"No target";
            break;
        }
        if (!status.KernelMode || status.Architecture != IMAGE_FILE_MACHINE_AMD64)
        {
            reason = L"Requires an x64 kernel target";
            break;
        }
        if (knengine::Epochs().State() == kncore::SessionState::Faulted)
        {
            reason = L"Session faulted; reconnect required";
            break;
        }
        const auto address = stamp.Context.ImplicitProcess;
        if (!address || *address == 0)
        {
            reason = L"Current EPROCESS unavailable";
            break;
        }
        result.Set(L"eprocess", knjson::Value(kncore::Hex(*address)));
        static kncore::EpochValue<kncore::ProcessLayout> layoutCache;
        auto fields = layoutCache.Get(stamp);
        if (!fields)
        {
            knengine::LayoutResolver layout(session);
            fields.emplace();
            fields->Pid = layout.Field(L"nt", L"_EPROCESS", L"UniqueProcessId");
            fields->Image = layout.Field(L"nt", L"_EPROCESS", L"ImageFileName");
            layoutCache.Set(*fields, stamp);
        }
        kncore::ProcessRow row;
        kncore::ReadProcess(session, *address, *fields, row);
        const bool pidKnown = row.PidKnown && row.Pid <= UINT32_MAX;
        const bool imageKnown = row.ImageKnown && !row.Image.empty();
        result.Set(L"pid", pidKnown ? knjson::Value(std::to_wstring(row.Pid)) : knjson::Value());
        result.Set(L"image", imageKnown ? knjson::Value(row.Image) : knjson::Value());
        if (!pidKnown || !imageKnown)
        {
            reason = L"Name or PID unavailable (symbols or memory)";
        }
    } while (false);
    result.Set(L"reason", knjson::Value(reason));
    return result;
}

knjson::Value StatusResult(knengine::DbgSession &session)
{
    const bool ready = session.IsReady();
    knengine::SessionStatus status = {};
    knjson::Value result = knjson::Value::MakeObject();

    if (!ready)
    {
        knengine::SetBreakCapability(knengine::Epochs().Stamp(), false);
        result.Set(L"connected", knjson::Value(false));
        return result;
    }

    const auto begin = session.RefreshStamp();
    session.QueryStatus(&status);
    auto process = CurrentProcessResult(session, status, begin);
    auto instructionPointer = InstructionPointer(session, status.Connected && status.Stopped);
    ULONG processorThread = DEBUG_ANY_ID;
    // Validate the common identity mapping without a processor walk on every status poll.
    auto currentProcessor = status.Connected && status.Stopped && status.KernelMode && begin.Context.Thread &&
                            *begin.Context.Thread < UINT32_MAX && session.SystemObjects()->GetThreadIdByProcessor(
                                static_cast<ULONG>(*begin.Context.Thread), &processorThread) == S_OK &&
                            processorThread == *begin.Context.Thread
        ? knjson::Value(std::to_wstring(*begin.Context.Thread)) : knjson::Value();
    auto contextDtb = session.HasContextDtb() ? knjson::Value(kncore::Hex(session.ContextDtb())) : knjson::Value();
    const auto sequenceBefore = knengine::ObservedBreakpointSequence();
    knjson::Value lastEvent;
    if (status.Connected && status.Stopped)
    {
        knengine::ReadLastEvent(session.Control(), lastEvent);
    }
    const auto current = session.RefreshStamp();
    const auto sequence = knengine::ObservedBreakpointSequence();
    if (sequence != sequenceBefore)
    {
        lastEvent = knjson::Value();
    }
    if (current != begin)
    {
        session.QueryStatus(&status);
        process = knjson::Value::MakeObject();
        process.Set(L"reason", knjson::Value(L"Debugger context changed; refresh again"));
        instructionPointer = knjson::Value();
        lastEvent = knjson::Value();
        currentProcessor = knjson::Value();
        contextDtb = knjson::Value();
    }

    result.Set(L"target", current.ToJson());
    result.Set(L"currentProcess", process);
    result.Set(L"instructionPointer", instructionPointer);
    result.Set(L"currentProcessor", currentProcessor);
    result.Set(L"contextDtbOverride", contextDtb);
    result.Set(L"registerContextOrigin", knjson::Value(L"Unknown"));
    result.Set(L"lastEvent", lastEvent);
    result.Set(L"breakpointSequence", sequence ? knjson::Value(std::to_wstring(*sequence)) : knjson::Value());
    result.Set(L"connected", knjson::Value(status.Connected));
    result.Set(L"kernelMode", knjson::Value(status.KernelMode));
    result.Set(L"dumpFile", knjson::Value(status.DumpFile));
    result.Set(L"localKernel", knjson::Value(status.LocalKernel));
    result.Set(L"sessionKind", knjson::Value(status.KindText.c_str()));
    result.Set(L"modulesLoaded", knjson::Value(static_cast<double>(status.ModulesLoaded)));
    result.Set(L"modulesUnloaded", knjson::Value(static_cast<double>(status.ModulesUnloaded)));
    result.Set(L"ntResolved", knjson::Value(status.NtModuleResolved));
    result.Set(L"execStatus", knjson::Value(status.ExecutionStatusText.c_str()));
    result.Set(L"stopped", knjson::Value(status.Stopped));
    result.Set(L"canEditBreakpoints", knjson::Value(status.Connected && status.Stopped && !status.DumpFile && !status.LocalKernel &&
                                                   current.Context.Complete() && knengine::SessionObserverReady()));
    result.Set(L"canControlExecution", result.Get(L"canEditBreakpoints"));
    const bool running = status.ExecutionStatusText == L"go" || status.ExecutionStatusText == L"go (handled)" ||
                         status.ExecutionStatusText == L"go (not handled)" || status.ExecutionStatusText == L"step over" ||
                         status.ExecutionStatusText == L"step into";
    const bool canBreak = status.Connected && !status.Stopped && running && !status.DumpFile && !status.LocalKernel &&
                          knengine::SessionObserverReady();
    knengine::SetBreakCapability(current, canBreak);
    result.Set(L"canBreakExecution", knjson::Value(canBreak));
    const bool processContext = status.Connected && status.KernelMode && status.Stopped && !status.LocalKernel &&
                                status.Architecture == IMAGE_FILE_MACHINE_AMD64;
    result.Set(L"canAttachProcess", knjson::Value(processContext));
    result.Set(L"processAttachReason", knjson::Value(processContext ? L"" : L"Requires a stopped x64 kernel target (remote or dump)."));
    result.Set(L"summary", knjson::Value(status.Summary.c_str()));
    result.Set(L"targetVersion", knjson::Value(status.TargetVersion));
    result.Set(L"hostVersion", knjson::Value(status.HostVersion));

    return result;
}

knjson::Value CatalogResult()
{
    knjson::Value groups = knjson::Value::MakeObject();

    for (const kncat::CommandInfo &info : kncat::All())
    {
        const std::wstring groupKey(info.Group);
        knjson::Value list = groups.Get(groupKey);

        if (!list.IsArray())
        {
            list = knjson::Value::MakeArray();
        }

        knjson::Value entry = knjson::Value::MakeObject();
        entry.Set(L"name", knjson::Value(info.Name));
        entry.Set(L"synopsis", knjson::Value(info.Synopsis));
        const auto *spec = kncmd::FindCommand(info.Name);
        entry.Set(L"grammar", knjson::Value(spec != nullptr ? spec->Grammar : info.Name));
        entry.Set(L"support", knjson::Value(spec != nullptr ? kncmd::SupportName(spec->Support) : L"Unsupported"));
        entry.Set(L"modes", knjson::Value(spec != nullptr ? kncmd::TargetModeDisplayName(*spec) : L"Any"));
        entry.Set(L"implementation", knjson::Value(kncat::SupportText(info.Level)));
        entry.Set(L"canonical", knjson::Value(spec != nullptr ? spec->Name : info.Name));
        auto aliases = knjson::Value::MakeArray();
        if (spec != nullptr)
        {
            for (const auto *alias : spec->Aliases)
            {
                aliases.Push(knjson::Value(alias));
            }
            entry.Set(L"requiresPreview", knjson::Value(kncmd::HasEffect(spec->Effects, kncmd::Effect::TargetMutation)));
            entry.Set(L"changesContext", knjson::Value(kncmd::HasEffect(spec->Effects, kncmd::Effect::SessionContextChange)));
        }
        entry.Set(L"aliases", aliases);
        auto operands = knjson::Value::MakeArray();
        for (const auto index : kncat::SymbolOperands(info.Name))
        {
            operands.Push(knjson::Value(static_cast<double>(index)));
        }
        entry.Set(L"symbolParameters", operands);
        auto options = knjson::Value::MakeArray();
        if (spec != nullptr)
        {
            for (const auto &option : spec->Options)
            {
                auto value = knjson::Value::MakeObject();
                value.Set(L"name", knjson::Value(option.Name));
                value.Set(L"takesValue", knjson::Value(option.TakesValue));
                options.Push(value);
            }
        }
        entry.Set(L"completionOptions", options);
        list.Push(entry);
        groups.Set(groupKey, list);
    }

    knjson::Value result = knjson::Value::MakeObject();
    result.Set(L"groups", groups);
    return result;
}

knjson::Value CompleteResult(const std::wstring &prefix)
{
    knjson::Value items = knjson::Value::MakeArray();

    for (const std::wstring &name : kncat::CompletionsFor(prefix))
    {
        items.Push(knjson::Value(name));
    }

    knjson::Value result = knjson::Value::MakeObject();
    result.Set(L"items", items);
    return result;
}

knjson::Value SymbolCompletions(knengine::DbgSession &session, const kncat::SymbolCompletionQuery &query,
                               const std::function<bool()> &cancelled)
{
    auto items = knjson::Value::MakeArray();
    auto *symbols = session.Symbols();
    const auto separator = query.Word.find(L'!');
    const bool qualified = separator != std::wstring::npos;
    const auto moduleWord = qualified ? query.Word.substr(0, separator) : query.Word;
    const auto symbolWord = qualified ? query.Word.substr(separator + 1) : query.Word;
    const auto deadline = GetTickCount64() + 200;
    unsigned searches = 0;
    std::set<std::wstring> seen;
    const auto stopped = [&]()
    {
        return GetTickCount64() >= deadline || items.Items().size() >= 24 || session.Cancelled() || (cancelled && cancelled());
    };
    const auto add = [&](const std::wstring &name, ULONG64 address, const wchar_t *kind)
    {
        if (kncat::SymbolCompletionWord(name) && name.size() <= 512 && seen.insert(name).second)
        {
            auto item = knjson::Value::MakeObject();
            item.Set(L"symbol", knjson::Value(name));
            item.Set(L"address", knjson::Value(kncore::Hex(address)));
            item.Set(L"kind", knjson::Value(kind));
            items.Push(item);
        }
    };
    ULONG loaded = 0;
    ULONG unloaded = 0;
    knengine::SymbolQueryScope passive;
    if (symbols->GetNumberModules(&loaded, &unloaded) == S_OK)
    {
        for (ULONG i = 0; i < (std::min)(loaded, 2048UL) && !stopped(); ++i)
        {
            DEBUG_MODULE_PARAMETERS module = {};
            ULONG64 base = 0;
            wchar_t name[512] = {};
            if (symbols->GetModuleByIndex(i, &base) != S_OK || base == 0 || base == DEBUG_INVALID_OFFSET ||
                symbols->GetModuleParameters(1, &base, 0, &module) != S_OK ||
                symbols->GetModuleNameStringWide(DEBUG_MODNAME_MODULE, i, base, name, _countof(name), nullptr) != S_OK ||
                !kncat::SymbolCompletionWord(name))
            {
                continue;
            }
            if (!qualified && _wcsnicmp(name, moduleWord.c_str(), moduleWord.size()) == 0)
            {
                add(std::wstring(name) + L"!", base, L"module");
            }
            if (stopped() || (qualified && _wcsicmp(name, moduleWord.c_str()) != 0) ||
                (!qualified && (symbolWord.size() < 2 || searches >= 8)) ||
                module.SymbolType == DEBUG_SYMTYPE_DEFERRED || module.SymbolType == DEBUG_SYMTYPE_NONE)
            {
                continue;
            }
            ++searches;
            ULONG64 search = 0;
            const auto pattern = std::wstring(name) + L"!" + symbolWord + L"*";
            if (symbols->StartSymbolMatchWide(pattern.c_str(), &search) != S_OK)
            {
                continue;
            }
            struct SearchLease
            {
                IDebugSymbols3 *Symbols;
                ULONG64 Search;
                ~SearchLease()
                {
                    Symbols->EndSymbolMatch(Search);
                }
            } lease = {symbols, search};
            for (unsigned entry = 0; entry < 256 && !stopped(); ++entry)
            {
                wchar_t symbol[1024] = {};
                ULONG64 address = 0;
                const HRESULT status = symbols->GetNextSymbolMatchWide(search, symbol, _countof(symbol), nullptr, &address);
                if (status == E_NOINTERFACE || FAILED(status))
                {
                    break;
                }
                const auto length = wcsnlen_s(symbol, _countof(symbol));
                if (status != S_OK || length >= _countof(symbol))
                {
                    continue;
                }
                const std::wstring candidate(symbol, length);
                const auto bang = candidate.find(L'!');
                const auto word = qualified || bang == std::wstring::npos ? candidate : candidate.substr(bang + 1);
                if (address != DEBUG_INVALID_OFFSET && _wcsnicmp(word.c_str(), query.Word.c_str(), query.Word.size()) == 0)
                {
                    add(candidate, address, L"symbol");
                }
            }
        }
    }
    return items;
}

bool CodeBreakpointAddressAvailable(knengine::DbgSession &session, uint64_t address)
{
    ULONG count = 0;
    if (session.Control()->GetNumberBreakpoints(&count) != S_OK || count > 4096)
    {
        return false;
    }
    for (ULONG index = 0; index < count; ++index)
    {
        IDebugBreakpoint2 *breakpoint = nullptr;
        DEBUG_BREAKPOINT_PARAMETERS entry = {};
        if (session.Cancelled() || session.Control()->GetBreakpointByIndex2(index, &breakpoint) != S_OK ||
            breakpoint->GetParameters(&entry) != S_OK ||
            ((entry.Flags & DEBUG_BREAKPOINT_DEFERRED) == 0 && entry.BreakType == DEBUG_BREAKPOINT_CODE && entry.Offset == address))
        {
            return false;
        }
    }
    return true;
}

knjson::Value ExecuteResult(knengine::DbgSession &session, const std::wstring &commandLine, const kncore::SessionStamp *expected = nullptr,
                            const std::function<bool()> &cancelled = {}, kncmd::CommandInput input = kncmd::CommandInput::Registered)
{
    knjson::Value result = knjson::Value::MakeObject();
    do
    {
        const kncmd::CommandResult dispatched = kncmd::DispatchCommand(session, commandLine, expected, cancelled, input);

        result.Set(L"ok", knjson::Value(dispatched.Ok));
        if (dispatched.Data.Analysis.Get(L"artifactCommitted").AsBool(false))
        {
            result.Set(L"artifactCommitted", knjson::Value(true));
        }
        const bool inspection = kncmd::IsResultInspection(dispatched.Data.CommandId);
        const auto retained = inspection ? nullptr
                              : dispatched.ResultId.empty()
                                  ? kncore::Results().Publish(knutil::NewToken(), dispatched.Data, dispatched.Output)
                                  : kncore::Results().Find(dispatched.ResultId);
        if (retained)
        {
            auto metadata = dispatched.Data;
            metadata.Rows = knjson::Value::MakeArray();
            metadata.Findings = knjson::Value::MakeArray();
            if (metadata.CommandId == L"windbg")
            {
                // The response already carries the command; keep its full copy in storage.
                metadata.Analysis = knjson::Value();
            }
            result.Set(L"data", metadata.ToJson());
            result.Set(L"resultId", knjson::Value(retained->Id));
            result.Set(L"rowCount", knjson::Value(std::to_wstring(retained->Data.Rows.Items().size())));
            result.Set(L"findingCount", knjson::Value(std::to_wstring(retained->Data.Findings.Items().size())));
            result.Set(L"rowsDelivery", knjson::Value(L"NotRequested"));
            result.Set(L"findingsDelivery", knjson::Value(L"NotRequested"));
            result.Set(L"outputLength", knjson::Value(std::to_wstring(retained->Text.size())));
        }
        else if (inspection)
        {
            auto metadata = dispatched.Data;
            metadata.Rows = knjson::Value::MakeArray();
            metadata.Findings = knjson::Value::MakeArray();
            result.Set(L"data", metadata.ToJson());
            const size_t units = knutil::Utf16PrefixUnits(dispatched.Output, 4096);
            auto preview = dispatched.Output.substr(0, units);
            if (units != dispatched.Output.size())
            {
                preview += L"\n[output] Inspection preview capped; open the original result or use the CLI for full inspection.\n";
            }
            result.Set(L"output", knjson::Value(preview));
            result.Set(L"ephemeral", knjson::Value(true));
        }
        else
        {
            result.Set(L"ok", knjson::Value(false));
            result.Set(L"retentionError", knjson::Value(L"Result retention budget exceeded"));
        }
        result.Set(L"command", knjson::Value(commandLine));
        if (input == kncmd::CommandInput::UiConsole && dispatched.Data.Source == L"windbg")
        {
            result.Set(L"currentTarget", knengine::Epochs().Stamp().ToJson());
        }
        result.Set(L"error", knjson::Value(dispatched.Ok ? L""
                                                         : (dispatched.Error.empty() ? L"execution failed (no session or engine error)"
                                                                                     : dispatched.Error.c_str())));
        result.Set(L"cls", knjson::Value(dispatched.Cls));
        result.Set(L"blocked", knjson::Value(dispatched.Blocked));
    } while (false);

    return result;
}
} // namespace

std::wstring MakeEvent(const wchar_t *name, const knjson::Value &data)
{
    knjson::Value event = knjson::Value::MakeObject();
    event.Set(L"event", knjson::Value(name));
    event.Set(L"data", data);
    return event.Write();
}

knjson::Value HandleRequest(const knjson::Value &request, knengine::DbgSession *ownedSession, const std::function<bool()> &cancelled,
                            const std::function<void(uint64_t)> &executionStarted)
{
    const std::wstring method = request.Get(L"method").AsString(L"");
    const knjson::Value &params = request.Get(L"params");

    knjson::Value reply = knjson::Value::MakeObject();
    reply.Set(L"requestId", request.Get(L"requestId"));

    reply.Set(L"schema", knjson::Value(L"kndbgx.rpc.v3"));
    reply.Set(L"uiGeneration", request.Get(L"uiGeneration"));
    reply.Set(L"type", knjson::Value(L"completed"));
    std::wstring validation;
    if (!kncore::RpcShape(request, validation))
    {
        reply.Set(L"ok", knjson::Value(false));
        reply.Set(L"error", knjson::Value(validation));
        return reply;
    }

    const auto cancellationRequested = [&]()
    {
        if (cancelled && cancelled())
        {
            reply.Set(L"ok", knjson::Value(false));
            reply.Set(L"error", knjson::Value(L"CancelledBeforeExecution"));
            return true;
        }
        return false;
    };
    if (cancellationRequested())
    {
        return reply;
    }
    kncmd::ParsedCommand executionRequest;
    const bool detachedRequest = method == L"execute" && kncmd::ParseCommand(params.Get(L"command").AsString(L""), &executionRequest) &&
                                 kncmd::DetachedCommand(executionRequest.Spec);
    knengine::DbgSession detachedSession;
    if (detachedRequest)
    {
        ownedSession = &detachedSession;
    }
    const bool engineMethod = method == L"status" || (method == L"execute" && !detachedRequest) || method == L"previewWrite" ||
                              method == L"executePlan" || method == L"navigateResult" || method == L"processAction" || method == L"memoryRead" ||
                              method == L"memoryDump" || method == L"disassemblyRead" || method == L"breakpointPlan" || method == L"breakpointApply" ||
                              method == L"debuggerAction" || method == L"completeSymbols" ||
                              method == L"symbolModules" || method == L"symbolHealth";
    const bool bindsTarget = (engineMethod && method != L"status") ||
                             method == L"breakExecution" ||
                             (detachedRequest && std::wstring(executionRequest.Spec->Name) == L"submit");
    std::unique_ptr<kncore::ExecutionLease> lease;
    if (engineMethod)
    {
        lease = std::make_unique<kncore::ExecutionLease>(knengine::Coordinator(), kncore::ExecutionDomain::Ui);
        if (!*lease || ownedSession == nullptr)
        {
            reply.Set(L"ok", knjson::Value(false));
            reply.Set(L"error", knjson::Value(!*lease ? L"EngineBusy" : L"OwnerThreadRequired"));
            return reply;
        }
        if (executionStarted)
        {
            executionStarted(knengine::Coordinator().Serial());
        }
        if (cancellationRequested())
        {
            return reply;
        }
        if (!ownedSession->IsReady())
        {
            ownedSession->Initialize();
        }
    }
    const auto expected = engineMethod ? ownedSession->RefreshStamp() : knengine::Epochs().Stamp();
    if (bindsTarget && (request.Get(L"sessionId").AsString(L"") != expected.SessionId ||
                        request.Get(L"expectedTargetGeneration").AsString(L"") != std::to_wstring(expected.TargetGeneration)))
    {
        reply.Set(L"ok", knjson::Value(false));
        reply.Set(L"error", knjson::Value(L"StaleTargetGeneration"));
        return reply;
    }
    if (cancellationRequested())
    {
        return reply;
    }

    bool ok = true;
    knjson::Value result;

    do
    {
        if (method == L"hello")
        {
            result = knjson::Value::MakeObject();
            result.Set(L"version", knjson::Value(L"0.2.0"));
            result.Set(L"target", knengine::Epochs().Stamp().ToJson());
            auto capabilities = knjson::Value::MakeArray();
            for (const auto capability : {L"contextExplanation.v1", L"operationObservation.v1", L"symbolHealth.v1"})
            {
                capabilities.Push(knjson::Value(capability));
            }
            result.Set(L"capabilities", capabilities);
            break;
        }

        if (method == L"status")
        {
            result = StatusResult(*ownedSession);
            break;
        }

        if (method == L"catalog")
        {
            result = CatalogResult();
            break;
        }

        if (method == L"symbolModules" || method == L"symbolHealth")
        {
            knengine::SessionStatus status = {};
            ownedSession->QueryStatus(&status);
            if (!status.Connected || !status.Stopped || status.Architecture != IMAGE_FILE_MACHINE_AMD64 ||
                !kncore::MatchesStamp(expected, params.Get(L"expectedStamp")))
            {
                ok = false;
                result = knjson::Value(L"StoppedCurrentX64ContextRequired");
                break;
            }
            if (method == L"symbolModules")
            {
                uint64_t cursor = 0;
                if (!kncore::ParseUnsigned(params.Get(L"cursor").AsString(L""), 10, &cursor))
                {
                    ok = false;
                    result = knjson::Value(L"InvalidModuleCursor");
                    break;
                }
                result = knengine::ReadSymbolModules(*ownedSession, expected, cursor);
            }
            else
            {
                const auto key = kncore::ParseSymbolModuleKey(params.Get(L"moduleKey"));
                if (!key)
                {
                    ok = false;
                    result = knjson::Value(L"InvalidModuleIdentity");
                    break;
                }
                result = knengine::InspectSymbolHealth(*ownedSession, expected, *key,
                    params.Get(L"typeName").AsString(L""), params.Get(L"fieldName").AsString(L""));
            }
            if (!result.Get(L"ok").AsBool(false))
            {
                ok = false;
                result = result.Get(L"error");
            }
            break;
        }

        if (method == L"complete")
        {
            const std::wstring prefix = params.Get(L"prefix").AsString(L"");
            result = CompleteResult(prefix);
            break;
        }

        if (method == L"completeSymbols")
        {
            knengine::SessionStatus status = {};
            ownedSession->QueryStatus(&status);
            if (!status.Connected || !status.Stopped || !kncore::MatchesStamp(expected, params.Get(L"expectedStamp")))
            {
                ok = false;
                result = knjson::Value(L"StoppedCurrentContextRequired");
                break;
            }
            result = knjson::Value::MakeObject();
            const auto query = kncat::SymbolQueryFor(params.Get(L"prefix").AsString(L""), params.Get(L"suffix").AsString(L""));
            result.Set(L"items", query ? SymbolCompletions(*ownedSession, *query, cancelled) : knjson::Value::MakeArray());
            if (ownedSession->RefreshStamp() != expected || cancellationRequested())
            {
                ok = false;
                result = knjson::Value(L"StaleOrCancelledSymbolCompletion");
                break;
            }
            result.Set(L"target", expected.ToJson());
            break;
        }

        if (method == L"classify")
        {
            const std::wstring command = params.Get(L"command").AsString(L"");
            kncmd::ParsedCommand parsed;
            if (!kncmd::ParseUiCommand(command, &parsed))
            {
                ok = false;
                result = knjson::Value(parsed.Error);
                break;
            }
            result = knjson::Value::MakeObject();
            result.Set(L"write", knjson::Value(kncmd::HasEffect(parsed.Spec->Effects, kncmd::Effect::TargetMutation)));
            result.Set(L"opaque", knjson::Value(kncmd::HasEffect(parsed.Spec->Effects, kncmd::Effect::OpaqueEngine)));
            result.Set(L"canonical", knjson::Value(parsed.Spec->Name));
            break;
        }

        if (method == L"previewWrite")
        {
            const auto prepared = kncmd::PrepareMutation(*ownedSession, params.Get(L"command").AsString(L""));
            if (prepared.Result.State != kncore::Status::Success)
            {
                ok = false;
                result = knjson::Value(prepared.Result.Error.Message.empty() ? L"Mutation plan unavailable for this target or range"
                                                                             : prepared.Result.Error.Message);
                break;
            }
            result = knjson::Value::MakeObject();
            const auto preview = kncore::Results().Publish(knutil::NewToken(), prepared.Result, prepared.Plan.ToJson().Write());
            if (!preview)
            {
                kncmd::PlanStore().Discard(prepared.Plan.Id, prepared.Plan.ApprovalToken);
                ok = false;
                result = knjson::Value(L"Could not store the complete plan preview");
                break;
            }
            auto approval = knjson::Value::MakeObject();
            approval.Set(L"planId", knjson::Value(prepared.Plan.Id));
            approval.Set(L"approvalToken", knjson::Value(prepared.Plan.ApprovalToken));
            result.Set(L"plan", approval);
            result.Set(L"previewResultId", knjson::Value(preview->Id));
            break;
        }

        if (method == L"executePlan")
        {
            const auto applied =
                kncmd::ExecuteApproved(*ownedSession, params.Get(L"planId").AsString(L""), params.Get(L"approvalToken").AsString(L""));
            result = knjson::Value::MakeObject();
            result.Set(L"ok", knjson::Value(applied.State == kncore::Status::Success));
            const auto retained = kncore::Results().Publish(knutil::NewToken(), applied, applied.ToJson().Write());
            if (retained)
            {
                result.Set(L"resultId", knjson::Value(retained->Id));
                result.Set(L"rowCount", knjson::Value(std::to_wstring(applied.Rows.Items().size())));
                result.Set(L"findingCount", knjson::Value(std::to_wstring(applied.Findings.Items().size())));
                auto metadata = applied;
                metadata.Rows = knjson::Value::MakeArray();
                metadata.Findings = knjson::Value::MakeArray();
                result.Set(L"data", metadata.ToJson());
                result.Set(L"outputLength", knjson::Value(std::to_wstring(retained->Text.size())));
                result.Set(L"rowsDelivery", knjson::Value(L"NotRequested"));
                result.Set(L"findingsDelivery", knjson::Value(L"NotRequested"));
            }
            result.Set(L"error", knjson::Value(applied.Error.Message.empty() ? kncore::StatusName(applied.State) : applied.Error.Message));
            break;
        }

        if (method == L"discardPlan")
        {
            kncmd::PlanStore().Discard(params.Get(L"planId").AsString(L""), params.Get(L"approvalToken").AsString(L""));
            kncore::ActionPlans().Discard(params.Get(L"planId").AsString(L""), params.Get(L"approvalToken").AsString(L""));
            result = knjson::Value::MakeObject();
            break;
        }

        if (method == L"execute")
        {
            const std::wstring command = params.Get(L"command").AsString(L"");

            if (command.empty())
            {
                ok = false;
                result = knjson::Value(L"empty command");
                break;
            }

            result = ExecuteResult(*ownedSession, command, bindsTarget ? &expected : nullptr, cancelled, kncmd::CommandInput::UiConsole);
            break;
        }

        if (method == L"breakExecution")
        {
            if (!kncore::MatchesStamp(expected, params.Get(L"expectedStamp")) || !knengine::RequestTargetBreak(expected))
            {
                ok = false;
                result = knjson::Value(L"Break was not confirmed. Refresh target or check WinDbg before trying again.");
                break;
            }
            result = knjson::Value::MakeObject();
            result.Set(L"requested", knjson::Value(true));
            result.Set(L"completed", knjson::Value(false));
            break;
        }

        if (method == L"debuggerAction")
        {
            const auto operation = params.Get(L"operation").AsString(L"");
            knengine::SessionStatus status = {};
            ownedSession->QueryStatus(&status);
            const auto stamp = ownedSession->RefreshStamp();
            if (!kncore::ExecutionOperation(operation) || !status.Connected || !status.Stopped || status.DumpFile || status.LocalKernel ||
                !stamp.Context.Complete() || !knengine::SessionObserverReady() || !kncore::MatchesStamp(stamp, params.Get(L"expectedStamp")))
            {
                ok = false;
                result = knjson::Value(L"Execution control requires a current stopped live target and a supported operation.");
                break;
            }
            const auto preview = ExecuteResult(*ownedSession, L"debug-plan " + operation, &stamp, cancelled);
            const auto retained = kncore::Results().Find(preview.Get(L"resultId").AsString(L""));
            if (!preview.Get(L"ok").AsBool(false) || !retained || retained->Data.Rows.Items().size() != 1)
            {
                result = preview;
                break;
            }
            const auto &row = retained->Data.Rows.Items()[0];
            const auto id = row.Get(L"planId").AsString(L"");
            const auto token = row.Get(L"approvalToken").AsString(L"");
            const auto plan = kncore::ActionPlans().Find(id, token);
            if (cancellationRequested() || !plan || plan->Operation != operation || plan->Stamp != stamp)
            {
                kncore::ActionPlans().Discard(id, token);
                ok = false;
                result = knjson::Value(L"Execution action cancelled or context changed before application.");
                break;
            }
            result = ExecuteResult(*ownedSession, L"debug-approve " + id + L" " + token, &stamp, cancelled);
            kncore::ActionPlans().Discard(id, token);
            result.Set(L"operation", knjson::Value(operation));
            result.Set(L"status", StatusResult(*ownedSession));
            break;
        }

        if (method == L"breakpointPlan" || method == L"breakpointApply")
        {
            knengine::SessionStatus status = {};
            ownedSession->QueryStatus(&status);
            const auto stamp = ownedSession->RefreshStamp();
            if (!status.Connected || !status.Stopped || status.DumpFile || status.LocalKernel || !stamp.Context.Complete() ||
                !knengine::SessionObserverReady() || !kncore::MatchesStamp(stamp, params.Get(L"expectedStamp")))
            {
                ok = false;
                result = knjson::Value(L"Breakpoint changes require a current stopped live target. Refresh the view and try again.");
                break;
            }
            if (method == L"breakpointApply")
            {
                const auto id = params.Get(L"planId").AsString(L"");
                const auto token = params.Get(L"approvalToken").AsString(L"");
                const auto plan = kncore::ActionPlans().Find(id, token);
                if (!plan || !kncore::BreakpointOperation(plan->Operation) || plan->Stamp != stamp ||
                    (plan->Operation == L"breakpoint-add" && !CodeBreakpointAddressAvailable(*ownedSession, plan->Operand)))
                {
                    kncore::ActionPlans().Discard(id, token);
                    ok = false;
                    result = knjson::Value(L"Breakpoint plan expired or changed. Create a new preview.");
                    break;
                }
                result = ExecuteResult(*ownedSession, L"debug-approve " + id + L" " + token, &stamp, cancelled);
                result.Set(L"currentTarget", ownedSession->RefreshStamp().ToJson());
                result.Set(L"status", StatusResult(*ownedSession));
                break;
            }
            const auto &binding = params.Get(L"source");
            const auto source = kncore::Results().Find(binding.Get(L"resultId").AsString(L""));
            const auto command = kncore::BreakpointPlanCommand(params, source.get(), stamp);
            if (!command)
            {
                ok = false;
                result = knjson::Value(L"Invalid breakpoint expression or stale source row. Refresh the view.");
                break;
            }
            const auto *row = kncore::BreakpointSourceRow(binding, source.get(), stamp);
            if (row != nullptr && source->Data.CommandId == L"breakpoints")
            {
                uint64_t id = 0;
                kncore::ParseUnsigned(row->Get(L"id").AsString(L""), 10, &id);
                IDebugBreakpoint2 *breakpoint = nullptr;
                if (ownedSession->Control()->GetBreakpointById2(static_cast<ULONG>(id), &breakpoint) != S_OK ||
                    kncmd::BreakpointIdentity(breakpoint) != row->Get(L"identity").AsString(L""))
                {
                    ok = false;
                    result = knjson::Value(L"Breakpoint changed or its ID was reused. Refresh the list.");
                    break;
                }
            }
            if (params.Get(L"operation").AsString(L"") == L"breakpoint-add")
            {
                kncmd::ParsedCommand parsed;
                uint64_t address = 0;
                const bool unique = kncmd::ParseCommand(*command, &parsed) && parsed.Arguments.size() == 3 &&
                                    kncmd::EvalAddress(*ownedSession, parsed.Arguments[2], &address) &&
                                    CodeBreakpointAddressAvailable(*ownedSession, address);
                if (!unique)
                {
                    ok = false;
                    result = knjson::Value(L"Address unavailable, breakpoint list incomplete, or a code breakpoint already exists. Refresh the list.");
                    break;
                }
            }
            result = ExecuteResult(*ownedSession, *command, &stamp, cancelled);
            const auto retained = kncore::Results().Find(result.Get(L"resultId").AsString(L""));
            if (result.Get(L"ok").AsBool(false) && retained && retained->Data.Rows.Items().size() == 1)
            {
                result.Set(L"plan", retained->Data.Rows.Items()[0]);
            }
            break;
        }

        if (method == L"memoryRead")
        {
            knengine::SessionStatus status = {};
            ownedSession->QueryStatus(&status);
            const auto stamp = ownedSession->RefreshStamp();
            const auto source = kncore::Results().Find(params.Get(L"source").Get(L"resultId").AsString(L""));
            const auto command = kncore::MemoryViewCommand(params, source.get(), &stamp);
            if (!command || !status.Connected || !status.Stopped || !kncore::MatchesStamp(stamp, params.Get(L"expectedStamp")))
            {
                ok = false;
                result = knjson::Value(!command ? L"Invalid memory address, address space, read size or source result." :
                    L"Memory context changed or target is not stopped. Refresh target, then read again.");
                break;
            }
            result = ExecuteResult(*ownedSession, *command, &stamp, cancelled);
            if (params.Get(L"space").AsString(L"") == L"virtual" && ownedSession->RefreshStamp() == stamp &&
                kncore::MatchesStamp(stamp, result.Get(L"data").Get(L"target")))
            {
                result.Set(L"pageTables", MemoryPageTables(*ownedSession, stamp, result.Get(L"data").Get(L"analysis").Get(L"memoryRead"), cancelled));
            }
            break;
        }

        if (method == L"memoryDump")
        {
            knengine::SessionStatus status = {};
            ownedSession->QueryStatus(&status);
            const auto source = kncore::Results().Find(params.Get(L"source").Get(L"resultId").AsString(L""));
            const auto command = source ? kncore::MemoryDumpCommand(params, *source, ownedSession->RefreshStamp(), status.KernelMode) : std::nullopt;
            if (!status.Connected || !status.Stopped || !command)
            {
                ok = false;
                result = knjson::Value(L"Invalid dump parameters or expired memory capture. Check the file path and read the stopped target again.");
                break;
            }
            result = ExecuteResult(*ownedSession, *command, &source->Data.Stamp, cancelled);
            break;
        }

        if (method == L"disassemblyRead")
        {
            knengine::SessionStatus status = {};
            ownedSession->QueryStatus(&status);
            const auto stamp = ownedSession->RefreshStamp();
            const auto source = kncore::Results().Find(params.Get(L"source").Get(L"resultId").AsString(L""));
            const auto command = kncore::DisassemblyViewCommand(params, source.get(), &stamp);
            if (!command || !status.Connected || !status.Stopped || !kncore::MatchesStamp(stamp, params.Get(L"expectedStamp")))
            {
                ok = false;
                result = knjson::Value(!command ? L"Invalid disassembly address, instruction count or source result." :
                    L"Disassembly context changed or target is not stopped. Refresh target, then read again.");
                break;
            }
            const auto instructionPointer = InstructionPointer(*ownedSession, true);
            result = ExecuteResult(*ownedSession, *command, &stamp, cancelled);
            result.Set(L"instructionPointer", instructionPointer);
            break;
        }

        if (method == L"navigateResult")
        {
            const auto source = kncore::Results().Find(params.Get(L"resultId").AsString(L""));
            const auto command = source ? kncore::BoundResultCommand(*source, params, ownedSession->RefreshStamp()) : std::nullopt;
            if (!command || cancellationRequested())
            {
                ok = false;
                result = knjson::Value(L"StaleResultOrInvalidNavigation: collect a current result before navigating");
                break;
            }
            result = ExecuteResult(*ownedSession, *command, &source->Data.Stamp);
            break;
        }

        if (method == L"processAction")
        {
            const auto source = kncore::Results().Find(params.Get(L"resultId").AsString(L""));
            const auto *row = source ? kncore::BoundProcessRow(*source, params, ownedSession->RefreshStamp()) : nullptr;
            if (!row || cancellationRequested())
            {
                ok = false;
                result = knjson::Value(L"StaleProcessList: refresh Processes before using this action.");
                break;
            }
            const auto action = params.Get(L"action").AsString(L"");
            uint64_t address = 0;
            kncore::ParseUnsigned(row->Get(L"eprocess").AsString(L""), 16, &address);
            const auto selector = L"eprocess:" + kncore::Hex(address);
            if (action == L"details" || action == L"threads" || action == L"vad" || action == L"token")
            {
                const std::wstring command = action == L"details" ? L"!process" : L"!" + action;
                result = ExecuteResult(*ownedSession, command + L" " + selector, &source->Data.Stamp, cancelled);
                break;
            }
            if (action != L"attach")
            {
                ok = false;
                result = knjson::Value(L"Unknown process action");
                break;
            }
            knengine::SessionStatus status = {};
            ownedSession->QueryStatus(&status);
            if (!status.Connected || !status.KernelMode || !status.Stopped || status.LocalKernel ||
                status.Architecture != IMAGE_FILE_MACHINE_AMD64 || !ownedSession->SystemObjects())
            {
                ok = false;
                result = knjson::Value(L"Process attach requires a stopped x64 kernel target (remote or dump).");
                break;
            }
            knengine::LayoutResolver layout(*ownedSession);
            kncmd::ProcRow current;
            const auto pcb = layout.Field(L"nt", L"_EPROCESS", L"Pcb");
            if (!pcb || pcb->Offset != 0 ||
                !kncmd::ResolveProcessTarget(*ownedSession, layout, {}, selector, &current, true) ||
                !kncore::SameProcessIdentity(*row, current))
            {
                ok = false;
                result = knjson::Value(L"Process identity or address-space layout is unavailable or changed. Refresh Processes.");
                break;
            }
            if (cancellationRequested() || ownedSession->Cancelled() || ownedSession->RefreshStamp() != source->Data.Stamp)
            {
                ok = false;
                result = knjson::Value(L"Process attach cancelled or debugger context changed before switching.");
                break;
            }
            auto *system = ownedSession->SystemObjects();
            const auto switched = kncore::SwitchImplicitProcess(address,
                [&]() -> std::optional<uint64_t>
                {
                    ULONG64 offset = 0;
                    return system->GetImplicitProcessDataOffset(&offset) == S_OK ? std::optional<uint64_t>(offset) : std::nullopt;
                },
                [&](uint64_t offset)
                {
                    return system->SetImplicitProcessDataOffset(offset) == S_OK;
                });
            ownedSession->RefreshStamp();
            if (switched != kncore::ProcessSwitchResult::Success)
            {
                if (switched == kncore::ProcessSwitchResult::RestoreFailed)
                {
                    ownedSession->MarkFault();
                }
                ok = false;
                result = knjson::Value(switched == kncore::ProcessSwitchResult::RestoreFailed
                                           ? L"Process switch and restoration failed. Verify the debugger context before continuing."
                                           : L"The debugger could not switch to this process; the previous context was retained.");
                break;
            }
            ownedSession->SetContextDtb(current.DirectoryTableBase);
            result = StatusResult(*ownedSession);
            result.Set(L"attached", knjson::Value(true));
            result.Set(L"process", *row);
            break;
        }

        if (method == L"interrupt")
        {
            ok = false;
            result = knjson::Value(L"Cancellation requires the UI request owner adapter");
            break;
        }

        if (method == L"resultTabs")
        {
            const auto &items = params.Get(L"resultIds").Items();
            std::vector<std::wstring> ids;
            if (items.size() <= kncore::ResultStore::MaximumUiPins)
            {
                for (const auto &item : items)
                {
                    ids.push_back(item.IsString() ? item.AsString(L"") : L"");
                }
            }
            std::vector<std::wstring> missing;
            if (items.size() > kncore::ResultStore::MaximumUiPins || !kncore::Results().SetUiPins(ids, &missing))
            {
                ok = false;
                result = knjson::Value(L"InvalidResultTabsOrLimitExceeded");
                break;
            }
            result = knjson::Value::MakeObject();
            auto absent = knjson::Value::MakeArray();
            for (const auto &id : missing)
            {
                absent.Push(knjson::Value(id));
            }
            result.Set(L"missing", std::move(absent));
            break;
        }

        if (method == L"outputChunk" || method == L"resultPage" || method == L"saveLog" || method == L"resultInfo")
        {
            const auto retained = kncore::Results().Find(params.Get(L"resultId").AsString(L""));
            if (!retained)
            {
                ok = false;
                result = knjson::Value(L"ResultExpiredOrUnknown");
                break;
            }
            result = knjson::Value::MakeObject();
            result.Set(L"resultId", knjson::Value(retained->Id));
            if (method == L"resultInfo")
            {
                auto metadata = retained->Data;
                metadata.Rows = knjson::Value::MakeArray();
                metadata.Findings = knjson::Value::MakeArray();
                if (metadata.CommandId == L"windbg" && metadata.Analysis.Get(L"hostCommandLine").IsString())
                {
                    result.Set(L"command", metadata.Analysis.Get(L"hostCommandLine"));
                    metadata.Analysis = knjson::Value();
                }
                result.Set(L"data", metadata.ToJson());
                result.Set(L"rowCount", knjson::Value(std::to_wstring(retained->Data.Rows.Items().size())));
                result.Set(L"findingCount", knjson::Value(std::to_wstring(retained->Data.Findings.Items().size())));
                result.Set(L"rowsDelivery", knjson::Value(L"NotRequested"));
                result.Set(L"findingsDelivery", knjson::Value(L"NotRequested"));
                result.Set(L"outputLength", knjson::Value(std::to_wstring(retained->Text.size())));
                break;
            }
            if (method == L"saveLog")
            {
                const auto path = knlog::LogDirectory() + L"\\result-" + knutil::UniqueSuffix() + L".json";
                const auto exported = knutil::ExportStoredResult(*retained, path, cancelled);
                if (exported.State != kncore::Status::Success)
                {
                    ok = false;
                    result = knjson::Value(std::wstring(kncore::StatusName(exported.State)) + L": " + exported.Error.Message);
                    break;
                }
                result.Set(L"path", knjson::Value(path));
                break;
            }
            uint64_t offset = 0;
            const bool output = method == L"outputChunk";
            const auto collection = params.Get(L"collection").AsString(L"");
            if (!output && collection != L"rows" && collection != L"findings")
            {
                ok = false;
                result = knjson::Value(L"InvalidResultCollection");
                break;
            }
            const size_t total = output                  ? retained->Text.size()
                                 : collection == L"rows" ? retained->Data.Rows.Items().size()
                                                         : retained->Data.Findings.Items().size();
            if (!kncore::ParseUnsigned(params.Get(output ? L"cursor" : L"offset").AsString(L""), 10, &offset) || offset > total)
            {
                ok = false;
                result = knjson::Value(L"InvalidResultCursor");
                break;
            }
            const auto start = offset;
            if (output)
            {
                if (offset < total && retained->Text[offset] >= 0xdc00 && retained->Text[offset] <= 0xdfff)
                {
                    ok = false;
                    result = knjson::Value(L"CursorSplitsUtf16Scalar");
                    break;
                }
                size_t count = std::min<size_t>(4096, total - static_cast<size_t>(offset));
                if (count > 0 && retained->Text[offset + count - 1] >= 0xd800 && retained->Text[offset + count - 1] <= 0xdbff)
                {
                    --count;
                }
                result.Set(L"text", knjson::Value(retained->Text.substr(static_cast<size_t>(offset), count)));
                offset += count;
            }
            else
            {
                auto page = kncore::PageRecords(*retained, collection, static_cast<size_t>(offset));
                auto addresses = knjson::Value::MakeArray();
                size_t recordBudget = 128;
                while (page.Valid)
                {
                    addresses = knjson::Value::MakeArray();
                    for (const auto &row : page.Records.Items())
                    {
                        addresses.Push(kncore::ResultAddressFields(row, &retained->Data));
                    }
                    if (knutil::WideToUtf8(addresses.Write()).size() <= 24000)
                    {
                        break;
                    }
                    recordBudget = page.Records.Items().size() / 2;
                    if (recordBudget == 0)
                    {
                        page.Valid = false;
                        break;
                    }
                    page = kncore::PageRecords(*retained, collection, static_cast<size_t>(offset), 24000, recordBudget);
                }
                if (!page.Valid)
                {
                    ok = false;
                    result = knjson::Value(L"ResultPageUnavailable: export the stored result");
                    break;
                }
                result.Set(collection, page.Records);
                result.Set(L"addressFields", std::move(addresses));
                result.Set(L"collection", knjson::Value(collection));
                result.Set(L"delivery", knjson::Value(page.Delivery()));
                result.Set(L"pageByteUnit", knjson::Value(L"UTF-8 JSON array bytes"));
                result.Set(L"payloadBytes", knjson::Value(std::to_wstring(page.PayloadBytes)));
                offset = page.Next;
            }
            result.Set(L"offset", knjson::Value(std::to_wstring(start)));
            result.Set(L"next", knjson::Value(std::to_wstring(offset)));
            result.Set(L"total", knjson::Value(std::to_wstring(total)));
            result.Set(L"complete", knjson::Value(offset == total));
            reply.Set(L"type", knjson::Value(L"resultChunk"));
            break;
        }

        ok = false;
        result = knjson::Value(L"unknown method: " + method);
    } while (false);

    reply.Set(L"ok", knjson::Value(ok));

    if (ok)
    {
        reply.Set(L"result", result);
    }
    else
    {
        reply.Set(L"error", result);
    }

    size_t wireBytes = 0;
    const bool fitsWireBudget = reply.WriteStream(
        [&](std::wstring_view fragment)
        {
            const auto bytes = knutil::WideToUtf8(std::wstring(fragment)).size();
            if (bytes > 65536 - wireBytes)
            {
                return false;
            }
            wireBytes += bytes;
            return true;
        });
    if (!fitsWireBudget)
    {
        auto bounded = knjson::Value::MakeObject();
        bounded.Set(L"resultId", result.Get(L"resultId"));
        bounded.Set(L"rowCount", result.Get(L"rowCount"));
        bounded.Set(L"findingCount", result.Get(L"findingCount"));
        bounded.Set(L"rowsDelivery", knjson::Value(L"NotRequested"));
        bounded.Set(L"findingsDelivery", knjson::Value(L"NotRequested"));
        bounded.Set(L"outputLength", result.Get(L"outputLength"));
        if (result.Get(L"artifactCommitted").AsBool(false))
        {
            bounded.Set(L"artifactCommitted", knjson::Value(true));
        }
        if (!result.Get(L"currentTarget").IsNull())
        {
            bounded.Set(L"currentTarget", result.Get(L"currentTarget"));
        }
        if (result.Get(L"command").IsString())
        {
            const auto command = result.Get(L"command").AsString(L"");
            const size_t count = knutil::Utf16PrefixUnits(command, 512);
            bounded.Set(L"command", knjson::Value(command.substr(0, count) + (count < command.size() ? L"..." : L"")));
        }
        auto metadata = knjson::Value::MakeObject();
        metadata.Set(L"target", result.Get(L"data").Get(L"target"));
        metadata.Set(L"status", result.Get(L"data").Get(L"status"));
        metadata.Set(L"metadataOmitted", knjson::Value(L"Metadata exceeds message budget; save the full result"));
        bounded.Set(L"data", metadata);
        bounded.Set(L"ok", result.Get(L"ok"));
        reply.Set(L"result", bounded);
        reply.Set(L"error", knjson::Value(L"Reply metadata exceeded the size limit; inspect the stored result"));
    }
    return reply;
}
} // namespace knbridge
