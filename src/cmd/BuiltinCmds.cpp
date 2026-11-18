#include "CommandSpec.h"
#include "ContextDefaults.h"
#include "MutationService.h"
#include "WriteGate.h"
#include "../util/ArtifactWriter.h"
#include "../util/Text.h"
#include "../engine/LayoutResolver.h"
#include "../engine/SymbolQuery.h"
#include "../core/Features.h"
#include "../core/DisassemblyView.h"
#include "../core/FieldObservation.h"
#include "../catalog/Catalog.h"
#include <array>
#include <cwctype>
#include <cwchar>
#include <cstring>
#include <dbgeng.h>

namespace kncmd
{
namespace
{
void FinishRows(CmdText &out, bool complete)
{
    out.Details.Collected.Read = out.Details.Rows.Items().size();
    out.Details.Collected.Visited = out.Details.Collected.Read;
    out.Details.Collected.Decoded = out.Details.Collected.Read;
    out.Details.Collected.Complete = complete;
    out.Details.Collected.StopReason = complete ? L"EndOfEnumeration" : L"Incomplete";
}

bool Address(Ctx &ctx, const std::wstring &input, ULONG64 *value)
{
    const bool ok = input.find_first_of(L";{}\r\n") == std::wstring::npos && EvalAddress(ctx.Session, input, value);
    if (!ok)
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"Invalid address expression");
    }
    return ok;
}

void Modules(Ctx &ctx)
{
    auto *symbols = ctx.Session.Symbols();
    ULONG loaded = 0;
    ULONG unloaded = 0;
    if (symbols == nullptr || FAILED(symbols->GetNumberModules(&loaded, &unloaded)) || loaded > 100000)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Module inventory unavailable");
        return;
    }
    ctx.Out.Details.Collected.Expected = loaded;
    bool complete = true;
    for (ULONG i = 0; i < loaded && !ctx.Session.Cancelled(); ++i)
    {
        ULONG64 base = 0;
        DEBUG_MODULE_PARAMETERS module = {};
        wchar_t name[1024] = {};
        if (FAILED(symbols->GetModuleByIndex(i, &base)) || FAILED(symbols->GetModuleParameters(1, &base, 0, &module)))
        {
            complete = false;
            ++ctx.Out.Details.Collected.Unknown;
            continue;
        }
        const HRESULT named = symbols->GetModuleNameStringWide(DEBUG_MODNAME_IMAGE, i, base, name, 1024, nullptr);
        if (named != S_OK)
        {
            complete = false;
            ++ctx.Out.Details.Collected.Unknown;
        }
        auto row = knjson::Value::MakeObject();
        row.Set(L"base", knjson::Value(kncore::Hex(base)));
        row.Set(L"size", knjson::Value(std::to_wstring(module.Size)));
        row.Set(L"timestamp", knjson::Value(kncore::Hex(module.TimeDateStamp)));
        row.Set(L"name", named == S_OK ? knjson::Value(name) : knjson::Value());
        row.Set(L"symbolType", knjson::Value(std::to_wstring(module.SymbolType)));
        ctx.Out.Details.Rows.Push(row);
        ctx.Out.AddLine(kncore::Hex(base) + L" size=" + kncore::Hex(module.Size) + L" " + (named == S_OK ? name : L"<name unavailable>"));
    }
    FinishRows(ctx.Out, complete && !ctx.Session.Cancelled());
    if (!ctx.Out.Details.Collected.Complete)
    {
        ctx.Out.Details.State = ctx.Session.Cancelled() ? kncore::Status::Cancelled : kncore::Status::Partial;
    }
}

void MatchSymbols(Ctx &ctx)
{
    knengine::SymbolQueryScope query;
    auto *symbols = ctx.Session.Symbols();
    ULONG64 search = 0;
    if (FAILED(symbols->StartSymbolMatchWide(ctx.Args[1].c_str(), &search)))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Symbol search unavailable");
        return;
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
    bool complete = false;
    for (unsigned i = 0; i < 4096 && !ctx.Session.Cancelled(); ++i)
    {
        ULONG64 address = 0;
        wchar_t name[4096] = {};
        const HRESULT status = symbols->GetNextSymbolMatchWide(search, name, 4096, nullptr, &address);
        if (status == E_NOINTERFACE)
        {
            complete = true;
            break;
        }
        if (status != S_OK)
        {
            break;
        }
        auto row = knjson::Value::MakeObject();
        row.Set(L"address", knjson::Value(kncore::Hex(address)));
        row.Set(L"addressSpace", knjson::Value(L"virtual"));
        row.Set(L"symbol", knjson::Value(name));
        row.Set(L"symbolSource", knjson::Value(L"LoadedDebuggerSymbols"));
        row.Set(L"symbolAddress", knjson::Value(kncore::Hex(address)));
        row.Set(L"symbolField", knjson::Value(L"address"));
        ctx.Out.Details.Rows.Push(row);
        ctx.Out.AddLine(kncore::Hex(address) + L" " + name);
    }
    FinishRows(ctx.Out, complete);
    if (!complete)
    {
        ctx.Out.Details.State = ctx.Session.Cancelled() ? kncore::Status::Cancelled : kncore::Status::Partial;
    }
}

bool ReadInstruction(Ctx &ctx, ULONG64 address, wchar_t *text, ULONG capacity, ULONG64 *next, std::wstring *encoded = nullptr)
{
    std::array<unsigned char, 16> bytes = {};
    ULONG transferred = 0;
    // DbgEng can return S_OK and advance past unreadable or invalid instructions.
    if (ctx.Session.Cancelled() ||
        ctx.Session.Control()->DisassembleWide(address, 0, text, capacity, nullptr, next) != S_OK ||
        *next <= address || *next - address > bytes.size())
    {
        return false;
    }
    // Reject the standalone decoder marker, not decorated symbol-name substrings.
    for (const wchar_t *marker = std::wcsstr(text, L"???"); marker != nullptr; marker = std::wcsstr(marker + 3, L"???"))
    {
        if ((marker == text || std::iswspace(marker[-1])) && (marker[3] == L'\0' || std::iswspace(marker[3])))
        {
            return false;
        }
    }
    const bool readable = ctx.Session.ReadVirtual(address, bytes.data(), static_cast<ULONG>(*next - address), &transferred) &&
                          transferred == *next - address;
    if (readable && encoded != nullptr)
    {
        *encoded = kncore::BytesHex(std::span<const unsigned char>(bytes.data(), transferred));
    }
    return readable;
}

void Disassemble(Ctx &ctx)
{
    std::vector<std::wstring> args = ctx.Args;
    if (ctx.Args[0] == L"u" && !DisplayArguments(ctx, kncore::DisplayKind::Disassembly, args))
    {
        return;
    }
    const auto begin = ctx.Session.RefreshStamp();
    knengine::SymbolQueryScope query;
    ULONG64 address = 0;
    uint64_t count = 32;
    if (!(args.size() == 1 ? CurrentInstruction(ctx, address) : Address(ctx, args[1], &address)))
    {
        return;
    }
    if (ctx.Args[0] == L"uf")
    {
        wchar_t instruction[4096] = {};
        ULONG64 next = 0;
        if (!ReadInstruction(ctx, address, instruction, _countof(instruction), &next))
        {
            ctx.Out.Details.Collected.Visited = 1;
            ctx.Out.Details.Collected.Unknown = 1;
            ctx.Out.Details.Collected.StopReason = L"InstructionBytesUnavailable";
            ctx.Out.Fail(kncore::Status::Unavailable, L"Instruction bytes or decoder unavailable at the requested function address");
            return;
        }
        std::wstring text;
        const bool complete = ctx.Session.Execute(L"uf " + kncore::Hex(address), knengine::DbgSession::OutputRouting::CaptureHere, &text);
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"HostFunctionDisassembly"));
        row.Set(L"addressSpace", knjson::Value(L"virtual"));
        row.Set(L"address", knjson::Value(kncore::Hex(address)));
        row.Set(L"source", knjson::Value(L"DbgEng uf"));
        row.Set(L"engineCompleted", knjson::Value(complete));
        const size_t prefix = knutil::Utf16PrefixUnits(text, 262144);
        row.Set(L"output", knjson::Value(text.substr(0, prefix)));
        row.Set(L"outputTruncated", knjson::Value(prefix != text.size()));
        row.Set(L"interpretation", knjson::Value(L"Host function output is unparsed; engine completion does not prove complete disassembly"));
        ctx.Out.Details.Rows.Push(row);
        ctx.Out.AddLine(L"[function] " + kncore::Hex(address));
        ctx.Out.Add(text);
        FinishRows(ctx.Out, false);
        ctx.Out.Details.Collected.Decoded = 0;
        ctx.Out.Details.Collected.Unknown = 1;
        ctx.Out.Details.Collected.StopReason = L"HostFunctionDisassemblyUnparsed";
        ctx.Out.Details.State = kncore::Status::Partial;
        if (!complete)
        {
            ctx.Out.Fail(kncore::Status::Partial, L"Host function disassembly failed, was cancelled or exceeded the output budget");
        }
        return;
    }
    if (args.size() == 3 && (args[2].size() < 2 || towlower(args[2][0]) != L'l' ||
                            !kncore::ParseUnsigned(args[2].substr(1), 16, &count) || count == 0 || count > 4096))
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"Instruction count must be L1..L1000");
        return;
    }
    bool instructionUnavailable = false;
    for (uint64_t i = 0; i < count && !ctx.Session.Cancelled(); ++i)
    {
        if (ctx.ExpectedStamp != nullptr && *ctx.ExpectedStamp != ctx.Session.RefreshStamp())
        {
            ctx.Out.Fail(kncore::Status::StaleContext, L"Source result context changed before disassembly");
            break;
        }
        wchar_t text[4096] = {};
        ULONG64 next = 0;
        std::wstring encoded;
        if (!ReadInstruction(ctx, address, text, _countof(text), &next, &encoded))
        {
            instructionUnavailable = true;
            ctx.Out.Details.Collected.Unknown = 1;
            ctx.Out.Fail(ctx.Out.Details.Rows.Items().empty() ? kncore::Status::Unavailable : kncore::Status::Partial,
                         L"Instruction bytes or decoder unavailable");
            break;
        }
        auto row = knjson::Value::MakeObject();
        row.Set(L"address", knjson::Value(kncore::Hex(address)));
        row.Set(L"addressSpace", knjson::Value(L"virtual"));
        row.Set(L"instruction", knjson::Value(text));
        row.Set(L"bytes", knjson::Value(encoded));
        row.Set(L"nextAddress", knjson::Value(kncore::Hex(next)));
        row.Set(L"instructionText", knjson::Value(kncore::InstructionBody(text, address, encoded)));
        ctx.Out.Details.Rows.Push(row);
        ctx.Out.Add(text);
        address = next;
    }
    FinishRows(ctx.Out, ctx.Out.Details.State == kncore::Status::Success && !ctx.Session.Cancelled());
    if (instructionUnavailable)
    {
        ++ctx.Out.Details.Collected.Visited;
        ctx.Out.Details.Collected.StopReason = L"InstructionBytesUnavailable";
    }
    if (ctx.Out.Details.Collected.Complete)
    {
        RememberDisplay(ctx, kncore::DisplayKind::Disassembly, begin, address);
    }
}

void TypeFields(Ctx &ctx)
{
    knengine::SymbolQueryScope query;
    ULONG64 base = 0;
    ULONG typeId = 0;
    wchar_t module[1024] = {};
    auto *symbols = ctx.Session.Symbols();
    const auto separator = ctx.Args[1].find(L'!');
    const auto type = separator == std::wstring::npos ? ctx.Args[1] : ctx.Args[1].substr(separator + 1);
    std::wstring moduleName = separator == std::wstring::npos ? L"" : ctx.Args[1].substr(0, separator);
    if (moduleName.empty() &&
        (symbols->GetSymbolTypeIdWide(ctx.Args[1].c_str(), &typeId, &base) != S_OK ||
         symbols->GetModuleNameStringWide(DEBUG_MODNAME_MODULE, DEBUG_ANY_ID, base, module, _countof(module), nullptr) != S_OK))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Type module unavailable");
        return;
    }
    if (moduleName.empty())
    {
        moduleName = module;
    }
    knengine::LayoutResolver layout(ctx.Session);
    const auto descriptor = layout.Describe(moduleName.c_str(), type.c_str());
    if (!descriptor)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Matching PDB type information required: " + layout.Diagnostic());
        return;
    }
    ULONG64 address = 0;
    if (ctx.Args.size() == 3 && !Address(ctx, ctx.Args[2], &address))
    {
        return;
    }
    if (ctx.Args.size() == 3 && !kncore::ValidRange(address, descriptor->Size))
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"Type instance address range overflows");
        return;
    }
    ctx.Out.Details.LayoutProfile = descriptor->Identity.Key();
    ctx.Out.AddLine(L"[type] " + ctx.Args[1] + L" size=" + std::to_wstring(descriptor->Size));
    for (const auto &[name, field] : descriptor->Fields)
    {
        if (ctx.Session.Cancelled())
        {
            break;
        }
        auto row = knjson::Value::MakeObject();
        row.Set(L"field", knjson::Value(name));
        row.Set(L"offset", knjson::Value(kncore::Hex(field.Offset)));
        row.Set(L"size", knjson::Value(std::to_wstring(field.Size)));
        row.Set(L"type", knjson::Value(field.TypeName));
        row.Set(L"source", knjson::Value(field.Source));
        row.Set(L"arrayCount", field.ArrayCount ? knjson::Value(std::to_wstring(*field.ArrayCount)) : knjson::Value());
        row.Set(L"bitOffset", field.BitOffset ? knjson::Value(std::to_wstring(*field.BitOffset)) : knjson::Value());
        row.Set(L"bitWidth", field.BitWidth ? knjson::Value(std::to_wstring(*field.BitWidth)) : knjson::Value());
        if (ctx.Args.size() == 3 && field.Size <= 256 && kncore::ValidRange(address, static_cast<uint64_t>(field.Offset) + field.Size))
        {
            const auto read = ctx.Session.Read(kncore::AddressSpace::Virtual, address + field.Offset, field.Size);
            const bool readable = kncore::ExactBytes(read, field.Size);
            row.Set(L"bytes", readable ? knjson::Value(kncore::BytesHex(read.Bytes)) : knjson::Value());
            row.Set(L"valueStatus", knjson::Value(kncore::StatusName(read.State)));
            if (field.Kind == kncore::FieldKind::Unsigned || field.Kind == kncore::FieldKind::Signed ||
                field.Kind == kncore::FieldKind::Boolean || field.Kind == kncore::FieldKind::Pointer)
            {
                row.Set(L"value", kncore::ScalarFieldObservation(field, read));
            }
            if (field.Kind == kncore::FieldKind::Pointer && (field.Size == 4 || field.Size == 8))
            {
                uint64_t pointer = 0;
                if (readable)
                {
                    std::memcpy(&pointer, read.Bytes.data(), field.Size);
                }
                row.Set(L"pointer", readable ? knjson::Value(kncore::Hex(pointer)) : knjson::Value());
            }
            if (!readable)
            {
                ++ctx.Out.Details.Collected.Unreadable;
            }
        }
        else if (ctx.Args.size() == 3)
        {
            row.Set(L"bytes", knjson::Value());
            row.Set(L"valueStatus", knjson::Value(L"NotRead:FieldSizeLimit"));
            ++ctx.Out.Details.Collected.Unknown;
        }
        ctx.Out.Details.Rows.Push(row);
        ctx.Out.AddLine(kncore::Hex(field.Offset) + L" " + name + L" size=" + std::to_wstring(field.Size) +
                        (field.BitWidth ? L" bits=" + std::to_wstring(*field.BitWidth) : L""));
    }
    for (const auto &name : descriptor->UnknownFields)
    {
        ctx.Out.AddLine(L"[unknown.field] " + name);
    }
    ctx.Out.Details.Collected.Unknown += descriptor->UnknownFields.size();
    const bool complete = descriptor->Complete && !ctx.Session.Cancelled() && ctx.Out.Details.Collected.Unreadable == 0 &&
                          ctx.Out.Details.Collected.Unknown == 0;
    FinishRows(ctx.Out, complete);
    if (!complete)
    {
        ctx.Out.Details.State = kncore::Status::Partial;
    }
}

void SearchMemory(Ctx &ctx)
{
    ULONG64 address = 0;
    uint64_t count = 0;
    if (!Address(ctx, ctx.Args[1], &address) || ctx.Args[2].size() < 2 || towlower(ctx.Args[2][0]) != L'l' ||
        !kncore::ParseUnsigned(ctx.Args[2].substr(1), 16, &count) || count == 0 || count > 16 * 1024 * 1024 ||
        !kncore::ValidRange(address, count))
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"Search range must be 1..16MiB");
        return;
    }
    std::vector<unsigned char> pattern;
    for (size_t i = 3; i < ctx.Args.size(); ++i)
    {
        uint64_t byte = 0;
        if (!kncore::ParseUnsigned(ctx.Args[i], 16, &byte) || byte > 255)
        {
            ctx.Out.Fail(kncore::Status::InvalidInput, L"Search pattern must contain bytes");
            return;
        }
        pattern.push_back(static_cast<unsigned char>(byte));
    }
    if (pattern.empty() || pattern.size() > 4096)
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"Empty or excessive search pattern");
        return;
    }
    std::vector<unsigned char> carry;
    for (uint64_t offset = 0; offset < count && !ctx.Session.Cancelled();)
    {
        const size_t take = static_cast<size_t>(std::min<uint64_t>(4096, count - offset));
        const auto read = ctx.Session.Read(kncore::AddressSpace::Virtual, address + offset, take);
        if (read.State != kncore::Status::Success)
        {
            carry.clear();
            ctx.Out.Details.State = kncore::Status::Partial;
            ctx.Out.Details.Collected.Unknown += take;
        }
        else
        {
            const size_t prefix = carry.size();
            carry.insert(carry.end(), read.Bytes.begin(), read.Bytes.end());
            for (size_t i = 0; i + pattern.size() <= carry.size(); ++i)
            {
                if (std::equal(pattern.begin(), pattern.end(), carry.begin() + i))
                {
                    auto row = knjson::Value::MakeObject();
                    const uint64_t hit = address + offset - prefix + i;
                    row.Set(L"address", knjson::Value(kncore::Hex(hit)));
                    ctx.Out.Details.Rows.Push(row);
                    ctx.Out.AddLine(kncore::Hex(hit));
                    if (ctx.Out.Details.Rows.Items().size() >= 4096)
                    {
                        ctx.Out.Fail(kncore::Status::Partial, L"Search result budget reached");
                        return;
                    }
                }
            }
            const size_t keep = std::min(carry.size(), pattern.size() - 1);
            carry.erase(carry.begin(), carry.end() - keep);
            ctx.Out.Details.Collected.Read += take;
        }
        offset += take;
    }
    ctx.Out.Details.Collected.Expected = count;
    ctx.Out.Details.Collected.Complete = ctx.Out.Details.Collected.Read == count;
}
} // namespace

void WinDbgCommand(Ctx &ctx)
{
    if (ctx.Session.Cancelled() || (ctx.RequestCancelled && ctx.RequestCancelled()))
    {
        ctx.Out.Fail(kncore::Status::Cancelled, L"CancelledBeforeExecution");
        return;
    }
    ctx.Out.Details.Source = L"windbg";
    ctx.Out.Details.Consistency = L"UnverifiedEffects";
    ctx.Out.Details.Limitations.Push(knjson::Value(L"WinDbg text output; command effects and diagnostic findings are not verified."));
    // Host commands can change memory, execution, symbols or debugger context.
    // Invalidate existing approvals even if execution fails or faults.
    knengine::Epochs().TargetChanged();
    DiscardChangePlans();
    std::wstring output;
    const bool ok = ctx.Session.Execute(ctx.Request->RawArguments, knengine::DbgSession::OutputRouting::CaptureHere, &output);
    ctx.Out.Add(output);
    if (!ok)
    {
        ctx.Out.Fail(kncore::Status::EngineError, L"WinDbg command failed; see debugger output");
    }
}

void BuiltinCommand(Ctx &ctx)
{
    const std::wstring &name = ctx.Args[0];
    if (name == L"help")
    {
        if (ctx.Args.size() == 2 && _wcsicmp(ctx.Args[1].c_str(), L"ui") == 0)
        {
            for (const auto &line : kncat::WorkspaceHelp())
            {
                ctx.Out.AddLine(line);
            }
            return;
        }
        const bool single = ctx.Args.size() > 1 && FindCommand(ctx.Args[1]) == nullptr;
        if (single)
        {
            ctx.Out.Fail(kncore::Status::Unsupported, L"Unknown command: " + ctx.Args[1] + L" (help lists every command)");
            return;
        }
        for (const auto &spec : CommandSpecs())
        {
            if (ctx.Args.size() == 1 || FindCommand(ctx.Args[1]) == &spec)
            {
                std::wstring line =
                    std::wstring(spec.Grammar) + L" - " + spec.Synopsis + L" [" + SupportName(spec.Support) + L"]";
                const TargetMode modes = EffectiveTargetModes(spec);
                if (modes == TargetMode::LiveKernel)
                {
                    line += spec.Requires == Capability::LocalKernelX64 ? L" [kernel: live only, local KD]"
                                                                       : L" [kernel: live only]";
                }
                else if (modes == TargetMode::KernelDump)
                {
                    line += L" [kernel: dump only]";
                }
                else if (modes == TargetMode::DumpAndLive)
                {
                    line += L" [kernel: dump+live]";
                }
                else
                {
                    line += L" [session: any]";
                }
                ctx.Out.AddLine(line);
                if (ctx.Args.size() > 1)
                {
                    std::wstring aliases = L"Aliases:";
                    for (const auto *alias : spec.Aliases)
                    {
                        aliases += L" " + std::wstring(alias);
                    }
                    ctx.Out.AddLine(spec.Aliases.empty() ? L"Aliases: none" : aliases);
                    for (const auto &option : spec.Options)
                    {
                        ctx.Out.AddLine(L"Option: " + std::wstring(option.Name) + (option.TakesValue ? L" <value>" : L""));
                    }
                }
            }
        }
        if (ctx.Args.size() == 1)
        {
            ctx.Out.AddLine(L"Use help <command> for aliases and options; help ui for Processes, Memory, Disassembly, Registers, "
                            L"floating windows, execution controls and shortcuts.");
            ctx.Out.AddLine(L"Session availability: [kernel: dump+live] works on kernel dumps and live kernel sessions; "
                            L"[kernel: live only] requires a live kernel target and is refused on a dump; "
                            L"[kernel: live only, local KD] additionally requires the target to be this machine "
                            L"(host-data collectors refuse remote live targets); "
                            L"[session: any] host or engine command that needs no kernel target.");
        }
    }
    else if (name == L"version")
    {
        ctx.Out.AddLine(L"KNDbgX 0.2.0-preview.8 (DbgEng ABI)");
    }
    else if (name == L"features")
    {
        ctx.Out.Details.Rows = kncore::FeatureStatus();
        ctx.Out.Details.Collected.Complete = true;
        ctx.Out.AddLine(ctx.Out.Details.Rows.Write());
    }
    else if (name == L"command-schema")
    {
        ctx.Out.Details.Rows = CommandContract();
        ctx.Out.AddLine(ctx.Out.Details.Rows.Write());
    }
    else if (name == L"policy")
    {
        if (ctx.Args.size() == 2)
        {
            const auto mode = ctx.Args[1];
            if (mode != L"planned" && mode != L"readonly" && mode != L"on" && mode != L"off")
            {
                ctx.Out.Fail(kncore::Status::InvalidInput, L"policy [readonly|planned]");
                return;
            }
        }
        ctx.Out.Fail(kncore::Status::Unsupported,
                     L"The global write policy has been removed. Changes use per-operation plans and approval.");
    }
    else if (name == L"status")
    {
        knengine::SessionStatus status = {};
        ctx.Session.QueryStatus(&status);
        auto row = knjson::Value::MakeObject();
        row.Set(L"engineReady", knjson::Value(status.EngineReady));
        row.Set(L"targetPresent", knjson::Value(status.TargetPresent));
        row.Set(L"stopped", knjson::Value(status.Stopped));
        row.Set(L"architecture", knjson::Value(kncore::Hex(status.Architecture)));
        row.Set(L"kind", knjson::Value(status.KindText));
        row.Set(L"targetVersion", status.TargetVersion.empty() ? knjson::Value() : knjson::Value(status.TargetVersion));
        row.Set(L"hostVersion", status.HostVersion.empty() ? knjson::Value() : knjson::Value(status.HostVersion));
        ctx.Out.Details.Rows.Push(row);
        ctx.Out.AddLine(status.Summary.empty() ? L"EngineUnavailable" : status.Summary);
    }
    else if (name == L"reconnect")
    {
        PlanStore().Clear();
        if (!ctx.Session.Reconnect())
        {
            ctx.Out.Fail(kncore::Status::EngineError, L"Reconnect failed");
        }
        else
        {
            ctx.Out.AddLine(L"Reconnected");
        }
    }
    else if (name == L"plan")
    {
        ParsedCommand mutation;
        if (ctx.Request == nullptr || !ParseCommand(ctx.Request->RawArguments, &mutation))
        {
            ctx.Out.Fail(kncore::Status::InvalidInput, L"Invalid mutation command");
            return;
        }
        Ctx nested = {ctx.Session, mutation.Arguments, ctx.Out, &mutation};
        MutationCommand(nested);
    }
    else if (name == L"approve")
    {
        ctx.Out.Details = ExecuteApproved(ctx.Session, ctx.Args[1], ctx.Args[2]);
        ctx.Out.AddLine(ctx.Out.Details.ToJson().Write());
    }
    else if (name == L"raw")
    {
        if (ctx.Args[1] != L"--ack-effects" || ctx.Request == nullptr)
        {
            ctx.Out.Fail(kncore::Status::InvalidInput, L"raw requires --ack-effects; opaque commands have no read-only guarantee");
            return;
        }
        const auto raw = knutil::Trim(ctx.Request->RawArguments.substr(std::wstring(L"--ack-effects").size()));
        std::wstring output;
        const bool ok = ctx.Session.Execute(raw, knengine::DbgSession::OutputRouting::CaptureHere, &output);
        ctx.Out.Details.Source = L"opaque-engine";
        ctx.Out.Details.Consistency = L"UnverifiedEffects";
        ctx.Out.Add(output);
        knengine::Epochs().TargetChanged();
        DiscardChangePlans();
        if (!ok)
        {
            ctx.Out.Fail(kncore::Status::EngineError, L"Opaque engine command failed");
        }
    }
    else if (name == L"lm")
    {
        Modules(ctx);
    }
    else if (name == L"x")
    {
        MatchSymbols(ctx);
    }
    else if (name == L"ln")
    {
        knengine::SymbolQueryScope query;
        ULONG64 address = 0;
        if (ctx.Args.size() == 1 ? CurrentInstruction(ctx, address) : Address(ctx, ctx.Args[1], &address))
        {
            wchar_t symbol[4096] = {};
            // Explicit ln may load symbols; the shared path still verifies the returned name.
            ctx.Session.Symbols()->GetNameByOffsetWide(address, symbol, 4096, nullptr, nullptr);
            auto row = knjson::Value::MakeObject();
            row.Set(L"address", knjson::Value(kncore::Hex(address)));
            row.Set(L"addressSpace", knjson::Value(L"virtual"));
            kncore::Result annotation;
            annotation.Rows.Push(row);
            AnnotateResultSymbols(ctx.Session, annotation);
            row = annotation.Rows.Items()[0];
            const auto text = row.Get(L"symbol").AsString(L"");
            if (text.empty())
            {
                ctx.Out.Fail(kncore::Status::Unavailable, L"Nearest symbol unavailable");
            }
            else
            {
                row.Set(L"displacement", row.Get(L"symbolDisplacement"));
                ctx.Out.Details.Rows.Push(row);
                ctx.Out.AddLine(text);
                ctx.Out.Details.Collected.Visited = 1;
                ctx.Out.Details.Collected.Read = 1;
                ctx.Out.Details.Collected.Decoded = 1;
                ctx.Out.Details.Collected.Complete = true;
                ctx.Out.Details.Collected.StopReason = L"NearestSymbolResolved";
            }
        }
    }
    else if (name == L"dt")
    {
        TypeFields(ctx);
    }
    else if (name == L"u" || name == L"uf")
    {
        Disassemble(ctx);
    }
    else if (name == L"s")
    {
        SearchMemory(ctx);
    }
    else if (name == L".sympath" || name == L".reload")
    {
        auto *symbols = ctx.Session.Symbols();
        HRESULT status = E_FAIL;
        if (name == L".reload")
        {
            const auto module = ctx.Args.size() == 2 ? ctx.Args[1] : L"";
            status = module.find_first_of(L";{}\r\n\"") == std::wstring::npos ? symbols->ReloadWide(module.c_str()) : E_INVALIDARG;
        }
        else if (ctx.Args.size() == 2)
        {
            status = symbols->SetSymbolPathWide(ctx.Args[1].c_str());
        }
        else
        {
            wchar_t path[32768] = {};
            status = symbols->GetSymbolPathWide(path, 32768, nullptr);
            ctx.Out.AddLine(path);
        }
        if (status != S_OK)
        {
            ctx.Out.Fail(kncore::Status::EngineError, L"Symbol operation failed", {L"HRESULT", static_cast<uint32_t>(status), name, L""});
        }
        else if (ctx.Args.size() == 2 || name == L".reload")
        {
            knengine::Epochs().SymbolsChanged();
            PlanStore().Clear();
            ctx.Out.AddLine(L"Symbol state updated");
        }
    }
    else if (name == L".dump")
    {
        knutil::ArtifactWriter file(nullptr,
                                    [&]()
                                    {
                                        return ctx.Session.Cancelled() || (ctx.RequestCancelled && ctx.RequestCancelled());
                                    });
        HRESULT status = E_FAIL;
        const bool ok = file.Open(ctx.Args[1]) &&
                        file.ProduceNative(
                            [&](HANDLE handle)
                            {
                                status = ctx.Session.Client()->WriteDumpFileWide(nullptr, reinterpret_cast<ULONG64>(handle),
                                                                                 DEBUG_DUMP_SMALL, 0, L"KNDbgX target dump");
                                return SUCCEEDED(status);
                            }) &&
                        !ctx.Session.Cancelled() && file.Commit();
        if (!ok)
        {
            ctx.Out.Fail(kncore::Status::IOError, L"Dump not committed; existing file preserved",
                         {L"HRESULT", static_cast<uint32_t>(status), L"WriteDumpFileWide", L""});
        }
        else
        {
            RecordDumpArtifact(ctx, file.Path(), file.Written(), L"DbgEngMinidump");
            ctx.Out.AddLine(L"Dump committed: " + file.Path() + L" bytes=" + std::to_wstring(file.Written()));
        }
    }
    else
    {
        ctx.Out.Fail(kncore::Status::Unsupported, L"Command capability unavailable");
    }
}
} // namespace kncmd
