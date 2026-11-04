#include "CommandSpec.h"
#include "../core/IrpAnalysis.h"
#include "../engine/LayoutResolver.h"
#include "../engine/ContextGuard.h"
#include "../engine/ModuleList.h"
#include "../util/Text.h"
#include <dbgeng.h>

namespace kncmd
{
namespace
{
void Emit(Ctx &ctx, const knjson::Value &row)
{
    ctx.Out.Details.Rows.Push(row);
    ctx.Out.AddLine(row.Write());
    ++ctx.Out.Details.Collected.Visited;
}

void Complete(Ctx &ctx, const wchar_t *reason)
{
    ctx.Out.Details.Collected.Complete = true;
    ctx.Out.Details.Collected.StopReason = reason;
    ctx.Out.Details.Collected.Decoded = ctx.Out.Details.Collected.Visited;
}

bool StoppedKernel(Ctx &ctx)
{
    knengine::SessionStatus status;
    ctx.Session.QueryStatus(&status);
    const bool valid = status.KernelMode && status.Architecture == IMAGE_FILE_MACHINE_AMD64 && status.Stopped;
    if (!valid)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"A stopped x64 kernel target or kernel dump is required");
    }
    return valid;
}

class DiagnosticContext
{
  public:
    explicit DiagnosticContext(knengine::DbgSession &session) : session_(session), context_(session)
    {
        // Host diagnostic extensions legitimately load module symbols on first use;
        // those additive loads must not invalidate the restore of the caller context.
        context_.AllowSymbolChanges();
        valid_ = context_.Valid() && session_.Symbols()->GetScope(&instruction_, &frame_, &registers_, sizeof(registers_)) == S_OK;
    }
    ~DiagnosticContext()
    {
        Restore();
    }
    bool Valid() const
    {
        return valid_;
    }
    bool Restore()
    {
        if (!finished_)
        {
            finished_ = true;
            restored_ = context_.Restore();
            if (valid_ && restored_)
            {
                restored_ = SUCCEEDED(session_.Symbols()->SetScope(instruction_, &frame_, &registers_, sizeof(registers_)));
                if (!restored_)
                {
                    session_.MarkFault();
                }
            }
        }
        return restored_;
    }

  private:
    knengine::DbgSession &session_;
    knengine::ContextGuard context_;
    ULONG64 instruction_ = 0;
    DEBUG_STACK_FRAME frame_ = {};
    CONTEXT registers_ = {};
    bool valid_ = false;
    bool finished_ = false;
    bool restored_ = false;
};

bool RunDiagnostic(Ctx &ctx, const kncore::DiagnosticRecipe &recipe, const std::wstring &operand)
{
    const auto command = kncore::DiagnosticCommand(recipe, operand);
    if (!command)
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"Invalid diagnostic operand; use diag-catalog for accepted inputs");
        return false;
    }
    const auto stamp = ctx.Session.RefreshStamp();
    if (ctx.ExpectedStamp != nullptr && !kncore::DiagnosticTargetMatches(*ctx.ExpectedStamp, stamp))
    {
        ctx.Out.Fail(kncore::Status::StaleContext, L"Diagnostic target or stop state changed before this step");
        return false;
    }
    DiagnosticContext restore(ctx.Session);
    if (!restore.Valid())
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Debugger context and scope could not be captured");
        return false;
    }
    std::wstring output;
    const bool accepted = ctx.Session.Execute(*command, knengine::DbgSession::OutputRouting::CaptureHere, &output);
    const bool restored = restore.Restore();
    const auto endStamp = ctx.Session.RefreshStamp();
    const bool sameTarget = kncore::DiagnosticTargetMatches(stamp, endStamp);
    const size_t prefix = knutil::Utf16PrefixUnits(output, 262144);
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"HostDiagnostic"));
    row.Set(L"recipe", knjson::Value(recipe.Name));
    row.Set(L"command", knjson::Value(*command));
    row.Set(L"engineAccepted", knjson::Value(accepted));
    row.Set(L"contextRestored", knjson::Value(restored));
    row.Set(L"outputTruncated", knjson::Value(prefix != output.size()));
    row.Set(L"output", knjson::Value(output.substr(0, prefix)));
    row.Set(L"interpretation", knjson::Value(L"Host extension output has not been parsed; inspect it for unsupported or missing data"));
    ctx.Out.Details.Rows.Push(row);
    ++ctx.Out.Details.Collected.Visited;
    ctx.Out.AddLine(L"[diagnostic " + std::wstring(recipe.Name) + L"] " + *command);
    ctx.Out.AddLine(output.substr(0, prefix));
    ctx.Out.Details.Source = L"target-host-extension";
    ctx.Out.Details.Consistency = L"stopped-best-effort";
    ctx.Out.Details.Collected.Complete = false;
    ctx.Out.Details.Collected.StopReason = L"HostDiagnosticUnparsed";
    ctx.Out.Details.State = kncore::Status::Partial;
    ++ctx.Out.Details.Collected.Unknown;
    if (!sameTarget || !restored || ctx.Session.Cancelled() || !accepted)
    {
        ctx.Out.Fail(!sameTarget               ? kncore::Status::StaleContext
                     : !restored               ? kncore::Status::InternalFault
                     : ctx.Session.Cancelled() ? kncore::Status::Cancelled
                                               : kncore::Status::EngineError,
                     L"Host diagnostic failed, was interrupted, exceeded capture limits, or changed target state");
        return false;
    }
    return true;
}

void InspectIrp(Ctx &ctx)
{
    uint64_t address = 0;
    if (!kncore::ParseUnsigned(ctx.Args[1], 16, &address) || address == 0)
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"IRP requires a nonzero hexadecimal address");
        return;
    }
    if (!StoppedKernel(ctx))
    {
        return;
    }
    knengine::LayoutResolver resolver(ctx.Session);
    kncore::IrpLayout layout;
    ULONG headerSize = 0;
    ULONG stackSize = 0;
    const auto identity = resolver.Identity(L"nt");
    if (!identity || !resolver.TypeSize(L"_IRP", &headerSize) || !resolver.TypeSize(L"_IO_STACK_LOCATION", &stackSize) ||
        headerSize > 4096 || stackSize > 4096)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Matched IRP/IO_STACK_LOCATION PDB layout unavailable");
        return;
    }
    layout.HeaderBytes = headerSize;
    layout.StackBytes = stackSize;
    for (const wchar_t *name : {L"Type", L"Size", L"StackCount", L"CurrentLocation", L"MdlAddress", L"UserBuffer", L"CancelRoutine",
                                L"Flags", L"Cancel", L"PendingReturned", L"RequestorMode"})
    {
        if (const auto field = resolver.Field(L"nt", L"_IRP", name))
        {
            layout.Header[name] = *field;
        }
    }
    for (const auto &names : {std::pair{L"SystemBuffer", L"AssociatedIrp.SystemBuffer"},
                              {L"Thread", L"Tail.Overlay.Thread"},
                              {L"CurrentStackLocation", L"Tail.Overlay.CurrentStackLocation"}})
    {
        if (const auto field = resolver.Field(L"nt", L"_IRP", names.second))
        {
            layout.Header[names.first] = *field;
        }
    }
    const auto ioStatus = resolver.Field(L"nt", L"_IRP", L"IoStatus");
    for (const wchar_t *name : {L"Status", L"Information"})
    {
        if (const auto field = kncore::NestedField(ioStatus, resolver.Field(L"nt", L"_IO_STATUS_BLOCK", name)))
        {
            layout.Header[name] = *field;
        }
    }
    for (const wchar_t *name :
         {L"MajorFunction", L"MinorFunction", L"Control", L"DeviceObject", L"FileObject", L"CompletionRoutine", L"Context"})
    {
        if (const auto field = resolver.Field(L"nt", L"_IO_STACK_LOCATION", name))
        {
            layout.Stack[name] = *field;
        }
    }
    for (const wchar_t *name : {L"IoControlCode", L"InputBufferLength", L"OutputBufferLength", L"Type3InputBuffer"})
    {
        const auto qualified = std::wstring(L"Parameters.DeviceIoControl.") + name;
        if (const auto field = resolver.Field(L"nt", L"_IO_STACK_LOCATION", qualified.c_str()))
        {
            layout.Stack[name] = *field;
        }
    }
    const auto header = ctx.Session.Read(kncore::AddressSpace::Virtual, address, headerSize);
    const auto size = kncore::ExactBytes(header, headerSize) ? kncore::BufferField(header.Bytes, layout.Header, L"Size", 2) : std::nullopt;
    if (!size || *size < headerSize || *size > 65535 || !kncore::ValidRange(address, *size))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"IRP header or allocation size unavailable");
        return;
    }
    const auto bytes = ctx.Session.Read(kncore::AddressSpace::Virtual, address, static_cast<size_t>(*size));
    if (!kncore::ExactBytes(bytes, static_cast<size_t>(*size)))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"IRP allocation is not fully readable");
        return;
    }
    ctx.Out.Details = kncore::InspectIrpBytes(address, bytes.Bytes, layout);
    ctx.Out.Details.LayoutProfile = identity->Key();
    auto annotated = knjson::Value::MakeArray();
    const auto ownership = knengine::CollectOwnershipIndex(ctx.Session);
    const auto deviceDriver = resolver.Field(L"nt", L"_DEVICE_OBJECT", L"DriverObject");
    const auto deviceType = resolver.Field(L"nt", L"_DEVICE_OBJECT", L"Type");
    const auto driverType = resolver.Field(L"nt", L"_DRIVER_OBJECT", L"Type");
    const auto dispatch = resolver.Field(L"nt", L"_DRIVER_OBJECT", L"MajorFunction");
    for (const auto &item : ctx.Out.Details.Rows.Items())
    {
        auto row = item;
        uint64_t device = 0;
        uint64_t major = 0;
        if (kncore::ParseUnsigned(row.Get(L"DeviceObject").AsString(L""), 16, &device) && device != 0 &&
            kncore::ParseUnsigned(row.Get(L"major").AsString(L""), 16, &major))
        {
            std::optional<uint64_t> handler;
            const auto type = deviceType && deviceType->Size == 2 ? kncore::ReadField(ctx.Session, device, deviceType) : std::nullopt;
            const auto driver =
                type == 3 && deviceDriver && deviceDriver->Size == 8 ? kncore::ReadField(ctx.Session, device, deviceDriver) : std::nullopt;
            const auto ownerType = driver && *driver != 0 && driverType && driverType->Size == 2
                                       ? kncore::ReadField(ctx.Session, *driver, driverType)
                                       : std::nullopt;
            if (ownerType == 4 && dispatch && dispatch->ArrayCount && dispatch->ElementSize && *dispatch->ElementSize == 8 &&
                major < *dispatch->ArrayCount && *dispatch->ArrayCount <= 256)
            {
                auto field = *dispatch;
                field.Offset += static_cast<uint32_t>(major * 8);
                field.Size = 8;
                handler = kncore::ReadField(ctx.Session, *driver, field);
            }
            row.Set(L"DriverObject", kncore::OptionalNumber(driver, true));
            row.Set(L"DispatchRoutine", kncore::OptionalNumber(handler, true));
            if (!handler)
            {
                ++ctx.Out.Details.Collected.Unknown;
            }
        }
        for (const wchar_t *field : {L"CompletionRoutine", L"CancelRoutine", L"DispatchRoutine"})
        {
            uint64_t pointer = 0;
            if (kncore::ParseUnsigned(row.Get(field).AsString(L""), 16, &pointer) && pointer != 0)
            {
                const auto owner = ownership.Find(pointer, ctx.Session.RefreshStamp());
                row.Set(std::wstring(field) + L"Module", owner.Image ? knjson::Value(owner.Image->Name) : knjson::Value());
                row.Set(std::wstring(field) + L"Rva", owner.Image ? knjson::Value(kncore::Hex(owner.Rva)) : knjson::Value());
                row.Set(std::wstring(field) + L"Ownership", knjson::Value(owner.Reason));
                if (owner.State == kncore::OwnershipState::Unknown)
                {
                    ++ctx.Out.Details.Collected.Unknown;
                }
            }
        }
        ctx.Out.AddLine(row.Write());
        annotated.Push(row);
    }
    ctx.Out.Details.Rows = annotated;
    if (ctx.Out.Details.Collected.Unknown != 0 && ctx.Out.Details.State == kncore::Status::Success)
    {
        ctx.Out.Details.State = kncore::Status::Partial;
        ctx.Out.Details.Collected.Complete = false;
        ctx.Out.Details.Collected.StopReason = L"IrpOwnershipOrFieldsUnavailable";
    }
    if (!ctx.Out.Details.Error.Message.empty())
    {
        ctx.Out.AddLine(ctx.Out.Details.Error.Message);
    }
}
} // namespace

void KernelAnalysisCommand(Ctx &ctx)
{
    const std::wstring command = ctx.Request->Spec->Name;
    if (command == L"ioctl" || command == L"ntstatus" || command == L"bugcheck-decode")
    {
        uint64_t code = 0;
        std::array<uint64_t, 4> parameters = {};
        bool valid = kncore::ParseUnsigned(ctx.Args[1], 16, &code) && code <= UINT32_MAX;
        for (size_t i = 2; i < ctx.Args.size(); ++i)
        {
            valid = kncore::ParseUnsigned(ctx.Args[i], 16, &parameters[i - 2]) && valid;
        }
        if (!valid)
        {
            ctx.Out.Fail(kncore::Status::InvalidInput, L"Expected hexadecimal integers; code must fit 32 bits and parameters 64 bits");
            return;
        }
        auto row = command == L"ioctl"      ? kncore::DecodeIoctl(static_cast<uint32_t>(code))
                   : command == L"ntstatus" ? kncore::DecodeNtStatus(static_cast<uint32_t>(code))
                                            : kncore::DecodeBugcheck(static_cast<uint32_t>(code), parameters);
        if (command == L"ntstatus")
        {
            wchar_t message[2048] = {};
            const DWORD count =
                FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS, GetModuleHandleW(L"ntdll.dll"),
                               static_cast<DWORD>(code), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), message, _countof(message), nullptr);
            row.Set(L"message", count != 0 ? knjson::Value(knutil::Trim(message)) : knjson::Value());
            row.Set(L"messageSource", knjson::Value(L"Host ntdll English message table; may differ from target build"));
        }
        Emit(ctx, row);
        ctx.Out.Details.Source = L"provided-values";
        ctx.Out.Details.Consistency = L"immutable-input";
        Complete(ctx, L"Decoded");
    }
    else if (command == L"diag-catalog")
    {
        for (const auto &recipe : kncore::DiagnosticRecipes())
        {
            auto row = knjson::Value::MakeObject();
            row.Set(L"kind", knjson::Value(L"DiagnosticRecipe"));
            row.Set(L"name", knjson::Value(recipe.Name));
            row.Set(L"group", knjson::Value(recipe.Group));
            row.Set(L"description", knjson::Value(recipe.Description));
            row.Set(L"operand", knjson::Value(recipe.Operand == kncore::DiagnosticOperand::None             ? L"none"
                                              : recipe.Operand == kncore::DiagnosticOperand::Address        ? L"hex-address"
                                              : recipe.Operand == kncore::DiagnosticOperand::OptionalModule ? L"optional-module"
                                                                                                            : L"module"));
            row.Set(L"hostCommand", knjson::Value(recipe.Command));
            row.Set(L"reference",
                    knjson::Value(std::wstring_view(recipe.Reference).starts_with(L"https://")
                                      ? std::wstring(recipe.Reference)
                                      : std::wstring(L"https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/") +
                                            recipe.Reference));
            Emit(ctx, row);
        }
        Complete(ctx, L"CatalogEnumerated");
    }
    else if (command == L"irp")
    {
        InspectIrp(ctx);
    }
    else if (command == L"bugcheck")
    {
        if (StoppedKernel(ctx))
        {
            ULONG code = 0;
            std::array<ULONG64, 4> parameters = {};
            const auto hr = ctx.Session.Control()->ReadBugCheckData(&code, &parameters[0], &parameters[1], &parameters[2], &parameters[3]);
            if (hr != S_OK || code == 0)
            {
                ctx.Out.Fail(kncore::Status::Unavailable, L"No bugcheck data available",
                             {L"HRESULT", static_cast<uint32_t>(hr), L"ReadBugCheckData", L""});
            }
            else
            {
                auto row = kncore::DecodeBugcheck(code, parameters);
                if (code == 0x1f2)
                {
                    row.Set(L"addressSpace", knjson::Value(L"virtual"));
                }
                Emit(ctx, row);
                Complete(ctx, L"BugcheckDecoded");
            }
        }
    }
    else if (command == L"diagnose")
    {
        const auto *recipe = kncore::FindDiagnostic(ctx.Args[1]);
        if (recipe == nullptr)
        {
            ctx.Out.Fail(kncore::Status::InvalidInput, L"Unknown diagnostic; use diag-catalog");
        }
        else if (StoppedKernel(ctx))
        {
            RunDiagnostic(ctx, *recipe, ctx.Args.size() > 2 ? ctx.Args[2] : L"");
        }
    }
    else if (command == L"triage")
    {
        const std::map<std::wstring, std::vector<std::wstring>> profiles = {
            {L"crash", {L"crash", L"blackbox-bsd", L"verifier"}},
            {L"hang", {L"hang", L"locks", L"deadlocks", L"running", L"dpcs"}},
            {L"io", {L"verifier", L"stacks", L"power"}},
            {L"power", {L"power-triage", L"power", L"pnp", L"blackbox-pnp", L"stacks"}},
            {L"network", {L"net-adapters", L"net-drivers", L"net-oids"}},
            {L"devices", {L"storage", L"usb", L"pnp"}},
            {L"memory", {L"vm", L"poolusage", L"memusage", L"verifier"}},
            {L"wdf", {L"wdf-driver", L"wdf-log", L"wdf-pool", L"verifier"}}};
        const auto profile = profiles.find(ctx.Args[1]);
        const std::wstring module = ctx.Args.size() > 2 ? ctx.Args[2] : L"";
        if (profile == profiles.end() || (profile->first == L"wdf" && module.empty()) ||
            (!module.empty() && !kncore::ValidModuleToken(module)))
        {
            ctx.Out.Fail(kncore::Status::InvalidInput,
                         L"Use triage crash|hang|io|power|memory|wdf|network|devices [module]; wdf requires a module");
            return;
        }
        if (!StoppedKernel(ctx))
        {
            return;
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        ctx.Out.Details.Collected.Expected = profile->second.size();
        bool stopped = false;
        uint64_t attempted = 0;
        for (const auto &name : profile->second)
        {
            if (!stopped && (ctx.Session.Cancelled() || std::chrono::steady_clock::now() >= deadline))
            {
                ctx.Out.Fail(ctx.Session.Cancelled() ? kncore::Status::Cancelled : kncore::Status::Partial,
                             L"Triage cancelled or step deadline reached");
                stopped = true;
            }
            const auto &recipe = *kncore::FindDiagnostic(name);
            auto step = knjson::Value::MakeObject();
            step.Set(L"kind", knjson::Value(L"DiagnosticStep"));
            step.Set(L"recipe", knjson::Value(name));
            step.Set(L"profile", knjson::Value(profile->first));
            step.Set(L"attempted", knjson::Value(!stopped));
            if (!stopped)
            {
                ++attempted;
                stopped = !RunDiagnostic(ctx, recipe, recipe.Operand == kncore::DiagnosticOperand::None ? L"" : module);
                step.Set(L"status", knjson::Value(kncore::StatusName(ctx.Out.Details.State)));
            }
            else
            {
                step.Set(L"status", knjson::Value(L"Skipped"));
                ++ctx.Out.Details.Collected.Unknown;
            }
            step.Set(L"reason", knjson::Value(ctx.Out.Details.Error.Message));
            Emit(ctx, step);
        }
        ctx.Out.Details.Collected.Visited = attempted;
        ctx.Out.Details.Limitations.Push(knjson::Value(
            L"Step deadline is cooperative; DbgEng extension calls may take longer. Host diagnostics require interpretation."));
    }
}
} // namespace kncmd
