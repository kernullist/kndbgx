#include "../engine/ContextGuard.h"
// Scanner commands part 1: process listing, SSDT/IDT audit, per-CPU
// MSR/control-register audit and address inspection.

#include "CollectorSupport.h"

#include <dbgeng.h>
#include <cstring>

#include "../engine/CpuContext.h"
#include "../engine/LayoutResolver.h"
#include "../engine/ModuleList.h"
#include "../engine/PageWalk.h"
#include "ProcCollect.h"
#include "../util/Jsonl.h"
#include "../util/Json.h"

namespace kncmd
{
// ---- !dml_proc ----

void ScanProcessList(Ctx &ctx)
{
    CmdText &out = ctx.Out;

    do
    {
        knengine::LayoutResolver layout(ctx.Session);
        std::vector<ProcRow> rows;
        std::wstring jsonPath;
        std::vector<std::wstring> rest;
        ExtractJsonPath(ctx.Args, 1, &jsonPath, &rest);

        if (ctx.Args[0] == L"!process" && (rest.empty() || rest[0] != L"0"))
        {
            ProcRow selected;
            if (!ResolveSelectedProcess(ctx, layout, rest.empty() ? L"" : rest[0], selected))
            {
                break;
            }
            rows.push_back(selected);
            rest.clear();
            kncore::SetSelectedProcessCoverage(selected, out.Details);
        }
        else if (!CollectProcesses(ctx.Session, layout, &rows, out))
        {
            if (!rest.empty() && ctx.Args[0] != L"!process")
            {
                ReportProcessSelectionFailure(out, out);
            }
            break;
        }
        else if (ctx.Args[0] == L"!process")
        {
            rest.clear();
        }

        if (rows.empty() && rest.empty())
        {
            out.AddLine(L"[proc] no processes enumerated");
            break;
        }

        std::vector<ProcRow> selected;

        if (!rest.empty())
        {
            ProcRow match = {};

            if (ResolveProcessTarget(ctx.Session, layout, rows, rest[0], &match, out.Details.Collected.Complete))
            {
                selected.push_back(match);
            }
            else
            {
                ReportProcessSelectionFailure(out, out, rest[0]);
                break;
            }
        }
        else
        {
            selected = rows;
        }

        out.Details.Rows = knjson::Value::MakeArray();
        for (const auto &row : selected)
        {
            out.Details.Rows.Push(row.ToJson());
        }
        knutil::JsonlWriter jsonl;

        if (!jsonPath.empty() && !jsonl.Open(jsonPath))
        {
            out.Fail(kncore::Status::IOError, L"[proc] json export failed: " + jsonPath);
        }

        out.AddLine(std::wstring(L"[proc.list] count=") + FmtDec(selected.size()) + (jsonl.IsOpen() ? L" [json export on]" : L""));

        for (const ProcRow &row : selected)
        {
            std::wstring line = L"[proc] eprocess=" + FmtAddr(row.Eprocess) + L" pid=" + (row.PidKnown ? FmtDec(row.Pid) : L"Unknown") +
                                L" image=" + (row.ImageKnown ? row.Image : L"Unknown");

            if (row.DirectoryTableBase != 0)
            {
                line += L" dtb=" + FmtAddr(row.DirectoryTableBase);
            }

            out.AddLine(line);

            if (jsonl.IsOpen())
            {
                const auto record = row.ToJson();
                if (!jsonl.WriteLine(record.Write()))
                {
                    out.Fail(kncore::Status::IOError, L"[export.error] JSONL write failed");
                }
            }
        }
        if (jsonl.IsOpen() && !jsonl.Commit(out.Details.Collected.Complete))
        {
            out.Fail(kncore::Status::IOError, L"[export.error] JSONL commit failed");
        }
    } while (false);
}

// ---- !ssdt ----

void ScanSsdt(Ctx &ctx)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:ServiceTables"))
    {
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    const auto table = SymbolAddress(ctx.Session, layout, L"nt", L"KiServiceTable");
    const auto limitAddress = SymbolAddress(ctx.Session, layout, L"nt", L"KiServiceLimit");
    const auto tableType = layout.Symbol(L"nt", L"KiServiceTable");
    const auto limitType = layout.Symbol(L"nt", L"KiServiceLimit");
    const auto identity = layout.Identity(L"nt");
    std::optional<uint64_t> expected;
    std::wstring profile = L"MatchedPdbArray";
    if (tableType && tableType->ElementSize == 4U && tableType->ArrayCount && *tableType->ArrayCount > 0 &&
        *tableType->ArrayCount <= 4096 && limitType && limitType->Size == 4)
    {
        expected = *tableType->ArrayCount;
    }
    else if (identity && identity->Matched && identity->Machine == IMAGE_FILE_MACHINE_AMD64 &&
             _wcsicmp(identity->PdbGuid.c_str(), L"{11D7FE79-CC24-5612-0555-03EE86BB0E3E}") == 0 && identity->PdbAge == 1 &&
             identity->Timestamp == 0x90b083da && identity->ImageSize == 0x1450000 && table && limitAddress &&
             *table - identity->Base == 0xda7d0 && *limitAddress - identity->Base == 0xdaf74)
    {
        // Exact-image profile: public PDB RVAs, PE limit and contiguous table extent agree.
        expected = 489;
        profile = L"NT-26100.8655-PDB-11D7FE79-age1";
    }
    uint32_t limit = 0;
    if (!expected || !table || !limitAddress || !architecture.KernelPointer(*table) ||
        !ctx.Session.ReadExact(kncore::AddressSpace::Virtual, *limitAddress, &limit) || limit != *expected ||
        !kncore::ValidRange(*table, *expected * 4))
    {
        UnknownScope(ctx, budget, L"NativeSSDT", L"Verified table extent/limit profile unavailable or differs from target");
    }
    else
    {
        const auto owners = knengine::CollectOwnershipIndex(ctx.Session);
        budget.Report.Collected.Expected = limit;
        for (uint32_t index = 0; index < limit && CheckCollection(ctx, budget); ++index)
        {
            ++budget.Report.Collected.Visited;
            int32_t encoded = 0;
            const uint64_t slot = *table + index * 4;
            std::optional<uint64_t> routine;
            if (ctx.Session.ReadExact(kncore::AddressSpace::Virtual, slot, &encoded))
            {
                ++budget.Report.Collected.Read;
                routine = kncore::DecodeServiceEntry(*table, encoded);
            }
            else
            {
                ++budget.Report.Collected.Unreadable;
            }
            auto row = kncore::RoutineObservation(budget.Report, architecture, owners, L"NativeSSDT", slot, routine);
            row.Set(L"index", knjson::Value(std::to_wstring(index)));
            row.Set(L"profile", knjson::Value(profile));
            row.Set(L"encoding", knjson::Value(L"x64SignedRelativeShift4"));
            EmitRow(ctx, budget, row);
        }
    }
    UnknownScope(ctx, budget, L"ShadowSSDT", L"No verified descriptor layout and GUI-session mapping in this profile");
    budget.Report.Limitations.Push(
        knjson::Value(L"A matching module does not prove that service code is unchanged. Checking a disk profile does not validate the running kernel."));
    FinishCollection(ctx, budget);
}

// ---- !idt ----

void ScanIdt(Ctx &ctx)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:PerProcessorIdt"))
    {
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    const auto special = kncore::NestedField(layout.Field(L"nt", L"_KPRCB", L"ProcessorState"),
                                             layout.Field(L"nt", L"_KPROCESSOR_STATE", L"SpecialRegisters"));
    const auto descriptor = kncore::NestedField(special, layout.Field(L"nt", L"_KSPECIAL_REGISTERS", L"Idtr"));
    const auto baseField = kncore::NestedField(descriptor, layout.Field(L"nt", L"_KDESCRIPTOR", L"Base"));
    const auto limitField = kncore::NestedField(descriptor, layout.Field(L"nt", L"_KDESCRIPTOR", L"Limit"));
    if (!baseField || baseField->Size != 8 || !limitField || limitField->Size != 2)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Saved IDTR base/limit layout unavailable");
        return;
    }
    const auto owners = knengine::CollectOwnershipIndex(ctx.Session);
    const auto count = knengine::CountProcessors(ctx.Session);
    if (count == 0 || count > 4096)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Processor inventory unavailable");
        return;
    }
    ULONG64 firstPrcb = 0;
    const bool firstPrcbKnown = !ctx.Session.Cancelled() && ctx.Session.ReadProcessorBlock(0, &firstPrcb) &&
                                architecture.KernelPointer(firstPrcb);
    budget.StartTraversal();
    for (ULONG cpu = 0; cpu < count && CheckCollection(ctx, budget); ++cpu)
    {
        ULONG64 prcb = firstPrcb;
        const bool prcbKnown = cpu == 0 ? firstPrcbKnown :
            ctx.Session.ReadProcessorBlock(cpu, &prcb) && architecture.KernelPointer(prcb);
        if (!prcbKnown)
        {
            UnknownScope(ctx, budget, L"IDT CPU " + std::to_wstring(cpu), L"PRCB unavailable");
            continue;
        }
        const auto base = kncore::ReadField(ctx.Session, prcb, baseField);
        const auto limit = kncore::ReadField(ctx.Session, prcb, limitField);
        if (!base || !architecture.KernelPointer(*base) || !limit || *limit > 4095 || (*limit + 1) % 16 != 0 ||
            !kncore::ValidRange(*base, *limit + 1))
        {
            UnknownScope(ctx, budget, L"IDT CPU " + std::to_wstring(cpu),
                         L"Saved descriptor unavailable or invalid");
            continue;
        }
        const uint64_t gates = (*limit + 1) / 16;
        budget.Report.Collected.Expected += gates;
        for (uint64_t vector = 0; vector < gates && CheckCollection(ctx, budget); ++vector)
        {
            ++budget.Report.Collected.Visited;
            const uint64_t slot = *base + vector * 16;
            const auto read = ctx.Session.Read(kncore::AddressSpace::Virtual, slot, 16);
            if (!kncore::ValidRange(*base, (vector + 1) * 16) || !kncore::ExactBytes(read, 16))
            {
                ++budget.Report.Collected.Unreadable;
                continue;
            }
            ++budget.Report.Collected.Read;
            const auto gate = kncore::DecodeIdt(read.Bytes);
            auto row = gate.Present && gate.Valid
                           ? kncore::RoutineObservation(budget.Report, architecture, owners, L"IdtGate", slot, gate.Handler)
                           : knjson::Value::MakeObject();
            row.Set(L"kind", knjson::Value(L"IdtGate"));
            row.Set(L"cpu", knjson::Value(std::to_wstring(cpu)));
            row.Set(L"vector", knjson::Value(std::to_wstring(vector)));
            row.Set(L"present", knjson::Value(gate.Present));
            row.Set(L"validGate", knjson::Value(gate.Valid));
            row.Set(L"type", knjson::Value(std::to_wstring(gate.Type)));
            row.Set(L"dpl", knjson::Value(std::to_wstring(gate.Dpl)));
            row.Set(L"descriptorSource", knjson::Value(L"SavedProcessorState"));
            if (!gate.Valid)
            {
                ++budget.Report.Collected.Unknown;
            }
            EmitRow(ctx, budget, row);
        }
    }
    budget.Report.Limitations.Push(knjson::Value(L"Descriptors come from each CPU's PDB-verified saved processor state without switching "
                                                 L"the debugger CPU. Saved state may lag a running local target; this does not establish system-wide integrity."));
    FinishCollection(ctx, budget);
}

namespace
{
void RegisterSweep(Ctx &ctx, bool msrs)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, msrs ? L"TargetRegisters:CurrentProcessorMsr" : L"TargetMemory:SavedProcessorControl"))
    {
        return;
    }
    struct RegisterSpec
    {
        const wchar_t *Name;
        const wchar_t *Field;
        ULONG Msr = 0;
    };
    const std::vector<RegisterSpec> registers = msrs ? std::vector<RegisterSpec>{{L"LSTAR", nullptr, 0xc0000082},
                                                                               {L"CSTAR", nullptr, 0xc0000083},
                                                                               {L"STAR", nullptr, 0xc0000081},
                                                                               {L"FMASK", nullptr, 0xc0000084},
                                                                               {L"EFER", nullptr, 0xc0000080}}
                                                    : std::vector<RegisterSpec>{{L"cr0", L"Cr0"}, {L"cr4", L"Cr4"}, {L"cr8", L"Cr8"}};
    const auto count = knengine::CountProcessors(ctx.Session);
    if (count == 0 || count > 4096)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Processor count unavailable");
        return;
    }
    std::vector<std::optional<kncore::FieldInfo>> fields;
    std::optional<ULONG> currentProcessor;
    if (msrs)
    {
        auto *system = ctx.Session.SystemObjects();
        ULONG currentThread = DEBUG_ANY_ID;
        ULONG eventThread = DEBUG_ANY_ID;
        // ReadMsr has no processor operand. Require the selected CPU to be
        // the event CPU, and never initiate a KD processor switch here.
        if (system && system->GetCurrentThreadId(&currentThread) == S_OK &&
            system->GetEventThread(&eventThread) == S_OK && currentThread == eventThread)
        {
            for (ULONG cpu = 0; cpu < count; ++cpu)
            {
                ULONG thread = DEBUG_ANY_ID;
                if (system->GetThreadIdByProcessor(cpu, &thread) != S_OK ||
                    (thread == currentThread && currentProcessor))
                {
                    currentProcessor.reset();
                    break;
                }
                if (thread == currentThread)
                {
                    currentProcessor = cpu;
                }
            }
        }
    }
    else
    {
        knengine::LayoutResolver layout(ctx.Session);
        const auto special = kncore::NestedField(layout.Field(L"nt", L"_KPRCB", L"ProcessorState"),
                                                 layout.Field(L"nt", L"_KPROCESSOR_STATE", L"SpecialRegisters"));
        for (const auto &item : registers)
        {
            auto field = kncore::NestedField(special, layout.Field(L"nt", L"_KSPECIAL_REGISTERS", item.Field));
            if (field && (field->Size != 8 || field->BitOffset || field->BitWidth))
            {
                field.reset();
            }
            fields.push_back(field);
        }
    }
    budget.Report.Collected.Expected = count * registers.size();
    std::map<std::wstring, std::set<uint64_t>> observed;
    // The first KD lookup can initialize processor transport state. Preserve
    // that first observation before applying one shared traversal deadline.
    ULONG64 firstPrcb = 0;
    const bool firstPrcbKnown = !msrs && !ctx.Session.Cancelled() && ctx.Session.ReadProcessorBlock(0, &firstPrcb) &&
                                architecture.KernelPointer(firstPrcb);
    ULONG64 firstMsr = 0;
    const bool firstMsrKnown = msrs && currentProcessor && !ctx.Session.Cancelled() &&
                               ctx.Session.ReadMsrValue(registers.front().Msr, &firstMsr);
    budget.StartTraversal();
    for (ULONG cpu = 0; cpu < count && CheckCollection(ctx, budget); ++cpu)
    {
        ULONG64 prcb = firstPrcb;
        const bool hasPrcb = !msrs && (cpu == 0 ? firstPrcbKnown :
            ctx.Session.ReadProcessorBlock(cpu, &prcb) && architecture.KernelPointer(prcb));
        for (size_t index = 0; index < registers.size(); ++index)
        {
            const auto &item = registers[index];
            if (!CheckCollection(ctx, budget))
            {
                break;
            }
            ++budget.Report.Collected.Visited;
            ULONG64 value = 0;
            bool read = false;
            const wchar_t *reason = nullptr;
            if (msrs)
            {
                if (!currentProcessor || cpu != *currentProcessor)
                {
                    reason = currentProcessor ? L"ProcessorSwitchRequired" : L"CurrentEventProcessorUnverified";
                    ++budget.Report.Collected.Unknown;
                }
                else
                {
                    if (index == 0)
                    {
                        read = firstMsrKnown;
                        value = firstMsr;
                    }
                    else
                    {
                        read = ctx.Session.ReadMsrValue(item.Msr, &value);
                    }
                    if (!read)
                    {
                        reason = L"CurrentProcessorMsrUnreadable";
                        ++budget.Report.Collected.Unreadable;
                    }
                }
            }
            else
            {
                const auto saved = hasPrcb ? kncore::ReadField(ctx.Session, prcb, fields[index]) : std::nullopt;
                read = saved.has_value();
                value = saved.value_or(0);
                if (!read)
                {
                    reason = !hasPrcb ? L"ProcessorBlockUnavailable" :
                             !fields[index] ? L"SavedRegisterLayoutUnavailable" : L"SavedRegisterUnreadable";
                    if (hasPrcb && fields[index])
                    {
                        ++budget.Report.Collected.Unreadable;
                    }
                    else
                    {
                        ++budget.Report.Collected.Unknown;
                    }
                }
            }
            auto row = knjson::Value::MakeObject();
            row.Set(L"kind", knjson::Value(L"ProcessorRegister"));
            row.Set(L"cpu", knjson::Value(std::to_wstring(cpu)));
            row.Set(L"register", knjson::Value(item.Name));
            row.Set(L"value", read ? knjson::Value(kncore::Hex(value)) : knjson::Value());
            row.Set(L"registerSource", knjson::Value(msrs ? L"CurrentProcessorMsr" : L"SavedProcessorState"));
            if (reason)
            {
                row.Set(L"unavailableReason", knjson::Value(reason));
            }
            if (read)
            {
                ++budget.Report.Collected.Read;
                observed[item.Name].insert(value);
                if (std::wstring(item.Name) == L"cr0")
                {
                    row.Set(L"writeProtect", knjson::Value((value & (uint64_t(1) << 16)) != 0));
                }
                if (std::wstring(item.Name) == L"cr4")
                {
                    row.Set(L"smep", knjson::Value((value & (uint64_t(1) << 20)) != 0));
                    row.Set(L"smap", knjson::Value((value & (uint64_t(1) << 21)) != 0));
                    row.Set(L"la57", knjson::Value((value & (uint64_t(1) << 12)) != 0));
                }
            }
            EmitRow(ctx, budget, row);
        }
    }
    for (const auto &[name, values] : observed)
    {
        ctx.Out.AddLine(L"[register.variation] " + name + L" distinct-observed-values=" + std::to_wstring(values.size()));
    }
    budget.Report.Limitations.Push(knjson::Value(msrs
        ? L"MSRs are read only on the selected event CPU. Other CPUs remain unknown because automatic KD CPU switches can complete "
          L"after context restoration. To inspect another CPU, select it in WinDbg, wait for its break prompt, and rerun. "
          L"The selected CPU must match the event CPU. Saved PRCB MSR fields are not used: "
          L"they may remain zero even when live MSRs are nonzero. This does not compare CPUs or determine whether hooks are present."
        : L"Values come from each CPU's PDB-verified saved processor state without switching the debugger CPU. Saved state may lag "
          L"a running target; CR8 and mitigations can differ legitimately. Differences alone do not indicate hooks."));
    FinishCollection(ctx, budget);
}
} // namespace

void ScanMsrCheck(Ctx &ctx)
{
    RegisterSweep(ctx, true);
}

void ScanControlRegisters(Ctx &ctx)
{
    RegisterSweep(ctx, false);
}

// ---- !address ----

void InspectAddress(Ctx &ctx)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:AddressTranslation"))
    {
        return;
    }
    ULONG64 address = 0;
    ULONG64 dtb = 0;
    if (!EvalAddress(ctx.Session, ctx.Args[1], &address) || !architecture.Canonical(address))
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"Invalid canonical target address");
        return;
    }
    if (ctx.Session.HasContextDtb())
    {
        dtb = ctx.Session.ContextDtb();
    }
    else if (!ctx.Session.ReadRegisterHex(L"cr3", &dtb))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Directory table base unavailable");
        return;
    }
    knengine::PageWalkResult walk;
    const bool translated = knengine::WalkVirtualToPhysical(ctx.Session, address, dtb, architecture.VirtualAddressBits == 57u, &walk);
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"Address"));
    row.Set(L"space", knjson::Value(L"Virtual"));
    row.Set(L"address", knjson::Value(kncore::Hex(address)));
    row.Set(L"dtb", knjson::Value(kncore::Hex(dtb)));
    row.Set(L"physical", translated ? knjson::Value(kncore::Hex(walk.PhysicalAddress)) : knjson::Value());
    row.Set(L"writable", translated ? knjson::Value(walk.EffectiveWritable) : knjson::Value());
    row.Set(L"executable", translated ? knjson::Value(walk.EffectiveExecutable) : knjson::Value());
    row.Set(L"pageSize", translated ? knjson::Value(std::to_wstring(walk.PageSize)) : knjson::Value());
    row.Set(L"error", translated ? knjson::Value() : knjson::Value(walk.Error));
    const auto owners = knengine::CollectOwnershipIndex(ctx.Session);
    row.Set(L"moduleObservation",
            knjson::Value(architecture.KernelPointer(address) ? OwnershipText(owners.Find(address, budget.Report.Stamp))
                                                              : L"UserModuleContextNotCollected"));
    auto levels = knjson::Value::MakeArray();
    for (int index = 0; index < walk.LevelCount; ++index)
    {
        auto level = knjson::Value::MakeObject();
        level.Set(L"physicalSlot", knjson::Value(kncore::Hex(walk.EntrySlotPhysical[index])));
        level.Set(L"entry", knjson::Value(kncore::Hex(walk.EntryValue[index])));
        levels.Push(level);
    }
    row.Set(L"pageTableLevels", levels);
    EmitRow(ctx, budget, row);
    budget.Report.Collected.Visited = 1;
    budget.Report.Collected.Unknown = translated ? 0 : 1;
    budget.Report.Limitations.Push(knjson::Value(L"Translation uses architectural maximum physical width when target CPUID width is "
                                                 L"unavailable; user module ownership requires an explicit process context."));
    FinishCollection(ctx, budget);
}
} // namespace kncmd
