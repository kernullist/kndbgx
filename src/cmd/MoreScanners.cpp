#include "CollectorSupport.h"
#include "../core/EtwRead.h"
#include <evntrace.h>

namespace kncmd
{
void ScanNmi(Ctx &ctx)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:NmiCallbacks"))
    {
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    auto head = SymbolAddress(ctx.Session, layout, L"nt", L"KiNmiCallbackListHead");
    if (!head)
    {
        head = SymbolAddress(ctx.Session, layout, L"nt", L"KiNmiCallbackList");
    }
    if (!head)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"NMI list symbol unavailable");
        return;
    }
    auto next = layout.Field(L"nt", L"_KNMI_HANDLER_CALLBACK", L"Next");
    auto routine = layout.Field(L"nt", L"_KNMI_HANDLER_CALLBACK", L"Callback");
    bool compatible = true;
    if ((!next || !routine) && layout.VerifyProfile(kncore::KernelLayoutFamily::Nmi))
    {
        compatible = layout.CanProfileField(L"nt", L"_KNMI_HANDLER_CALLBACK", L"Next") &&
                     layout.CanProfileField(L"nt", L"_KNMI_HANDLER_CALLBACK", L"Callback") && kncore::ApplyKernelProfileField(next, 0, 8) &&
                     kncore::ApplyKernelProfileField(routine, 8, 8);
        budget.Report.LayoutProfile = kncore::KernelSymbolProfileId;
    }
    uint64_t first = 0;
    const bool headRead = ctx.Session.ReadExact(kncore::AddressSpace::Virtual, *head, &first);
    if (!compatible || !next || next->Size != 8 || !routine || routine->Size != 8 || !headRead)
    {
        UnknownScope(ctx, budget, L"NMI", L"Callback layout unavailable; no guessed node dereference");
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"RawSymbolObservation"));
        row.Set(L"symbol", knjson::Value(L"NmiCallbackList"));
        row.Set(L"address", knjson::Value(kncore::Hex(*head)));
        row.Set(L"rawValue", headRead ? knjson::Value(kncore::Hex(first)) : knjson::Value());
        EmitRow(ctx, budget, row);
    }
    else
    {
        const auto owners = knengine::CollectOwnershipIndex(ctx.Session);
        kncore::WalkChain(ctx.Session, first, 0, next->Offset, architecture, budget,
                          [&](uint64_t node)
                          {
                              const auto callback = kncore::ReadField(ctx.Session, node, routine);
                              EmitRow(ctx, budget,
                                      kncore::RoutineObservation(budget.Report, architecture, owners, L"Nmi.Callback", node, callback));
                              if (!callback)
                              {
                                  ++budget.Report.Collected.Unreadable;
                              }
                              return kncore::VisitDecision::Continue;
                          });
    }
    FinishCollection(ctx, budget);
}

void ScanHal(Ctx &ctx)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:HalDispatchTables"))
    {
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    const auto owners = knengine::CollectOwnershipIndex(ctx.Session);
    for (const auto &table :
         {std::pair(L"HalDispatchTable", L"_HAL_DISPATCH"), std::pair(L"HalPrivateDispatchTable", L"HAL_PRIVATE_DISPATCH")})
    {
        const auto address = SymbolAddress(ctx.Session, layout, L"nt", table.first);
        auto type = layout.Describe(L"nt", table.second);
        if (!type)
        {
            type = layout.Describe(L"nt", table.first == std::wstring(L"HalDispatchTable") ? L"HAL_DISPATCH" : L"_HAL_PRIVATE_DISPATCH");
        }
        if (!address || !type)
        {
            UnknownScope(ctx, budget, table.first, L"Matched table type or symbol unavailable");
            continue;
        }
        for (const auto &[name, field] : type->Fields)
        {
            if (!CheckCollection(ctx, budget))
            {
                break;
            }
            if (field.Kind != kncore::FieldKind::Pointer || !field.FunctionPointer)
            {
                continue;
            }
            ++budget.Report.Collected.Expected;
            ++budget.Report.Collected.Visited;
            const auto routine = kncore::ReadField(ctx.Session, *address, field);
            if (routine)
            {
                ++budget.Report.Collected.Read;
                ++budget.Report.Collected.Decoded;
            }
            else
            {
                ++budget.Report.Collected.Unreadable;
            }
            auto row = kncore::RoutineObservation(budget.Report, architecture, owners, std::wstring(table.first) + L"." + name,
                                                  *address + field.Offset, routine, kncore::RoutinePresence::Optional);
            EmitRow(ctx, budget, row);
        }
        if (!type->Complete)
        {
            UnknownScope(ctx, budget, table.first, L"Some PDB fields unavailable");
        }
    }
    FinishCollection(ctx, budget);
}

namespace
{
void HostEtw(Ctx &ctx, kncore::WalkBudget &budget)
{
    constexpr size_t nameUnits = 1024;
    constexpr size_t stride = sizeof(EVENT_TRACE_PROPERTIES) + nameUnits * 2 * sizeof(wchar_t);
    ULONG capacity = 64;
    ULONG count = 0;
    ULONG status = ERROR_MORE_DATA;
    std::vector<unsigned char> storage;
    std::vector<EVENT_TRACE_PROPERTIES *> properties;
    for (unsigned attempt = 0; attempt < 8 && capacity <= 1024 && CheckCollection(ctx, budget); ++attempt)
    {
        storage.assign(stride * capacity, 0);
        properties.resize(capacity);
        for (ULONG i = 0; i < capacity; ++i)
        {
            auto *property = reinterpret_cast<EVENT_TRACE_PROPERTIES *>(storage.data() + stride * i);
            property->Wnode.BufferSize = static_cast<ULONG>(stride);
            property->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            property->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + nameUnits * sizeof(wchar_t);
            properties[i] = property;
        }
        status = QueryAllTracesW(properties.data(), capacity, &count);
        if (status != ERROR_MORE_DATA)
        {
            break;
        }
        capacity = std::max(capacity * 2, count);
    }
    if (status != ERROR_SUCCESS || count > properties.size())
    {
        budget.Report.Error = {L"Win32", status, L"QueryAllTracesW", L"Host ETW session inventory unavailable"};
        UnknownScope(ctx, budget, L"Host ETW", L"Query failed or did not converge within budget");
        return;
    }
    budget.Report.Collected.Expected += count;
    for (ULONG i = 0; i < count && CheckCollection(ctx, budget); ++i)
    {
        const auto &property = *properties[i];
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"EtwSession"));
        row.Set(L"source", knjson::Value(L"HostQueryAllTracesW"));
        const auto offset = property.LoggerNameOffset;
        bool validName = offset >= sizeof(EVENT_TRACE_PROPERTIES) && offset < stride && offset % 2 == 0;
        std::wstring name;
        if (validName)
        {
            const auto *text = reinterpret_cast<const wchar_t *>(reinterpret_cast<const unsigned char *>(&property) + offset);
            const size_t maximum = (stride - offset) / 2;
            const auto length = wcsnlen_s(text, maximum);
            validName = length < maximum;
            if (validName)
            {
                name.assign(text, length);
            }
        }
        row.Set(L"name", validName ? knjson::Value(name) : knjson::Value());
        row.Set(L"id", knjson::Value(kncore::Hex(property.Wnode.HistoricalContext)));
        row.Set(L"eventsLost", knjson::Value(std::to_wstring(property.EventsLost)));
        row.Set(L"logFileMode", knjson::Value(kncore::Hex(property.LogFileMode)));
        row.Set(L"clockConfiguration", knjson::Value(std::to_wstring(property.Wnode.ClientContext)));
        if (!validName)
        {
            ++budget.Report.Collected.Unknown;
        }
        ++budget.Report.Collected.Visited;
        EmitRow(ctx, budget, row);
    }
    budget.Report.Limitations.Push(knjson::Value(L"Host API exposes sessions visible to caller permissions and excludes private sessions; "
                                                 L"kernel clock-function integrity is not observed."));
}
} // namespace

void ScanEtwLoggers(Ctx &ctx)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"EtwSessionInventory"))
    {
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    const auto siloSymbol = layout.Symbol(L"nt", L"PspHostSiloGlobals");
    const auto siloAddress = SymbolAddress(ctx.Session, layout, L"nt", L"PspHostSiloGlobals");
    const auto etwField = layout.Field(L"nt", L"_ESERVERSILO_GLOBALS", L"EtwSiloState");
    const auto loggerArray = layout.Field(L"nt", L"_ETW_SILODRIVERSTATE", L"EtwpLoggerContext");
    const auto loggerCount = layout.Field(L"nt", L"_ETW_SILODRIVERSTATE", L"MaxLoggers");
    bool collectedTarget = false;
    if (siloSymbol && siloSymbol->Kind == kncore::FieldKind::Composite && siloSymbol->TypeName == L"_ESERVERSILO_GLOBALS" && siloAddress)
    {
        const auto table = kncore::ReadEtwLoggerTable(ctx.Session, architecture, *siloAddress, etwField, loggerArray, loggerCount);
        if (table)
        {
            collectedTarget = true;
            const auto nameField = layout.Field(L"nt", L"_WMI_LOGGER_CONTEXT", L"LoggerName");
            const auto clockField = layout.Field(L"nt", L"_WMI_LOGGER_CONTEXT", L"GetCpuClock");
            const auto clockType = layout.Field(L"nt", L"_WMI_LOGGER_CONTEXT", L"ClockType");
            const bool typeAbsent = !clockType && layout.CanProfileField(L"nt", L"_WMI_LOGGER_CONTEXT", L"ClockType");
            const auto idField = layout.Field(L"nt", L"_WMI_LOGGER_CONTEXT", L"LoggerId");
            const bool knownSlots = loggerArray && loggerArray->Offset == 0x2c8 && clockField && clockField->Offset == 0x18 &&
                                    clockField->Size == 8 && kncore::EtwIntegerField(clockField) &&
                                    layout.VerifyProfile(kncore::KernelLayoutFamily::HostSilo);
            if (!clockType && !typeAbsent)
            {
                UnknownScope(ctx, budget, L"ETW ClockType", L"Optional field absence is not established by the matched PDB");
            }
            budget.Report.Collected.Expected = table->Count;
            for (uint64_t index = 0; index < table->Count && CheckCollection(ctx, budget); ++index)
            {
                ++budget.Report.Collected.Visited;
                uint64_t logger = 0;
                if (!ctx.Session.ReadExact(kncore::AddressSpace::Virtual, table->Address + index * architecture.PointerBytes, &logger))
                {
                    ++budget.Report.Collected.Unreadable;
                    continue;
                }
                if (logger == 0 || (knownSlots && logger == 1))
                {
                    ++budget.Report.Collected.Read;
                    ++budget.Report.Collected.Decoded;
                    continue;
                }
                ++budget.Report.Collected.Read;
                if (!architecture.KernelPointer(logger))
                {
                    ++budget.Report.Collected.Unknown;
                    continue;
                }
                auto row = knjson::Value::MakeObject();
                row.Set(L"kind", knjson::Value(L"EtwLoggerContext"));
                row.Set(L"object", knjson::Value(kncore::Hex(logger)));
                std::wstring name;
                const bool known = nameField && kncore::ValidRange(logger, static_cast<uint64_t>(nameField->Offset) + nameField->Size) &&
                                   ReadUnicodeString(ctx.Session, layout, logger + nameField->Offset, &name);
                row.Set(L"name", known ? knjson::Value(name) : knjson::Value());
                const auto clock = kncore::ReadEtwClock(ctx.Session, architecture, logger, clockField, clockType, typeAbsent, knownSlots);
                const auto id = kncore::ReadField(ctx.Session, logger, idField);
                row.Set(L"loggerId", kncore::OptionalNumber(id));
                row.Set(L"rawClock", kncore::OptionalNumber(clock.Raw, true));
                row.Set(L"clockType", kncore::OptionalNumber(clock.Type));
                row.Set(L"clockRepresentation", knjson::Value(clock.Representation));
                if (!known || !clock.Known || !id || *id != index)
                {
                    ++budget.Report.Collected.Unknown;
                }
                else
                {
                    ++budget.Report.Collected.Decoded;
                }
                EmitRow(ctx, budget, row);
            }
        }
    }
    if (!collectedTarget)
    {
        UnknownScope(ctx, budget, L"Target ETW", L"Global storage/type relationship unavailable; no fixed EtwpDebuggerData stride");
        if (SessionIsLocalLiveKernel(ctx.Session))
        {
            HostEtw(ctx, budget);
        }
    }
    budget.Report.Limitations.Push(
        knjson::Value(L"Host-silo logger inventory only. ClockType may be absent from the matched PDB. "
                      L"Integer selectors are decoded only with the verified profile; other integers are shown as raw values. "
                      L"Clock values do not establish integrity."));
    FinishCollection(ctx, budget);
}

void DecodeWnf(Ctx &ctx)
{
    CmdText &out = ctx.Out;

    do
    {
        if (ctx.Args.size() < 2)
        {
            out.AddLine(L"[wnf] usage: !wnf decode <hex-state-name>");
            break;
        }

        size_t hexIndex = 1;

        if (_wcsicmp(ctx.Args[1].c_str(), L"decode") == 0)
        {
            if (ctx.Args.size() < 3)
            {
                out.AddLine(L"[wnf] usage: !wnf decode <hex-state-name>");
                break;
            }

            hexIndex = 2;
        }

        uint64_t raw = 0;
        if (!kncore::ParseUnsigned(ctx.Args[hexIndex], 16, &raw))
        {
            out.Fail(kncore::Status::InvalidInput, L"[wnf] invalid complete encoded state name");
            break;
        }

        const unsigned long long decoded = raw ^ 0x41C64E6DA3BC0074ULL;

        const unsigned version = static_cast<unsigned>(decoded & 0xF);
        const unsigned lifetime = static_cast<unsigned>((decoded >> 4) & 0x3);
        const unsigned dataScope = static_cast<unsigned>((decoded >> 6) & 0xF);
        const unsigned permanentData = static_cast<unsigned>((decoded >> 10) & 0x1);
        const unsigned long long sequence = (decoded >> 11) & 0x1FFFFFULL;
        const unsigned long long ownerTag = (decoded >> 32) & 0xFFFFFFFFULL;

        static const wchar_t *kLifetime[] = {L"WellKnown", L"Permanent", L"Persistent", L"Temporary"};
        static const wchar_t *kScope[] = {L"System", L"Session", L"User", L"Process", L"Machine", L"PhysicalMachine", L"5?", L"6?"};

        wchar_t ownerAscii[5] = L"";

        for (int i = 0; i < 4; ++i)
        {
            const unsigned char byte = static_cast<unsigned char>(ownerTag >> ((3 - i) * 8));

            ownerAscii[i] = (byte >= 0x20 && byte < 0x7F) ? static_cast<wchar_t>(byte) : L'.';
        }
        ownerAscii[4] = L'\0';

        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"WnfNameDecode"));
        row.Set(L"encoded", knjson::Value(kncore::Hex(raw)));
        row.Set(L"version", knjson::Value(std::to_wstring(version)));
        row.Set(L"lifetime", knjson::Value(std::to_wstring(lifetime)));
        row.Set(L"scope", knjson::Value(std::to_wstring(dataScope)));
        row.Set(L"sequence", knjson::Value(std::to_wstring(sequence)));
        out.Details.Rows.Push(row);
        out.Details.Source = L"InputDecoder";
        out.Details.Collected.Complete = version == 1 && dataScope < 6;
        out.Details.State = out.Details.Collected.Complete ? kncore::Status::Success : kncore::Status::Partial;
        out.Details.Collected.StopReason = out.Details.Collected.Complete ? L"NameDecoded" : L"UnknownWnfEncodingVersionOrScope";
        out.Details.Limitations.Push(
            knjson::Value(L"Windows WNF name encoding decoder only; subscription/state data and security properties were not collected."));
        out.AddLine(L"[wnf.decode] raw=0x" + FmtHexN(raw, 16));
        out.AddLine(L"[wnf.decode] decoded=0x" + FmtHexN(decoded, 16));
        out.AddLine(std::wstring(L"[wnf.decode] version=") + FmtDec(version) + L" lifetime=" + kLifetime[lifetime & 3] + L" scope=" +
                    (dataScope < 6 ? kScope[dataScope] : L"Unknown"));
        out.AddLine(std::wstring(L"[wnf.decode] permanent=") + FmtDec(permanentData) + L" sequence=" + FmtHexN(sequence, 1) +
                    L" ownertag=0x" + FmtHexN(ownerTag, 8) + L" ('" + ownerAscii + L"')");
    } while (false);
}
} // namespace kncmd
