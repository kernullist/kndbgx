// Scanner commands part 6 (M5): registry hives, per-CPU DPC/timer audit,
// ALPC port enumeration and loaded-module PE integrity.

#include "CollectorSupport.h"
#include "../core/MemoryString.h"
#include "../core/KernelAnalysis.h"
#include "../core/PeIdentity.h"
#include "../core/TimerDpc.h"
#include "../core/QueueRead.h"
#include "../core/Piddb.h"
#include "../core/AlpcPorts.h"
#include "../util/FileReader.h"

#include <dbgeng.h>
#include <cstring>
#include <mutex>
#include <set>
#include <vector>

#include "../engine/CpuContext.h"
#include "../engine/LayoutResolver.h"
#include "../engine/ModuleList.h"
#include "../engine/ObjectDirectory.h"
#include "ProcCollect.h"

namespace kncmd
{
void ScanHive(Ctx &ctx)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:CmpHiveListHead"))
    {
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    const auto head = SymbolAddress(ctx.Session, layout, L"nt", L"CmpHiveListHead");
    const auto link = layout.Field(L"nt", L"_CMHIVE", L"HiveList");
    const auto routine = kncore::NestedField(layout.Field(L"nt", L"_CMHIVE", L"Hive"), layout.Field(L"nt", L"_HHIVE", L"GetCellRoutine"));
    const auto rootPath = layout.Field(L"nt", L"_CMHIVE", L"HiveRootPath");
    const auto filePath = layout.Field(L"nt", L"_CMHIVE", L"FileFullPath");
    const auto userPath = layout.Field(L"nt", L"_CMHIVE", L"FileUserName");
    const auto flags = layout.Field(L"nt", L"_CMHIVE", L"Flags");
    const auto fileSize = layout.Field(L"nt", L"_CMHIVE", L"ActualFileSize");
    if (!head || !link || link->Size != 16)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Hive list layout or symbol unavailable");
        return;
    }
    const auto owners = knengine::CollectOwnershipIndex(ctx.Session);
    budget.StartTraversal(std::chrono::steady_clock::now(), std::chrono::seconds(30));
    kncore::WalkList(ctx.Session, *head, architecture, budget,
                     [&](uint64_t entry)
                     {
                         if (entry < link->Offset)
                         {
                             return kncore::VisitDecision::Failed;
                         }
                         const auto object = entry - link->Offset;
                         auto row = kncore::RoutineObservation(budget.Report, architecture, owners, L"Hive.GetCellRoutine", object,
                                                               kncore::ReadField(ctx.Session, object, routine));
                         row.Set(L"kind", knjson::Value(L"RegistryHive"));
                         row.Set(L"hive", knjson::Value(kncore::Hex(object)));
                         for (const auto &named : {std::pair(L"rootPath", rootPath), std::pair(L"filePath", filePath),
                                                  std::pair(L"fileUserName", userPath)})
                         {
                             const auto value = RecordUnicode(ctx.Session, layout, object, named.second);
                             row.Set(named.first, value);
                             if (value.IsNull())
                             {
                                 ++budget.Report.Collected.Unknown;
                             }
                         }
                         const auto observedFlags = kncore::ReadField(ctx.Session, object, flags);
                         const auto observedSize = kncore::ReadField(ctx.Session, object, fileSize);
                         row.Set(L"flags", kncore::OptionalNumber(observedFlags, true));
                         row.Set(L"fileSize", kncore::OptionalNumber(observedSize));
                         if (!observedFlags || !observedSize)
                         {
                             ++budget.Report.Collected.Unknown;
                         }
                         EmitRow(ctx, budget, row);
                         return kncore::VisitDecision::Continue;
                     });
    FinishCollection(ctx, budget);
}

namespace
{
std::optional<kncore::FieldInfo> DpcSingleHead(knengine::LayoutResolver &layout)
{
    return kncore::NestedField(
        kncore::NestedField(layout.Field(L"nt", L"_KDPC_DATA", L"DpcList"), layout.Field(L"nt", L"_KDPC_LIST", L"ListHead")),
        layout.Field(L"nt", L"_SINGLE_LIST_ENTRY", L"Next"));
}

void CpuQueues(Ctx &ctx, bool timers)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, timers ? L"TargetMemory:ProcessorTimers" : L"TargetMemory:ProcessorDpcs"))
    {
        return;
    }
    const auto count = knengine::CountProcessors(ctx.Session);
    if (count == 0 || count > 4096)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Processor inventory unavailable");
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    const auto owners = knengine::CollectOwnershipIndex(ctx.Session);
    const auto routine = layout.Field(L"nt", L"_KDPC", L"DeferredRoutine");
    const auto link = layout.Field(L"nt", timers ? L"_KTIMER" : L"_KDPC", timers ? L"TimerListEntry" : L"DpcListEntry");
    const auto timerDpc = layout.Field(L"nt", L"_KTIMER", L"Dpc");
    const auto dueTime = layout.Field(L"nt", L"_KTIMER", L"DueTime");
    const auto period = layout.Field(L"nt", L"_KTIMER", L"Period");
    const auto signalState = kncore::NestedField(layout.Field(L"nt", L"_KTIMER", L"Header"),
                                                layout.Field(L"nt", L"_DISPATCHER_HEADER", L"SignalState"));
    const auto context = layout.Field(L"nt", L"_KDPC", L"DeferredContext");
    const auto importance = layout.Field(L"nt", L"_KDPC", L"Importance");
    const auto dpcType = layout.Field(L"nt", L"_KDPC", L"Type");
    const auto never = timers ? layout.Address(L"nt", L"KiWaitNever") : std::nullopt;
    const auto always = timers ? layout.Address(L"nt", L"KiWaitAlways") : std::nullopt;
    std::optional<kncore::TimerDpcKeys> timerKeys;
    const auto readKeys = [&]() -> std::optional<kncore::TimerDpcKeys>
    {
        kncore::TimerDpcKeys keys;
        if (never && always && ctx.Session.ReadExact(kncore::AddressSpace::Virtual, *never, &keys.Never) &&
            ctx.Session.ReadExact(kncore::AddressSpace::Virtual, *always, &keys.Always))
        {
            return keys;
        }
        return {};
    };
    if (timers && never && always && layout.VerifyProfile(kncore::KernelLayoutFamily::TimerDpc) &&
        kncore::PiddbFieldMatches(timerDpc, 0x30, 8, kncore::FieldKind::Pointer) &&
        kncore::PiddbFieldMatches(dpcType, 0, 1, kncore::FieldKind::Unsigned) &&
        kncore::PiddbFieldMatches(routine, 0x18, 8, kncore::FieldKind::Pointer))
    {
        const auto scalar = [&](const wchar_t *name)
        {
            const auto shape = layout.Symbol(L"nt", name);
            return shape ? kncore::PiddbFieldMatches(shape, 0, 8, kncore::FieldKind::Unsigned) : layout.PublicOnlySymbol(L"nt", name);
        };
        if (scalar(L"KiWaitNever") && scalar(L"KiWaitAlways"))
        {
            timerKeys = readKeys();
        }
    }
    const auto queue = layout.Field(L"nt", L"_KPRCB", timers ? L"TimerTable" : L"DpcData");
    const auto entries = timers ? layout.Field(L"nt", L"_KTIMER_TABLE", L"TimerEntries") : queue;
    const auto list = timers ? layout.Field(L"nt", L"_KTIMER_TABLE_ENTRY", L"Entry") : DpcSingleHead(layout);
    ULONG stride = 0;
    const bool hasStride = layout.TypeSize(timers ? L"_KTIMER_TABLE_ENTRY" : L"_KDPC_DATA", &stride);
    if (!link || link->Size != (timers ? 16u : 8u) || !queue || !entries || !entries->LeafElementSize || !hasStride ||
        stride == 0 || *entries->LeafElementSize != stride || !list || list->Size != (timers ? 16u : 8u) ||
        !list->ValidFor(stride) || !routine || routine->Size != 8)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"PDB queue dimensions or link form unavailable");
        return;
    }
    const uint32_t banks = entries->Size / stride;
    if (banks == 0 || banks > 4096)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Queue dimensions exceed collection limits");
        return;
    }
    const auto singleNext = layout.Field(L"nt", L"_SINGLE_LIST_ENTRY", L"Next");
    if (!timers && (!singleNext || singleNext->Size != 8))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Single-link layout unavailable");
        return;
    }
    // Resolve the first CPU before starting the shared traversal budget.
    // Cold PDB and KD lookups must not consume the entire queue walk.
    ULONG64 firstPrcb = 0;
    const bool firstPrcbKnown = !ctx.Session.Cancelled() && ctx.Session.ReadProcessorBlock(0, &firstPrcb) &&
                                architecture.KernelPointer(firstPrcb);
    uint64_t completedQueues = 0;
    kncore::QueueReadMeter readMeter(ctx.Session);
    kncore::QueueReadCache queueReader(readMeter, budget, architecture,
        timers && (budget.Report.Consistency == L"stopped" || budget.Report.Consistency == L"dump"));
    const auto prepareDpc = [&](uint64_t object)
    {
        queueReader.PrepareRecord(kncore::QueueReadCache::Dpc, object, {dpcType, routine, context, importance});
    };
    const uint32_t banksPerRead = (std::max)(1u, static_cast<uint32_t>(kncore::QueueReadCache::MaxRead / stride));
    const auto traversalStart = std::chrono::steady_clock::now();
    budget.StartTraversal(traversalStart, std::chrono::seconds(30));
    for (ULONG cpu = 0; cpu < count && CheckCollection(ctx, budget); ++cpu)
    {
        ULONG64 prcb = firstPrcb;
        const bool prcbKnown = cpu == 0 ? firstPrcbKnown :
            ctx.Session.ReadProcessorBlock(cpu, &prcb) && architecture.KernelPointer(prcb);
        if (!prcbKnown)
        {
            UnknownScope(ctx, budget, L"CPU " + std::to_wstring(cpu), L"Processor block unavailable");
            continue;
        }
        for (uint32_t bank = 0; bank < banks && CheckCollection(ctx, budget); ++bank)
        {
            auto entry = kncore::ArrayElement(entries, bank, true);
            if (timers)
            {
                entry = kncore::NestedField(queue, entry);
            }
            const auto listField = kncore::NestedField(entry, list);
            if (!listField || !kncore::ValidRange(prcb, static_cast<uint64_t>(listField->Offset) + listField->Size))
            {
                UnknownScope(ctx, budget, L"Queue", L"Container extent mismatch");
                continue;
            }
            const uint64_t head = prcb + listField->Offset;
            const auto table = timers ? kncore::NestedField(queue, entries) : std::nullopt;
            if (table && bank % banksPerRead == 0 && stride <= kncore::QueueReadCache::MaxRead &&
                kncore::ValidRange(prcb, static_cast<uint64_t>(table->Offset) + table->Size))
            {
                const uint64_t address = prcb + table->Offset + static_cast<uint64_t>(bank) * stride;
                queueReader.Prepare(kncore::QueueReadCache::Heads, address, (std::min)(banksPerRead, banks - bank) * stride);
            }
            const auto prepareTimer = [&](uint64_t node)
            {
                if (node >= link->Offset && architecture.KernelPointer(node - link->Offset))
                {
                    queueReader.PrepareRecord(kncore::QueueReadCache::Timer, node - link->Offset,
                        {link, timerDpc, dueTime, period, signalState});
                }
            };
            auto visitor = [&](uint64_t node)
            {
                if (node < link->Offset || !architecture.KernelPointer(node - link->Offset))
                {
                    return kncore::VisitDecision::Failed;
                }
                const uint64_t object = node - link->Offset;
                const auto rawDpc = timers ? kncore::ReadField(queueReader, object, timerDpc) : std::optional<uint64_t>(object);
                std::optional<uint64_t> function;
                const auto dpc = timers ? kncore::ValidatedTimerDpc(queueReader, architecture, object, rawDpc, timerKeys, dpcType, prepareDpc) : rawDpc;
                if (!timers)
                {
                    function = kncore::ReadField(queueReader, object, routine);
                }
                else if (dpc && *dpc == 0)
                {
                    function = 0;
                }
                else if (dpc)
                {
                    function = kncore::ReadField(queueReader, *dpc, routine);
                    if (function == 0)
                    {
                        function.reset();
                    }
                }
                auto row = kncore::RoutineObservation(budget.Report, architecture, owners, timers ? L"Timer.Dpc" : L"Dpc.DeferredRoutine",
                                                      object, function, timers ? kncore::RoutinePresence::Optional : kncore::RoutinePresence::Required);
                row.Set(L"kind", knjson::Value(timers ? L"KernelTimer" : L"QueuedDpc"));
                row.Set(L"object", knjson::Value(kncore::Hex(object)));
                row.Set(L"cpu", knjson::Value(std::to_wstring(cpu)));
                row.Set(L"queue", knjson::Value(std::to_wstring(bank)));
                row.Set(L"rawDpc", kncore::OptionalNumber(rawDpc, true));
                row.Set(L"dpc", kncore::OptionalNumber(dpc, true));
                if (timers)
                {
                    const auto due = kncore::ReadField(queueReader, object, dueTime);
                    const auto interval = kncore::ReadField(queueReader, object, period);
                    const auto signal = kncore::ReadField(queueReader, object, signalState);
                    row.Set(L"dueTimeRaw", kncore::OptionalNumber(due, true));
                    row.Set(L"periodMs", kncore::OptionalNumber(interval));
                    row.Set(L"signalState", kncore::OptionalNumber(signal));
                    if (!due || !interval || !signal)
                    {
                        ++budget.Report.Collected.Unknown;
                    }
                }
                if (dpc && *dpc != 0)
                {
                    const auto parameter = kncore::ReadField(queueReader, *dpc, context);
                    const auto priority = kncore::ReadField(queueReader, *dpc, importance);
                    row.Set(L"deferredContext", kncore::OptionalNumber(parameter, true));
                    row.Set(L"importance", kncore::OptionalNumber(priority));
                    if (!parameter || !priority)
                    {
                        ++budget.Report.Collected.Unknown;
                    }
                }
                if (timers)
                {
                    row.Set(L"decode", knjson::Value(!timerKeys ? L"Timer DPC profile or keys unavailable" :
                        !dpc ? L"Encoded DPC unavailable or invalid" : *dpc == 0 ? L"Verified encoded NULL DPC" : L"Verified encoded DPC"));
                    row.Set(L"decoderProfile", timerKeys ? knjson::Value(kncore::KernelSymbolProfile28000Id) : knjson::Value());
                }
                if (budget.Stopped)
                {
                    return kncore::VisitDecision::Failed;
                }
                EmitRow(ctx, budget, row);
                return kncore::VisitDecision::Continue;
            };
            if (timers)
            {
                if (kncore::WalkList(queueReader, head, architecture, budget, visitor, prepareTimer))
                {
                    ++completedQueues;
                }
            }
            else
            {
                uint64_t first = 0;
                if (!queueReader.ReadExact(kncore::AddressSpace::Virtual, head, &first))
                {
                    ++budget.Report.Collected.Unreadable;
                    continue;
                }
                if (kncore::WalkChain(queueReader, first, 0, singleNext->Offset, architecture, budget, visitor))
                {
                    ++completedQueues;
                }
            }
        }
    }
    budget.Report.Limitations.Push(
        knjson::Value(L"Queues are transient; completed/active work outside these declared queues is not covered."));
    if (timers)
    {
        const bool stableKeys = !timerKeys || readKeys() == timerKeys;
        if (ctx.Session.Cancelled())
        {
            budget.Stop(kncore::Status::Cancelled, L"Cancelled");
        }
        else if (!stableKeys)
        {
            budget.Stop(kncore::Status::StaleContext, L"TimerDpcKeysChanged");
        }
        budget.Report.Limitations.Push(knjson::Value(L"DueTime is the raw kernel timer value in 100-nanosecond units, not a UTC date. "
            L"Period is in milliseconds; zero denotes a one-shot timer. DPC decoding requires the exact reviewed NT image and code."));
    }
    budget.Report.Analysis = knjson::Value::MakeObject();
    budget.Report.Analysis.Set(L"expectedQueues", knjson::Value(std::to_wstring(static_cast<uint64_t>(count) * banks)));
    budget.Report.Analysis.Set(L"completedQueues", knjson::Value(std::to_wstring(completedQueues)));
    budget.Report.Analysis.Set(L"readRequests", knjson::Value(std::to_wstring(readMeter.Requests)));
    budget.Report.Analysis.Set(L"requestedBytes", knjson::Value(std::to_wstring(readMeter.Bytes)));
    budget.Report.Analysis.Set(L"cachedReads", knjson::Value(std::to_wstring(queueReader.CacheHits)));
    budget.Report.Analysis.Set(L"readMilliseconds", knjson::Value(std::to_wstring(
        std::chrono::duration_cast<std::chrono::milliseconds>(readMeter.Elapsed).count())));
    budget.Report.Analysis.Set(L"traversalMilliseconds", knjson::Value(std::to_wstring(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - traversalStart).count())));
    FinishCollection(ctx, budget);
}
} // namespace

void ScanDpc(Ctx &ctx)
{
    CpuQueues(ctx, false);
}

void ScanTimer(Ctx &ctx)
{
    CpuQueues(ctx, true);
}

// ---- !alpc ports ----

void ScanAlpc(Ctx &ctx)
{
    const auto setupStart = std::chrono::steady_clock::now();
    CollectorWalk collection;
    knengine::ObjectDirectoryWalker walker(ctx.Session);
    knengine::LayoutResolver layout(ctx.Session);
    kncore::TargetArchitecture architecture;
    unsigned typeIndex = 0;
    if (!KernelArchitecture(ctx.Session, &architecture) || !walker.Initialize() ||
        !walker.ResolveTypeIndex(L"ALPC Port", &typeIndex, L"AlpcPortObjectType"))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"ALPC object namespace/type unavailable");
        return;
    }
    const auto ownerField = layout.Field(L"nt", L"_ALPC_PORT", L"OwnerProcess");
    const auto connectionField = layout.Field(L"nt", L"_ALPC_PORT", L"ConnectionPort");
    const auto communicationField = layout.Field(L"nt", L"_ALPC_PORT", L"CommunicationInfo");
    const auto indirectConnection = layout.Field(L"nt", L"_ALPC_COMMUNICATION_INFO", L"ConnectionPort");
    const bool allowIndirect = !connectionField && layout.CanProfileField(L"nt", L"_ALPC_PORT", L"ConnectionPort");
    std::vector<ProcRow> processes;
    CmdText processReport;
    const auto inventoryStart = std::chrono::steady_clock::now();
    CollectProcesses(ctx.Session, layout, &processes, processReport);
    const auto inventoryElapsed = std::chrono::steady_clock::now() - inventoryStart;
    if (layout.VerifyProfile(kncore::KernelLayoutFamily::AlpcPorts) &&
        layout.VerifyProfile(kncore::KernelLayoutFamily::ObjectTypes) && layout.VerifyProfile(kncore::KernelLayoutFamily::ObjectNames))
    {
        kncore::WalkBudget budget;
        if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:AlpcpPortList"))
        {
            return;
        }
        kncore::AlpcPortLayout fields;
        fields.Names = knengine::ResolveNamespaceLayout(layout);
        fields.Links = layout.Field(L"nt", L"_ALPC_PORT", L"PortListEntry");
        fields.Communication = communicationField;
        fields.Owner = ownerField;
        fields.State = layout.Field(L"nt", L"_ALPC_PORT", L"u1.State");
        fields.Initialized = layout.Field(L"nt", L"_ALPC_PORT", L"u1.s1.Initialized");
        fields.Type = layout.Field(L"nt", L"_ALPC_PORT", L"u1.s1.Type");
        fields.Connection = indirectConnection;
        fields.Server = layout.Field(L"nt", L"_ALPC_COMMUNICATION_INFO", L"ServerCommunicationPort");
        fields.Client = layout.Field(L"nt", L"_ALPC_COMMUNICATION_INFO", L"ClientCommunicationPort");
        const auto head = layout.Address(L"nt", L"AlpcpPortList");
        const auto rootAddress = layout.Address(L"nt", L"ObpRootDirectoryObject");
        const auto cookie = layout.Address(L"nt", L"ObHeaderCookie");
        const auto offsets = layout.Address(L"nt", L"ObpInfoMaskToOffset");
        const auto headShape = layout.Symbol(L"nt", L"AlpcpPortList");
        const bool listStorage = headShape ? kncore::PiddbFieldMatches(headShape, 0, 16, kncore::FieldKind::Composite)
                                          : layout.PublicOnlySymbol(L"nt", L"AlpcpPortList");
        uint64_t root = 0;
        unsigned directoryType = 0;
        if (!head || !rootAddress || !cookie || !offsets || !listStorage ||
            !walker.ResolveTypeIndex(L"Directory", &directoryType, L"ObpDirectoryObjectType") ||
            !ctx.Session.ReadExact(kncore::AddressSpace::Virtual, *rootAddress, &root))
        {
            budget.Stop(ctx.Session.Cancelled() ? kncore::Status::Cancelled : kncore::Status::Unavailable,
                        ctx.Session.Cancelled() ? L"Cancelled" : L"AlpcPortSymbolsUnavailable");
        }
        else
        {
            std::map<uint64_t, const ProcRow *> owners;
            for (const auto &process : processes)
            {
                owners[process.Eprocess] = &process;
            }
            kncore::NamespaceReadMeter measured(ctx.Session);
            const auto setupElapsed = std::chrono::steady_clock::now() - setupStart;
            kncore::CollectAlpcPorts(measured, architecture, fields, *head, root, *cookie, *offsets, typeIndex, directoryType, budget,
                [&](knjson::Value row)
                {
                    uint64_t ownerAddress = 0;
                    kncore::ParseUnsigned(row.Get(L"ownerProcess").AsString(L""), 16, &ownerAddress);
                    const auto owner = owners.find(ownerAddress);
                    row.Set(L"owner", owner != owners.end() ? owner->second->ToJson() : knjson::Value());
                    if (owner == owners.end() || !owner->second->PidKnown || !owner->second->ImageKnown)
                    {
                        ++budget.Report.Collected.Unknown;
                    }
                    EmitRow(ctx, budget, row);
                });
            budget.Report.Analysis.Set(L"portTargetReads", knjson::Value(std::to_wstring(measured.Requests)));
            budget.Report.Analysis.Set(L"portRequestedBytes", knjson::Value(std::to_wstring(measured.Bytes)));
            budget.Report.Analysis.Set(L"portReadElapsedMs", knjson::Value(std::to_wstring(
                std::chrono::duration_cast<std::chrono::milliseconds>(measured.Elapsed).count())));
            budget.Report.Analysis.Set(L"portReadLatency", measured.Latency.ToJson());
            budget.Report.Analysis.Set(L"setupElapsedMs", knjson::Value(std::to_wstring(
                std::chrono::duration_cast<std::chrono::milliseconds>(setupElapsed).count())));
            budget.Report.Analysis.Set(L"processInventoryElapsedMs", knjson::Value(std::to_wstring(
                std::chrono::duration_cast<std::chrono::milliseconds>(inventoryElapsed).count())));
            kncore::AttachAlpcConnectionNames(budget.Report);
        }
        budget.Report.Limitations.Push(knjson::Value(L"Initialized ports linked in AlpcpPortList only; detached, freed and not-yet-linked "
            L"objects are outside this collection. Names follow verified parent directories, at most 32 components and 4096 directories. "
            L"Blocking debugger calls can exceed the shared 180-second traversal bound."));
        FinishCollection(ctx, budget);
        return;
    }
    knjson::Value rows = knjson::Value::MakeArray();
    uint64_t unknown = 0;
    std::wstring error;
    walker.VisitNamespace(
        [&](ULONG64 body, unsigned type, int depth, const std::wstring &path)
        {
            if (type != typeIndex)
            {
                return true;
            }
            auto row = knjson::Value::MakeObject();
            row.Set(L"kind", knjson::Value(L"AlpcPort"));
            row.Set(L"address", knjson::Value(kncore::Hex(body)));
            row.Set(L"name", path.empty() ? knjson::Value() : knjson::Value(path));
            row.Set(L"nameState", knjson::Value(path.empty() ? L"Unknown" : L"Named"));
            row.Set(L"source", knjson::Value(L"ObjectNamespace"));
            row.Set(L"depth", knjson::Value(std::to_wstring(depth)));
            const auto owner = kncore::ReadField(ctx.Session, body, ownerField);
            const auto connection =
                connectionField ? kncore::ReadField(ctx.Session, body, connectionField)
                : allowIndirect ? kncore::ReadIndirectKernelPointer(ctx.Session, architecture, body, communicationField, indirectConnection)
                                : std::nullopt;
            row.Set(L"ownerProcess", kncore::OptionalNumber(owner, true));
            row.Set(L"connectionPort", kncore::OptionalNumber(connection, true));
            knjson::Value process;
            if (owner)
            {
                for (const auto &candidate : processes)
                {
                    if (candidate.Eprocess == *owner)
                    {
                        process = candidate.ToJson();
                        break;
                    }
                }
            }
            row.Set(L"owner", process);
            if (path.empty() || !owner || !connection || (*connection != 0 && !architecture.KernelPointer(*connection)) || process.IsNull())
            {
                ++unknown;
            }
            rows.Push(row);
            if (rows.Items().size() <= 256)
            {
                const std::wstring image = process.IsNull() ? L"Unknown" : process.Get(L"image").AsString(L"Unknown");
                const std::wstring pid = process.IsNull() ? L"?" : process.Get(L"pid").AsString(L"?");
                ctx.Out.AddLine(L"[alpc] name=" + path + L" address=" + kncore::Hex(body) + L" owner=" + image + L" pid=" + pid);
            }
            return !ctx.Session.Cancelled();
        },
        typeIndex, 16, &error);
    const auto command = ctx.Out.Details.CommandId;
    ctx.Out.Details = walker.Report();
    ctx.Out.Details.CommandId = command;
    ctx.Out.Details.Rows = rows;
    ctx.Out.Details.Collected.Unknown += unknown;
    ++ctx.Out.Details.Collected.Unknown;
    auto gap = knjson::Value::MakeObject();
    gap.Set(L"kind", knjson::Value(L"CoverageGap"));
    gap.Set(L"scope", knjson::Value(L"UnnamedAlpcPorts"));
    gap.Set(L"reason", knjson::Value(L"Reviewed global ALPC port-list profile unavailable; only named namespace ports were collected"));
    ctx.Out.Details.Rows.Push(gap);
    ctx.Out.Details.Limitations.Push(
        knjson::Value(L"Root object namespace hash buckets only, depth 16; unnamed ports, private namespaces and shadow directories "
                       L"are outside this enumeration."));
    if (ctx.Out.Details.Collected.Unknown != 0 && ctx.Out.Details.State == kncore::Status::Success)
    {
        ctx.Out.Details.State = kncore::Status::Partial;
        ctx.Out.Details.Collected.Complete = false;
    }
}

namespace
{
class MappedImageReader final : public kncore::ByteReader
{
  public:
    MappedImageReader(knengine::DbgSession &session, uint64_t base, uint32_t size) : session_(session), base_(base), size_(size)
    {
    }
    uint64_t Size() const override
    {
        return size_;
    }
    bool Read(uint64_t offset, std::span<unsigned char> bytes) override
    {
        if (!kncore::Contains(size_, offset, bytes.size()) || !kncore::ValidRange(base_, offset + bytes.size()))
        {
            return false;
        }
        const auto read = session_.Read(kncore::AddressSpace::Virtual, base_ + offset, bytes.size());
        if (!kncore::ExactBytes(read, bytes.size()))
        {
            return false;
        }
        std::copy(read.Bytes.begin(), read.Bytes.end(), bytes.begin());
        return true;
    }

  private:
    knengine::DbgSession &session_;
    uint64_t base_;
    uint32_t size_;
};
} // namespace

void ScanModuleIntegrity(Ctx &ctx)
{
    bool disk = false;
    std::wstring selector;
    for (size_t index = 1; index < ctx.Args.size(); ++index)
    {
        if (_wcsicmp(ctx.Args[index].c_str(), L"/disk") == 0)
        {
            disk = true;
        }
        else
        {
            selector = ctx.Args[index];
        }
    }
    if (disk && !SessionIsLocalLiveKernel(ctx.Session))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"/disk requires a verified local kernel target");
        return;
    }
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:ModulePe"))
    {
        return;
    }
    std::vector<knengine::KernelModuleInfo> modules;
    kncore::Result inventory;
    if (!knengine::EnumerateKernelModules(ctx.Session, &modules, &inventory))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Module inventory unavailable", inventory.Error);
        return;
    }
    budget.Report.Collected.Expected = modules.size();
    bool selected = false;
    for (const auto &module : modules)
    {
        if (!selector.empty() && _wcsicmp(selector.c_str(), module.ModuleName.c_str()) != 0)
        {
            continue;
        }
        selected = true;
        if (!CheckCollection(ctx, budget))
        {
            break;
        }
        ++budget.Report.Collected.Visited;
        MappedImageReader memory(ctx.Session, module.Base, module.Size);
        std::vector<unsigned char> headers(std::min<uint32_t>(module.Size, 65536));
        // Parse a bounded header window; the fallback may be partial on sparse images.
        std::vector<unsigned char> first(std::min<uint32_t>(module.Size, 4096));
        kncore::PeImage image;
        bool parsed = memory.Read(0, first) && bool(kncore::ParsePeHeaders(first, &image));
        if (!parsed)
        {
            parsed = memory.Read(0, headers) && bool(kncore::ParsePeHeaders(headers, &image));
        }
        if (!parsed || image.ImageSize != module.Size || image.File.TimeDateStamp != module.Timestamp)
        {
            UnknownScope(ctx, budget, module.ModuleName, L"PE headers unavailable/invalid or debugger image identity differs");
            continue;
        }
        ++budget.Report.Collected.Read;
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"ModulePeObservation"));
        row.Set(L"module", knjson::Value(module.ModuleName));
        row.Set(L"base", knjson::Value(kncore::Hex(module.Base)));
        row.Set(L"timestamp", knjson::Value(kncore::Hex(image.File.TimeDateStamp)));
        row.Set(L"size", knjson::Value(std::to_wstring(image.ImageSize)));
        auto sections = knjson::Value::MakeArray();
        for (const auto &section : image.Sections)
        {
            auto item = knjson::Value::MakeObject();
            item.Set(L"name", knjson::Value(kncore::DecodeMemoryString(section.Name, false).Text));
            item.Set(L"rva", knjson::Value(kncore::Hex(section.VirtualAddress)));
            item.Set(L"size", knjson::Value(std::to_wstring(section.Misc.VirtualSize)));
            item.Set(L"staticWritable", knjson::Value((section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0));
            item.Set(L"staticExecutable", knjson::Value((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0));
            sections.Push(item);
        }
        row.Set(L"sections", sections);
        if (disk)
        {
            knutil::FileReader file(module.ImageName);
            std::vector<unsigned char> diskHeaders(static_cast<size_t>(std::min<uint64_t>(65536, file.Size())));
            kncore::PeImage diskImage;
            const bool match = file.IsOpen() && file.Read(0, diskHeaders) &&
                               bool(kncore::ParsePeHeaders(diskHeaders, &diskImage, file.Size())) &&
                               kncore::SamePeIdentity(image, diskImage, kncore::CodeViewIdentity(memory, image, true),
                                                      kncore::CodeViewIdentity(file, diskImage, false));
            row.Set(L"diskIdentityMatches", knjson::Value(match));
            row.Set(L"diskPath", knjson::Value(module.ImageName));
            auto samples = knjson::Value::MakeArray();
            if (match)
            {
                for (const auto &section : diskImage.Sections)
                {
                    if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 || section.SizeOfRawData == 0 ||
                        !CheckCollection(ctx, budget))
                    {
                        continue;
                    }
                    const size_t length = std::min<uint32_t>(4096, std::min(section.SizeOfRawData, section.Misc.VirtualSize));
                    std::vector<unsigned char> a(length), b(length);
                    auto sample = knjson::Value::MakeObject();
                    sample.Set(L"rva", knjson::Value(kncore::Hex(section.VirtualAddress)));
                    sample.Set(L"requestedBytes", knjson::Value(std::to_wstring(length)));
                    const bool read = length != 0 && memory.Read(section.VirtualAddress, a) && file.Read(section.PointerToRawData, b);
                    sample.Set(L"equalRawBytes", read ? knjson::Value(a == b) : knjson::Value());
                    if (!read)
                    {
                        ++budget.Report.Collected.Unreadable;
                    }
                    samples.Push(sample);
                }
            }
            else
            {
                ++budget.Report.Collected.Unknown;
            }
            row.Set(L"diskSamples", samples);
        }
        EmitRow(ctx, budget, row);
    }
    if (!selected)
    {
        budget.Stop(kncore::Status::Unavailable, L"ModuleSelectorNotFound");
    }
    budget.Report.Limitations.Push(
        knjson::Value(L"PE section flags are static metadata. Disk comparison requires timestamp/size/machine/PDB identity, samples the "
                      L"first 4096 bytes per executable section, and does not normalize relocations, hotpatches or discardable pages. Byte "
                      L"differences are not integrity verdicts."));
    FinishCollection(ctx, budget);
}

void ScanMinifilters(Ctx &ctx)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:FltGlobals.FrameList"))
    {
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    const auto globals = SymbolAddress(ctx.Session, layout, L"fltmgr", L"FltGlobals");
    auto frames = layout.Field(L"fltmgr", L"_GLOBALS", L"FrameList");
    if (!frames)
    {
        frames = layout.Field(L"fltmgr", L"_FLT_GLOBALS", L"FrameList");
    }
    const auto list = layout.Field(L"fltmgr", L"_FLT_RESOURCE_LIST_HEAD", L"rList");
    auto frameLink = layout.Field(L"fltmgr", L"_FLTP_FRAME", L"Links");
    auto filters = layout.Field(L"fltmgr", L"_FLTP_FRAME", L"RegisteredFilters");
    if (!frameLink && !filters && layout.CanProfileField(L"fltmgr", L"_FLTP_FRAME", L"Links") &&
        layout.CanProfileField(L"fltmgr", L"_FLTP_FRAME", L"RegisteredFilters"))
    {
        frameLink = layout.Field(L"fltmgr", L"_FLT_FRAME", L"Links");
        filters = layout.Field(L"fltmgr", L"_FLT_FRAME", L"RegisteredFilters");
    }
    const auto frameHead = kncore::NestedField(frames, list);
    const auto filterHead = kncore::NestedField(filters, list);
    const auto filterLink =
        kncore::NestedField(layout.Field(L"fltmgr", L"_FLT_FILTER", L"Base"), layout.Field(L"fltmgr", L"_FLT_OBJECT", L"PrimaryLink"));
    const auto nameField = layout.Field(L"fltmgr", L"_FLT_FILTER", L"Name");
    const auto altitudeField = layout.Field(L"fltmgr", L"_FLT_FILTER", L"DefaultAltitude");
    const auto operations = layout.Field(L"fltmgr", L"_FLT_FILTER", L"Operations");
    const auto major = layout.Field(L"fltmgr", L"_FLT_OPERATION_REGISTRATION", L"MajorFunction");
    const auto pre = layout.Field(L"fltmgr", L"_FLT_OPERATION_REGISTRATION", L"PreOperation");
    const auto post = layout.Field(L"fltmgr", L"_FLT_OPERATION_REGISTRATION", L"PostOperation");
    ULONG operationSize = 0;
    const bool operationLayout = layout.TypeSize(L"fltmgr", L"_FLT_OPERATION_REGISTRATION", &operationSize) && operationSize <= 256 &&
                                 major && major->Size == 1 && pre && pre->Size == 8 && post && post->Size == 8;
    if (!globals || !frameHead || frameHead->Size != 16 || !frameLink || frameLink->Size != 16 || !filterHead || filterHead->Size != 16 ||
        !filterLink || filterLink->Size != 16 || !kncore::ValidRange(*globals, static_cast<uint64_t>(frameHead->Offset) + frameHead->Size))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Matched fltmgr frame/filter list layouts unavailable");
        return;
    }
    if (const auto identity = layout.Identity(L"fltmgr"))
    {
        budget.Report.LayoutProfile = identity->Key();
    }
    const auto owners = knengine::CollectOwnershipIndex(ctx.Session);
    kncore::StartMinifilterTraversal(budget);
    kncore::WalkList(
        ctx.Session, *globals + frameHead->Offset, architecture, budget,
        [&](uint64_t frameEntry)
        {
            if (frameEntry < frameLink->Offset)
            {
                return kncore::VisitDecision::Failed;
            }
            const auto frame = frameEntry - frameLink->Offset;
            if (!kncore::ValidRange(frame, static_cast<uint64_t>(filterHead->Offset) + filterHead->Size))
            {
                return kncore::VisitDecision::Failed;
            }
            kncore::WalkList(
                ctx.Session, frame + filterHead->Offset, architecture, budget,
                [&](uint64_t filterEntry)
                {
                    if (filterEntry < filterLink->Offset)
                    {
                        return kncore::VisitDecision::Failed;
                    }
                    const auto filter = filterEntry - filterLink->Offset;
                    auto row = knjson::Value::MakeObject();
                    row.Set(L"kind", knjson::Value(L"Minifilter"));
                    row.Set(L"object", knjson::Value(kncore::Hex(filter)));
                    row.Set(L"frame", knjson::Value(kncore::Hex(frame)));
                    for (const auto &named : {std::pair(L"name", nameField), std::pair(L"altitude", altitudeField)})
                    {
                        std::wstring text;
                        const bool known = named.second &&
                                           kncore::ValidRange(filter, static_cast<uint64_t>(named.second->Offset) + named.second->Size) &&
                                           ReadUnicodeString(ctx.Session, layout, filter + named.second->Offset, &text);
                        row.Set(named.first, known ? knjson::Value(text) : knjson::Value());
                        if (!known)
                        {
                            ++budget.Report.Collected.Unknown;
                        }
                    }
                    EmitRow(ctx, budget, row);
                    const auto operationArray = kncore::ReadField(ctx.Session, filter, operations);
                    if (!operationLayout || !operationArray || (*operationArray != 0 && !architecture.KernelPointer(*operationArray)))
                    {
                        UnknownScope(ctx, budget, L"Minifilter operations", L"Registration layout or pointer unavailable");
                        return kncore::VisitDecision::Continue;
                    }
                    if (*operationArray == 0)
                    {
                        return kncore::VisitDecision::Continue;
                    }
                    bool terminated = false;
                    for (uint32_t i = 0; i < 256 && CheckCollection(ctx, budget); ++i)
                    {
                        if (!kncore::ValidRange(*operationArray, static_cast<uint64_t>(i + 1) * operationSize))
                        {
                            break;
                        }
                        const auto operation = *operationArray + static_cast<uint64_t>(i) * operationSize;
                        const auto mj = kncore::ReadField(ctx.Session, operation, major);
                        if (!mj)
                        {
                            ++budget.Report.Collected.Unreadable;
                            break;
                        }
                        if (*mj == 0x80)
                        {
                            terminated = true;
                            break;
                        }
                        ++budget.Report.Collected.Visited;
                        for (const auto &slot : {std::pair(L"Minifilter.PreOperation", pre), std::pair(L"Minifilter.PostOperation", post)})
                        {
                            auto callback = kncore::RoutineObservation(budget.Report, architecture, owners, slot.first, operation,
                                                                       kncore::ReadField(ctx.Session, operation, slot.second),
                                                                       kncore::RoutinePresence::Optional);
                            callback.Set(L"filter", knjson::Value(kncore::Hex(filter)));
                            callback.Set(L"major", kncore::OptionalNumber(mj));
                            callback.Set(L"majorName", knjson::Value(kncore::MinifilterMajorName(static_cast<unsigned>(*mj))));
                            EmitRow(ctx, budget, callback);
                        }
                    }
                    if (!terminated)
                    {
                        UnknownScope(ctx, budget, L"Minifilter operations", L"No readable IRP_MJ_OPERATION_END within budget");
                    }
                    return kncore::VisitDecision::Continue;
                });
            return budget.Stopped ? kncore::VisitDecision::Failed : kncore::VisitDecision::Continue;
        });
    FinishCollection(ctx, budget);
}
} // namespace kncmd
