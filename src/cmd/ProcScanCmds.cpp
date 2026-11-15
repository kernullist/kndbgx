#include "CollectorSupport.h"
#include "CommandSpec.h"
#include <dbgeng.h>
#include "../core/Vad.h"
#include "../core/ProcessViews.h"
#include "../core/HandleTable.h"
#include "../engine/ObjectDirectory.h"
#include "../engine/PageWalk.h"
#include <tlhelp32.h>

namespace kncmd
{
namespace
{
bool TargetProcess(Ctx &ctx, knengine::LayoutResolver &layout, ProcRow &target)
{
    const auto selector = ctx.Request != nullptr && !ctx.Request->Positionals.empty() ? ctx.Request->Positionals.front() : L"";
    return ResolveSelectedProcess(ctx, layout, selector, target);
}

std::vector<uint32_t> ProtectionTable(knengine::DbgSession &session, knengine::LayoutResolver &layout)
{
    const auto address = layout.Address(L"nt", L"MmProtectToValue");
    const auto shape = layout.Symbol(L"nt", L"MmProtectToValue");
    std::vector<uint32_t> table;
    const bool shaped = shape && shape->Kind == kncore::FieldKind::Array && shape->ArrayCount == 32u &&
                        shape->ElementSize == 4u && shape->Size == 128 && shape->ValidFor(shape->Size);
    if (address && (!shape || shaped) && kncore::ValidRange(*address, 128))
    {
        const auto read = session.Read(kncore::AddressSpace::Virtual, *address, 128);
        if (kncore::ExactBytes(read, 128))
        {
            table.resize(32);
            std::memcpy(table.data(), read.Bytes.data(), 128);
            // Public PDBs can omit the array type. Verify every observed entry.
            if (!kncore::ValidProtectionTable(table))
            {
                table.clear();
            }
        }
    }
    return table;
}

bool QueryExtendedHandles(knengine::DbgSession &session, std::vector<kncore::HandleEntry> &entries, kncore::NativeError &error)
{
    using QueryFn = LONG(NTAPI *)(ULONG, void *, ULONG, ULONG *);
    auto query = reinterpret_cast<QueryFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    error = {L"NTSTATUS", 0, L"SystemExtendedHandleInformation", L"Host handle query unavailable"};
    if (query == nullptr)
    {
        return false;
    }
    ULONG size = 1024 * 1024;
    for (unsigned attempt = 0; attempt < 12 && size <= 160 * 1024 * 1024 && !session.Cancelled(); ++attempt)
    {
        std::vector<unsigned char> bytes(size);
        ULONG returned = 0;
        const LONG status = query(64, bytes.data(), size, &returned);
        error.Code = static_cast<uint32_t>(status);
        if (status == 0)
        {
            if (returned < 16 || returned > size || !kncore::ParseExtendedHandles64(std::span(bytes.data(), returned), entries))
            {
                error.Message = L"Malformed or oversized native x64 handle snapshot";
                return false;
            }
            return true;
        }
        if (static_cast<uint32_t>(status) != 0xc0000004)
        {
            break;
        }
        size = std::max(size * 2, returned);
    }
    return false;
}

kncore::Result HostProcesses(knengine::DbgSession &session, std::vector<ProcRow> &rows)
{
    kncore::Result result;
    result.Source = L"HostToolhelp+GetProcessTimes";
    result.Consistency = L"live-nonatomic";
    result.State = kncore::Status::Unavailable;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        result.Error = {L"Win32", GetLastError(), L"CreateToolhelp32Snapshot", L"Host process view unavailable"};
        return result;
    }
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    BOOL more = Process32FirstW(snapshot, &pe);
    DWORD error = more ? ERROR_SUCCESS : GetLastError();
    while (more && rows.size() < 65536 && !session.Cancelled())
    {
        ProcRow row;
        row.Pid = pe.th32ProcessID;
        row.PidKnown = true;
        row.Image = pe.szExeFile;
        row.ImageKnown = true;
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (process != nullptr)
        {
            FILETIME create = {}, exit = {}, kernel = {}, user = {};
            if (GetProcessTimes(process, &create, &exit, &kernel, &user))
            {
                row.CreateTime = (static_cast<uint64_t>(create.dwHighDateTime) << 32) | create.dwLowDateTime;
                row.CreateTimeKnown = true;
            }
            CloseHandle(process);
        }
        rows.push_back(row);
        more = Process32NextW(snapshot, &pe);
        error = more ? ERROR_SUCCESS : GetLastError();
    }
    CloseHandle(snapshot);
    result.Collected.Visited = rows.size();
    result.Collected.Complete = !more && error == ERROR_NO_MORE_FILES;
    result.State = result.Collected.Complete ? kncore::Status::Success
                   : session.Cancelled()     ? kncore::Status::Cancelled
                                             : kncore::Status::Partial;
    result.Collected.StopReason = result.Collected.Complete ? L"ToolhelpEnd" : L"ToolhelpIncomplete";
    if (!result.Collected.Complete)
    {
        result.Error = {L"Win32", error, L"Process32NextW", L"Host process enumeration incomplete"};
    }
    return result;
}

kncore::HandleTableLayout TargetHandleLayout(knengine::LayoutResolver &layout, bool cid = false)
{
    kncore::HandleTableLayout fields;
    fields.TableCode = layout.Field(L"nt", L"_HANDLE_TABLE", L"TableCode");
    fields.NextHandle = layout.Field(L"nt", L"_HANDLE_TABLE", L"NextHandleNeedingPool");
    fields.ObjectBits = layout.Field(L"nt", L"_HANDLE_TABLE_ENTRY", L"ObjectPointerBits");
    fields.AccessBits = layout.Field(L"nt", L"_HANDLE_TABLE_ENTRY", L"GrantedAccessBits");
    const auto entry = layout.Describe(L"nt", L"_HANDLE_TABLE_ENTRY");
    const auto body = layout.Field(L"nt", L"_OBJECT_HEADER", L"Body");
    fields.EntrySize = entry ? entry->Size : 0;
    fields.BodyOffset = !cid && body ? body->Offset : 0;
    fields.CidTable = cid;
    return fields;
}

class TargetObjectTypes
{
  public:
    bool Initialize(Ctx &ctx, knengine::LayoutResolver &layout, unsigned processType)
    {
        const auto body = layout.Field(L"nt", L"_OBJECT_HEADER", L"Body");
        const auto index = layout.Field(L"nt", L"_OBJECT_HEADER", L"TypeIndex");
        const auto cookie = layout.Address(L"nt", L"ObHeaderCookie");
        const auto system = layout.Address(L"nt", L"PsInitialSystemProcess");
        uint64_t process = 0;
        if (!body || !index || index->Size != 1 || index->Offset >= body->Offset || body->Offset > 256 || !cookie || !system ||
            !ctx.Session.ReadExact(kncore::AddressSpace::Virtual, *cookie, &cookie_) ||
            !ctx.Session.ReadExact(kncore::AddressSpace::Virtual, *system, &process))
        {
            return false;
        }
        bodyOffset_ = body->Offset;
        indexOffset_ = index->Offset;
        return Read(ctx, process) == processType;
    }

    unsigned Read(Ctx &ctx, uint64_t body) const
    {
        unsigned char raw = 0;
        if (body < bodyOffset_ || !kncore::ValidRange(body - bodyOffset_, indexOffset_ + 1) ||
            !ctx.Session.ReadExact(kncore::AddressSpace::Virtual, body - bodyOffset_ + indexOffset_, &raw))
        {
            return UINT32_MAX;
        }
        return static_cast<unsigned char>(raw ^ cookie_ ^ ((body - bodyOffset_) >> 8));
    }

  private:
    uint32_t bodyOffset_ = 0;
    uint32_t indexOffset_ = 0;
    unsigned char cookie_ = 0;
};

kncore::Result TargetCidProcesses(Ctx &ctx, knengine::LayoutResolver &layout, std::vector<ProcRow> &rows)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:PspCidTable"))
    {
        return ctx.Out.Details;
    }
    const auto symbol = layout.Address(L"nt", L"PspCidTable");
    uint64_t table = 0;
    knengine::ObjectDirectoryWalker objects(ctx.Session);
    unsigned processType = UINT32_MAX;
    const auto handles = TargetHandleLayout(layout, true);
    const auto processFields = ResolveProcessLayout(layout);
    TargetObjectTypes types;
    if (!symbol || !ctx.Session.ReadExact(kncore::AddressSpace::Virtual, *symbol, &table) ||
        !handles.Valid() || !objects.ResolveTypeIndex(L"Process", &processType) || !types.Initialize(ctx, layout, processType))
    {
        budget.Stop(kncore::Status::Unavailable, L"CidTableLayoutOrProcessTypeUnavailable");
        return budget.Report;
    }
    const auto systemSymbol = layout.Address(L"nt", L"PsInitialSystemProcess");
    uint64_t systemProcess = 0;
    if (!systemSymbol || !ctx.Session.ReadExact(kncore::AddressSpace::Virtual, *systemSymbol, &systemProcess) ||
        !architecture.KernelPointer(systemProcess))
    {
        budget.Stop(kncore::Status::Unavailable, L"SystemProcessCorroborationUnavailable");
        return budget.Report;
    }
    bool systemMatched = false;
    kncore::ProcessRecordReader processReader(ctx.Session, processFields, budget);
    // Serial KD can require thousands of object-header round trips.
    budget.StartTraversal(std::chrono::steady_clock::now(), std::chrono::seconds(120));
    kncore::WalkTargetHandleTable(ctx.Session, table, handles, architecture, budget,
        [&](const kncore::TargetHandleEntry &entry)
        {
            const unsigned type = types.Read(ctx, entry.Object);
            if (type == UINT32_MAX)
            {
                ++budget.Report.Collected.Unknown;
            }
            else if (type == processType)
            {
                ProcRow process;
                processReader.Prepare(entry.Object);
                const bool complete = kncore::ReadProcess(processReader, entry.Object, processFields, process);
                if (!complete || process.Pid != entry.Handle)
                {
                    ++budget.Report.Collected.Unknown;
                }
                if (process.PidKnown && process.Pid == entry.Handle)
                {
                    rows.push_back(process);
                    ++budget.Report.Collected.Classified;
                    systemMatched = systemMatched || (entry.Handle == 4 && entry.Object == systemProcess);
                }
            }
            return !budget.Stopped;
        });
    if (!systemMatched && (budget.Report.State == kncore::Status::Success || budget.Report.State == kncore::Status::Partial ||
                           budget.Report.State == kncore::Status::Unavailable))
    {
        rows.clear();
        budget.Stop(kncore::Status::Unavailable, L"CidSystemProcessCorroborationFailed");
    }
    if (!budget.Stopped && budget.Report.Collected.Unknown != 0)
    {
        budget.Stop(kncore::Status::Partial, L"CidObjectIdentityUnavailable");
    }
    budget.Complete();
    return budget.Report;
}

void ScanTargetHandles(Ctx &ctx, std::optional<uint64_t> ownerFilter, std::optional<uint64_t> targetFilter)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:ProcessHandleTables"))
    {
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    const auto handles = TargetHandleLayout(layout);
    const auto objectTable = layout.Field(L"nt", L"_EPROCESS", L"ObjectTable");
    const auto tablePid = layout.Field(L"nt", L"_HANDLE_TABLE", L"UniqueProcessId");
    knengine::ObjectDirectoryWalker objects(ctx.Session);
    unsigned processType = UINT32_MAX;
    TargetObjectTypes types;
    if (!handles.Valid() || !objectTable || objectTable->Kind != kncore::FieldKind::Pointer || objectTable->Size != 8 ||
        !tablePid || tablePid->Size != 4 || !objects.ResolveTypeIndex(L"Process", &processType) ||
        !types.Initialize(ctx, layout, processType))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Matched target handle-table layout or Process object type unavailable");
        return;
    }
    std::vector<ProcRow> owners;
    CmdText inventory;
    CollectProcesses(ctx.Session, layout, &owners, inventory);
    if (inventory.Details.State != kncore::Status::Success && inventory.Details.State != kncore::Status::Partial)
    {
        ReportProcessSelectionFailure(inventory, ctx.Out);
        return;
    }
    if (!inventory.Details.Collected.Complete)
    {
        UnknownScope(ctx, budget, L"HandleOwners", L"The active process inventory is incomplete");
    }
    const auto processFields = ResolveProcessLayout(layout);
    struct ObjectIdentity
    {
        unsigned Type = UINT32_MAX;
        ProcRow Process;
    };
    std::map<uint64_t, ObjectIdentity> targets;
    budget.MaxNodes = 1024 * 1024;
    budget.StartTraversal(std::chrono::steady_clock::now(), std::chrono::seconds(30));
    bool ownerFound = false;
    for (const auto &owner : owners)
    {
        if (ownerFilter && (!owner.PidKnown || owner.Pid != *ownerFilter))
        {
            continue;
        }
        ownerFound = true;
        if (!CheckCollection(ctx, budget))
        {
            break;
        }
        const auto table = kncore::ReadField(ctx.Session, owner.Eprocess, objectTable);
        const auto pid = table && architecture.KernelPointer(*table) ? kncore::ReadField(ctx.Session, *table, tablePid) : std::nullopt;
        if (!owner.PidKnown || !pid || *pid != owner.Pid)
        {
            UnknownScope(ctx, budget, L"HandleTable", L"Process handle table or owner identity unavailable");
            continue;
        }
        kncore::WalkTargetHandleTable(ctx.Session, *table, handles, architecture, budget,
            [&](const kncore::TargetHandleEntry &entry)
            {
                if ((entry.Access & 0x38) == 0)
                {
                    return true;
                }
                auto found = targets.find(entry.Object);
                if (found == targets.end())
                {
                    ObjectIdentity identity;
                    identity.Type = types.Read(ctx, entry.Object);
                    if (identity.Type == processType)
                    {
                        kncore::ProcessRecordReader reader(ctx.Session, processFields, budget);
                        reader.Prepare(entry.Object);
                        kncore::ReadProcess(reader, entry.Object, processFields, identity.Process);
                    }
                    found = targets.emplace(entry.Object, identity).first;
                }
                const auto &identity = found->second;
                if (identity.Type == UINT32_MAX)
                {
                    ++budget.Report.Collected.Unknown;
                    return true;
                }
                if (identity.Type != processType)
                {
                    return true;
                }
                const auto &target = identity.Process;
                const auto targetPid = target.PidKnown ? std::optional<uint64_t>(target.Pid) : std::nullopt;
                if (!targetPid || !target.CreateTimeKnown)
                {
                    ++budget.Report.Collected.Unknown;
                }
                const kncore::HandleEntry observed{entry.Object, owner.Pid, entry.Handle, entry.Access, static_cast<uint16_t>(processType)};
                if (!kncore::HandleMatches(observed, targetPid, ownerFilter, targetFilter))
                {
                    return true;
                }
                if (budget.Report.Rows.Items().size() >= 65536)
                {
                    return budget.Stop(kncore::Status::Partial, L"HandleResultBudget");
                }
                auto row = knjson::Value::MakeObject();
                row.Set(L"kind", knjson::Value(L"ProcessHandle"));
                row.Set(L"ownerPid", knjson::Value(std::to_wstring(owner.Pid)));
                row.Set(L"targetPid", kncore::OptionalNumber(targetPid));
                row.Set(L"targetCreateTime", target.CreateTimeKnown ? knjson::Value(std::to_wstring(target.CreateTime)) : knjson::Value());
                row.Set(L"handle", knjson::Value(kncore::Hex(entry.Handle)));
                row.Set(L"object", knjson::Value(kncore::Hex(entry.Object)));
                row.Set(L"typeIndex", knjson::Value(std::to_wstring(processType)));
                row.Set(L"grantedAccess", knjson::Value(kncore::Hex(entry.Access)));
                row.Set(L"crossProcess", targetPid ? knjson::Value(*targetPid != owner.Pid) : knjson::Value());
                EmitRow(ctx, budget, row, 50);
                ++budget.Report.Collected.Classified;
                return !budget.Stopped;
            });
        if (budget.Stopped)
        {
            if ((budget.Report.State != kncore::Status::Partial && budget.Report.State != kncore::Status::Unavailable) ||
                budget.Report.Collected.StopReason == L"HandleTableBudget" ||
                budget.Report.Collected.StopReason == L"GlobalWalkBudget" ||
                budget.Report.Collected.StopReason == L"HandleResultBudget")
            {
                break;
            }
            const auto reason = budget.Report.Collected.StopReason;
            budget.Stopped = false;
            budget.Report.State = kncore::Status::Success;
            UnknownScope(ctx, budget, L"HandleTable", L"PID " + std::to_wstring(owner.Pid) + L": " + reason);
        }
    }
    if (ownerFilter && !ownerFound)
    {
        budget.Stop(kncore::Status::Unavailable, L"RequestedHandleOwnerNotObserved");
    }
    budget.Report.Limitations.Push(knjson::Value(L"Target handle tables are observed through matched x64 layouts and verified object "
                                                L"types. VM access alone does not prove injection. Unreadable or incomplete tables "
                                                L"remain coverage gaps. Display capped at 50; export contains collected rows."));
    FinishCollection(ctx, budget);
    ExportCollected(ctx);
}
} // namespace

void ScanVad(Ctx &ctx)
{
    knengine::LayoutResolver layout(ctx.Session);
    ProcRow target;
    if (!TargetProcess(ctx, layout, target))
    {
        return;
    }
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:VadTree"))
    {
        return;
    }
    bool execOnly = false;
    bool pageSamples = false;
    uint64_t displayLimit = 128;
    for (size_t i = 1; i < ctx.Args.size(); ++i)
    {
        const auto option = kncore::FoldName(ctx.Args[i]);
        if (option == L"/exec")
        {
            execOnly = true;
        }
        else if (option == L"/hiddenpte")
        {
            pageSamples = true;
        }
        else if (option == L"/limit" && ++i < ctx.Args.size())
        {
            if (!kncore::ParseUnsigned(ctx.Args[i], 10, &displayLimit) || displayLimit == 0 || displayLimit > 65536)
            {
                ctx.Out.Fail(kncore::Status::InvalidInput, L"VAD display limit must be 1..65536");
                return;
            }
        }
        else if (option == L"/json")
        {
            ++i;
        }
    }
    const auto tree = kncore::NestedField(layout.Field(L"nt", L"_EPROCESS", L"VadRoot"), layout.Field(L"nt", L"_RTL_AVL_TREE", L"Root"));
    const auto root = kncore::ReadField(ctx.Session, target.Eprocess, tree);
    if (!root)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"VAD root layout or memory unavailable");
        return;
    }
    kncore::VadLayout fields;
    fields.Node = layout.Field(L"nt", L"_MMVAD_SHORT", L"VadNode");
    fields.Left = layout.Field(L"nt", L"_RTL_BALANCED_NODE", L"Left");
    fields.Right = layout.Field(L"nt", L"_RTL_BALANCED_NODE", L"Right");
    fields.Start = layout.Field(L"nt", L"_MMVAD_SHORT", L"StartingVpn");
    fields.End = layout.Field(L"nt", L"_MMVAD_SHORT", L"EndingVpn");
    fields.StartHigh = layout.Field(L"nt", L"_MMVAD_SHORT", L"StartingVpnHigh");
    fields.EndHigh = layout.Field(L"nt", L"_MMVAD_SHORT", L"EndingVpnHigh");
    fields.Protection =
        kncore::NestedField(layout.Field(L"nt", L"_MMVAD_SHORT", L"u"), layout.Field(L"nt", L"_MMVAD_FLAGS", L"Protection"));
    if (!fields.StartHigh && !fields.EndHigh)
    {
        const auto type = layout.Describe(L"nt", L"_MMVAD_SHORT");
        fields.NoHighFields =
            type && type->Complete && !type->Fields.contains(L"StartingVpnHigh") && !type->Fields.contains(L"EndingVpnHigh");
    }
    const auto table = ProtectionTable(ctx.Session, layout);
    budget.MaxNodes = 8192;
    uint64_t shown = 0;
    uint64_t sampled = 0;
    kncore::WalkVadTree(
        ctx.Session, *root, fields, architecture, table, budget,
        [&](const kncore::VadRow &vad)
        {
            const auto executable = kncore::ExecutableProtection(vad.PageProtection);
            auto row = knjson::Value::MakeObject();
            row.Set(L"kind", knjson::Value(L"Vad"));
            row.Set(L"process", target.ToJson());
            row.Set(L"object", knjson::Value(kncore::Hex(vad.Object)));
            row.Set(L"start", kncore::OptionalNumber(vad.Start, true));
            row.Set(L"end", kncore::OptionalNumber(vad.End, true));
            row.Set(L"protectionIndex", kncore::OptionalNumber(vad.ProtectionIndex));
            row.Set(L"pageProtection", kncore::OptionalNumber(vad.PageProtection, true));
            row.Set(L"executableByVad", executable ? knjson::Value(*executable) : knjson::Value());
            auto samples = knjson::Value::MakeArray();
            if (pageSamples && vad.Start && vad.End)
            {
                const uint64_t first = *vad.Start;
                const uint64_t last = *vad.End & ~uint64_t(4095);
                for (uint64_t address : {first, last})
                {
                    if (address == first && !samples.Items().empty())
                    {
                        continue;
                    }
                    auto sample = knjson::Value::MakeObject();
                    sample.Set(L"address", knjson::Value(kncore::Hex(address)));
                    knengine::PageWalkResult walk;
                    const bool ok = sampled < 256 && !ctx.Session.Cancelled() && target.DtbKnown && target.DirectoryTableBase != 0 &&
                                    knengine::WalkVirtualToPhysical(ctx.Session, address, target.DirectoryTableBase,
                                                                    architecture.VirtualAddressBits == 57u, &walk);
                    if (sampled < 256)
                    {
                        ++sampled;
                    }
                    sample.Set(L"status", knjson::Value(ok ? L"Observed" : sampled >= 256 ? L"SampleBudgetOrUnavailable" : L"Unavailable"));
                    sample.Set(L"executable", ok ? knjson::Value(walk.EffectiveExecutable) : knjson::Value());
                    sample.Set(L"writable", ok ? knjson::Value(walk.EffectiveWritable) : knjson::Value());
                    sample.Set(L"vadMismatch", ok && executable ? knjson::Value(walk.EffectiveExecutable != *executable) : knjson::Value());
                    samples.Push(sample);
                    if (!ok)
                    {
                        ++budget.Report.Collected.Unknown;
                    }
                }
            }
            row.Set(L"pageSamples", samples);
            budget.Report.Rows.Push(row);
            if (shown < displayLimit && (!execOnly || !executable || *executable || pageSamples))
            {
                std::wstring protection = L"Unknown";
                if (vad.PageProtection)
                {
                    protection = kncore::Hex(*vad.PageProtection) + L" (target table)";
                }
                else if (vad.ProtectionIndex)
                {
                    const auto standard = kncore::StandardProtectionName(*vad.ProtectionIndex);
                    protection = standard.empty() ? L"index=" + std::to_wstring(*vad.ProtectionIndex)
                                                  : standard + L" (standard encoding)";
                }
                ctx.Out.AddLine(L"[vad] object=" + kncore::Hex(vad.Object) + L" range=" +
                                (vad.Start ? kncore::Hex(*vad.Start) : L"Unknown") + L".." +
                                (vad.End ? kncore::Hex(*vad.End) : L"Unknown") + L" protection=" + protection +
                                L" sampled-pages=" + std::to_wstring(samples.Items().size()));
                ++shown;
            }
            return true;
        });
    budget.Report.Limitations.Push(knjson::Value(L"Protection mapping requires target MmProtectToValue. Page samples cover first/last "
                                                 L"pages only, at most 256 pages; the rest of the region is not checked."));
    ctx.Out.AddLine(L"[vad.display] shown=" + std::to_wstring(shown) + L" collected=" + std::to_wstring(budget.Report.Rows.Items().size()));
    FinishCollection(ctx, budget);
    ExportCollected(ctx);
}

void ScanThreads(Ctx &ctx)
{
    knengine::LayoutResolver layout(ctx.Session);
    ProcRow target;
    uint64_t selectedThread = 0;
    const bool currentThread = ctx.Args.size() == 1;
    const bool explicitThread = ctx.Args.size() == 2 && kncore::FoldName(ctx.Args[1]).starts_with(L"ethread:");
    if (!currentThread && !explicitThread && !TargetProcess(ctx, layout, target))
    {
        return;
    }
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:ThreadList"))
    {
        return;
    }
    if (currentThread || explicitThread)
    {
        if (currentThread && !CurrentKernelThread(ctx, selectedThread))
        {
            return;
        }
        if (explicitThread)
        {
            knengine::ObjectDirectoryWalker objects(ctx.Session);
            unsigned threadType = UINT32_MAX;
            unsigned actualType = UINT32_MAX;
            // The current idle thread is a static kernel object without an object header.
            ULONG64 current = 0;
            const bool isCurrent = EvalAddress(ctx.Session, L"@$thread", &current);
            if (!kncore::ParseUnsigned(ctx.Args[1].substr(8), 16, &selectedThread) || !architecture.KernelPointer(selectedThread) ||
                !((isCurrent && selectedThread == current) ||
                  (objects.ResolveTypeIndex(L"Thread", &threadType) && objects.ObjectTypeIndex(selectedThread, &actualType) &&
                   actualType == threadType)))
            {
                ctx.Out.Fail(kncore::Status::InvalidInput, L"ETHREAD selector is not a corroborated thread object");
                return;
            }
        }
        const auto process =
            kncore::ReadField(ctx.Session, selectedThread,
                              kncore::NestedField(layout.Field(L"nt", L"_ETHREAD", L"Tcb"), layout.Field(L"nt", L"_KTHREAD", L"Process")));
        const auto pcb = layout.Field(L"nt", L"_EPROCESS", L"Pcb");
        if (!process || !pcb || *process < pcb->Offset || !architecture.KernelPointer(*process - pcb->Offset) ||
            !kncore::ReadProcess(ctx.Session, *process - pcb->Offset, ResolveProcessLayout(layout), target))
        {
            ctx.Out.Fail(kncore::Status::Unavailable, L"Thread owning process layout or memory unavailable");
            return;
        }
        budget.Report.Source = currentThread ? L"TargetMemory:CurrentThread" : L"TargetMemory:SelectedThread";
    }
    const auto head = layout.Field(L"nt", L"_EPROCESS", L"ThreadListHead");
    const auto link = layout.Field(L"nt", L"_ETHREAD", L"ThreadListEntry");
    const auto tidField =
        kncore::NestedField(layout.Field(L"nt", L"_ETHREAD", L"Cid"), layout.Field(L"nt", L"_CLIENT_ID", L"UniqueThread"));
    const auto startField = layout.Field(L"nt", L"_ETHREAD", L"StartAddress");
    const auto win32Field = layout.Field(L"nt", L"_ETHREAD", L"Win32StartAddress");
    if (!head || !link || head->Size != 16 || link->Size != 16 ||
        !kncore::ValidRange(target.Eprocess, static_cast<uint64_t>(head->Offset) + head->Size))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Thread list layout unavailable");
        return;
    }
    const auto owners = knengine::CollectOwnershipIndex(ctx.Session);
    const auto visit = [&](uint64_t entry)
    {
        if (entry < link->Offset || !architecture.KernelPointer(entry - link->Offset))
        {
            return kncore::VisitDecision::Failed;
        }
        const auto object = entry - link->Offset;
        const auto tid = kncore::ReadField(ctx.Session, object, tidField);
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"Thread"));
        row.Set(L"process", target.ToJson());
        row.Set(L"ethread", knjson::Value(kncore::Hex(object)));
        row.Set(L"tid", kncore::OptionalNumber(tid));
        if (!tid)
        {
            ++budget.Report.Collected.Unknown;
        }
        std::wstring starts[2];
        for (const auto &slot : {std::pair(L"start", startField), std::pair(L"win32Start", win32Field)})
        {
            const auto address = kncore::ReadField(ctx.Session, object, slot.second);
            row.Set(slot.first, kncore::OptionalNumber(address, true));
            std::wstring owner = L"Unknown";
            std::wstring where;
            if (address)
            {
                if (architecture.KernelPointer(*address))
                {
                    const auto found = owners.Find(*address, ctx.Session.RefreshStamp());
                    owner = OwnershipText(found);
                    if (found.State == kncore::OwnershipState::Unknown)
                    {
                        ++budget.Report.Collected.Unknown;
                    }
                    where = kncore::Hex(*address) + L" " + owner;
                }
                else
                {
                    owner = architecture.Canonical(*address) ? L"UserAddressNotResolvedInProcessContext" : L"Noncanonical";
                    where = kncore::Hex(*address) + L" (" + owner + L")";
                }
            }
            else
            {
                ++budget.Report.Collected.Unknown;
            }
            row.Set(std::wstring(slot.first) + L"Owner", knjson::Value(owner));
            starts[std::wstring_view(slot.first) == L"start" ? 0 : 1] = where.empty() ? L"unavailable" : where;
        }
        budget.Report.Rows.Push(row);
        ctx.Out.AddLine(L"[thread] tid=" + (tid ? std::to_wstring(*tid) : L"Unknown") + L" ethread=" + kncore::Hex(object) + L" start=" +
                        starts[0] + L" win32Start=" + starts[1] + L" process=" + target.Image + L" pid=" + std::to_wstring(target.Pid));
        return kncore::VisitDecision::Continue;
    };
    budget.StartTraversal();
    if (currentThread || explicitThread)
    {
        budget.Report.Collected.Expected = 1;
        if (!kncore::ValidRange(selectedThread, static_cast<uint64_t>(link->Offset) + link->Size))
        {
            budget.Stop(kncore::Status::Unavailable, L"ThreadObjectRangeInvalid");
        }
        else if (CheckCollection(ctx, budget))
        {
            ++budget.Report.Collected.Visited;
            if (visit(selectedThread + link->Offset) == kncore::VisitDecision::Continue)
            {
                ++budget.Report.Collected.Read;
                ++budget.Report.Collected.Decoded;
            }
        }
    }
    else
    {
        kncore::WalkList(ctx.Session, target.Eprocess + head->Offset, architecture, budget, visit);
    }
    FinishCollection(ctx, budget);
}

void ScanHandles(Ctx &ctx)
{
    std::optional<uint64_t> ownerFilter;
    std::optional<uint64_t> targetFilter;
    for (size_t i = 1; i < ctx.Args.size(); ++i)
    {
        const auto option = kncore::FoldName(ctx.Args[i]);
        if (option == L"/json")
        {
            ++i;
        }
        else if (++i < ctx.Args.size())
        {
            uint64_t pid = 0;
            if (!kncore::ParseUnsigned(ctx.Args[i], 10, &pid) || pid > UINT32_MAX)
            {
                ctx.Out.Fail(kncore::Status::InvalidInput, L"PID filter must be a complete unsigned 32-bit value");
                return;
            }
            if (option == L"/owner" || option == L"/owner-pid")
            {
                ownerFilter = pid;
            }
            else
            {
                targetFilter = pid;
            }
        }
    }
    if (!SessionIsLocalLiveKernel(ctx.Session))
    {
        ScanTargetHandles(ctx, ownerFilter, targetFilter);
        return;
    }
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"HostSystemExtendedHandleInformation+TargetProcessIdentity"))
    {
        return;
    }
    std::vector<kncore::HandleEntry> entries;
    kncore::NativeError error;
    if (!QueryExtendedHandles(ctx.Session, entries, error))
    {
        ctx.Out.Fail(ctx.Session.Cancelled() ? kncore::Status::Cancelled : kncore::Status::Unavailable, L"Host handle snapshot unavailable",
                     error);
        return;
    }
    knengine::ObjectDirectoryWalker objects(ctx.Session);
    unsigned processType = UINT32_MAX;
    if (!objects.ResolveTypeIndex(L"Process", &processType))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Verified Process object type unavailable; VM access masks were not applied");
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    const auto fields = ResolveProcessLayout(layout);
    std::map<uint64_t, ProcRow> targets;
    budget.Report.Collected.Expected = entries.size();
    budget.Report.Consistency = L"host-target-nonatomic";
    for (const auto &entry : entries)
    {
        if (ctx.Session.Cancelled() || std::chrono::steady_clock::now() >= budget.Deadline)
        {
            budget.Stop(ctx.Session.Cancelled() ? kncore::Status::Cancelled : kncore::Status::Partial, L"HandleWalkStopped");
            break;
        }
        ++budget.Report.Collected.Visited;
        if (!kncore::ProcessVmAccess(entry, processType))
        {
            continue;
        }
        auto found = targets.find(entry.Object);
        if (found == targets.end())
        {
            ProcRow process;
            unsigned currentType = UINT32_MAX;
            if (architecture.KernelPointer(entry.Object) && objects.ObjectTypeIndex(entry.Object, &currentType) &&
                currentType == processType)
            {
                kncore::ReadProcess(ctx.Session, entry.Object, fields, process);
            }
            found = targets.emplace(entry.Object, process).first;
        }
        const auto &target = found->second;
        const auto targetPid = target.PidKnown ? std::optional<uint64_t>(target.Pid) : std::nullopt;
        if (!targetPid)
        {
            ++budget.Report.Collected.Unknown;
        }
        if (!kncore::HandleMatches(entry, targetPid, ownerFilter, targetFilter))
        {
            continue;
        }
        if (budget.Report.Rows.Items().size() >= 65536)
        {
            budget.Stop(kncore::Status::Partial, L"HandleResultBudget");
            break;
        }
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"ProcessHandle"));
        row.Set(L"ownerPid", knjson::Value(std::to_wstring(entry.OwnerPid)));
        row.Set(L"targetPid", kncore::OptionalNumber(targetPid));
        row.Set(L"targetCreateTime", target.CreateTimeKnown ? knjson::Value(std::to_wstring(target.CreateTime)) : knjson::Value());
        row.Set(L"handle", knjson::Value(kncore::Hex(entry.Handle)));
        row.Set(L"object", knjson::Value(kncore::Hex(entry.Object)));
        row.Set(L"typeIndex", knjson::Value(std::to_wstring(entry.TypeIndex)));
        row.Set(L"grantedAccess", knjson::Value(kncore::Hex(entry.Access)));
        row.Set(L"crossProcess", targetPid ? knjson::Value(*targetPid != entry.OwnerPid) : knjson::Value());
        budget.Report.Rows.Push(row);
        ++budget.Report.Collected.Classified;
        if (budget.Report.Rows.Items().size() <= 50)
        {
            ctx.Out.AddLine(L"[handle.observation] " + row.Write());
        }
    }
    budget.Report.Limitations.Push(
        knjson::Value(L"Native x64 host snapshot ABI; object/PID reads occur later. Races and redacted addresses remain Unknown. VM access "
                      L"alone does not show that code was injected. Display capped at 50; export contains all collected rows."));
    FinishCollection(ctx, budget);
    ExportCollected(ctx);
}

void ScanHiddenProc(Ctx &ctx)
{
    const auto stamp = ctx.Session.RefreshStamp();
    const auto started = GetTickCount64();
    knengine::LayoutResolver layout(ctx.Session);
    std::vector<ProcRow> kernel;
    CmdText kernelOutput;
    CollectProcesses(ctx.Session, layout, &kernel, kernelOutput);
    const auto hostStarted = GetTickCount64();
    std::vector<ProcRow> host;
    const bool local = SessionIsLocalLiveKernel(ctx.Session);
    const auto hostResult = local ? HostProcesses(ctx.Session, host) : TargetCidProcesses(ctx, layout, host);
    ctx.Out.Details = local ? kncore::CompareProcessViews(kernel, kernelOutput.Details, host, hostResult)
                           : kncore::CompareTargetProcessViews(kernel, kernelOutput.Details, host, hostResult);
    ctx.Out.Details.Analysis = knjson::Value::MakeObject();
    ctx.Out.Details.Analysis.Set(L"processComparison", kncore::ProcessComparisonSummary(ctx.Out.Details));
    ctx.Out.Details.Stamp = stamp;
    ctx.Out.Details.Limitations.Push(knjson::Value(L"Collection offsets in milliseconds: kernel=" + std::to_wstring(hostStarted - started) +
                                                   (local ? L", host=" : L", cid=") + std::to_wstring(GetTickCount64() - hostStarted)));
    if (!(stamp == ctx.Session.RefreshStamp()))
    {
        ctx.Out.Fail(kncore::Status::StaleContext, L"Cross-view target changed");
        return;
    }
    for (const auto &row : ctx.Out.Details.Rows.Items())
    {
        ctx.Out.AddLine(L"[process.crossview] " + row.Write());
    }
    ctx.Out.AddLine(L"[crossview] " + ctx.Out.Details.Collected.StopReason + L"; collect again to confirm differences");
}
} // namespace kncmd
