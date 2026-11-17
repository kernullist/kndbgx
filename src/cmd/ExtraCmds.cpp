#include "CollectorSupport.h"
#include "../core/ObjectRead.h"
#include "../core/Piddb.h"
#include "../core/CiHash.h"
#include "../core/HistoryRows.h"
#include "../core/DriverRecord.h"
#include "../util/SnapshotStore.h"

#include <windows.h>
#include <dbgeng.h>

#include <cstring>
#include <set>
#include <string>
#include <vector>

#include "../engine/LayoutResolver.h"
#include "../engine/ModuleList.h"
#include "../engine/ObjectDirectory.h"
#include "../engine/PageWalk.h"
#include "../util/Log.h"
#include "ProcCollect.h"

namespace kncmd
{
void ClearScreenCmd(Ctx &ctx)
{
    ctx.Out.AddLine(L"[kndbgx.cls]");
}

void ProcessContextCmd(Ctx &ctx)
{
    knengine::DbgSession &session = ctx.Session;
    CmdText &out = ctx.Out;

    do
    {
        if (ctx.Args.size() < 2 || _wcsicmp(ctx.Args[1].c_str(), L"show") == 0)
        {
            if (session.HasContextDtb())
            {
                out.AddLine(L"[procctx] dtb=" + FmtAddr(session.ContextDtb()) + L" (override on)");
            }
            else
            {
                ULONG64 cr3 = 0;
                if (!session.ReadRegisterHex(L"cr3", &cr3))
                {
                    out.Fail(kncore::Status::Unavailable, L"[procctx] current CR3 unavailable");
                    break;
                }
                out.AddLine(L"[procctx] dtb=" + FmtAddr(cr3) + L" (current CR3, no override)");
            }
            break;
        }

        if (_wcsicmp(ctx.Args[1].c_str(), L"reset") == 0 || _wcsicmp(ctx.Args[1].c_str(), L"clear") == 0)
        {
            session.ClearContextDtb();
            out.AddLine(L"[procctx] override cleared");
            break;
        }

        knengine::LayoutResolver layout(session);
        std::vector<ProcRow> rows;
        CmdText sink;

        if (!CollectProcesses(session, layout, &rows, sink))
        {
            out.Details = sink.Details;
            out.AddLine(L"[procctx] process list unavailable");
            break;
        }

        ProcRow match = {};

        if (!ResolveProcessTarget(session, layout, rows, ctx.Args[1], &match, sink.Details.Collected.Complete) ||
            !match.DtbKnown || match.DirectoryTableBase == 0)
        {
            out.Fail(kncore::Status::Unavailable, L"[procctx] no unique readable process/DTB for " + ctx.Args[1]);
            break;
        }

        session.SetContextDtb(match.DirectoryTableBase);
        out.AddLine(L"[procctx] pid=" + FmtDec(match.Pid) + L" image=" + match.Image + L" eprocess=" + FmtAddr(match.Eprocess) + L" dtb=" +
                    FmtAddr(match.DirectoryTableBase));
    } while (false);
}

void ScanToken(Ctx &ctx)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:ProcessToken"))
    {
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    ProcRow process;
    if (!ResolveSelectedProcess(ctx, layout, ctx.Args.size() == 2 ? ctx.Args[1] : L"", process))
    {
        return;
    }
    uint64_t thread = 0;
    std::optional<uint64_t> impersonationToken;
    if (ctx.Args.size() == 1)
    {
        if (!CurrentKernelThread(ctx, thread))
        {
            return;
        }
        const auto active = kncore::ReadField(ctx.Session, thread, layout.Field(L"nt", L"_ETHREAD", L"ActiveImpersonationInfo"));
        if (!active || *active > 1)
        {
            ctx.Out.Fail(kncore::Status::Unavailable, L"Current thread impersonation state unavailable");
            return;
        }
        if (*active != 0)
        {
            const auto security = layout.Field(L"nt", L"_ETHREAD", L"ClientSecurity");
            const auto level = layout.Field(L"nt", L"_PS_CLIENT_SECURITY_CONTEXT", L"ImpersonationLevel");
            const auto effective = layout.Field(L"nt", L"_PS_CLIENT_SECURITY_CONTEXT", L"EffectiveOnly");
            const auto data =
                kncore::ReadField(ctx.Session, thread,
                                  kncore::NestedField(security, layout.Field(L"nt", L"_PS_CLIENT_SECURITY_CONTEXT", L"ImpersonationData")));
            if (!data || !level || !effective || level->Offset != 0 || effective->Offset != 0 || level->BitOffset != 0U ||
                level->BitWidth != 2U || effective->BitOffset != 2U || effective->BitWidth != 1U)
            {
                ctx.Out.Fail(kncore::Status::Unavailable, L"Current thread token encoding unavailable");
                return;
            }
            impersonationToken = *data & ~uint64_t(7);
        }
    }
    uint64_t token = impersonationToken.value_or(0);
    if (!impersonationToken)
    {
        const auto fastRef = kncore::ReadField(ctx.Session, process.Eprocess, layout.Field(L"nt", L"_EPROCESS", L"Token"));
        const auto countBits = layout.Field(L"nt", L"_EX_FAST_REF", L"RefCnt");
        if (!fastRef || !countBits || countBits->BitOffset != 0U || !countBits->BitWidth || *countBits->BitWidth == 0 ||
            *countBits->BitWidth > 8)
        {
            ctx.Out.Fail(kncore::Status::Unavailable, L"Token fast-reference metadata/value unavailable");
            return;
        }
        token = *fastRef & ~((uint64_t(1) << *countBits->BitWidth) - 1);
    }
    if (!architecture.KernelPointer(token))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Token pointer is not a canonical kernel address");
        return;
    }
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(impersonationToken ? L"ThreadToken" : L"ProcessToken"));
    row.Set(L"process", process.ToJson());
    row.Set(L"selection", knjson::Value(ctx.Args.size() == 1 ? L"CurrentThreadEffectiveToken" : L"SelectedProcessPrimaryToken"));
    row.Set(L"ethread", thread != 0 ? knjson::Value(kncore::Hex(thread)) : knjson::Value());
    row.Set(L"address", knjson::Value(kncore::Hex(token)));
    const auto read = [&](const wchar_t *field)
    {
        ++budget.Report.Collected.Expected;
        ++budget.Report.Collected.Visited;
        const auto value = kncore::ReadField(ctx.Session, token, layout.Field(L"nt", L"_TOKEN", field));
        if (value)
        {
            ++budget.Report.Collected.Read;
        }
        else
        {
            ++budget.Report.Collected.Unknown;
        }
        row.Set(field, kncore::OptionalNumber(value));
        return value;
    };
    read(L"TokenId");
    read(L"AuthenticationId");
    read(L"SessionId");
    const auto type = read(L"TokenType");
    row.Set(L"tokenTypeName", knjson::Value(type == 1ULL ? L"Primary" : type == 2ULL ? L"Impersonation" : L"Unknown"));
    const auto integrityIndex = read(L"IntegrityLevelIndex");
    const auto groupCount = read(L"UserAndGroupCount");
    const auto groups = read(L"UserAndGroups");
    const auto privileges = layout.Field(L"nt", L"_TOKEN", L"Privileges");
    for (const auto field : {L"Present", L"Enabled", L"EnabledByDefault"})
    {
        const auto value =
            kncore::ReadField(ctx.Session, token, kncore::NestedField(privileges, layout.Field(L"nt", L"_SEP_TOKEN_PRIVILEGES", field)));
        row.Set(std::wstring(L"privileges") + field, kncore::OptionalNumber(value, true));
        if (!value)
        {
            ++budget.Report.Collected.Unknown;
        }
    }
    ULONG groupSize = 0;
    const auto sidField = layout.Field(L"nt", L"_SID_AND_ATTRIBUTES", L"Sid");
    std::optional<uint64_t> integrityRid;
    if (integrityIndex && groupCount && groups && *integrityIndex < *groupCount && *groupCount <= 65536 &&
        layout.TypeSize(L"_SID_AND_ATTRIBUTES", &groupSize) && groupSize >= 8 && groupSize <= 256 &&
        kncore::ValidRange(*groups, (*integrityIndex + 1) * groupSize))
    {
        const auto sid = kncore::ReadField(ctx.Session, *groups + *integrityIndex * groupSize, sidField);
        if (sid && architecture.KernelPointer(*sid))
        {
            // SID is a documented variable-length Windows binary ABI.
            const auto bytes = ctx.Session.Read(kncore::AddressSpace::Virtual, *sid, 12);
            if (kncore::ExactBytes(bytes, 12))
            {
                integrityRid = kncore::MandatoryLabelRid(bytes.Bytes);
            }
        }
    }
    row.Set(L"mandatoryLabelRid", kncore::OptionalNumber(integrityRid));
    if (!integrityRid)
    {
        ++budget.Report.Collected.Unknown;
    }
    budget.StartTraversal();
    EmitRow(ctx, budget, row);
    FinishCollection(ctx, budget);
}

void ScanUnloadedDrivers(Ctx &ctx)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:UnloadedDrivers"))
    {
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    const auto symbol = SymbolAddress(ctx.Session, layout, L"nt", L"MmUnloadedDrivers");
    const auto arrayType = layout.Symbol(L"nt", L"MmUnloadedDrivers");
    auto name = layout.Field(L"nt", L"_UNLOADED_DRIVERS", L"Name");
    auto start = layout.Field(L"nt", L"_UNLOADED_DRIVERS", L"StartAddress");
    auto end = layout.Field(L"nt", L"_UNLOADED_DRIVERS", L"EndAddress");
    auto time = layout.Field(L"nt", L"_UNLOADED_DRIVERS", L"CurrentTime");
    ULONG recordSize = 0;
    uint32_t count = 0;
    uint64_t table = symbol.value_or(0);
    std::optional<uint64_t> nextIndex;
    bool known = symbol && arrayType && arrayType->Kind == kncore::FieldKind::Array && arrayType->ArrayCount && arrayType->ElementSize &&
                 arrayType->ValidFor(arrayType->Size) && layout.TypeSize(L"_UNLOADED_DRIVERS", &recordSize) &&
                 recordSize == *arrayType->ElementSize;
    if (known)
    {
        count = *arrayType->ArrayCount;
    }
    else if (symbol &&
             kncore::ProfilePointerStorageAllowed(arrayType, !arrayType && layout.PublicOnlySymbol(L"nt", L"MmUnloadedDrivers"), 8) &&
             layout.VerifyProfile(kncore::KernelLayoutFamily::Unloaded))
    {
        const auto indexAddress = layout.Address(L"nt", L"MmLastUnloadedDriver");
        nextIndex = indexAddress ? kncore::ReadField(ctx.Session, *indexAddress, kncore::KernelProfileField(0, 4)) : std::nullopt;
        const auto pointer = kncore::ReadField(ctx.Session, *symbol, kncore::KernelProfileField(0, 8));
        known = pointer && nextIndex && *nextIndex <= 50 && layout.CanProfileField(L"nt", L"_UNLOADED_DRIVERS", L"Name") &&
                layout.CanProfileField(L"nt", L"_UNLOADED_DRIVERS", L"StartAddress") &&
                layout.CanProfileField(L"nt", L"_UNLOADED_DRIVERS", L"EndAddress") &&
                layout.CanProfileField(L"nt", L"_UNLOADED_DRIVERS", L"CurrentTime") && kncore::ApplyKernelProfileField(name, 0, 16) &&
                kncore::ApplyKernelProfileField(start, 0x10, 8) && kncore::ApplyKernelProfileField(end, 0x18, 8) &&
                kncore::ApplyKernelProfileField(time, 0x20, 8);
        if (known)
        {
            table = *pointer;
            recordSize = 0x28;
            // The next-write index wraps; it is not the number of occupied slots.
            count = table == 0 && *nextIndex == 0 ? 0 : 50;
            if (const auto identity = layout.Identity(L"nt"))
            {
                budget.Report.LayoutProfile = kncore::KernelProfileName(*identity);
            }
        }
    }
    if (!known || count > 4096 || !name || !start || !end || !time || recordSize == 0 || recordSize > 4096 || !name->ValidFor(recordSize) ||
        !start->ValidFor(recordSize) || !end->ValidFor(recordSize) || !time->ValidFor(recordSize) ||
        (count != 0 && (!architecture.KernelPointer(table) || !kncore::ValidRange(table, uint64_t(count) * recordSize))))
    {
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"UnloadedDriverRoot"));
        row.Set(L"address", kncore::OptionalNumber(symbol, true));
        EmitRow(ctx, budget, row);
        UnknownScope(ctx, budget, L"UnloadedDrivers", L"Verified array capacity, pointer storage or record fields unavailable");
    }
    else
    {
        budget.Report.Collected.Expected = count;
        const auto length = layout.Field(L"nt", L"_UNICODE_STRING", L"Length");
        for (uint32_t index = 0; index < count && CheckCollection(ctx, budget); ++index)
        {
            ++budget.Report.Collected.Visited;
            const uint64_t address = table + uint64_t(index) * recordSize;
            const auto bytes = ctx.Session.Read(kncore::AddressSpace::Virtual, address, recordSize);
            if (!kncore::ExactBytes(bytes, recordSize))
            {
                ++budget.Report.Collected.Unreadable;
                continue;
            }
            ++budget.Report.Collected.Read;
            const auto nameLength = kncore::ReadField(ctx.Session, address + name->Offset, length);
            if (nameLength == 0)
            {
                ++budget.Report.Collected.Decoded;
                continue;
            }
            auto row = knjson::Value::MakeObject();
            row.Set(L"kind", knjson::Value(L"UnloadedDriver"));
            row.Set(L"index", knjson::Value(std::to_wstring(index)));
            row.Set(L"record", knjson::Value(kncore::Hex(address)));
            row.Set(L"ringNextIndex", kncore::OptionalNumber(nextIndex));
            std::wstring text;
            const bool named = ReadUnicodeString(ctx.Session, layout, address + name->Offset, &text);
            const auto from = kncore::ReadField(ctx.Session, address, start);
            const auto to = kncore::ReadField(ctx.Session, address, end);
            const auto when = kncore::ReadField(ctx.Session, address, time);
            row.Set(L"name", named ? knjson::Value(text) : knjson::Value());
            row.Set(L"StartAddress", kncore::OptionalNumber(from, true));
            row.Set(L"EndAddress", kncore::OptionalNumber(to, true));
            row.Set(L"CurrentTime", kncore::OptionalNumber(when, true));
            row.Set(L"timeBasis", knjson::Value(budget.Report.LayoutProfile == kncore::KernelSymbolProfile28000Id ?
                L"UnbiasedInterruptTime100ns" : L"RawKernelValue"));
            const bool identityComplete = named && !text.empty() && nameLength && from && to && when && *when != 0 &&
                architecture.KernelPointer(*from) && architecture.KernelPointer(*to) && *from < *to;
            row.Set(L"identityComplete", knjson::Value(identityComplete));
            if (!identityComplete)
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
    budget.Report.Limitations.Push(knjson::Value(L"Unload history has a size limit and can change; a missing entry does not show that it was erased."));
    FinishCollection(ctx, budget);
}

void ScanPiddb(Ctx &ctx)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:PiDDBCache"))
    {
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    const auto table = SymbolAddress(ctx.Session, layout, L"nt", L"PiDDBCacheTable");
    const auto compare = layout.Address(L"nt", L"PiCompareDDBCacheEntries");
    ULONG linksSize = 0;
    const auto field = [&](const wchar_t *type, const wchar_t *name, uint32_t offset, uint32_t size, kncore::FieldKind kind)
    {
        return kncore::PiddbFieldMatches(layout.Field(L"nt", type, name), offset, size, kind);
    };
    using kncore::FieldKind;
    const bool verified = table && compare && layout.VerifyProfile(kncore::KernelLayoutFamily::Piddb) &&
        layout.PublicOnlySymbol(L"nt", L"PiDDBCacheTable") &&
        layout.TypeSize(L"_RTL_BALANCED_LINKS", &linksSize) && linksSize == 0x20 &&
        field(L"_RTL_AVL_TABLE", L"BalancedRoot", 0, 0x20, FieldKind::Composite) &&
        field(L"_RTL_AVL_TABLE", L"NumberGenericTableElements", 0x2c, 4, FieldKind::Unsigned) &&
        field(L"_RTL_AVL_TABLE", L"DeleteCount", 0x40, 4, FieldKind::Unsigned) &&
        field(L"_RTL_AVL_TABLE", L"CompareRoutine", 0x48, 8, FieldKind::Pointer) &&
        field(L"_RTL_BALANCED_LINKS", L"Parent", 0, 8, FieldKind::Pointer) &&
        field(L"_RTL_BALANCED_LINKS", L"LeftChild", 8, 8, FieldKind::Pointer) &&
        field(L"_RTL_BALANCED_LINKS", L"RightChild", 0x10, 8, FieldKind::Pointer) &&
        field(L"_UNICODE_STRING", L"Length", 0, 2, FieldKind::Unsigned) &&
        field(L"_UNICODE_STRING", L"MaximumLength", 2, 2, FieldKind::Unsigned) &&
        field(L"_UNICODE_STRING", L"Buffer", 8, 8, FieldKind::Pointer);
    if (!verified)
    {
        UnknownScope(ctx, budget, L"PiDDBPayload", L"No verified PiDDB entry layout for this kernel: " + layout.Diagnostic());
    }
    else
    {
        budget.Report.LayoutProfile = kncore::PiddbProfileId;
        kncore::CollectPiddbEntries(ctx.Session, architecture, *table, *compare, budget);
        size_t printed = 0;
        for (const auto &row : budget.Report.Rows.Items())
        {
            if (++printed > 256)
            {
                break;
            }
            ctx.Out.AddLine(row.Write());
        }
    }
    budget.Report.Limitations.Push(knjson::Value(L"PiDDB stores cached driver load results, not processes or current module residency. "
        L"TimeDateStamp is the raw PE header value, not a load time; reproducible builds can use a hash. "
        L"Missing cache entries do not establish history erasure."));
    FinishCollection(ctx, budget);
}

void ScanCiHash(Ctx &ctx)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:CiHashRoot"))
    {
        return;
    }
    knengine::LayoutResolver layout(ctx.Session);
    const auto root = SymbolAddress(ctx.Session, layout, L"ci", L"g_KernelHashBucketList");
    const auto type = layout.Symbol(L"ci", L"g_KernelHashBucketList");
    if (root && kncore::ProfilePointerStorageAllowed(type, layout.PublicOnlySymbol(L"ci", L"g_KernelHashBucketList"), 8) &&
        layout.VerifyProfile(kncore::KernelLayoutFamily::CiHash))
    {
        budget.Report.LayoutProfile = kncore::CiHashProfileId;
        kncore::CollectCiHashEntries(ctx.Session, architecture, *root, budget);
        for (size_t i = 0; i < budget.Report.Rows.Items().size() && i < 256; ++i)
        {
            ctx.Out.AddLine(budget.Report.Rows.Items()[i].Write());
        }
    }
    else
    {
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"CiHashRoot"));
        row.Set(L"address", kncore::OptionalNumber(root, true));
        EmitRow(ctx, budget, row);
        UnknownScope(ctx, budget, L"CiHashBuckets", L"Exact CI image, root storage or record code profile unavailable");
    }
    budget.Report.Limitations.Push(knjson::Value(L"CI cache names, two raw 20-byte hashes and raw cached status are observations. "
        L"Hash algorithm, current signature trust, module residency and history erasure are not established."));
    FinishCollection(ctx, budget);
}

void ScanMapper(Ctx &ctx)
{
    const std::vector<std::pair<const wchar_t *, HandlerFn>> collectors = {
        {L"!unloaded", ScanUnloadedDrivers}, {L"!piddb", ScanPiddb}, {L"!cihash", ScanCiHash}};
    ctx.Out.Details.Source = L"Composite:MapperHistoryObservations";
    ctx.Out.Details.Collected.Complete = true;
    ctx.Out.Details.Collected.StopReason = L"AllCollectionsComplete";
    for (const auto &[name, handler] : collectors)
    {
        if (ctx.Session.Cancelled())
        {
            ctx.Out.Fail(kncore::Status::Cancelled, L"Mapper collection cancelled");
            break;
        }
        CmdText child;
        child.Details.CommandId = name;
        const std::vector<std::wstring> args = {name};
        Ctx nested{ctx.Session, args, child};
        handler(nested);
        ctx.Out.AddLine(child.Text());
        if (!kncore::AppendHistoryCollection(ctx.Out.Details, child.Details))
        {
            break;
        }
    }
}

void ScanPayload(Ctx &ctx)
{
    ScanPool(ctx);
}

void ScanDriverList(Ctx &ctx)
{
    kncore::TargetArchitecture architecture;
    if (!KernelArchitecture(ctx.Session, &architecture))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Target architecture unavailable");
        return;
    }
    knengine::ObjectDirectoryWalker walker(ctx.Session);
    knengine::LayoutResolver layout(ctx.Session);
    unsigned driverType = 0;
    const bool typeVerified = walker.Initialize() && walker.ResolveTypeIndex(L"Driver", &driverType);
    const auto nameField = layout.Field(L"nt", L"_DRIVER_OBJECT", L"DriverName");
    if (!walker.Initialize() || (!typeVerified && !nameField))
    {
        ctx.Out.Fail(kncore::Status::Unavailable,
                     typeVerified ? L"Driver namespace unavailable"
                                  : L"Driver namespace/type unavailable and no DriverName echo fallback");
        return;
    }
    knjson::Value rows = knjson::Value::MakeArray();
    std::wstring error;
    uint64_t unknown = 0;
    walker.VisitDirectoryNamed(
        L"Driver",
        [&](ULONG64 body, const std::wstring &entryName)
        {
            if (typeVerified)
            {
                unsigned type = 0;
                if (!walker.ObjectTypeIndex(body, &type) || type != driverType)
                {
                    ++unknown;
                    return true;
                }
            }
            auto row = knjson::Value::MakeObject();
            row.Set(L"kind", knjson::Value(L"DriverObject"));
            row.Set(L"address", knjson::Value(kncore::Hex(body)));
            std::wstring name;
            const bool readable = nameField && kncore::ValidRange(body, uint64_t(nameField->Offset) + nameField->Size) &&
                                  ReadUnicodeString(ctx.Session, layout, body + nameField->Offset, &name);
            // Without a verified type index, a driver object is accepted when
            // its own DriverName echoes the directory entry name.
            const bool echoVerified = !typeVerified && readable && !entryName.empty() &&
                                      kncore::FoldName(name).ends_with(L"\\" + kncore::FoldName(entryName));
            const bool accepted = typeVerified ? readable : echoVerified;
            row.Set(L"name", accepted ? knjson::Value(name) : knjson::Value());
            row.Set(L"verification", knjson::Value(typeVerified ? L"ObTypeIndexTable" : L"DriverNameEcho"));
            unknown += accepted ? 0 : 1;
            if (typeVerified || echoVerified)
            {
                const auto fields = kncore::ReadDriverRecordFields(ctx.Session, architecture, body, [&](const wchar_t *field)
                {
                    return layout.Field(L"nt", L"_DRIVER_OBJECT", field);
                });
                for (const auto &[key, value] : fields.Fields.Fields())
                {
                    row.Set(key, value);
                }
                unknown += fields.Unknown;
            }
            rows.Push(row);
            if (rows.Items().size() <= 256)
            {
                ctx.Out.AddLine(L"[driver] " + (accepted ? name : entryName + L" (unverified)") + L" object=" + kncore::Hex(body));
            }
            return !ctx.Session.Cancelled();
        },
        &error);
    const auto command = ctx.Out.Details.CommandId;
    ctx.Out.Details = walker.Report();
    ctx.Out.Details.CommandId = command;
    ctx.Out.Details.Rows = rows;
    ctx.Out.Details.Collected.Unknown += unknown;
    if (unknown != 0)
    {
        ctx.Out.Details.State = kncore::Status::Partial;
        ctx.Out.Details.Collected.Complete = false;
    }
}

void ScanKpage(Ctx &ctx)
{
    uint64_t pages = 1;
    ULONG64 va = 0;
    if (ctx.Args.size() < 2 || !EvalAddress(ctx.Session, ctx.Args[1], &va) ||
        (ctx.Args.size() == 3 && (ctx.Args[2].size() < 2 || towlower(ctx.Args[2][0]) != L'l' ||
                                  !kncore::ParseUnsigned(std::wstring_view(ctx.Args[2]).substr(1), 16, &pages))) ||
        pages == 0 || pages > 65536 || !kncore::ValidRange(va & ~uint64_t(4095), pages * 4096))
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"Expected a valid VA and L<hex page count>, 1..10000");
        return;
    }
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetPhysical:PageTables"))
    {
        return;
    }
    ULONG64 dtb = ctx.Session.ContextDtb();
    if (!ctx.Session.HasContextDtb() && !ctx.Session.ReadRegisterHex(L"cr3", &dtb))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"CR3/DTB unavailable");
        return;
    }
    budget.Report.Collected.Expected = pages;
    for (uint64_t index = 0; index < pages && CheckCollection(ctx, budget); ++index)
    {
        ++budget.Report.Collected.Visited;
        const uint64_t address = (va & ~uint64_t(4095)) + index * 4096;
        knengine::PageWalkResult walk;
        const bool known = knengine::WalkPageTables(ctx.Session, architecture, address, dtb, &walk);
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"PageTranslation"));
        row.Set(L"va", knjson::Value(kncore::Hex(address)));
        row.Set(L"dtb", knjson::Value(kncore::Hex(dtb)));
        row.Set(L"pa", known ? knjson::Value(kncore::Hex(walk.PhysicalAddress)) : knjson::Value());
        row.Set(L"writable", known ? knjson::Value(walk.EffectiveWritable) : knjson::Value());
        row.Set(L"executable", known ? knjson::Value(walk.EffectiveExecutable) : knjson::Value());
        row.Set(L"error", knjson::Value(walk.Error));
        if (!known)
        {
            ++budget.Report.Collected.Unknown;
        }
        else
        {
            ++budget.Report.Collected.Read;
        }
        EmitRow(ctx, budget, row);
    }
    budget.Report.Limitations.Push(
        knjson::Value(L"Physical width uses the architectural maximum; unavailable translations are not proof of unmapped memory."));
    FinishCollection(ctx, budget);
}

void SnapshotCmd(Ctx &ctx)
{
    if (ctx.Args.size() != 2)
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"Expected a new snapshot directory");
        return;
    }
    kncore::Snapshot snapshot;
    const auto stamp = ctx.Session.RefreshStamp();
    FILETIME started = {};
    GetSystemTimePreciseAsFileTime(&started);
    const auto fileTime = [](FILETIME time)
    {
        return std::to_wstring((uint64_t(time.dwHighDateTime) << 32) | time.dwLowDateTime);
    };
    snapshot.Metadata.Set(L"schema", knjson::Value(L"kndbgx.snapshot.v2"));
    snapshot.Metadata.Set(L"target", stamp.ToJson());
    snapshot.Metadata.Set(L"startedUtcFileTime", knjson::Value(fileTime(started)));
    snapshot.Metadata.Set(L"collectorVersion", knjson::Value(L"3"));
    snapshot.Metadata.Set(L"rawMemoryIncluded", knjson::Value(false));
    snapshot.Metadata.Set(L"consistency", knjson::Value(L"per-collector; not atomic across collectors"));
    const std::vector<std::tuple<const wchar_t *, const wchar_t *, HandlerFn>> collectors = {
        {L"processes", L"!dml_proc", ScanProcessList},
        {L"callbacks", L"!callbacks", ScanCallbacks},
        {L"ssdt", L"!ssdt", ScanSsdt},
        {L"idt", L"!idt", ScanIdt},
        {L"control-registers", L"!cr", ScanControlRegisters},
        {L"hal", L"!hal", ScanHal},
        {L"unloaded-drivers", L"!unloaded", ScanUnloadedDrivers}};
    bool complete = true;
    for (const auto &[name, command, handler] : collectors)
    {
        if (ctx.Session.Cancelled())
        {
            ctx.Out.Fail(kncore::Status::Cancelled, L"Snapshot cancelled before the output directory was saved");
            return;
        }
        CmdText child;
        child.Details.CommandId = command;
        const std::vector<std::wstring> args = {command};
        Ctx nested{ctx.Session, args, child};
        ExecuteCollector(handler, nested);
        complete = complete && child.Details.State == kncore::Status::Success && child.Details.Collected.Complete;
        snapshot.Collections.emplace(name, child.Details.ToJson());
    }
    knengine::LayoutResolver layout(ctx.Session);
    std::vector<knengine::KernelModuleInfo> modules;
    kncore::Result moduleResult;
    moduleResult.CommandId = L"lm";
    knengine::EnumerateKernelModules(ctx.Session, &modules, &moduleResult);
    const auto identityDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    for (const auto &module : modules)
    {
        if (ctx.Session.Cancelled() || (ctx.RequestCancelled && ctx.RequestCancelled()))
        {
            ctx.Out.Fail(kncore::Status::Cancelled, L"Snapshot cancelled before the output directory was saved");
            return;
        }
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"Module"));
        row.Set(L"name", knjson::Value(module.ModuleName));
        row.Set(L"base", knjson::Value(kncore::Hex(module.Base)));
        row.Set(L"size", knjson::Value(std::to_wstring(module.Size)));
        row.Set(L"path", knjson::Value(module.ImageName));
        const auto identity = std::chrono::steady_clock::now() < identityDeadline
                                  ? layout.LoadedIdentity(module.ModuleName.c_str())
                                  : std::nullopt;
        row.Set(L"moduleIdentity", identity
                                       ? knjson::Value(identity->PdbGuid + L":" + std::to_wstring(identity->PdbAge) + L":" +
                                                       std::to_wstring(identity->Machine) + L":" + std::to_wstring(identity->Timestamp) +
                                                       L":" + std::to_wstring(identity->ImageSize))
                                       : knjson::Value());
        moduleResult.Rows.Push(row);
        if (!identity)
        {
            ++moduleResult.Collected.Unknown;
            moduleResult.State = kncore::Status::Partial;
            moduleResult.Collected.Complete = false;
        }
    }
    moduleResult.Limitations.Push(knjson::Value(L"Module identities use already loaded matched symbols within a five-second budget; "
                                                L"deferred or missing identities remain unknown."));
    complete = complete && moduleResult.State == kncore::Status::Success && moduleResult.Collected.Complete;
    snapshot.Collections.emplace(L"modules", moduleResult.ToJson());
    FILETIME ended = {};
    GetSystemTimePreciseAsFileTime(&ended);
    snapshot.Metadata.Set(L"completedUtcFileTime", knjson::Value(fileTime(ended)));
    const bool stable = ctx.Session.RefreshStamp() == stamp;
    snapshot.Metadata.Set(L"endTarget", ctx.Session.RefreshStamp().ToJson());
    snapshot.Metadata.Set(L"targetStable", knjson::Value(stable));
    snapshot.Metadata.Set(L"collectionComplete", knjson::Value(complete && stable));
    const auto cancelled = [&]()
    {
        return ctx.Session.Cancelled() || (ctx.RequestCancelled && ctx.RequestCancelled());
    };
    const auto exported = knutil::SaveSnapshot(ctx.Args[1], snapshot, cancelled);
    if (exported.State != kncore::Status::Success)
    {
        ctx.Out.Fail(exported.State, L"Snapshot directory commit failed; existing destination preserved", exported.Error);
        return;
    }
    ctx.Out.Details = exported;
    ctx.Out.Details.CommandId = L"!snapshot";
    ctx.Out.Details.Stamp = stamp;
    ctx.Out.AddLine(L"[snapshot] committed directory: " + ctx.Args[1]);
    if (!stable || !complete)
    {
        ctx.Out.Details.State = stable ? kncore::Status::Partial : kncore::Status::StaleContext;
        ctx.Out.Details.Collected.Complete = false;
        ctx.Out.AddLine(L"[snapshot] files saved; some collections are incomplete, with limits recorded in each result");
    }
}

void DiffCmd(Ctx &ctx)
{
    std::vector<std::wstring> paths;
    bool cross = false;
    for (size_t i = 1; i < ctx.Args.size(); ++i)
    {
        if (ctx.Args[i] == L"/cross-session")
        {
            cross = true;
        }
        else
        {
            paths.push_back(ctx.Args[i]);
        }
    }
    if (paths.size() != 2)
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"Expected before/after snapshot directories");
        return;
    }
    kncore::Snapshot before, after;
    const auto first = knutil::LoadSnapshot(paths[0], before);
    const auto second = knutil::LoadSnapshot(paths[1], after);
    if (first.State != kncore::Status::Success || second.State != kncore::Status::Success)
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"Snapshot import failed: schema/checksum/footer/path validation");
        return;
    }
    ctx.Out.Details = kncore::DiffSnapshots(before, after, cross);
    size_t printed = 0;
    for (const auto &row : ctx.Out.Details.Rows.Items())
    {
        if (++printed <= 256)
        {
            ctx.Out.AddLine(row.Write());
        }
    }
    ctx.Out.AddLine(L"[diff] status=" + std::wstring(kncore::StatusName(ctx.Out.Details.State)) + L" compared=" +
                    std::to_wstring(ctx.Out.Details.Rows.Items().size()) + L" unknown=" +
                    std::to_wstring(ctx.Out.Details.Collected.Unknown));
}

void ImportLegacySnapshot(Ctx &ctx)
{
    if (ctx.Args.size() != 3)
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"Expected legacy text file and new snapshot directory");
        return;
    }
    std::vector<unsigned char> bytes;
    std::wstring text;
    if (!knutil::ReadArtifact(ctx.Args[1], bytes, 1024 * 1024) || !knutil::StrictUtf8(bytes, text))
    {
        ctx.Out.Fail(kncore::Status::IOError, L"Legacy UTF-8 file is unavailable or exceeds 1 MiB");
        return;
    }
    kncore::Snapshot snapshot;
    snapshot.Metadata.Set(L"schema", knjson::Value(L"kndbgx.snapshot.v2"));
    kncore::SessionStamp stamp;
    stamp.SessionId = L"legacy-unidentified-" + knutil::Sha256Bytes(bytes);
    snapshot.Metadata.Set(L"target", stamp.ToJson());
    snapshot.Metadata.Set(L"legacy", knjson::Value(true));
    kncore::Result legacy;
    legacy.State = kncore::Status::Partial;
    legacy.Source = L"LegacyTextImport";
    legacy.Collected.StopReason = L"NoTargetIdentityOrStructuredCoverage";
    size_t cursor = 0;
    while (cursor < text.size() && legacy.Rows.Items().size() < 10000)
    {
        auto end = text.find(L'\n', cursor);
        end = end == std::wstring::npos ? text.size() : end;
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"LegacyText"));
        row.Set(L"text", knjson::Value(text.substr(cursor, end - cursor)));
        legacy.Rows.Push(row);
        cursor = end + 1;
    }
    snapshot.Collections.emplace(L"legacy", legacy.ToJson());
    const auto saved = knutil::SaveSnapshot(ctx.Args[2], snapshot, ctx.RequestCancelled);
    ctx.Out.Details = saved;
    if (saved.State == kncore::Status::Success)
    {
        ctx.Out.Details.State = kncore::Status::Partial;
        ctx.Out.Details.Collected.Complete = false;
        ctx.Out.AddLine(L"[snapshot.import] legacy text preserved with Unknown identity/coverage: " + ctx.Args[2]);
    }
    else
    {
        ctx.Out.Fail(saved.State, L"Could not finish saving the imported legacy file", saved.Error);
    }
}

void SetFieldCmd(Ctx &ctx)
{
    ctx.Out.Fail(kncore::Status::Unsupported, L"Verified field metadata and a complete change plan are required");
}
} // namespace kncmd
