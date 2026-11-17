#include "CollectorSupport.h"
#include "../core/Pool.h"
#include "../util/SystemInformation.h"
#include "../engine/LayoutResolver.h"
#include "../engine/PageWalk.h"
#include <algorithm>
#include <map>

namespace kncmd
{
namespace
{
// Read the target's own big-pool table using the matched kernel PDB.
// A plausible slot does not confirm the layout or size unit.
bool CollectTargetBigPool(Ctx &ctx, kncore::WalkBudget &budget, const kncore::TargetArchitecture &architecture,
                          std::vector<kncore::BigPoolEntry> &entries)
{
    budget.StartTraversal();
    budget.Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(150);
    knengine::LayoutResolver layout(ctx.Session);
    auto tableAddress = layout.Address(L"nt", L"PoolBigPageTable");
    auto tableSymbol = layout.Symbol(L"nt", L"PoolBigPageTable");
    auto sizeAddress = layout.Address(L"nt", L"PoolBigPageTableSize");
    auto sizeSymbol = layout.Symbol(L"nt", L"PoolBigPageTableSize");
    std::wstring symbolNote;
    if (!tableAddress || !tableSymbol || tableSymbol->Size != 8 || !sizeAddress || !sizeSymbol || sizeSymbol->Size != 4)
    {
        // Public kernel PDBs on current Insider builds ship these globals as
        // untyped public symbols: no verified type data and no exact-identity
        // profile exists for such builds. The engine still resolves their
        // storage addresses. Accept those addresses only with a runtime
        // contract: the values must be a canonical kernel pointer and a
        // bounded count, and element offsets must resolve from matched PDB
        // type data below; otherwise the collection refuses.
        ULONG64 publicTable = 0;
        ULONG64 publicSize = 0;
        if (ctx.Session.Symbols() == nullptr ||
            ctx.Session.Symbols()->GetOffsetByNameWide(L"nt!PoolBigPageTable", &publicTable) != S_OK ||
            ctx.Session.Symbols()->GetOffsetByNameWide(L"nt!PoolBigPageTableSize", &publicSize) != S_OK)
        {
            ctx.Out.Fail(kncore::Status::Unavailable,
                         L"Target big-pool table unavailable: nt!PoolBigPageTable/PoolBigPageTableSize are neither typed "
                         L"symbols in the matched PDB nor resolvable public storage; a remote target has no host fallback");
            return false;
        }
        kncore::FieldInfo publicPointer = {};
        publicPointer.Size = 8;
        kncore::FieldInfo publicCount = {};
        publicCount.Size = 4;
        tableAddress = publicTable;
        tableSymbol = publicPointer;
        sizeAddress = publicSize;
        sizeSymbol = publicCount;
        symbolNote = L"PoolBigPageTable storage resolved from untyped public symbols; runtime pointer/count and matched element-type "
                     L"verification is mandatory for this source.";
    }
    const auto tablePointer = kncore::ReadPoolTableGlobal(ctx.Session, architecture, *tableAddress, tableSymbol, 8);
    const auto declaredCount = kncore::ReadPoolTableGlobal(ctx.Session, architecture, *sizeAddress, sizeSymbol, 4);
    if (!tablePointer || *tablePointer == 0 || !declaredCount || *declaredCount == 0 ||
        *declaredCount > kncore::kPoolMaxTableEntries)
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"nt!PoolBigPageTable pointer/count is unavailable or implausible");
        return false;
    }
    const uint64_t total = *declaredCount;

    kncore::PoolTableLayout poolLayout = {};
    ULONG entrySize = 0;
    layout.TypeSize(L"nt", L"_POOL_TRACKER_BIG_PAGES", &entrySize);
    const auto va = layout.Field(L"nt", L"_POOL_TRACKER_BIG_PAGES", L"Va");
    const auto tag = layout.Field(L"nt", L"_POOL_TRACKER_BIG_PAGES", L"Key");
    const auto bytesField = layout.Field(L"nt", L"_POOL_TRACKER_BIG_PAGES", L"NumberOfBytes");
    if (entrySize == 0 || !va || va->Size != 8 || va->BitOffset || va->BitWidth ||
        !tag || tag->Size != 4 || tag->BitOffset || tag->BitWidth ||
        !bytesField || (bytesField->Size != 4 && bytesField->Size != 8) || bytesField->BitOffset || bytesField->BitWidth)
    {
        ctx.Out.Fail(kncore::Status::Unavailable,
                     L"Target big-pool layout unavailable: matched _POOL_TRACKER_BIG_PAGES field metadata is required");
        return false;
    }
    poolLayout = {entrySize, va->Offset, tag->Offset, bytesField->Offset, bytesField->Size};
    if (!kncore::ValidPoolTableLayout(poolLayout))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"Target big-pool field bounds are invalid");
        return false;
    }
    if (!kncore::ValidPoolTableStorage(architecture, *tablePointer, total, poolLayout))
    {
        ctx.Out.Fail(kncore::Status::Unavailable, L"nt!PoolBigPageTable storage is not an aligned kernel address range");
        return false;
    }
    const std::wstring layoutNote = L"Element layout resolved from matched _POOL_TRACKER_BIG_PAGES type data; "
                                   L"NumberOfBytes is measured in bytes; freed slots are excluded.";

    const size_t perChunk = std::max<size_t>(1, 4096 / poolLayout.EntrySize);
    for (uint64_t index = 0; index < total;)
    {
        if (!CheckCollection(ctx, budget))
        {
            break;
        }
        const uint64_t take = std::min<uint64_t>(perChunk, total - index);
        const auto read = ctx.Session.Read(kncore::AddressSpace::Virtual, *tablePointer + index * poolLayout.EntrySize,
                                           static_cast<size_t>(take) * poolLayout.EntrySize);
        const size_t bytes = static_cast<size_t>(take) * poolLayout.EntrySize;
        if (read.Bytes.size() != bytes || read.Valid.size() != bytes)
        {
            budget.Report.Collected.Unreadable += take;
            budget.Stop(kncore::Status::Partial, L"PoolTableChunkUnreadable");
            break;
        }
        for (uint64_t slot = 0; slot < take; ++slot, ++index)
        {
            const auto *raw = read.Bytes.data() + static_cast<size_t>(slot) * poolLayout.EntrySize;
            if (!std::all_of(read.Valid.begin() + static_cast<ptrdiff_t>(slot) * poolLayout.EntrySize,
                             read.Valid.begin() + static_cast<ptrdiff_t>(slot + 1) * poolLayout.EntrySize,
                             [](unsigned char valid)
                             {
                                 return valid != 0;
                             }))
            {
                ++budget.Report.Collected.Unreadable;
                continue;
            }
            kncore::BigPoolEntry entry;
            const auto kind = kncore::DecodePoolTableEntry64(raw, poolLayout, entry);
            if (kind == kncore::PoolTableEntryKind::Entry)
            {
                if (!entry.NonPagedKnown)
                {
                    // The pool class encoding is not verified for this kernel.
                    ++budget.Report.Collected.Unknown;
                }
                entries.push_back(entry);
            }
            else if (kind == kncore::PoolTableEntryKind::Invalid)
            {
                ++budget.Report.Collected.Unknown;
            }
            // Free slots are not allocations and are skipped without a gap.
        }
    }
    if (!layoutNote.empty())
    {
        budget.Report.Limitations.Push(knjson::Value(layoutNote));
    }
    if (!symbolNote.empty())
    {
        budget.Report.Limitations.Push(knjson::Value(symbolNote));
    }
    return true;
}
} // namespace

void ScanPool(Ctx &ctx)
{
    const bool payload = ctx.Args[0] == L"!payload";
    kncore::PoolDisplayOptions mode(payload);
    std::wstring tag;
    uint64_t minimum = 0;
    uint64_t maximum = UINT64_MAX;
    uint64_t display = 64;
    std::optional<uint64_t> contains;
    for (size_t i = 1; i < ctx.Args.size(); ++i)
    {
        auto option = ctx.Args[i];
        std::transform(option.begin(), option.end(), option.begin(), towlower);
        if (mode.Apply(option))
        {
            continue;
        }
        else if (option == L"/json")
        {
            ++i;
        }
        else if (i + 1 < ctx.Args.size())
        {
            const auto value = ctx.Args[++i];
            if (option == L"/tag" || option == L"/t")
            {
                tag = value;
                if (tag.size() != 4 || std::any_of(tag.begin(), tag.end(),
                                                   [](wchar_t c)
                                                   {
                                                       return c > 127;
                                                   }))
                {
                    ctx.Out.Fail(kncore::Status::InvalidInput, L"Pool tag must be exactly four ASCII bytes, matched case-sensitively");
                    return;
                }
            }
            else
            {
                uint64_t parsed = 0;
                ULONG64 address = 0;
                const bool ok = option == L"/addr" ? EvalAddress(ctx.Session, value, &address)
                                                   : kncore::ParseUnsigned(value, option == L"/limit" ? 10 : 16, &parsed);
                if (!ok || (option == L"/limit" && (parsed == 0 || parsed > 65536)))
                {
                    ctx.Out.Fail(kncore::Status::InvalidInput, L"Invalid pool option value");
                    return;
                }
                if (option == L"/min")
                {
                    minimum = parsed;
                }
                else if (option == L"/max")
                {
                    maximum = parsed;
                }
                else if (option == L"/limit")
                {
                    display = parsed;
                }
                else if (option == L"/addr")
                {
                    contains = address;
                }
                else
                {
                    ctx.Out.Fail(kncore::Status::InvalidInput, L"Unknown pool option");
                    return;
                }
            }
        }
        else
        {
            ctx.Out.Fail(kncore::Status::InvalidInput, L"Invalid pool subcommand/option");
            return;
        }
    }
    const bool summary = mode.Summary;
    const bool permissions = mode.Permissions;
    const bool full = mode.Full;
    if (minimum > maximum)
    {
        ctx.Out.Fail(kncore::Status::InvalidInput, L"Pool minimum exceeds maximum");
        return;
    }
    knengine::SessionStatus sessionStatus = {};
    ctx.Session.QueryStatus(&sessionStatus);
    const bool hostQuery = sessionStatus.Kind == knengine::SessionKind::KernelLocal;
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture,
                         hostQuery ? L"Host:SystemBigPoolInformation+TargetPageTables"
                                   : L"TargetMemory:PoolBigPageTable+TargetPageTables"))
    {
        return;
    }
    std::vector<kncore::BigPoolEntry> entries;
    kncore::WalkBudget acquisition = budget;
    if (hostQuery)
    {
        const auto native = knutil::QuerySystemInformation(0x42,
                                                           [&ctx]()
                                                           {
                                                               return ctx.Session.Cancelled();
                                                           });
        if (native.Report.State != kncore::Status::Success || !kncore::ParseBigPool64(native.Bytes, entries))
        {
            ctx.Out.Fail(native.Report.State == kncore::Status::Success ? kncore::Status::IOError : native.Report.State,
                         L"Big-pool query failed or returned an invalid/truncated native buffer", native.Report.Error);
            return;
        }
    }
    else if (!CollectTargetBigPool(ctx, acquisition, architecture, entries))
    {
        return;
    }
    budget.Report = acquisition.Report;
    if (acquisition.Stopped && acquisition.Report.State != kncore::Status::Partial)
    {
        FinishCollection(ctx, acquisition);
        ExportCollected(ctx);
        return;
    }
    if (acquisition.Stopped)
    {
        budget.Report.Limitations.Push(knjson::Value(L"Pool table acquisition stopped: " +
                                                     acquisition.Report.Collected.StopReason));
    }
    ULONG64 dtb = ctx.Session.ContextDtb();
    const bool dtbKnown = ctx.Session.HasContextDtb() || ctx.Session.ReadRegisterHex(L"cr3", &dtb);
    const auto owners = knengine::CollectOwnershipIndex(ctx.Session);
    // Build result rows from entries already read even when acquisition used
    // its entire budget. Keep the acquisition gap in the final result.
    budget.Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    budget.Report.Collected.Expected = entries.size();
    uint64_t inspectedPages = 0;
    uint64_t matching = 0;
    std::map<std::wstring, std::pair<uint64_t, uint64_t>> totals;
    struct PermissionTotals
    {
        uint64_t WxObserved = 0;
        uint64_t FullyClassified = 0;
        uint64_t Incomplete = 0;
        uint64_t InspectedPages = 0;
        uint64_t UnavailablePages = 0;
    };
    std::map<std::wstring, PermissionTotals> permissionTotals;
    for (const auto &entry : entries)
    {
        if (!CheckCollection(ctx, budget))
        {
            break;
        }
        ++budget.Report.Collected.Visited;
        ++budget.Report.Collected.Read;
        const std::wstring entryTag(entry.Tag.begin(), entry.Tag.end());
        if ((!tag.empty() && entryTag != tag) || entry.Size < minimum || entry.Size > maximum ||
            (contains && (*contains < entry.Address || *contains - entry.Address >= entry.Size)))
        {
            continue;
        }
        ++matching;
        auto &aggregate = totals[entryTag];
        if (entry.Size > UINT64_MAX - aggregate.second)
        {
            budget.Stop(kncore::Status::Partial, L"AggregateSizeOverflow");
            break;
        }
        ++aggregate.first;
        aggregate.second += entry.Size;
        auto row = knjson::Value::MakeObject();
        row.Set(L"kind", knjson::Value(L"BigPoolAllocation"));
        row.Set(L"address", knjson::Value(kncore::Hex(entry.Address)));
        row.Set(L"size", knjson::Value(std::to_wstring(entry.Size)));
        row.Set(L"tag", knjson::Value(entryTag));
        row.Set(L"nonPaged", entry.NonPagedKnown ? knjson::Value(entry.NonPaged) : knjson::Value());
        const auto owner = owners.Find(entry.Address, budget.Report.Stamp);
        row.Set(L"ownership", knjson::Value(owner.Reason));
        const auto totalPages = kncore::PoolPageCount(entry);
        uint64_t tested = 0;
        uint64_t unknown = 0;
        bool wx = false;
        if (permissions)
        {
            const uint64_t count = full ? totalPages : 1;
            for (uint64_t page = 0; page < count; ++page)
            {
                if (!CheckCollection(ctx, budget) || inspectedPages >= 65536)
                {
                    if (!budget.Stopped)
                    {
                        budget.Stop(kncore::Status::Partial, L"PageBudgetExceeded");
                    }
                    break;
                }
                ++tested;
                ++inspectedPages;
                knengine::PageWalkResult walk;
                const uint64_t va = (entry.Address & ~uint64_t(4095)) + page * 4096;
                if (!dtbKnown || !knengine::WalkPageTables(ctx.Session, architecture, va, dtb, &walk))
                {
                    ++unknown;
                }
                else
                {
                    wx = wx || (walk.EffectiveWritable && walk.EffectiveExecutable);
                }
            }
            row.Set(L"mode", knjson::Value(full ? L"AllPagesWithinGlobalBudget" : L"FirstPageSample"));
            row.Set(L"dtb", dtbKnown ? knjson::Value(kncore::Hex(dtb)) : knjson::Value());
            row.Set(L"wxObserved", tested > unknown ? knjson::Value(wx) : knjson::Value());
            row.Set(L"inspectedPages", knjson::Value(std::to_wstring(tested)));
            row.Set(L"unavailablePages", knjson::Value(std::to_wstring(unknown)));
            row.Set(L"totalPages", knjson::Value(std::to_wstring(totalPages)));
            row.Set(L"skippedPages", knjson::Value(std::to_wstring(totalPages - tested)));
            row.Set(L"rangeClassified", knjson::Value(tested == totalPages && unknown == 0));
            auto &permission = permissionTotals[entryTag];
            permission.WxObserved += wx ? 1 : 0;
            permission.FullyClassified += tested == totalPages && unknown == 0 ? 1 : 0;
            permission.Incomplete += tested != totalPages || unknown != 0 ? 1 : 0;
            permission.InspectedPages += tested;
            permission.UnavailablePages += unknown;
            if (unknown != 0 || tested != totalPages)
            {
                ++budget.Report.Collected.Unknown;
            }
        }
        if (!summary)
        {
            EmitRow(ctx, budget, row, static_cast<size_t>(display));
        }
    }
    if (summary)
    {
        for (const auto &[key, value] : totals)
        {
            auto row = knjson::Value::MakeObject();
            row.Set(L"kind", knjson::Value(L"PoolTagSummary"));
            row.Set(L"tag", knjson::Value(key));
            row.Set(L"allocationCount", knjson::Value(std::to_wstring(value.first)));
            row.Set(L"totalBytes", knjson::Value(std::to_wstring(value.second)));
            if (permissions)
            {
                const auto &permission = permissionTotals[key];
                row.Set(L"wxObservedAllocations", knjson::Value(std::to_wstring(permission.WxObserved)));
                row.Set(L"fullyClassifiedAllocations", knjson::Value(std::to_wstring(permission.FullyClassified)));
                row.Set(L"incompleteAllocations", knjson::Value(std::to_wstring(permission.Incomplete)));
                row.Set(L"inspectedPages", knjson::Value(std::to_wstring(permission.InspectedPages)));
                row.Set(L"unavailablePages", knjson::Value(std::to_wstring(permission.UnavailablePages)));
            }
            budget.Report.Rows.Push(row);
            ctx.Out.AddLine(L"[pool.tag] " + key + L" count=" + std::to_wstring(value.first) + L" bytes=" +
                            std::to_wstring(value.second) + L" (" + kncore::HumanBytes(value.second) + L")");
        }
    }
    ctx.Out.AddLine(L"[pool] totalCandidates=" + std::to_wstring(entries.size()) + L" matching=" + std::to_wstring(matching) +
                    L" inspectedPages=" + std::to_wstring(inspectedPages));
    budget.Report.Limitations.Push(knjson::Value(
        hostQuery
            ? L"Big-pool allocations only; host query and target page tables are non-atomic. W+X permissions and a matching module "
              L"alone do not identify a malicious payload. Physical width uses the architectural maximum."
            : L"Big-pool allocations only; the target PoolBigPageTable snapshot and page tables are non-atomic on a running "
              L"target. Free table slots are skipped; undecodable slots remain Unknown. W+X permissions and a matching module "
              L"alone do not identify a malicious payload."));
    if (acquisition.Stopped && !budget.Stopped)
    {
        budget.Stop(acquisition.Report.State, acquisition.Report.Collected.StopReason.c_str());
    }
    FinishCollection(ctx, budget);
    ExportCollected(ctx);
}
} // namespace kncmd
