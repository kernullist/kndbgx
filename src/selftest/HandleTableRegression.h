#pragma once

#include "CollectorRegression.h"
#include "../core/HandleTable.h"

namespace knself
{
template <typename Check> void RunHandleTableRegression(Check check)
{
    using namespace kncore;
    const TargetArchitecture architecture{IMAGE_FILE_MACHINE_AMD64, 8, 48, {}};
    const uint64_t table = 0xffff800000001000;
    const uint64_t root = 0xffff800000002000;
    const uint64_t middle = 0xffff800000003000;
    const uint64_t leaf = 0xffff800000004000;
    const uint64_t second = 0xffff800000005000;
    const uint64_t object = 0xffff800000010040;
    HandleTableLayout layout;
    layout.TableCode = FixtureField(8, 8);
    layout.NextHandle = FixtureField(0, 4);
    layout.ObjectBits = FixtureField(0, 8);
    layout.ObjectBits->BitOffset = 20;
    layout.ObjectBits->BitWidth = 44;
    layout.AccessBits = FixtureField(8, 8);
    layout.AccessBits->BitOffset = 0;
    layout.AccessBits->BitWidth = 25;
    layout.EntrySize = 16;
    layout.BodyOffset = 0x30;
    const auto page = [](ByteFixture &memory, uint64_t address)
    {
        for (unsigned offset = 0; offset < 4096; offset += 8)
        {
            memory.Put(address + offset, 0);
        }
    };
    const auto entry = [](ByteFixture &memory, uint64_t address, uint64_t pointer)
    {
        memory.Put(address, ((pointer >> 4) & 0xfffffffffff) << 20 | 0xffff);
        memory.Put(address + 8, 0xffffffff00000038);
    };
    ByteFixture memory;
    memory.Put(table, 4 * 257, 4);
    memory.Put(table + 8, root | 1);
    page(memory, root);
    page(memory, leaf);
    page(memory, second);
    memory.Put(root, leaf);
    memory.Put(root + 8, second);
    entry(memory, leaf + 16, object - 0x30);
    entry(memory, second, object - 0x30);
    WalkBudget budget;
    std::vector<TargetHandleEntry> rows;
    const auto collect = [&](const TargetHandleEntry &row)
    {
        rows.push_back(row);
        return true;
    };
    check(WalkTargetHandleTable(memory, table, layout, architecture, budget, collect) && rows.size() == 2 &&
              rows[0].Handle == 4 && rows[1].Handle == 1024 && rows[0].Object == object && rows[0].Access == 0x38 &&
              budget.Report.Collected.Visited == 256 && memory.LargestRead == 4096,
          "handles.target-two-leaves-header-offset-and-access-width");

    memory.Put(table, 8, 4);
    memory.Put(table + 8, leaf);
    entry(memory, leaf + 16, object);
    auto cid = layout;
    cid.BodyOffset = 0;
    cid.CidTable = true;
    budget = {};
    rows.clear();
    check(WalkTargetHandleTable(memory, table, cid, architecture, budget, collect) && rows.size() == 1 && rows[0].Object == object,
          "handles.cid-entries-point-directly-to-object-body");

    memory.Put(table + 8, root | 2);
    memory.Put(root, middle);
    page(memory, middle);
    memory.Put(middle, leaf);
    budget = {};
    rows.clear();
    check(WalkTargetHandleTable(memory, table, cid, architecture, budget, collect) && rows.size() == 1 && rows[0].Handle == 4,
          "handles.target-three-level-page-table");
    memory.Put(middle, root);
    budget = {};
    check(!WalkTargetHandleTable(memory, table, cid, architecture, budget, collect) &&
              budget.Report.Collected.StopReason == L"HandleTablePageInvalidOrRepeated",
          "handles.target-page-cycle-is-not-a-complete-enumeration");

    memory.Put(table + 8, leaf);
    memory.Bytes.erase(leaf + 4095);
    budget = {};
    rows.clear();
    check(!WalkTargetHandleTable(memory, table, cid, architecture, budget, collect) && rows.empty() &&
              budget.Report.Collected.Unreadable == 1 && !budget.Report.Collected.Complete,
          "handles.target-short-page-is-not-zero-filled");
    memory.Put(leaf + 4095, 0, 1);
    auto malformed = cid;
    malformed.ObjectBits->BitWidth = 43;
    const auto reads = memory.Reads;
    budget = {};
    check(!WalkTargetHandleTable(memory, table, malformed, architecture, budget, collect) && memory.Reads == reads,
          "handles.unknown-pointer-encoding-refused-before-target-read");
    memory.Put(table, 0xffffffff, 4);
    budget = {};
    check(!WalkTargetHandleTable(memory, table, cid, architecture, budget, collect) &&
              budget.Report.Collected.StopReason == L"HandleTableBoundsUnavailable",
          "handles.target-extent-overflow-refused");
    memory.Put(table, 8, 4);
    budget = {};
    budget.Cancelled = []()
    {
        return true;
    };
    rows.clear();
    check(!WalkTargetHandleTable(memory, table, cid, architecture, budget, collect) && rows.empty() &&
              budget.Report.State == Status::Cancelled,
          "handles.target-cancellation-retains-no-invented-rows");
    budget = {};
    budget.MaxNodes = 0;
    check(!WalkTargetHandleTable(memory, table, cid, architecture, budget, collect) &&
              budget.Report.Collected.StopReason == L"HandleTableBudget",
          "handles.target-global-budget-is-enforced");
    budget = {};
    budget.MaxNodes = 1;
    rows.clear();
    check(WalkTargetHandleTable(memory, table, cid, architecture, budget, collect) && rows.size() == 1 && !budget.Stopped,
          "handles.exact-node-budget-can-complete-the-table");

    struct PageFaultReader : TargetReader
    {
        ByteFixture Memory;
        Status Failure = Status::InternalFault;
        std::optional<uint64_t> FailureAddress;
        WalkBudget *ExpireBudget = nullptr;
        ReadResult Read(AddressSpace space, uint64_t address, size_t length) override
        {
            auto result = Memory.Read(space, address, length);
            if (FailureAddress ? address == *FailureAddress : length == 4096)
            {
                result.State = Failure;
                result.Error = {L"HRESULT", 0x80004005, L"ReadVirtual", L"Synthetic read failure"};
                if (ExpireBudget != nullptr)
                {
                    ExpireBudget->Deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
                }
            }
            return result;
        }
    };
    PageFaultReader fault;
    fault.Memory.Bytes = memory.Bytes;
    for (const auto failure : {Status::InternalFault, Status::EngineError, Status::Cancelled, Status::StaleContext})
    {
        fault.Failure = failure;
        budget = {};
        rows.clear();
        check(!WalkTargetHandleTable(fault, table, cid, architecture, budget, collect) &&
                  budget.Report.State == failure && rows.empty(),
              "handles.page-read-terminal-failure-is-not-downgraded");
    }
    for (const auto address : {table + 8, table})
    {
        fault.FailureAddress = address;
        for (const auto failure : {Status::InternalFault, Status::EngineError, Status::Cancelled, Status::StaleContext})
        {
            fault.Failure = failure;
            const auto before = fault.Memory.Reads;
            budget = {};
            rows.clear();
            check(!WalkTargetHandleTable(fault, table, cid, architecture, budget, collect) &&
                      budget.Report.State == failure && budget.Report.Error.Code == 0x80004005 && rows.empty() &&
                      fault.Memory.Reads - before == (address == table + 8 ? 1 : 2),
                  "handles.header-read-failure-preserves-error-and-stops-further-reads");
        }
    }
    fault.FailureAddress.reset();
    fault.Failure = Status::EngineError;
    fault.ExpireBudget = &budget;
    budget = {};
    check(!WalkTargetHandleTable(fault, table, cid, architecture, budget, collect) &&
              budget.Report.State == Status::EngineError && budget.Report.Error.Code == 0x80004005,
          "handles.read-error-is-not-hidden-by-expired-walk-budget");
    const auto cancelledReads = memory.Reads;
    budget = {};
    budget.Stop(Status::Cancelled, L"Cancelled");
    check(!WalkTargetHandleTable(memory, table, cid, architecture, budget, collect) && memory.Reads == cancelledReads &&
              budget.Report.State == Status::Cancelled,
          "handles.already-stopped-walk-does-not-read-table-metadata");

    ProcessRow active;
    active.Pid = 4;
    active.PidKnown = true;
    active.Eprocess = object;
    active.CreateTime = 100;
    active.CreateTimeKnown = true;
    Result complete;
    complete.Collected.Complete = true;
    complete.Consistency = L"stopped";
    const auto matching = CompareTargetProcessViews({active}, complete, {active}, complete);
    check(matching.State == Status::Success && matching.Rows.Items()[0].Get(L"observation").AsString(L"") == L"SameObservedIdentity" &&
              matching.Rows.Items()[0].Get(L"host").IsNull(),
          "crossview.remote-uses-two-target-identities-without-host-data");
    auto incomplete = complete;
    incomplete.State = Status::Partial;
    incomplete.Collected.Complete = false;
    const auto missing = CompareTargetProcessViews({active}, complete, {}, incomplete);
    check(missing.State == Status::Partial && missing.Rows.Items()[0].Get(L"observation").AsString(L"") == L"OtherViewIncomplete" &&
              !missing.Collected.Complete,
          "crossview.incomplete-cid-view-cannot-prove-an-absence");
    const auto candidate = CompareTargetProcessViews({}, complete, {active}, complete);
    check(candidate.Rows.Items()[0].Get(L"observation").AsString(L"") == L"CidOnlyReobserveCandidate",
          "crossview.cid-only-process-is-an-observation-candidate");
    auto reused = active;
    reused.Eprocess += 0x1000;
    check(CompareTargetProcessViews({active}, complete, {reused}, complete).Rows.Items()[0].Get(L"observation").AsString(L"") ==
              L"PidReusedOrViewsChanged",
          "crossview.pointer-identity-disagreement-is-not-a-match");
    check(CompareTargetProcessViews({active, active}, complete, {active}, complete).State == Status::Unavailable,
          "crossview.duplicate-pids-refuse-comparison");
    auto activeOnly = active;
    activeOnly.Pid = 8;
    auto cidOnly = active;
    cidOnly.Pid = 12;
    auto reusedPid = active;
    reusedPid.Pid = 16;
    auto changedIdentity = reusedPid;
    ++changedIdentity.CreateTime;
    auto unknown = active;
    unknown.Pid = 20;
    unknown.CreateTimeKnown = false;
    const std::vector<ProcessRow> activeRows = {active, activeOnly, reusedPid, unknown};
    const std::vector<ProcessRow> cidRows = {active, cidOnly, changedIdentity, unknown};
    for (const auto &comparison : {CompareTargetProcessViews(activeRows, complete, cidRows, complete),
                                   CompareProcessViews(activeRows, complete, cidRows, complete)})
    {
        const auto summary = ProcessComparisonSummary(comparison);
        check(summary.Get(L"total").AsString(L"") == L"5" && summary.Get(L"matched").AsString(L"") == L"1" &&
                  summary.Get(L"mismatchCandidates").AsString(L"") == L"3" && summary.Get(L"indeterminate").AsString(L"") == L"1",
              "crossview.summary-partitions-matches-one-sided-pid-reuse-and-unknown-identities");
    }
    const auto unknownOneSide = CompareProcessViews({}, complete, {unknown}, complete);
    check(unknownOneSide.Rows.Items()[0].Get(L"observation").AsString(L"") == L"IdentityUnknown" &&
              ProcessComparisonSummary(unknownOneSide).Get(L"mismatchCandidates").AsString(L"") == L"0" &&
              ProcessComparisonSummary(unknownOneSide).Get(L"indeterminate").AsString(L"") == L"1",
          "crossview.one-sided-unknown-identity-is-not-a-mismatch-candidate");
    const auto incompleteSummary = ProcessComparisonSummary(missing);
    check(incompleteSummary.Get(L"total").AsString(L"") == L"1" &&
              incompleteSummary.Get(L"mismatchCandidates").AsString(L"") == L"0" &&
              incompleteSummary.Get(L"indeterminate").AsString(L"") == L"1",
          "crossview.summary-keeps-incomplete-opposing-view-indeterminate");
    auto futureObservation = matching;
    auto unknownRow = knjson::Value::MakeObject();
    unknownRow.Set(L"observation", knjson::Value(L"FutureObservation"));
    futureObservation.Rows.Push(unknownRow);
    const auto futureSummary = ProcessComparisonSummary(futureObservation);
    check(futureSummary.Get(L"total").AsString(L"") == L"2" && futureSummary.Get(L"matched").AsString(L"") == L"1" &&
              futureSummary.Get(L"indeterminate").AsString(L"") == L"1" && matching.Rows.Items().size() == 1,
          "crossview.summary-keeps-unknown-observations-and-original-capture");
    const auto emptySummary = ProcessComparisonSummary(Result{});
    check(emptySummary.Get(L"total").AsString(L"") == L"0" && emptySummary.Get(L"matched").AsString(L"") == L"0" &&
              emptySummary.Get(L"mismatchCandidates").AsString(L"") == L"0" &&
              emptySummary.Get(L"indeterminate").AsString(L"") == L"0",
          "crossview.empty-summary-has-four-explicit-counts");
    for (const auto failure : {Status::InternalFault, Status::EngineError, Status::Cancelled, Status::StaleContext})
    {
        incomplete.State = failure;
        const auto failed = CompareTargetProcessViews({active}, complete, {}, incomplete);
        check(failed.State == failure && !failed.Collected.Complete && failed.Rows.Items().size() == 1,
              "crossview.failed-input-preserves-terminal-state-and-observed-rows");
        check(CompareTargetProcessViews({active, active}, complete, {}, incomplete).State == failure &&
                  CompareTargetProcessViews({}, incomplete, {active, active}, complete).State == failure,
              "crossview.invalid-identities-do-not-mask-terminal-input-failure");
    }
}
} // namespace knself
