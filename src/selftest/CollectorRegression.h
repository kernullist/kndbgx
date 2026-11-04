#pragma once

#include "../core/ProcessViews.h"
#include "../core/Vad.h"
#include "../core/ObjectRead.h"
#include "../cmd/ProcCollect.h"

namespace knself
{
class ByteFixture final : public kncore::TargetReader
{
  public:
    std::map<uint64_t, unsigned char> Bytes;
    size_t Reads = 0;
    size_t LargestRead = 0;
    std::function<void()> BeforeRead;

    void Put(uint64_t address, uint64_t value, size_t length = 8)
    {
        for (size_t i = 0; i < length; ++i)
        {
            Bytes[address + i] = static_cast<unsigned char>(value >> (8 * i));
        }
    }
    void Text(uint64_t address, const std::string &text, size_t width)
    {
        for (size_t i = 0; i < width; ++i)
        {
            Bytes[address + i] = i < text.size() ? static_cast<unsigned char>(text[i]) : 0;
        }
    }
    kncore::ReadResult Read(kncore::AddressSpace space, uint64_t address, size_t length) override
    {
        ++Reads;
        LargestRead = (std::max)(LargestRead, length);
        if (BeforeRead)
        {
            BeforeRead();
        }
        kncore::ReadResult read;
        read.Space = space;
        read.Address = address;
        read.Requested = length;
        read.Bytes.resize(length);
        read.Valid.resize(length);
        for (size_t i = 0; i < length; ++i)
        {
            if (const auto found = Bytes.find(address + i); found != Bytes.end())
            {
                read.Bytes[i] = found->second;
                read.Valid[i] = 1;
                ++read.Transferred;
            }
        }
        read.State = read.Transferred == length ? kncore::Status::Success : kncore::Status::Partial;
        return read;
    }
};

inline kncore::FieldInfo FixtureField(uint32_t offset, uint32_t size)
{
    kncore::FieldInfo field;
    field.Offset = offset;
    field.Size = size;
    field.Kind = kncore::FieldKind::Unsigned;
    return field;
}

template <typename Check> void RunCollectorRegression(Check check)
{
    ByteFixture sparse;
    sparse.Put(0x1000, 0);
    sparse.Put(0x1010, 0xffff800000002000);
    const kncore::TargetArchitecture sparseArchitecture{IMAGE_FILE_MACHINE_AMD64, 8, 48, {}};
    const auto slot = kncore::FindSparsePointerSlot(
        sparse, 0x1000, 3, sparseArchitecture,
        [](unsigned index, uint64_t object)
        {
            return index == 2 && object == 0xffff800000002000;
        },
        []()
        {
            return false;
        });
    check(slot == 2U && sparse.Reads == 3, "object.sparse-type-table-survives-null-and-unreadable-slots");
    const size_t beforeSparse = sparse.Reads;
    check(!kncore::FindSparsePointerSlot(
              sparse, UINT64_MAX - 7, 3, sparseArchitecture,
              [](unsigned, uint64_t)
              {
                  return true;
              },
              []()
              {
                  return false;
              }) &&
              sparse.Reads == beforeSparse,
          "object.sparse-type-table-overflow-rejected-before-read");
    using namespace kncore;
    constexpr uint64_t head = 0xffff800000001000;
    constexpr uint64_t process = 0xffff800000002000;
    TargetArchitecture architecture{0x8664, 8, 48, 52};
    ProcessLayout layout;
    layout.Links = FixtureField(0x20, 16);
    layout.Pid = FixtureField(0, 8);
    layout.CreateTime = FixtureField(8, 8);
    layout.Dtb = FixtureField(16, 8);
    layout.Image = FixtureField(0x40, 15);
    ByteFixture memory;
    memory.Put(head, process + 0x20);
    memory.Put(head + 8, process + 0x20);
    memory.Put(process, 123);
    memory.Put(process + 8, 999);
    memory.Put(process + 16, 0x1000);
    memory.Put(process + 0x20, head);
    memory.Put(process + 0x28, head);
    memory.Text(process + 0x40, "LongProcessName", 15);
    std::vector<ProcessRow> rows;
    WalkBudget budget;
    check(CollectProcessList(memory, head, layout, architecture, budget, rows) && rows.size() == 1 && rows[0].Image == L"LongProcessName" &&
              rows[0].CreateTime == 999 && budget.Report.Collected.Complete,
          "proc.actual-reader-exact-15-byte-image-offset-zero");
    ProcessRow pid;
    ProcessRow address;
    check(SelectProcess(rows, L"pid:123", &pid, true) && SelectProcess(rows, L"eprocess:ffff800000002000", &address, true) &&
              pid.DirectoryTableBase == address.DirectoryTableBase && pid.CreateTime == address.CreateTime,
          "proc.pid-address-same-identity-dtb");
    check(!SelectProcess(rows, L"eprocess:ffff800000009000", &address, true) && !SelectProcess(rows, L"pid:123junk", &pid, true),
          "proc.no-fabricated-record-or-partial-number");
    Result selectedReport;
    SetSelectedProcessCoverage(pid, selectedReport);
    check(selectedReport.State == Status::Success && selectedReport.Collected.Complete && selectedReport.Collected.Unknown == 0,
          "proc.selected-complete-record-reports-complete-coverage");
    memory.Bytes.erase(process + 8);
    WalkBudget partialSelection;
    std::vector<ProcessRow> partialRows;
    ProcessRow partialSelected;
    const bool partialRead = !CollectProcessList(memory, head, layout, architecture, partialSelection, partialRows);
    const bool partialMatch = SelectProcess(partialRows, L"pid:123", &partialSelected, partialSelection.Report.Collected.Complete);
    SetSelectedProcessCoverage(partialSelected, selectedReport);
    check(partialRead && partialMatch && !partialSelected.CreateTimeKnown && partialSelected.PidKnown &&
              partialSelected.ToJson().Get(L"createTime").IsNull() && selectedReport.State == Status::Partial &&
              !selectedReport.Collected.Complete && selectedReport.Collected.Unknown == 1 &&
              selectedReport.Collected.StopReason == L"ProcessFieldsUnavailable",
          "proc.selected-partial-record-does-not-become-success");
    memory.Put(process + 8, 999);
    check(SelectProcess(rows, L"image:LONGprocess", &pid, true), "proc.case-insensitive-selector");
    rows.push_back(rows.front());
    check(!SelectProcess(rows, L"image:long", &pid, true), "proc.ambiguous-name-rejected");
    memory.Bytes.erase(process);
    budget = {};
    check(!CollectProcessList(memory, head, layout, architecture, budget, rows) && !rows[0].PidKnown &&
              rows[0].ToJson().Get(L"pid").IsNull() && budget.Report.State == Status::Partial,
          "proc.unreadable-pid-null-not-zero");
    memory.Put(process, 123);
    memory.Put(process + 0x20, process + 0x20);
    budget = {};
    check(!CollectProcessList(memory, head, layout, architecture, budget, rows) &&
              budget.Report.Collected.StopReason == L"CycleOrRepeatedNode",
          "proc.cycle-partial");
    pid.Eprocess = 0;
    check(!SelectProcess(rows, L"image:long", &pid, budget.Report.Collected.Complete) &&
              !SelectProcess(rows, L"LongProcessName", &pid, budget.Report.Collected.Complete) && pid.Eprocess == 0,
          "proc.partial-inventory-cannot-prove-unique-name");
    check(SelectProcess(rows, L"pid:123", &pid, budget.Report.Collected.Complete) && pid.Eprocess == process &&
              SelectProcess(rows, L"123", &pid, budget.Report.Collected.Complete) && pid.Eprocess == process &&
              SelectProcess(rows, L"eprocess:ffff800000002000", &address, budget.Report.Collected.Complete) && address.Eprocess == process &&
              SelectProcess(rows, L"ffff800000002000", &address, budget.Report.Collected.Complete) && address.Eprocess == process,
          "proc.partial-inventory-keeps-observed-numeric-selectors");
    memory.Put(process + 0x20, head);
    memory.Put(process + 0x28, 0);
    budget = {};
    check(!CollectProcessList(memory, head, layout, architecture, budget, rows) && rows.empty(), "proc.backlink-corruption");
    memory.Put(process + 0x28, head);
    budget = {};
    budget.MaxNodes = 0;
    check(!CollectProcessList(memory, head, layout, architecture, budget, rows) && !budget.Report.Collected.Complete,
          "proc.global-budget-not-complete");

    auto missingLayout = layout;
    missingLayout.Links.reset();
    missingLayout.LinksDiagnostic = L"DIA provider unavailable: loader=126";
    budget = {};
    const auto beforeMissingLayout = memory.Reads;
    check(!CollectProcessList(memory, head, missingLayout, architecture, budget, rows) && rows.empty() &&
              memory.Reads == beforeMissingLayout && budget.Report.State == Status::Unavailable &&
              budget.Report.Collected.StopReason == L"ProcessListLayoutUnavailable" &&
              budget.Report.Error.Message.find(L"DIA provider unavailable: loader=126") != std::wstring::npos,
          "proc.missing-layout-preserves-provider-failure-before-memory-read");
    missingLayout.Links = FixtureField(0x20, 8);
    budget = {};
    check(!CollectProcessList(memory, head, missingLayout, architecture, budget, rows) && memory.Reads == beforeMissingLayout &&
              budget.Report.Error.Message.find(L"storage size") != std::wstring::npos &&
              budget.Report.Error.Message.find(L"DIA provider") == std::wstring::npos,
          "proc.wrong-link-width-reports-metadata-conflict");
    budget = {};
    budget.Deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    check(CollectProcessList(memory, head, layout, architecture, budget, rows) && rows.size() == 1 && budget.Report.Collected.Complete,
          "proc.symbol-discovery-does-not-consume-traversal-budget");
    budget = {};
    budget.StartTraversal(std::chrono::steady_clock::now() - std::chrono::seconds(6));
    check(!CollectProcessList(memory, head, layout, architecture, budget, rows) && rows.empty() &&
              budget.Report.Collected.StopReason == L"GlobalWalkBudget",
          "proc.started-traversal-budget-is-not-renewed");

    ByteFixture inventory;
    constexpr size_t processCount = 128;
    for (size_t i = 0; i < processCount; ++i)
    {
        const uint64_t object = process + i * 0x1000;
        inventory.Text(object, "", 0x80);
        inventory.Put(object, 1000 + i);
        inventory.Put(object + 8, 2000 + i);
        inventory.Put(object + 16, 0x1000 * (i + 1));
        inventory.Put(object + 0x20, i + 1 == processCount ? head : object + 0x1020);
        inventory.Put(object + 0x28, i == 0 ? head : object - 0x1000 + 0x20);
        inventory.Text(object + 0x40, "Process" + std::to_string(i), 15);
    }
    inventory.Put(head, process + 0x20);
    inventory.Put(head + 8, process + (processCount - 1) * 0x1000 + 0x20);
    budget = {};
    check(CollectProcessList(inventory, head, layout, architecture, budget, rows) && rows.size() == processCount &&
              budget.Report.Collected.Complete && budget.Report.Collected.Visited == processCount &&
              rows.back().Pid == 1127 && rows.back().CreateTime == 2127 && rows.back().Image == L"Process127" &&
              rows.back().DirectoryTableBase == 0x80000 && inventory.Reads <= 2 + 2 * processCount,
          "proc.remote-inventory-bounds-read-round-trips-without-losing-records");

    bool selectionCancelled = false;
    inventory.Reads = 0;
    inventory.BeforeRead = [&]()
    {
        selectionCancelled = inventory.Reads >= 10;
    };
    budget = {};
    budget.Cancelled = [&]()
    {
        return selectionCancelled;
    };
    check(!CollectProcessList(inventory, head, layout, architecture, budget, rows) &&
              budget.Report.State == Status::Cancelled && !budget.Report.Rows.Items().empty(),
          "proc.selection-cancel-fixture-retains-prerequisite-process-rows");
    kncmd::CmdText failedInventory;
    failedInventory.Details = budget.Report;
    failedInventory.Details.CommandId = L"!dml_proc";
    failedInventory.Details.RequestId = L"inventory-request";
    failedInventory.Details.Stamp.SessionId = L"selection-session";
    failedInventory.Details.Stamp.StopEpoch = 7;
    failedInventory.Details.Source = L"TargetMemory:PsActiveProcessHead";
    failedInventory.Details.Consistency = L"stopped";
    failedInventory.Details.LayoutProfile = L"fixture-layout";
    failedInventory.Details.Findings.Push(knjson::Value(L"inventory-only finding"));
    failedInventory.AddLine(L"[proc.coverage] Cancelled");
    kncmd::CmdText selectedCommand;
    selectedCommand.Details.CommandId = L"!threads";
    selectedCommand.Details.RequestId = L"thread-request";
    kncmd::ReportProcessSelectionFailure(failedInventory, selectedCommand);
    check(selectedCommand.Details.Rows.Items().empty() && selectedCommand.Details.Findings.Items().empty() &&
              selectedCommand.Details.CommandId == L"!threads" && selectedCommand.Details.RequestId == L"thread-request" &&
              !failedInventory.Details.Rows.Items().empty(),
          "proc.selection-cancel-does-not-publish-inventory-as-command-records");
    check(selectedCommand.Details.State == Status::Cancelled && !selectedCommand.Details.Collected.Complete &&
              selectedCommand.Details.Collected.StopReason == L"Cancelled" &&
              selectedCommand.Details.Collected.Visited == failedInventory.Details.Collected.Visited &&
              selectedCommand.Details.Stamp == failedInventory.Details.Stamp &&
              selectedCommand.Details.Source == failedInventory.Details.Source &&
              selectedCommand.Details.LayoutProfile == failedInventory.Details.LayoutProfile &&
              failedInventory.Details.Limitations.Items().empty() && failedInventory.Details.Findings.Items().size() == 1 &&
              selectedCommand.Text().find(L"[proc.coverage] Cancelled") != std::wstring::npos,
          "proc.selection-cancel-preserves-cause-coverage-and-context");
    kncmd::CmdText filteredInventory = failedInventory;
    kncmd::ReportProcessSelectionFailure(filteredInventory, filteredInventory);
    check(filteredInventory.Details.State == Status::Cancelled && filteredInventory.Details.Rows.Items().empty() &&
              filteredInventory.Details.CommandId == L"!dml_proc" &&
              filteredInventory.Details.RequestId == failedInventory.Details.RequestId &&
              filteredInventory.Text() == failedInventory.Text(),
          "proc.filtered-inventory-cancel-keeps-diagnostics-once-without-unselected-rows");

    for (const bool complete : {true, false})
    {
        for (const auto *selector : {L"pid:4294967295", L"image:Process"})
        {
            kncmd::CmdText lookup;
            lookup.Details = failedInventory.Details;
            lookup.Details.State = complete ? Status::Success : Status::Partial;
            lookup.Details.Collected.Complete = complete;
            lookup.Details.Collected.StopReason = complete ? L"ListSentinel" : L"GlobalWalkBudget";
            lookup.AddLine(L"[proc.coverage] " + lookup.Details.Collected.StopReason);
            ProcessRow absent;
            const bool resolved = SelectProcess(rows, selector, &absent, complete);
            kncmd::CmdText dependent;
            dependent.Details.CommandId = L"!threads";
            dependent.Details.RequestId = L"dependent-request";
            kncmd::ReportProcessSelectionFailure(lookup, dependent, selector);
            kncmd::ReportProcessSelectionFailure(lookup, lookup, selector);
            check(!resolved && dependent.Details.Rows.Items().empty() && lookup.Details.Rows.Items().empty() &&
                      lookup.Details.Findings.Items().empty() && !lookup.Details.Collected.Complete &&
                      lookup.Details.State == (complete ? Status::InvalidInput : Status::Unavailable) &&
                      dependent.Details.State == lookup.Details.State &&
                      dependent.Details.CommandId == L"!threads" && dependent.Details.RequestId == L"dependent-request" &&
                      dependent.Details.Collected.Visited == failedInventory.Details.Collected.Visited &&
                      dependent.Details.Collected.StopReason == lookup.Details.Collected.StopReason &&
                      dependent.Details.Stamp == failedInventory.Details.Stamp &&
                      lookup.Details.Error.Message.find(selector) != std::wstring::npos &&
                      dependent.Text().find(L"[proc.coverage]") != std::wstring::npos,
                  complete ? "proc.absent-or-ambiguous-selection-has-no-unselected-rows"
                           : "proc.unresolved-partial-selection-keeps-coverage-without-unselected-rows");
        }
    }
    kncmd::CmdText emptyInventory;
    emptyInventory.Details.Collected.Complete = true;
    kncmd::ReportProcessSelectionFailure(emptyInventory, emptyInventory, L"pid:123");
    check(emptyInventory.Details.State == Status::InvalidInput && emptyInventory.Details.Rows.Items().empty() &&
              !emptyInventory.Details.Collected.Complete,
          "proc.empty-inventory-selector-is-not-a-successful-match");
    for (const auto state : {Status::Cancelled, Status::StaleContext, Status::Unavailable})
    {
        auto failure = failedInventory;
        failure.Details.State = state;
        failure.Details.Error = {L"fixture", 23, L"ProcessSelection", L"prerequisite failure"};
        const auto original = failure.Details.ToJson().Write();
        kncmd::CmdText requested;
        requested.Details.CommandId = L"!vad";
        kncmd::ReportProcessSelectionFailure(failure, requested, L"image:Process");
        check(requested.Details.State == state && requested.Details.Rows.Items().empty() &&
                  requested.Details.Error.ToJson().Write() == failure.Details.Error.ToJson().Write() &&
                  requested.Details.Collected.ToJson().Write() == failure.Details.Collected.ToJson().Write() &&
                  requested.Details.Consistency == failure.Details.Consistency &&
                  failure.Details.ToJson().Write() == original,
              "proc.selection-preserves-prerequisite-failure-instead-of-reporting-a-lookup-miss");
    }
    inventory.BeforeRead = {};

    inventory.Put(head + 8, process + 0x20);
    inventory.Put(process + 0x20, head);
    inventory.Bytes.erase(process + 0x18);
    budget = {};
    check(CollectProcessList(inventory, head, layout, architecture, budget, rows) && rows.size() == 1 &&
              rows[0].Pid == 1000 && rows[0].Image == L"Process0" && budget.Report.Collected.Complete,
          "proc.unreadable-padding-falls-back-to-readable-fields");
    inventory.Put(process + 0x18, 0);
    inventory.Bytes.erase(process + 8);
    budget = {};
    check(!CollectProcessList(inventory, head, layout, architecture, budget, rows) && rows.size() == 1 &&
              !rows[0].CreateTimeKnown && rows[0].PidKnown && rows[0].ImageKnown &&
              budget.Report.Collected.StopReason == L"ProcessFieldsUnavailable",
          "proc.short-record-does-not-promote-unreadable-fields-to-known");
    inventory.Put(process + 8, 2000);

    auto distantLayout = layout;
    distantLayout.Image = FixtureField(0x100000, 15);
    inventory.Text(process + 0x100000, "Distant", 15);
    inventory.LargestRead = 0;
    budget = {};
    check(CollectProcessList(inventory, head, distantLayout, architecture, budget, rows) && rows[0].Image == L"Distant" &&
              inventory.LargestRead <= 16,
          "proc.distant-layout-fields-never-trigger-unbounded-prefetch");

    bool cancelledRead = false;
    inventory.Reads = 0;
    inventory.BeforeRead = [&]()
    {
        cancelledRead = inventory.Reads >= 3;
    };
    budget = {};
    budget.Cancelled = [&]()
    {
        return cancelledRead;
    };
    check(!CollectProcessList(inventory, head, layout, architecture, budget, rows) &&
              budget.Report.State == Status::Cancelled && !budget.Report.Collected.Complete && rows.empty() && inventory.Reads == 3,
          "proc.cancel-during-final-record-does-not-complete-or-issue-more-reads");
    inventory.BeforeRead = {};
    inventory.Reads = 0;
    budget = {};
    budget.MaxNodes = 0;
    check(!CollectProcessList(inventory, head, layout, architecture, budget, rows) && rows.empty() && inventory.Reads == 2,
          "proc.exhausted-node-budget-does-not-prefetch-records");

    inventory.BeforeRead = [&]()
    {
        if (inventory.Reads >= 3)
        {
            budget.Deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
        }
    };
    inventory.Reads = 0;
    budget = {};
    check(!CollectProcessList(inventory, head, layout, architecture, budget, rows) && !budget.Report.Collected.Complete &&
              budget.Report.Collected.StopReason == L"GlobalWalkBudget",
          "proc.expiry-during-final-record-does-not-report-complete");
    inventory.Reads = 0;
    budget = {};
    inventory.BeforeRead = [&]()
    {
        if (inventory.Reads == 3)
        {
            budget.Deadline -= std::chrono::seconds(6);
        }
    };
    check(CollectProcessList(inventory, head, layout, architecture, budget, rows) && rows.size() == 1 &&
              budget.Report.Collected.Complete,
          "proc.remote-first-record-latency-can-exceed-general-scanner-budget");
    const auto inventoryDeadline = budget.Deadline;
    budget.StartTraversal(std::chrono::steady_clock::now() + std::chrono::minutes(1), std::chrono::seconds(30));
    check(budget.Deadline == inventoryDeadline && inventoryDeadline <= std::chrono::steady_clock::now() + std::chrono::seconds(30),
          "proc.inventory-deadline-is-bounded-and-never-renewed");
    inventory.BeforeRead = {};

    VadLayout vad;
    vad.Node = FixtureField(0, 24);
    vad.Left = FixtureField(0, 8);
    vad.Right = FixtureField(8, 8);
    vad.Start = FixtureField(24, 4);
    vad.End = FixtureField(28, 4);
    vad.StartHigh = FixtureField(32, 1);
    vad.EndHigh = FixtureField(33, 1);
    vad.Protection = FixtureField(48, 4);
    vad.Protection->BitOffset = 7;
    vad.Protection->BitWidth = 5;
    constexpr uint64_t node = 0xffff800000003000;
    memory.Put(node, 0);
    memory.Put(node + 8, 0);
    memory.Put(node + 24, 0, 4);
    memory.Put(node + 28, 2, 4);
    memory.Put(node + 32, 0, 1);
    memory.Put(node + 33, 0, 1);
    memory.Put(node + 48, 0, 4);
    std::vector<uint32_t> protections{1, 2, 0x10, 0x20, 4, 8, 0x40, 0x80};
    auto record = ReadVad(memory, node, vad, protections);
    check(record.Start == 0 && record.End == 0x2fff && record.ProtectionIndex == 0 && ExecutableProtection(record.PageProtection) == false,
          "vad.protection-zero-and-zero-start-retained");
    memory.Put(node + 48, 7 << 7, 4);
    record = ReadVad(memory, node, vad, protections);
    check(record.ProtectionIndex == 7 && ExecutableProtection(record.PageProtection) == true,
          "vad.pdb-bit-seven-and-execute-copy-on-write");
    check(!ExecutableProtection(ReadVad(memory, node, vad, {}).PageProtection).has_value(), "vad.missing-mapping-is-unknown");
    memory.Bytes.erase(node + 33);
    check(!ReadVad(memory, node, vad, protections).End, "vad.unreadable-high-vpn-not-zero");
    memory.Put(node + 33, 0, 1);
    memory.Put(node, node);
    budget = {};
    unsigned visited = 0;
    WalkVadTree(memory, node, vad, architecture, protections, budget,
                [&](const VadRow &)
                {
                    ++visited;
                    return true;
                });
    check(visited == 1 && budget.Report.State == Status::Partial, "vad.cycle-budget-production-walk");
    memory.Put(node, 0);
    memory.Bytes.erase(node + 8);
    budget = {};
    WalkVadTree(memory, node, vad, architecture, protections, budget,
                [](const VadRow &)
                {
                    return true;
                });
    check(budget.Report.Collected.Unreadable == 1 && !budget.Report.Collected.Complete, "vad.unreadable-child-not-empty-subtree");

    std::vector<unsigned char> nativeHandles(16 + 3 * 40);
    uint64_t count = 3;
    std::memcpy(nativeHandles.data(), &count, 8);
    for (size_t i = 0; i < 3; ++i)
    {
        const uint16_t type = static_cast<uint16_t>(i + 5);
        const uint32_t access = 0x38;
        std::memcpy(nativeHandles.data() + 16 + i * 40 + 30, &type, 2);
        std::memcpy(nativeHandles.data() + 16 + i * 40 + 24, &access, 4);
    }
    std::vector<HandleEntry> handles;
    check(ParseExtendedHandles64(nativeHandles, handles) && handles.size() == 3 && ProcessVmAccess(handles[0], 5) &&
              !ProcessVmAccess(handles[1], 5) && !ProcessVmAccess(handles[2], 5),
          "handles.file-thread-bits-not-process-vm-access");
    handles[0].OwnerPid = 123;
    check(HandleMatches(handles[0], 456, 123, 456) && !HandleMatches(handles[0], 456, {}, 123) && !HandleMatches(handles[0], {}, {}, 456),
          "handles.owner-target-independent-and-unknown");
    nativeHandles.pop_back();
    check(!ParseExtendedHandles64(nativeHandles, handles), "handles.truncated-count-rejected-not-clamped");

    ProcessRow kernel;
    ReadProcess(memory, process, layout, kernel);
    ProcessRow host = kernel;
    Result complete;
    complete.Collected.Complete = true;
    Result failed;
    failed.State = Status::Unavailable;
    check(CompareProcessViews({kernel}, complete, {}, failed).Rows.Items().empty() &&
              CompareProcessViews({kernel}, complete, {}, failed).State == Status::Unavailable,
          "crossview.toolhelp-failure-not-ghosts");
    auto partial = complete;
    partial.State = Status::Partial;
    partial.Collected.Complete = false;
    check(CompareProcessViews({kernel}, partial, {host}, complete).State == Status::Unavailable, "crossview.partial-kernel-unavailable");
    ++host.CreateTime;
    check(CompareProcessViews({kernel}, complete, {host}, complete).Rows.Items()[0].Get(L"observation").AsString(L"") ==
              L"PidReusedOrViewsChanged",
          "crossview.pid-reuse-not-same-identity");
    check(CompareProcessViews({kernel}, complete, {}, complete).Rows.Items()[0].Get(L"observation").AsString(L"") ==
              L"KernelOnlyReobserveCandidate",
          "crossview.exit-race-only-candidate");
    host.CreateTimeKnown = false;
    const auto unknownIdentity = CompareProcessViews({kernel}, complete, {host}, complete);
    check(unknownIdentity.State == Status::Partial && !unknownIdentity.Collected.Complete && unknownIdentity.Collected.Unknown == 1 &&
              unknownIdentity.Rows.Items().size() == 1,
          "crossview.missing-instance-identity-not-complete");
    check(CompareProcessViews({}, complete, {host}, complete).State == Status::Partial,
          "crossview.one-sided-unknown-identity-remains-partial");

    check(NormalizeDriverName(L"kbdclass") == NormalizeDriverName(L"\\Driver\\kbdclass") && !NormalizeDriverName(L"\\Device\\kbdclass"),
          "driver.normalization-no-double-prefix");
    memory.Put(node + 64, 0xabcdef1234567890);
    check(ReadField(memory, node, FixtureField(64, 4)) == 0x34567890, "driver.ULONG-size-excludes-adjacent-flags");
    memory.Put(node, 3, 2);
    memory.Put(node + 2, 4, 2);
    memory.Put(node + 8, node + 100);
    std::wstring unicode;
    check(!ReadUnicodeValue(memory, node, FixtureField(0, 2), FixtureField(2, 2), FixtureField(8, 8), architecture, &unicode),
          "object.odd-unicode-length-rejected");
    memory.Put(node, 4, 2);
    memory.Put(node + 100, 0x00420041, 4);
    check(ReadUnicodeValue(memory, node, FixtureField(0, 2), FixtureField(2, 2), FixtureField(8, 8), architecture, &unicode) &&
              unicode == L"AB",
          "object.typed-unicode-exact-positive");
    memory.Bytes.erase(node + 102);
    check(!ReadUnicodeValue(memory, node, FixtureField(0, 2), FixtureField(2, 2), FixtureField(8, 8), architecture, &unicode),
          "object.partial-unicode-not-zero-filled");
    memory.Put(node + 8, 0x1000);
    memory.Put(0x1000, 0x00420041, 4);
    const auto readsBeforeUserBuffer = memory.Reads;
    check(!ReadUnicodeValue(memory, node, FixtureField(0, 2), FixtureField(2, 2), FixtureField(8, 8), architecture, &unicode) &&
              memory.Reads == readsBeforeUserBuffer + 3,
          "object.kernel-name-rejects-user-buffer-before-reading");
    const auto readsBeforeUserObject = memory.Reads;
    check(!ReadUnicodeValue(memory, 0x1000, FixtureField(0, 2), FixtureField(2, 2), FixtureField(8, 8), architecture, &unicode) &&
              memory.Reads == readsBeforeUserObject,
          "object.kernel-name-rejects-user-descriptor-before-reading");
}
} // namespace knself
