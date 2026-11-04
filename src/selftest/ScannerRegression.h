#pragma once

#include "CollectorRegression.h"
#include "../core/ScannerRules.h"
#include "../core/KernelAnalysis.h"
#include "../core/Pool.h"
#include "../core/PeIdentity.h"
#include "../core/HashCatalog.h"
#include "../core/Epochs.h"
#include "../cmd/Dispatcher.h"

namespace knself
{
template <typename Check> void RunScannerRegression(Check check)
{
    using namespace kncore;
    check(MinifilterMajorName(0) == L"IRP_MJ_CREATE" && MinifilterMajorName(3) == L"IRP_MJ_READ" &&
              MinifilterMajorName(4) == L"IRP_MJ_WRITE" && MinifilterMajorName(0x1b) == L"IRP_MJ_PNP",
          "minifilter.standard-irp-majors-have-prefixed-names");
    check(MinifilterMajorName(0xff) == L"IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION" &&
              MinifilterMajorName(0xf9) == L"IRP_MJ_QUERY_OPEN" &&
              MinifilterMajorName(0xf3) == L"IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE" &&
              MinifilterMajorName(0xec) == L"IRP_MJ_VOLUME_DISMOUNT" && MinifilterMajorName(0x80) == L"IRP_MJ_OPERATION_END",
          "minifilter.fltmgr-byte-codes-and-end-marker-are-distinct");
    check(MinifilterMajorName(0xf8) == L"IRP_MJ_UNKNOWN (248)" && MinifilterMajorName(0x1c) == L"IRP_MJ_UNKNOWN (28)" &&
              MinifilterMajorName(0x100) == L"IRP_MJ_UNKNOWN (256)",
          "minifilter.reserved-and-out-of-range-codes-retain-their-number");
    std::array<unsigned char, 16> gate = {0x34, 0x12, 0x10, 0, 0, 0x8e, 0x78, 0x56, 0x98, 0xba, 0xff, 0xff};
    check(DecodeIdt(gate).Valid && DecodeIdt(gate).Handler == 0xffffba9856781234ULL, "idt.product-hardware-gate-positive");
    gate[12] = 1;
    check(!DecodeIdt(gate).Valid, "idt.reserved-present-gate-invalid");
    gate[5] = 0;
    check(DecodeIdt(gate).Valid && !DecodeIdt(gate).Present, "idt.nonpresent-is-absence-not-hook");
    check(!DecodeIdt(std::span(gate).first(15)).Valid, "idt.short-gate-no-zero-fill");
    check(DecodeServiceEntry(0x1000, -0x101) == 0xfefULL, "ssdt.signed-arithmetic-shift-negative");
    check(!DecodeServiceEntry(0, -16) && !DecodeServiceEntry(UINT64_MAX, 16), "ssdt.address-overflow-rejected");

    FieldInfo array;
    array.Kind = FieldKind::Array;
    array.Offset = 512;
    array.Size = 16384;
    array.ArrayCount = 2;
    array.ElementSize = 8192;
    array.ArrayDimensions = {2, 256};
    array.LeafElementSize = 32;
    array.LeafKind = FieldKind::Composite;
    check(array.ValidFor(16920) && ArrayElement(array, 511, true)->Offset == 512 + 511 * 32 && !ArrayElement(array, 512, true),
          "timer.two-dimensional-PDB-leaf-stride-bounds");
    check(ArrayElement(array, 1)->Size == 8192 && !ArrayElement(array, 2), "layout.immediate-and-leaf-array-distinct");
    check(ArrayElement(array, 1)->Kind == FieldKind::Array && ArrayElement(array, 1)->ArrayCount == 256u &&
              ArrayElement(array, 511, true)->Kind == FieldKind::Composite,
          "review.array-selection-retains-nesting-and-leaf-kind");
    array.ArrayDimensions[1] = 255;
    check(!array.ValidFor(16920), "layout.array-dimensions-inconsistent-rejected");
    check(!ArrayElement(array, 511, true), "review.array-selection-rejects-inconsistent-dimensions");
    array.ArrayDimensions = {4, 128};
    check(!array.ValidFor(16920) && !ArrayElement(array, 1), "review.array-immediate-count-must-match-first-dimension");

    auto outer = FixtureField(32, 16);
    auto member = FixtureField(4, 4);
    outer.Kind = FieldKind::Composite;
    check(NestedField(outer, member) && NestedField(outer, member)->Offset == 36, "review.nested-composite-retains-member-offset");
    outer.Kind = FieldKind::Pointer;
    check(!NestedField(outer, member), "review.nested-pointer-is-not-inline-storage");
    outer.Kind = FieldKind::Unsigned;
    check(!NestedField(outer, member), "review.nested-scalar-is-not-inline-storage");
    outer.Kind = FieldKind::Unknown;
    check(!NestedField(outer, member), "review.nested-unknown-kind-is-not-inline-storage");
    outer.Kind = FieldKind::Composite;
    outer.BitOffset = 0;
    outer.BitWidth = 8;
    check(!NestedField(outer, member), "review.nested-bitfield-is-not-inline-storage");

    constexpr uint64_t node = 0xffff800000010000ULL;
    TargetArchitecture architecture{0x8664, 8, 48, 52};
    const auto ready = std::chrono::steady_clock::now();
    WalkBudget delayedLayout;
    delayedLayout.Deadline = ready - std::chrono::seconds(1);
    check(delayedLayout.Consume(node, architecture), "walk.first-node-starts-budget-after-layout-discovery");
    WalkBudget expiredWalk;
    expiredWalk.StartTraversal(ready - std::chrono::seconds(6));
    check(!expiredWalk.Consume(node, architecture) && expiredWalk.Report.Collected.StopReason == L"GlobalWalkBudget",
          "walk.first-node-does-not-renew-an-already-started-budget");
    WalkBudget delayedCpu;
    delayedCpu.Deadline = ready - std::chrono::seconds(1);
    delayedCpu.StartTraversal(ready);
    check(delayedCpu.Consume(node, architecture), "cpu.budget-starts-after-delayed-processor-mapping");
    delayedCpu.StartTraversal(ready + std::chrono::seconds(20));
    check(delayedCpu.Deadline == ready + std::chrono::seconds(5), "cpu.later-processors-do-not-renew-budget");
    delayedCpu.Stop(Status::Partial, L"CollectionBudget");
    delayedCpu.StartTraversal(ready + std::chrono::seconds(30));
    check(!delayedCpu.Consume(node + 8, architecture) && delayedCpu.Report.State == Status::Partial,
          "cpu.exhausted-walk-is-not-restarted");
    WalkBudget cancelledCpu;
    cancelledCpu.Cancelled = []()
    {
        return true;
    };
    cancelledCpu.StartTraversal(ready);
    check(!cancelledCpu.Consume(node, architecture) && cancelledCpu.Report.State == Status::Cancelled,
          "cpu.preparation-cancellation-is-preserved");
    WalkBudget minifilter;
    StartMinifilterTraversal(minifilter, ready - std::chrono::seconds(6));
    check(minifilter.Consume(node, architecture), "minifilter.slow-walk-survives-the-general-five-second-limit");
    const auto minifilterDeadline = minifilter.Deadline;
    StartMinifilterTraversal(minifilter, ready + std::chrono::seconds(30));
    check(minifilter.Deadline == minifilterDeadline && minifilterDeadline == ready + std::chrono::seconds(54),
          "minifilter.nested-frames-and-filters-cannot-renew-the-deadline");
    WalkBudget expiredMinifilter;
    StartMinifilterTraversal(expiredMinifilter, ready - std::chrono::seconds(61));
    check(!expiredMinifilter.Consume(node, architecture) && !expiredMinifilter.Report.Collected.Complete &&
              expiredMinifilter.Report.Collected.StopReason == L"GlobalWalkBudget",
          "minifilter.minute-limit-remains-incomplete");
    WalkBudget limitedMinifilter;
    limitedMinifilter.MaxNodes = 0;
    StartMinifilterTraversal(limitedMinifilter, ready);
    check(!limitedMinifilter.Consume(node, architecture), "minifilter.entry-limit-is-still-enforced");
    WalkBudget cancelledMinifilter;
    cancelledMinifilter.Cancelled = []()
    {
        return true;
    };
    StartMinifilterTraversal(cancelledMinifilter, ready);
    check(!cancelledMinifilter.Consume(node, architecture) && cancelledMinifilter.Report.State == Status::Cancelled,
          "minifilter.extended-walk-remains-cancellable");
    ByteFixture memory;
    memory.Put(node, 0);
    memory.Put(node + 8, 0xffff800000020000ULL);
    memory.Put(node + 24, 0xffff800000030000ULL);
    check(ReadField(memory, node, FixtureField(24, 8)) != ReadField(memory, node, FixtureField(8, 8)),
          "callback.named-function-not-first-canonical-member");
    WalkBudget dpc;
    size_t nodes = 0;
    check(WalkChain(memory, node, 0, 0, architecture, dpc,
                    [&](uint64_t)
                    {
                        ++nodes;
                        return VisitDecision::Continue;
                    }) &&
              nodes == 1 && memory.Reads == 3,
          "dpc.single-list-no-listentry-stride-assumption");
    ByteFixture corrupt;
    corrupt.Put(0x1000, 0);
    corrupt.Put(node, 0x1000);
    const auto visit = [](uint64_t)
    {
        return VisitDecision::Continue;
    };
    WalkBudget userHead;
    check(!WalkChain(corrupt, 0x1000, 0, 0, architecture, userHead, visit) && corrupt.Reads == 0 && !userHead.Report.Collected.Complete &&
              userHead.Report.State == Status::Partial,
          "review.kernel-chain-rejects-user-head-before-read");
    corrupt.Reads = 0;
    WalkBudget userNext;
    check(!WalkChain(corrupt, node, 0, 0, architecture, userNext, visit) && corrupt.Reads == 1 && userNext.Report.Collected.Decoded == 1 &&
              userNext.Report.State == Status::Partial,
          "review.kernel-chain-rejects-user-next-before-read");
    corrupt.Put(node, 0x1000);
    corrupt.Put(node + 8, 0x1000);
    corrupt.Reads = 0;
    WalkBudget userList;
    check(!WalkList(corrupt, node, architecture, userList, visit) && corrupt.Reads == 2, "review.kernel-list-never-reads-user-flink");
    Result report;
    OwnershipIndex owners({}, false, report.Stamp);
    const auto unknown = RoutineObservation(report, architecture, owners, L"Test", node, node);
    check(report.Collected.Unknown == 1 && unknown.Get(L"ownership").AsString(L"") == L"IncompleteModuleInventory",
          "scanner.incomplete-ownership-never-clean");
    const auto zero = RoutineObservation(report, architecture, owners, L"Test", node, 0, RoutinePresence::Optional);
    check(zero.Get(L"ownership").AsString(L"") == L"NullObserved" && report.Collected.Unknown == 1, "scanner.null-routine-known-absence");
    const auto invalid = RoutineObservation(report, architecture, owners, L"Test", node, 0x800000000000ULL);
    check(invalid.Get(L"ownership").AsString(L"") == L"NotCanonicalKernelAddress" && report.Collected.Unknown == 2,
          "symbols.invalid-routine-pointer-must-reduce-coverage");
    Result registration;
    const auto required = RoutineObservation(registration, architecture, owners, L"Nmi.Callback", node, 0);
    check(registration.Collected.Unknown == 1 && required.Get(L"ownership").AsString(L"") == L"NullRequiredRoutine",
          "review.required-callback-null-reduces-coverage");

    std::vector<unsigned char> pool(32);
    uint32_t count = 1;
    uint64_t address = node | 1;
    uint64_t size = 8192;
    std::memcpy(pool.data(), &count, 4);
    std::memcpy(pool.data() + 8, &address, 8);
    std::memcpy(pool.data() + 16, &size, 8);
    std::memcpy(pool.data() + 24, "KnX1", 4);
    std::vector<BigPoolEntry> entries;
    check(ParseBigPool64(pool, entries) && entries.size() == 1 && entries[0].Address == node && entries[0].NonPaged && entries[0].NonPagedKnown &&
              PoolPageCount(entries[0]) == 2,
          "pool.native-positive-and-full-page-count");
    pool[0] = 2;
    check(!ParseBigPool64(pool, entries) && entries.empty(), "pool.truncated-count-not-clamped");
    pool[0] = 1;
    size = UINT64_MAX;
    std::memcpy(pool.data() + 16, &size, 8);
    check(!ParseBigPool64(pool, entries), "pool.overflow-allocation-rejected");
    check(PoolPageCount({node + 1, 4096}) == 2, "pool.unaligned-allocation-last-page-included");

    const PoolTableLayout tableLayout{32, 0, 8, 16, 8};
    ByteFixture poolGlobals;
    poolGlobals.Put(node, node + 0x1000);
    poolGlobals.Put(node + 8, 128, 4);
    check(ReadPoolTableGlobal(poolGlobals, architecture, node, FixtureField(0, 8), 8) == node + 0x1000 &&
              ReadPoolTableGlobal(poolGlobals, architecture, node + 8, FixtureField(0, 4), 4) == 128 && poolGlobals.Reads == 2,
          "pool.globals-read-from-validated-kernel-storage");
    poolGlobals.Reads = 0;
    for (const uint64_t invalidStorage : {0ull, 0x1000ull, 0xffff000000001000ull, node + 1, UINT64_MAX - 3})
    {
        check(!ReadPoolTableGlobal(poolGlobals, architecture, invalidStorage, FixtureField(0, 8), 8) && poolGlobals.Reads == 0,
              "pool.invalid-global-storage-refused-before-read");
    }
    check(!ReadPoolTableGlobal(poolGlobals, architecture, node, FixtureField(1, 8), 8) &&
              !ReadPoolTableGlobal(poolGlobals, architecture, node, FixtureField(0, 4), 8) &&
              !ReadPoolTableGlobal(poolGlobals, architecture, node, {}, 8) && poolGlobals.Reads == 0,
          "pool.invalid-global-field-refused-before-read");
    check(ValidPoolTableStorage(architecture, node, 128, tableLayout) &&
              ValidPoolTableStorage(architecture, UINT64_MAX - 31, 1, tableLayout),
          "pool.table-storage-valid-including-last-address");
    for (const uint64_t invalidStorage : {0ull, 0x1000ull, 0xffff000000001000ull, node + 1, UINT64_MAX - 31})
    {
        check(!ValidPoolTableStorage(architecture, invalidStorage, 2, tableLayout),
              "pool.user-noncanonical-unaligned-or-wrapping-table-refused");
    }
    check(!ValidPoolTableStorage(architecture, node, 0, tableLayout) &&
              !ValidPoolTableStorage(architecture, node, kPoolMaxTableEntries + 1ull, tableLayout) &&
              !ValidPoolTableStorage(architecture, node, UINT64_MAX, tableLayout) &&
              !ValidPoolTableStorage(architecture, node, 1, {UINT32_MAX, 0, 8, 16, 8}),
          "pool.table-count-and-stride-bounded-before-multiplication");
    check(ValidPoolTableStorage({0x8664, 8, 57, {}}, 0xff00000000000000, 1, tableLayout) &&
              !ValidPoolTableStorage(architecture, 0xff00000000000000, 1, tableLayout) &&
              !ValidPoolTableStorage({0x8664, 8, {}, {}}, node, 1, tableLayout),
          "pool.table-storage-uses-known-target-address-width");
    check(!ValidPoolStorageRange(architecture, node, 0) && !ValidPoolStorageRange(architecture, UINT64_MAX - 7, 9),
          "pool.storage-range-empty-and-overflow-rejected");
    check(ValidPoolTableLayout(tableLayout) && !ValidPoolTableLayout({12, 0, 8, 16, 8}) &&
              !ValidPoolTableLayout({24, 17, 8, 16, 8}) && !ValidPoolTableLayout({32, 0, 8, 16, 3}) &&
              !ValidPoolTableLayout({32, UINT32_MAX, 8, 16, 8}),
          "pool.table-layout-bounds-checked");
    std::vector<unsigned char> poolSlot(32);
    uint64_t storedVa = node;
    uint64_t storedBytes = 0x1010;
    std::memcpy(poolSlot.data(), &storedVa, 8);
    std::memcpy(poolSlot.data() + 8, "SeSs", 4);
    std::memcpy(poolSlot.data() + 16, &storedBytes, 8);
    BigPoolEntry decoded;
    check(DecodePoolTableEntry64(poolSlot.data(), tableLayout, decoded) == PoolTableEntryKind::Entry &&
              decoded.Address == node && decoded.Size == storedBytes && decoded.Tag[0] == 'S' && decoded.Tag[3] == 's',
          "pool.table-number-of-bytes-not-page-count");
    check(!decoded.NonPagedKnown && PoolPageCount(decoded) == 2,
          "pool.table-pool-class-not-guessed-from-address");
    storedVa = node | 1;
    std::memcpy(poolSlot.data(), &storedVa, 8);
    check(DecodePoolTableEntry64(poolSlot.data(), tableLayout, decoded) == PoolTableEntryKind::Free && decoded.Address == 0,
          "pool.table-freed-allocation-not-nonpaged");
    for (const uint64_t freeVa : {0ull, 1ull})
    {
        std::memcpy(poolSlot.data(), &freeVa, 8);
        check(DecodePoolTableEntry64(poolSlot.data(), tableLayout, decoded) == PoolTableEntryKind::Free,
              "pool.table-empty-or-tombstone-free");
    }
    storedVa = node;
    storedBytes = UINT64_MAX;
    std::memcpy(poolSlot.data(), &storedVa, 8);
    std::memcpy(poolSlot.data() + 16, &storedBytes, 8);
    check(DecodePoolTableEntry64(poolSlot.data(), tableLayout, decoded) == PoolTableEntryKind::Invalid,
          "pool.table-overflow-allocation-rejected");
    storedBytes = 0;
    std::memcpy(poolSlot.data() + 16, &storedBytes, 8);
    check(DecodePoolTableEntry64(poolSlot.data(), tableLayout, decoded) == PoolTableEntryKind::Invalid,
          "pool.table-zero-bytes-invalid");
    storedBytes = 0x2650;
    std::memcpy(poolSlot.data() + 16, &storedBytes, 8);
    for (const uint64_t invalidVa : {0x1000ull, 0xffff000000001000ull, node + 2})
    {
        std::memcpy(poolSlot.data(), &invalidVa, 8);
        check(DecodePoolTableEntry64(poolSlot.data(), tableLayout, decoded) == PoolTableEntryKind::Invalid,
              "pool.table-noncanonical-or-unaligned-address-rejected");
    }
    std::memcpy(poolSlot.data(), &node, 8);
    check(DecodePoolTableEntry64(poolSlot.data(), {32, 0, 8, 16, 4}, decoded) == PoolTableEntryKind::Entry &&
              decoded.Size == storedBytes,
          "pool.table-verified-narrow-byte-count");
    check(DecodePoolTableEntry64(nullptr, tableLayout, decoded) == PoolTableEntryKind::Invalid &&
              DecodePoolTableEntry64(poolSlot.data(), {32, 0, 8, UINT32_MAX, 8}, decoded) == PoolTableEntryKind::Invalid,
          "pool.table-invalid-layout-refused-before-read");

    EpochTracker epoch(L"scanner-test");
    TargetObservation observed{true, true, 1, 1, 1, 1, 10, 0x8664};
    epoch.Observe(observed);
    const auto stamp = epoch.Stamp();
    observed.Thread = 20;
    epoch.Observe(observed, true);
    check(epoch.Stamp() == stamp, "epoch.internal-processor-switch-preserves-context");
    epoch.Observe(observed);
    check(epoch.Stamp().ContextGeneration > stamp.ContextGeneration, "epoch.external-context-still-invalidates");
    const auto beforeRun = epoch.Stamp();
    observed.Stopped = false;
    epoch.Observe(observed, true);
    check(epoch.Stamp().StopEpoch > beforeRun.StopEpoch, "epoch.internal-scope-never-hides-resume");

    std::array<unsigned char, 12> sid = {1, 1, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0};
    check(MandatoryLabelRid(sid) == 0U, "token.zero-integrity-RID-is-known");
    sid[7] = 5;
    check(!MandatoryLabelRid(sid) && !MandatoryLabelRid(std::span(sid).first(8)), "token.wrong-authority-or-short-SID-unavailable");

    PeImage a;
    a.File.Machine = 0x8664;
    a.File.TimeDateStamp = 1;
    a.ImageSize = 0x2000;
    PeImage b = a;
    const std::array<unsigned char, 20> pdb = {1};
    check(SamePeIdentity(a, b, pdb, pdb), "module.disk-identity-positive");
    b.File.TimeDateStamp = 2;
    check(!SamePeIdentity(a, b, pdb, pdb) && !SamePeIdentity(a, a, {}, pdb), "module.wrong-file-or-missing-PDB-not-comparable");
    a.HeadersSize = 0x400;
    IMAGE_SECTION_HEADER section = {};
    section.VirtualAddress = 0x1000;
    section.PointerToRawData = 0x400;
    section.SizeOfRawData = 0x200;
    a.Sections.push_back(section);
    check(PeFileOffset(a, 0x1100, 16) == 0x500 && !PeFileOffset(a, 0x1200, 1), "module.disk-vs-mapped-RVA-bounds");
    a.Sections.push_back(section);
    check(!PeFileOffset(a, 0x1100, 16), "module.overlapping-RVA-ambiguous");
    a.Sections.resize(1);
    section.VirtualAddress = 0x200;
    a.Sections.push_back(section);
    check(!PeFileOffset(a, 0x200, 16), "module.header-section-RVA-alias-rejected");
    a.Sections.back().VirtualAddress = 0x1108;
    check(!PeFileOffset(a, 0x1100, 16), "module.partially-overlapping-RVA-range-rejected");
    a.Sections.back().VirtualAddress = 0x1000;
    a.Sections.back().SizeOfRawData = 0;
    a.Sections.back().Misc.VirtualSize = 0x200;
    check(!PeFileOffset(a, 0x1100, 16), "module.virtual-only-section-alias-rejected");

    knjson::Value metadata;
    std::set<std::wstring> hashes;
    const std::wstring prefix = L"{\"schema\":\"kndbgx.hash-catalog.v1\",\"source\":\"fixture\",\"version\":\"1\",\"sha256\":[\"";
    check(ParseHashCatalog(prefix + std::wstring(64, L'a') + L"\"]}", metadata, hashes) && hashes.size() == 1,
          "catalog.versioned-SHA256-positive");
    check(!ParseHashCatalog(prefix + std::wstring(63, L'a') + L"\"]}", metadata, hashes) &&
              !ParseHashCatalog(prefix + std::wstring(64, L'g') + L"\"]}", metadata, hashes),
          "catalog.truncated-or-nonhex-digest-rejected");

    // Exercise the real dispatcher and capability gate without a target.
    knengine::DbgSession detached;
    const std::pair<const wchar_t *, const char *> unavailable[] = {
        {L"!msrcheck", "collector.msr-no-target-not-zero"},  {L"!cr", "collector.cr-no-target-not-clean"},
        {L"!etw", "collector.etw-no-layout-not-clean"},      {L"!unloaded", "collector.unloaded-no-profile-not-clean"},
        {L"!piddb", "collector.piddb-no-profile-not-clean"}, {L"!cihash", "collector.ci-no-profile-not-clean"}};
    for (const auto &[command, assertion] : unavailable)
    {
        const auto result = kncmd::DispatchCommand(detached, command);
        check(!result.Ok && (result.Data.State == Status::Unavailable || result.Data.State == Status::Unsupported) &&
                  result.Data.Rows.Items().empty(),
              assertion);
    }
    const auto hypervisor = kncmd::DispatchCommand(detached, L"!hv");
    check(!hypervisor.Ok && hypervisor.Data.State == Status::Partial && hypervisor.Data.Rows.Items().size() == 2 &&
              hypervisor.Data.Rows.Items()[0].Get(L"source").AsString(L"") == L"DebuggerHostCpuid" &&
              hypervisor.Data.Rows.Items()[1].Get(L"cr4").IsNull() && hypervisor.Data.Rows.Items()[1].Get(L"bit13").IsNull() &&
              !hypervisor.Data.Collected.Complete && hypervisor.Data.Collected.Unknown > 0,
          "collector.hv-no-target-not-conclusion");

    // Untyped ObTypeIndexTable storage: the slot bound comes from the table
    // itself (dense front, sustained null tail) and stays self-verified.
    {
        ByteFixture types;
        const uint64_t table = 0xfffff80000001000;
        for (uint64_t slot = 0; slot < 5; ++slot)
        {
            types.Put(table + slot * 8, 0xfffff80200002000 + slot * 0x100);
        }
        check(StructurallyBoundedTypeSlotCount(types, table) == 5, "types.table-bound-dense-front-null-tail");
        // A short null gap keeps scanning; a sustained run terminates it.
        for (uint64_t slot = 5; slot < 15; ++slot)
        {
            types.Put(table + slot * 8, 0);
        }
        types.Put(table + 15 * 8, 0xfffff80200006000);
        check(StructurallyBoundedTypeSlotCount(types, table) == 16, "types.table-bound-bridges-short-null-gap");
        for (uint64_t slot = 16; slot < 48; ++slot)
        {
            types.Put(table + slot * 8, 0);
        }
        check(StructurallyBoundedTypeSlotCount(types, table) == 16, "types.table-bound-sustained-null-run-terminates");
        ByteFixture empty;
        check(StructurallyBoundedTypeSlotCount(empty, table) == 0, "types.table-bound-unreadable-is-zero");
    }
    // MmProtectToValue captured from NT 28000.2952; also matches the 26100.8655 profile.
    const uint32_t protectionValues[] = {
        0x01, 0x02, 0x10, 0x20, 0x04, 0x08, 0x40, 0x80,
        0x01, 0x202, 0x210, 0x220, 0x204, 0x208, 0x240, 0x280,
        0x01, 0x102, 0x110, 0x120, 0x104, 0x108, 0x140, 0x180,
        0x01, 0x402, 0x410, 0x420, 0x404, 0x408, 0x440, 0x480};
    const std::map<uint32_t, std::wstring> protectionNames = {
        {PAGE_NOACCESS, L"NoAccess"}, {PAGE_READONLY, L"ReadOnly"}, {PAGE_READWRITE, L"ReadWrite"},
        {PAGE_WRITECOPY, L"WriteCopy"}, {PAGE_EXECUTE, L"Execute"}, {PAGE_EXECUTE_READ, L"ExecuteRead"},
        {PAGE_EXECUTE_READWRITE, L"ExecuteReadWrite"}, {PAGE_EXECUTE_WRITECOPY, L"ExecuteWriteCopy"}};
    bool protectionNamesMatch = true;
    for (size_t index = 0; index < std::size(protectionValues); ++index)
    {
        const auto protection = protectionValues[index];
        auto expected = protectionNames.at(protection & 0xff);
        if ((protection & PAGE_GUARD) != 0)
        {
            expected += L"+Guard";
        }
        if ((protection & PAGE_NOCACHE) != 0)
        {
            expected += L"+NoCache";
        }
        if ((protection & PAGE_WRITECOMBINE) != 0)
        {
            expected += L"+WriteCombine";
        }
        protectionNamesMatch = StandardProtectionName(index) == expected && protectionNamesMatch;
    }
    check(protectionNamesMatch, "vad.standard-protection-names-match-captured-target-table");
    check(StandardProtectionName(32).empty() && StandardProtectionName(UINT64_MAX).empty(),
          "vad.standard-protection-names-reject-out-of-range-indices");
    check(HumanBytes(512) == L"512 B" && HumanBytes(2048) == L"2.00 KiB" && HumanBytes(5167382528ULL) == L"4.81 GiB",
          "pool.human-bytes-format");
}
} // namespace knself
