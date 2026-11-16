#pragma once

#include "CollectorRegression.h"
#include "../core/KernelSymbolProfile.h"
#include "../core/Piddb.h"
#include "../core/ResultAddress.h"

namespace knself
{
template <typename Check> void RunPiddbRegression(Check check)
{
    using namespace kncore;
    constexpr uint64_t base = 0xfffff80000000000ULL;
    constexpr uint64_t table = base + 0x1000;
    constexpr uint64_t root = base + 0x2000;
    constexpr uint64_t child = base + 0x3000;
    constexpr uint64_t compare = base + 0x4000;
    constexpr uint64_t name = base + 0x5000;
    const TargetArchitecture architecture{0x8664, 8, 48, {}};
    ByteFixture fixture;
    const auto zero = [&](uint64_t address, size_t length)
    {
        for (size_t i = 0; i < length; ++i)
        {
            fixture.Put(address + i, 0, 1);
        }
    };
    zero(table, 0x50);
    fixture.Put(table + 0x10, root);
    fixture.Put(table + 0x2c, 2, 4);
    fixture.Put(table + 0x48, compare);
    const auto entry = [&](uint64_t node, uint64_t parent, const std::wstring &text, uint64_t buffer, uint32_t status)
    {
        zero(node, 0x48);
        fixture.Put(node, parent);
        fixture.Put(node + 0x30, text.size() * 2, 2);
        fixture.Put(node + 0x32, text.size() * 2, 2);
        fixture.Put(node + 0x38, buffer);
        fixture.Put(node + 0x40, 0xfedcba98, 4);
        fixture.Put(node + 0x44, status, 4);
        for (size_t i = 0; i < text.size(); ++i)
        {
            fixture.Put(buffer + i * 2, text[i], 2);
        }
    };
    entry(root, table, L"alpha.sys", name, 0);
    entry(child, root, L"beta.sys", name + 0x100, 0xc0000428);
    fixture.Put(root + 8, child);
    const auto collect = [&](ByteFixture &memory)
    {
        WalkBudget budget;
        CollectPiddbEntries(memory, architecture, table, compare, budget);
        budget.Complete();
        return budget.Report;
    };
    const auto valid = collect(fixture);
    check(valid.State == Status::Success && valid.Collected.Complete && valid.Collected.Expected == 2 &&
              valid.Collected.Visited == 2 && valid.Collected.Decoded == 2 && valid.Rows.Items().size() == 2,
          "piddb.verified-tree-produces-complete-driver-records");
    const auto &row = valid.Rows.Items()[0];
    check(row.Get(L"kind").AsString(L"") == L"PiDDBEntry" && row.Get(L"name").AsString(L"") == L"alpha.sys" &&
              row.Get(L"entry").AsString(L"") == Hex(root + 0x20) && row.Get(L"timeDateStamp").AsString(L"") == L"0xfedcba98" &&
              row.Get(L"loadStatus").AsString(L"") == L"0x00000000" &&
              row.Get(L"loadStatusClass").AsString(L"") == L"STATUS_SUCCESS",
          "piddb.payload-offset-name-raw-timestamp-and-zero-status");
    std::set<std::wstring> addressPaths;
    bool virtualPointers = true;
    const auto addressFields = ResultAddressFields(row);
    for (const auto &descriptor : addressFields.Items())
    {
        addressPaths.insert(descriptor.Get(L"path").Write());
        virtualPointers = virtualPointers && descriptor.Get(L"space").AsString(L"") == L"virtual" &&
            !descriptor.Get(L"allowZero").AsBool(true);
    }
    check(addressPaths == std::set<std::wstring>{L"[\"entry\"]", L"[\"topology\",\"address\"]",
              L"[\"topology\",\"parent\"]", L"[\"topology\",\"left\"]", L"[\"topology\",\"right\"]"} && virtualPointers,
          "piddb.nested-tree-pointers-remain-address-navigation-fields");
    check(valid.Rows.Items()[1].Get(L"loadStatus").AsString(L"") == L"0xc0000428" &&
              valid.Rows.Items()[1].Get(L"loadStatusClass").AsString(L"") == L"Error" &&
              std::wstring_view(PiddbStatusClass(0x40000001)) == L"Informational" &&
              std::wstring_view(PiddbStatusClass(0x80000001)) == L"Warning",
          "piddb.cached-failure-is-not-an-unreadable-record-or-loaded-verdict");
    const auto partial = [&](ByteFixture memory, const wchar_t *reason, const char *test)
    {
        const auto result = collect(memory);
        check(result.State == Status::Partial && !result.Collected.Complete && result.Collected.StopReason == reason, test);
    };
    auto broken = fixture;
    broken.Put(child + 8, root);
    partial(broken, L"CycleOrRepeatedNode", "piddb.cycle-cannot-report-complete");
    broken = fixture;
    broken.Put(child, table);
    partial(broken, L"PiDDBParentMismatch", "piddb.parent-mismatch-rejected");
    broken = fixture;
    broken.Put(table + 0x2c, 3, 4);
    partial(broken, L"PiDDBElementCountMismatch", "piddb.missing-node-count-does-not-look-complete");
    broken = fixture;
    broken.Put(table + 0x2c, 1, 4);
    partial(broken, L"PiDDBElementCountMismatch", "piddb.extra-nodes-rejected");
    broken = fixture;
    broken.Put(table + 0x48, compare + 8);
    partial(broken, L"InvalidPiDDBTableHeader", "piddb.wrong-comparison-routine-rejected");
    broken = fixture;
    broken.Put(root + 8, 0x1000);
    partial(broken, L"InvalidPiDDBNodeAddress", "piddb.user-pointer-is-not-traversed");
    broken = fixture;
    broken.Put(root + 8, UINT64_MAX - 7);
    partial(broken, L"InvalidPiDDBNodeAddress", "piddb.node-range-overflow-rejected");
    broken = fixture;
    broken.Bytes.erase(child + 0x47);
    partial(broken, L"PiDDBElementCountMismatch", "piddb.partial-node-read-cannot-synthesize-status-zero");
    broken = fixture;
    broken.Bytes.erase(name);
    const auto unreadable = collect(broken);
    check(unreadable.State == Status::Partial && unreadable.Rows.Items().size() == 2 &&
              unreadable.Rows.Items()[0].Get(L"name").IsNull() && unreadable.Collected.Unreadable == 1 &&
              unreadable.Rows.Items()[1].Get(L"name").AsString(L"") == L"beta.sys",
          "piddb.unreadable-name-preserves-other-driver-records");
    for (const uint64_t length : {0ULL, 3ULL, 2050ULL})
    {
        broken = fixture;
        broken.Put(root + 0x30, length, 2);
        partial(broken, L"PiDDBFieldsUnavailable", "piddb.empty-odd-oversized-name-is-unknown");
    }
    broken = fixture;
    broken.Put(name, 0xd800, 2);
    partial(broken, L"PiDDBFieldsUnavailable", "piddb.invalid-utf16-not-displayed-as-driver-name");
    broken = fixture;
    broken.Put(root + 0x38, 0x1000);
    partial(broken, L"PiDDBFieldsUnavailable", "piddb.user-name-pointer-is-not-read");
    broken = fixture;
    broken.Reads = 0;
    broken.BeforeRead = [&]()
    {
        if (broken.Reads == 6)
        {
            broken.Put(table + 0x40, 1, 4);
        }
    };
    const auto changed = collect(broken);
    check(changed.State == Status::Partial && changed.Collected.StopReason == L"PiDDBTableChangedDuringWalk",
          "piddb.table-change-during-walk-invalidates-completeness");
    broken = fixture;
    WalkBudget cancelled;
    cancelled.Cancelled = [&]()
    {
        return cancelled.Report.Collected.Visited == 1;
    };
    CollectPiddbEntries(broken, architecture, table, compare, cancelled);
    check(cancelled.Report.State == Status::Cancelled && cancelled.Report.Collected.StopReason == L"Cancelled" &&
              cancelled.Report.Rows.Items().size() == 1, "piddb.cancellation-retains-status-and-partial-records");
    for (const bool cancelAtEnd : {false, true})
    {
        broken = fixture;
        broken.Reads = 0;
        WalkBudget late;
        bool requested = false;
        late.Cancelled = [&]()
        {
            return requested;
        };
        broken.BeforeRead = [&]()
        {
            if (broken.Reads == 6)
            {
                if (cancelAtEnd)
                {
                    requested = true;
                }
                else
                {
                    late.Deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
                }
            }
        };
        CollectPiddbEntries(broken, architecture, table, compare, late);
        late.Complete();
        check(late.Report.State == (cancelAtEnd ? Status::Cancelled : Status::Partial) &&
                  !late.Report.Collected.Complete && late.Report.Rows.Items().size() == 2 &&
                  late.Report.Collected.StopReason == (cancelAtEnd ? L"Cancelled" : L"GlobalWalkBudget"),
              cancelAtEnd ? "piddb.cancel-during-final-read-cannot-report-complete" :
                            "piddb.deadline-during-final-read-cannot-report-complete");
    }
    broken = fixture;
    broken.Put(table + 0x10, 0);
    broken.Put(table + 0x2c, 0, 4);
    const auto empty = collect(broken);
    check(empty.State == Status::Success && empty.Collected.Complete && empty.Rows.Items().empty(),
          "piddb.verified-empty-cache-is-not-a-layout-failure");
    const auto readsBeforeExpired = broken.Reads;
    WalkBudget expired;
    expired.StartTraversal(std::chrono::steady_clock::now() - std::chrono::seconds(31));
    CollectPiddbEntries(broken, architecture, table, compare, expired);
    check(expired.Report.State == Status::Partial && expired.Report.Collected.StopReason == L"GlobalWalkBudget" &&
              broken.Reads == readsBeforeExpired, "piddb.expired-budget-does-not-read-even-an-empty-cache");
    auto field = FixtureField(8, 8);
    field.Kind = FieldKind::Pointer;
    check(PiddbFieldMatches(field, 8, 8, FieldKind::Pointer) && !PiddbFieldMatches(field, 0, 8, FieldKind::Pointer) &&
              !PiddbFieldMatches(field, 8, 8, FieldKind::Unsigned), "piddb.conflicting-pdb-field-shape-rejected");

    const ModuleIdentity identity{L"{4660396C-2030-4C03-9AF4-5FC6B15ADF98}", 1, 0x8664, 0xe1a9f520, 0x1459000, base, true};
    ByteFixture code;
    std::map<std::wstring, uint64_t> symbols;
    for (const auto &[symbol, rva] : KernelProfileSymbols(KernelLayoutFamily::Piddb))
    {
        symbols[symbol] = base + rva;
    }
    for (const auto &window : KernelProfileWindows(KernelLayoutFamily::Piddb))
    {
        symbols[window.Symbol] = base + window.SymbolRva;
        const std::wstring bytes(window.Bytes);
        for (size_t i = 0; i < bytes.size(); i += 2)
        {
            code.Put(base + window.SymbolRva + window.Offset + i / 2, std::stoul(bytes.substr(i, 2), nullptr, 16), 1);
        }
    }
    const auto verify = [&](const ModuleIdentity &target)
    {
        return std::wstring_view(VerifyKernelProfile(code, target, KernelLayoutFamily::Piddb,
            [&](const wchar_t *symbol) -> std::optional<uint64_t>
            {
                const auto found = symbols.find(symbol);
                return found == symbols.end() ? std::nullopt : std::optional<uint64_t>(found->second);
            }));
    };
    check(verify(identity) == L"Verified", "piddb.exact-image-symbols-and-code-required");
    auto different = identity;
    different.Timestamp ^= 1;
    const auto reads = code.Reads;
    check(verify(different) == L"NoMatchingKernelProfile" && code.Reads == reads, "piddb.other-kernels-not-decoded-with-fixed-offsets");
    symbols[L"PiDDBCacheTable"] += 8;
    check(verify(identity) == L"KernelProfileSymbolMismatch", "piddb.table-symbol-mismatch-rejected");
    symbols[L"PiDDBCacheTable"] -= 8;
    const auto &window = KernelProfileWindows(KernelLayoutFamily::Piddb).front();
    const auto codeAddress = base + window.SymbolRva + window.Offset;
    code.Bytes[codeAddress] ^= 1;
    check(verify(identity) == L"KernelProfileBytesMismatch", "piddb.changed-kernel-code-rejects-private-layout");
    code.Bytes.erase(codeAddress);
    check(verify(identity) == L"KernelProfileBytesUnavailable", "piddb.missing-code-page-rejects-private-layout");
}
} // namespace knself
