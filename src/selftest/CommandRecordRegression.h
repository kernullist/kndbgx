#pragma once

#include "CollectorRegression.h"
#include "../core/CiHash.h"
#include "../core/HistoryRows.h"
#include "../core/KernelSymbolProfile.h"
#include "../core/ResultAddress.h"

namespace knself
{
template <typename Check> void RunCommandRecordRegression(Check check)
{
    using namespace kncore;
    constexpr uint64_t base = 0xfffff80000000000ULL;
    constexpr uint64_t root = base + 0x1000;
    constexpr uint64_t first = base + 0x2000;
    constexpr uint64_t second = base + 0x3000;
    const TargetArchitecture architecture{0x8664, 8, 48, {}};
    ByteFixture fixture;
    const auto entry = [&](uint64_t address, uint64_t next, const std::wstring &name, uint32_t status)
    {
        for (size_t i = 0; i < 0x48; ++i)
        {
            fixture.Put(address + i, i, 1);
        }
        fixture.Put(address, next);
        fixture.Put(address + 8, name.size() * 2, 2);
        fixture.Put(address + 0xa, name.size() * 2, 2);
        fixture.Put(address + 0x10, address + 0x48);
        fixture.Put(address + 0x40, status, 4);
        for (size_t i = 0; i < name.size(); ++i)
        {
            fixture.Put(address + 0x48 + i * 2, name[i], 2);
        }
    };
    fixture.Put(root, first);
    entry(first, second, L"alpha.sys", 0);
    entry(second, 0, L"beta.sys", 0xc0000428);
    const auto collect = [&](ByteFixture &memory)
    {
        WalkBudget budget;
        CollectCiHashEntries(memory, architecture, root, budget);
        budget.Complete();
        return budget.Report;
    };
    const auto result = collect(fixture);
    const auto &row = result.Rows.Items().front();
    check(result.State == Status::Success && result.Collected.Complete && result.Collected.Decoded == 2 &&
              row.Get(L"name").AsString(L"") == L"alpha.sys" && row.Get(L"cacheStatusRaw").AsString(L"") == L"0x00000000" &&
              result.Rows.Items()[1].Get(L"cacheStatusRaw").AsString(L"") == L"0xc0000428",
          "cihash.records-contain-names-and-raw-zero-or-nonzero-status");
    check(row.Get(L"hash").AsString(L"") == L"18191a1b1c1d1e1f202122232425262728292a2b" &&
              row.Get(L"secondaryHash").AsString(L"") == L"2c2d2e2f303132333435363738393a3b3c3d3e3f",
          "cihash.both-hashes-preserve-all-twenty-bytes-in-memory-order");
    std::set<std::wstring> paths;
    const auto addressFields = ResultAddressFields(row);
    for (const auto &field : addressFields.Items())
    {
        paths.insert(field.Get(L"path").Write());
    }
    check(paths == std::set<std::wstring>{L"[\"entry\"]", L"[\"topology\",\"next\"]"},
          "cihash.hash-and-status-are-not-addresses-but-link-navigation-remains");
    auto broken = fixture;
    broken.Put(second, first);
    const auto cycle = collect(broken);
    check(cycle.State == Status::Partial && !cycle.Collected.Complete && cycle.Rows.Items().size() == 2,
          "cihash.cycle-retains-records-with-incomplete-coverage");
    broken = fixture;
    broken.Bytes.erase(second + 0x31);
    check(collect(broken).Collected.StopReason == L"UnreadableCiHashEntry", "cihash.partial-record-never-becomes-a-zero-hash");
    for (const uint64_t length : {3ULL, 4096ULL})
    {
        broken = fixture;
        broken.Put(first + 8, length, 2);
        const auto invalid = collect(broken);
        check(invalid.State == Status::Partial && invalid.Rows.Items().front().Get(L"name").IsNull(),
              "cihash.invalid-name-descriptor-preserves-other-record-fields");
    }
    broken = fixture;
    broken.Put(first + 8, 0, 2);
    broken.Put(first + 0x10, 0);
    const auto unnamed = collect(broken);
    check(unnamed.Collected.Complete && unnamed.Rows.Items().front().Get(L"name").IsString() &&
              unnamed.Rows.Items().front().Get(L"name").AsString(L"missing").empty(),
          "cihash.empty-counted-name-is-preserved-without-reading-a-buffer");
    broken = fixture;
    broken.Put(first + 0x48, 0xd800, 2);
    check(collect(broken).Rows.Items().front().Get(L"name").IsNull(), "cihash.invalid-utf16-is-not-a-cache-name");
    broken = fixture;
    broken.Put(first + 0x10, 0x1000);
    check(collect(broken).Collected.Unknown == 1, "cihash.user-buffer-is-not-dereferenced-as-kernel-name");
    broken = fixture;
    broken.Put(root, 0);
    check(collect(broken).Collected.Complete && collect(broken).Rows.Items().empty(), "cihash.verified-null-root-is-an-empty-cache");
    broken.Bytes.erase(root);
    check(collect(broken).State == Status::Unavailable, "cihash.unreadable-root-is-not-empty-success");
    broken = fixture;
    broken.Reads = 0;
    broken.BeforeRead = [&]()
    {
        if (broken.Reads == 6)
        {
            broken.Put(root, second);
        }
    };
    check(collect(broken).Collected.StopReason == L"CiHashRootChangedDuringWalk", "cihash.changed-root-invalidates-completeness");
    for (const bool cancel : {false, true})
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
                if (cancel)
                {
                    requested = true;
                }
                else
                {
                    late.Deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
                }
            }
        };
        CollectCiHashEntries(broken, architecture, root, late);
        late.Complete();
        check(!late.Report.Collected.Complete && late.Report.State == (cancel ? Status::Cancelled : Status::Partial),
              "cihash.final-blocking-read-honors-cancel-and-deadline");
    }
    WalkBudget limited;
    limited.MaxNodes = 1;
    CollectCiHashEntries(fixture, architecture, root, limited);
    check(limited.Report.Rows.Items().size() == 1 && limited.Report.State == Status::Partial, "cihash.node-budget-is-shared");
    broken = fixture;
    bool cancelRoot = false;
    WalkBudget rootBudget;
    rootBudget.Cancelled = [&]()
    {
        return cancelRoot;
    };
    broken.BeforeRead = [&]()
    {
        cancelRoot = true;
        broken.Bytes.erase(root);
    };
    CollectCiHashEntries(broken, architecture, root, rootBudget);
    check(rootBudget.Report.State == Status::Cancelled, "cihash.cancel-during-failed-root-read-retains-cancel-status");

    const ModuleIdentity nt{L"{4660396C-2030-4C03-9AF4-5FC6B15ADF98}", 1, 0x8664, 0xe1a9f520, 0x1459000, base, true};
    const ModuleIdentity ci{L"{F660C9DA-4538-E0B7-62AA-C762F4FA8CDB}", 1, 0x8664, 0x773f58da, 0x11c000, base, true};
    for (const auto family : {KernelLayoutFamily::HostSilo, KernelLayoutFamily::Nmi, KernelLayoutFamily::Unloaded,
                              KernelLayoutFamily::Firmware, KernelLayoutFamily::CiHash})
    {
        const auto identity = family == KernelLayoutFamily::CiHash ? ci : nt;
        ByteFixture code;
        std::map<std::wstring, uint64_t> symbols;
        for (const auto &[name, rva] : KernelProfileSymbols(family, true))
        {
            symbols[name] = base + rva;
        }
        for (const auto &window : KernelProfileWindows(family, true))
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
            return std::wstring_view(VerifyKernelProfile(code, target, family,
                [&](const wchar_t *name) -> std::optional<uint64_t>
                {
                    const auto found = symbols.find(name);
                    return found == symbols.end() ? std::nullopt : std::optional<uint64_t>(found->second);
                }));
        };
        check(verify(identity) == L"Verified", "records.exact-28000-or-ci-profile-accepts-reviewed-bytes");
        auto mismatch = identity;
        mismatch.Timestamp ^= 1;
        const auto reads = code.Reads;
        check(verify(mismatch) == L"NoMatchingKernelProfile" && code.Reads == reads,
              "records.profile-rejects-other-images-before-private-reads");
        const auto &window = KernelProfileWindows(family, true).front();
        code.Bytes[base + window.SymbolRva + window.Offset] ^= 1;
        check(verify(identity) == L"KernelProfileBytesMismatch", "records.code-change-rejects-private-layout");
        code.Bytes.erase(base + window.SymbolRva + window.Offset);
        check(verify(identity) == L"KernelProfileBytesUnavailable", "records.unreadable-code-cannot-validate-layout");
    }
    Result combined;
    combined.Collected.Complete = true;
    auto child = result;
    child.CommandId = L"!cihash";
    check(AppendHistoryCollection(combined, child) && combined.Rows.Items().size() == 2 &&
              combined.Rows.Items()[0].Get(L"sourceCommand").AsString(L"") == L"!cihash" &&
              combined.Rows.Items()[0].Get(L"name").AsString(L"") == L"alpha.sys" &&
              combined.Analysis.Get(L"collections").Items()[0].Get(L"rows").Items().empty() &&
              child.Rows.Items()[0].Get(L"sourceCommand").IsNull(),
          "mapper.flattens-actual-records-and-retains-separate-collection-metadata");
    child.State = Status::Partial;
    child.Collected.Complete = false;
    child.Collected.Unknown = 1;
    AppendHistoryCollection(combined, child);
    check(combined.State == Status::Partial && !combined.Collected.Complete && combined.Collected.Unknown == 1,
          "mapper.partial-child-remains-partial-after-flattening");
    Result capped;
    capped.Collected.Complete = true;
    check(!AppendHistoryCollection(capped, child, 1) && capped.Rows.Items().size() == 1 &&
              capped.Collected.StopReason == L"CompositeRowLimit", "mapper.flattened-records-respect-global-row-limit");
    child.State = Status::Cancelled;
    check(!AppendHistoryCollection(combined, child) && combined.State == Status::Cancelled,
          "mapper.cancelled-child-stops-composition-with-terminal-status");
}
} // namespace knself
