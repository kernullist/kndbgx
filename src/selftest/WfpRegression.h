#pragma once

#include "CollectorRegression.h"
#include "../core/WfpProfile.h"
#include "../core/WfpRead.h"

namespace knself
{
template <typename Check> void RunWfpRegression(Check check)
{
    using namespace kncore;
    constexpr uint64_t base = 0xfffff80000000000ULL;
    const TargetArchitecture architecture{0x8664, 8, 48, {}};
    for (const auto module : {L"NETIO", L"fwpkclnt", L"nt"})
    {
        ModuleIdentity identity;
        identity.Matched = true;
        identity.Machine = 0x8664;
        identity.Base = base;
        identity.PdbAge = 1;
        const bool netio = std::wstring_view(module) == L"NETIO";
        const bool nt = std::wstring_view(module) == L"nt";
        identity.PdbGuid = netio ? L"{DE265633-63BA-3A8B-E44C-0496BB5EAE44}" :
                           nt ? L"{4660396C-2030-4C03-9AF4-5FC6B15ADF98}" : L"{EACE892D-E775-C77A-413A-BDE50BC0A90B}";
        identity.Timestamp = netio ? 0x3bce0554 : nt ? 0xe1a9f520 : 0xfc07e3f8;
        identity.ImageSize = netio ? 0xbc000 : nt ? 0x1459000 : 0x8b000;
        ByteFixture memory;
        std::map<std::wstring, uint64_t> symbols;
        symbols[netio ? L"gWfpGlobal" : L"gFwppCallouts"] = base + (netio ? 0x99a98 : 0x498a0);
        for (const auto &window : WfpProfileWindows(module))
        {
            symbols[window.Symbol] = base + window.SymbolRva;
            for (size_t i = 0; i < std::wcslen(window.Bytes) / 2; ++i)
            {
                const auto nibble = [](wchar_t c)
                {
                    return c <= L'9' ? c - L'0' : c - L'a' + 10;
                };
                memory.Put(base + window.SymbolRva + window.Offset + i,
                           (nibble(window.Bytes[i * 2]) << 4) | nibble(window.Bytes[i * 2 + 1]), 1);
            }
        }
        const auto verify = [&]()
        {
            return std::wstring(VerifyWfpProfile(memory, identity, module, [&](const wchar_t *symbol) -> std::optional<uint64_t>
            {
                const auto found = symbols.find(symbol);
                return found == symbols.end() ? std::nullopt : std::optional<uint64_t>(found->second);
            }));
        };
        check(verify() == L"Verified", "wfp.profile-matched-image-symbols-and-code");
        identity.PdbAge = 2;
        memory.Reads = 0;
        check(verify() == L"NoMatchingWfpProfile" && memory.Reads == 0, "wfp.profile-rejects-other-pdb-before-reads");
        identity.PdbAge = 1;
        const auto window = WfpProfileWindows(module).front();
        symbols[window.Symbol] += 8;
        check(verify() == L"WfpCodeSymbolMismatch", "wfp.profile-rejects-symbol-rva-mismatch");
        symbols[window.Symbol] -= 8;
        memory.Bytes[base + window.SymbolRva + window.Offset] ^= 1;
        check(verify() == L"WfpCodeMismatch", "wfp.profile-rejects-patched-code");
        memory.Bytes.erase(base + window.SymbolRva + window.Offset);
        check(verify() == L"WfpCodeUnavailable", "wfp.profile-rejects-short-code-read");
    }
    constexpr uint64_t table = base + 0x100;
    constexpr uint64_t directory = base + 0x1000;
    constexpr uint64_t first = base + 0x5000;
    constexpr uint64_t second = base + 0x5100;
    constexpr uint64_t internal = base + 0x6000;
    constexpr uint64_t runtime = base + 0x7000;
    constexpr uint64_t filterId = 9007199254740993ULL;
    ByteFixture fixture;
    fixture.Text(table, {}, 0x28);
    fixture.Put(table + 8, 128, 4);
    fixture.Put(table + 0x10, 127, 4);
    fixture.Put(table + 0x14, 2, 4);
    fixture.Put(table + 0x18, 1, 4);
    fixture.Put(table + 0x20, directory);
    for (unsigned i = 0; i < 128; ++i)
    {
        const auto head = directory + i * 16;
        fixture.Put(head, head);
        fixture.Put(head + 8, head);
    }
    fixture.Put(directory, first);
    fixture.Put(directory + 8, second);
    fixture.Text(first, {}, 0x30);
    fixture.Put(first, second);
    fixture.Put(first + 8, directory);
    fixture.Put(first + 0x10, 1);
    fixture.Put(first + 0x18, 1, 4);
    fixture.Put(first + 0x1c, FWPS_LAYER_ALE_AUTH_CONNECT_V4, 4);
    fixture.Put(first + 0x20, filterId);
    fixture.Put(first + 0x28, internal);
    fixture.Text(second, {}, 0x20);
    fixture.Put(second, directory);
    fixture.Put(second + 8, first);
    fixture.Put(second + 0x10, 2);
    fixture.Put(second + 0x18, 6, 4);
    const auto walk = [&](ByteFixture memory, const wchar_t *reason, uint64_t expectedFilters)
    {
        WalkBudget budget;
        WfpReader read(memory, architecture, budget);
        uint64_t physical = 0;
        uint64_t other = 0;
        uint64_t filters = 0;
        const auto ok = WalkWfpFilters(read, table, 1, 99, [&](const WfpHashEntry &entry)
        {
            ++filters;
            check(entry.Id == filterId && entry.Internal == internal && entry.Layer == FWPS_LAYER_ALE_AUTH_CONNECT_V4,
                  "wfp.hash-retains-full-id-and-runtime-payload");
            return true;
        }, physical, other);
        check(filters == expectedFilters && (ok ? std::wstring(reason).empty() : budget.Report.Collected.StopReason == reason),
              "wfp.hash-coverage-and-explicit-stop");
        if (ok)
        {
            check(physical == 2 && other == 1 && budget.Report.Collected.Read == 2, "wfp.hash-excludes-other-namespace-without-reading-filter-payload");
        }
    };
    walk(fixture, L"", 1);
    auto corrupt = fixture;
    corrupt.Put(second + 8, directory);
    walk(corrupt, L"WfpHashBacklinkOrSignatureMismatch", 1);
    corrupt = fixture;
    corrupt.Put(second, first);
    walk(corrupt, L"CycleOrRepeatedNode", 1);
    corrupt = fixture;
    corrupt.Put(directory + 8, first);
    walk(corrupt, L"WfpHashTailMismatch", 1);
    corrupt = fixture;
    corrupt.Put(table + 0x14, 3, 4);
    walk(corrupt, L"WfpHashCountMismatch", 1);
    corrupt = fixture;
    corrupt.Put(table + 0x1c, 1, 4);
    walk(corrupt, L"WfpInvalidOrEnumeratingHashTable", 0);
    corrupt = fixture;
    corrupt.Bytes.erase(first + 0x28);
    walk(corrupt, L"WfpUnreadableMemory", 0);
    corrupt = fixture;
    corrupt.Put(first + 0x1c, 99, 4);
    walk(corrupt, L"WfpInvalidOrDuplicateFilter", 0);
    {
        ByteFixture memory;
        memory.Put(directory, base + 0x3000);
        memory.Put(directory + 8, base + 0x4000);
        WalkBudget budget;
        WfpReader read(memory, architecture, budget);
        check(WfpBucketHead(read, directory, 129, 0) == base + 0x3000 &&
                  WfpBucketHead(read, directory, 129, 127) == base + 0x37f0 &&
                  WfpBucketHead(read, directory, 129, 128) == base + 0x4000,
              "wfp.hash-two-level-directory-boundary");
        check(!WfpBucketHead(read, directory, 129, 129), "wfp.hash-rejects-out-of-range-bucket");
    }
    {
        WalkBudget budget;
        budget.Cancelled = []()
        {
            return true;
        };
        WfpReader read(fixture, architecture, budget);
        const auto before = fixture.Reads;
        check(!read.Bytes(first, 8) && fixture.Reads == before && budget.Report.State == Status::Cancelled,
              "wfp.cancellation-prevents-memory-read");
    }
    {
        WalkBudget budget;
        budget.StartTraversal(std::chrono::steady_clock::now() - std::chrono::seconds(181), std::chrono::seconds(180));
        WfpReader read(fixture, architecture, budget);
        check(!read.Bytes(first, 8) && budget.Report.Collected.StopReason == L"WfpCollectionDeadline",
              "wfp.shared-deadline-is-not-renewed");
    }
    ByteFixture calloutMemory;
    calloutMemory.Text(first, {}, 0x60);
    calloutMemory.Put(first, 3, 4);
    calloutMemory.Put(first + 4, 1, 4);
    calloutMemory.Put(first + 0x10, base + 0x9999);
    calloutMemory.Put(first + 0x28, base + 0x8888);
    auto bytes = calloutMemory.Read(AddressSpace::Virtual, first, 0x60).Bytes;
    const auto fast = DecodeWfpCallout(bytes, 7, architecture);
    check(fast && fast->Classify == base + 0x8888 && fast->Notify == 0 && !fast->Added && fast->Registered,
          "wfp.type-three-selects-fast-classify-and-preserves-null-callbacks");
    bytes[0] = 2;
    const auto ordinary = DecodeWfpCallout(bytes, 7, architecture);
    check(ordinary && ordinary->Classify == base + 0x9999, "wfp.ordinary-registration-selects-primary-classify");
    bytes[0] = 5;
    check(!DecodeWfpCallout(bytes, 7, architecture), "wfp.unknown-registration-is-not-a-guessed-layout");
    bytes[0] = 2;
    bytes[4] = 2;
    check(!DecodeWfpCallout(bytes, 7, architecture), "wfp.invalid-registration-state-rejected");
    bytes.resize(0x5f);
    check(!DecodeWfpCallout(bytes, 7, architecture), "wfp.short-callout-is-not-empty");
    {
        ByteFixture memory = calloutMemory;
        memory.Text(second, {}, 0x28);
        memory.Put(second + 0x20, 5, 4);
        WalkBudget budget;
        WfpReader read(memory, architecture, budget);
        std::map<uint32_t, WfpCallout> callouts;
        check(ReadWfpCallouts(read, first, 1, second, 1, 99, callouts) && callouts.size() == 1 &&
                  callouts.at(0).Classify == base + 0x8888 && !callouts.at(0).Key.empty(),
              "wfp.callout-joins-guid-by-verified-id-and-registration-state");
        memory.Put(second + 0x10, 1, 4);
        WalkBudget mismatch;
        WfpReader mismatchRead(memory, architecture, mismatch);
        callouts.clear();
        check(!ReadWfpCallouts(mismatchRead, first, 1, second, 1, 99, callouts) && callouts.empty() &&
                  mismatch.Report.Collected.StopReason == L"WfpCalloutKeyStateMismatch",
              "wfp.callout-guid-id-mismatch-is-not-cross-associated");
        memory.Put(second + 0x10, 0, 4);
        memory.Put(second + 0x20, 3, 4);
        WalkBudget transition;
        WfpReader transitionRead(memory, architecture, transition);
        check(!ReadWfpCallouts(transitionRead, first, 1, second, 1, 99, callouts),
              "wfp.in-progress-registration-cannot-be-complete");
        memory.Put(first + 4, 0, 4);
        WalkBudget empty;
        WfpReader emptyRead(memory, architecture, empty);
        check(ReadWfpCallouts(emptyRead, first, 1, second, 1, 99, callouts) && callouts.empty(),
              "wfp.reserved-key-does-not-create-an-active-runtime-callout");
    }
    {
        ByteFixture memory;
        memory.Text(internal, {}, 0x38);
        memory.Put(internal + 0x18, runtime);
        memory.Put(internal + 0x30, FWPS_LAYER_ALE_AUTH_CONNECT_V4, 2);
        memory.Text(runtime, {}, 0x40);
        memory.Put(runtime, filterId);
        memory.Put(runtime + 8, FWP_UINT64, 4);
        memory.Put(runtime + 0x10, runtime + 0x80);
        memory.Put(runtime + 0x80, 0xffffffffffffffffULL);
        memory.Put(runtime + 0x18, 3, 2);
        memory.Put(runtime + 0x1c, 1, 4);
        memory.Put(runtime + 0x20, runtime + 0x100);
        memory.Put(runtime + 0x28, FWP_ACTION_PERMIT, 4);
        memory.Text(runtime + 0x100, {}, 0x18);
        memory.Put(runtime + 0x100, FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL, 2);
        memory.Put(runtime + 0x108, FWP_UINT8, 4);
        memory.Put(runtime + 0x110, 6);
        WalkBudget budget;
        WfpReader read(memory, architecture, budget);
        const WfpHashEntry entry{first, FWPS_LAYER_ALE_AUTH_CONNECT_V4, filterId, internal};
        knjson::Value row;
        check(ReadWfpFilter(read, entry, {}, row) && row.Get(L"filterId").AsString(L"") == L"9007199254740993" &&
                  row.Get(L"weight").AsString(L"") == L"18446744073709551615" && row.Get(L"actionName").AsString(L"") == L"Permit" &&
                  row.Get(L"conditionSummary").AsString(L"") == L"IP_PROTOCOL Equal 6" && row.Get(L"calloutId").IsNull(),
              "wfp.filter-displays-actual-id-weight-action-and-typed-conditions");
        WalkBudget bounded;
        WfpReader boundedRead(memory, architecture, bounded);
        boundedRead.ConditionUnits = WfpReader::MaximumConditionUnits;
        knjson::Value boundedRow;
        check(!ReadWfpFilter(boundedRead, entry, {}, boundedRow) && boundedRow.Get(L"conditions").Items().empty() &&
                  boundedRow.Get(L"conditionCount").AsString(L"") == L"1" && boundedRow.Get(L"conditionsState").AsString(L"") == L"Partial" &&
                  bounded.Report.Collected.StopReason == L"WfpConditionOutputBudget",
              "wfp.condition-output-budget-retains-truncated-row-and-declared-count");
        WalkBudget rowBudget;
        WfpReader rowRead(memory, architecture, rowBudget);
        rowRead.RowUnits = WfpReader::MaximumRowUnits;
        check(!rowRead.Retain(row, false) && rowBudget.Report.Collected.StopReason == L"WfpRowOutputBudget",
              "wfp.row-output-budget-stops-before-unbounded-result-retention");
        rowBudget.Stop(Status::Cancelled, L"Cancelled");
        check(!rowRead.Retain(row, false) && rowBudget.Report.State == Status::Cancelled,
              "wfp.output-budget-cannot-replace-cancellation-with-partial");
        memory.Put(runtime, filterId + 1);
        check(!ReadWfpFilter(read, entry, {}, row) && budget.Report.Collected.StopReason == L"WfpFilterIdentityMismatch",
              "wfp.filter-id-corrobates-hash-and-public-runtime-record");
        memory.Put(runtime, filterId);
        memory.Put(runtime + 0x1c, 1025, 4);
        WalkBudget oversized;
        WfpReader oversizedRead(memory, architecture, oversized);
        check(!ReadWfpFilter(oversizedRead, entry, {}, row) && row.Get(L"conditionCount").AsString(L"") == L"1025" &&
                  oversized.Report.Collected.StopReason == L"WfpConditionLimitExceeded",
              "wfp.excessive-condition-count-retains-filter-with-partial-coverage");
        memory.Put(runtime + 0x1c, 0, 4);
        memory.Put(runtime + 0x28, FWP_ACTION_CALLOUT_TERMINATING, 4);
        memory.Put(runtime + 0x2c, 7, 4);
        WalkBudget missing;
        WfpReader missingRead(memory, architecture, missing);
        check(ReadWfpFilter(missingRead, entry, {}, row) && row.Get(L"calloutId").AsString(L"") == L"7" &&
                  missing.Report.Collected.Unknown == 1 && row.Get(L"calloutKey").IsNull(),
              "wfp.missing-referenced-callout-is-an-unknown-not-absence");
    }
    {
        ByteFixture memory;
        memory.Put(first, 0xc0a80100, 4);
        memory.Put(first + 4, 0xffffff00, 4);
        memory.Text(second, {}, 17);
        memory.Put(second, 0x2001, 2);
        memory.Put(second + 16, 64, 1);
        memory.Text(internal, {}, 32);
        memory.Put(internal, FWP_UINT16, 4);
        memory.Put(internal + 8, 80);
        memory.Put(internal + 16, FWP_UINT16, 4);
        memory.Put(internal + 24, 443);
        WalkBudget budget;
        WfpReader read(memory, architecture, budget);
        check(read.Value(FWP_V4_ADDR_MASK, first).Get(L"value").AsString(L"") == L"192.168.1.0/255.255.255.0",
              "wfp.ipv4-mask-is-not-a-target-pointer");
        check(read.Value(FWP_V6_ADDR_MASK, second).Get(L"value").AsString(L"").ends_with(L"/64"), "wfp.ipv6-prefix-decoded");
        check(read.Value(FWP_RANGE_TYPE, internal).Get(L"value").AsString(L"") == L"80..443", "wfp.port-range-decoded");
        memory.Put(internal, FWP_RANGE_TYPE, 4);
        memory.Put(internal + 8, internal);
        read.ValueCache.clear();
        check(read.Value(FWP_RANGE_TYPE, internal).Get(L"value").IsNull() && budget.Report.Collected.Unknown != 0,
              "wfp.cyclic-range-values-are-bounded-and-unknown");
        check(read.Value(0xffffffff, 0).Get(L"value").IsNull(), "wfp.unknown-value-type-is-not-zero-or-empty");
    }
    {
        std::vector<unsigned char> sid{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0};
        check(WfpSid(sid, 0) == L"S-1-5-18", "wfp.sid-decoded-without-target-pointer-dereference");
        sid.pop_back();
        check(!WfpSid(sid, 0), "wfp.truncated-sid-rejected");
        std::vector<unsigned char> sd(20);
        sd[0] = 1;
        sd[2] = 4;
        sd[3] = 0x80;
        check(WfpSecurityDescriptor(sd) == L"SD SACL=Absent DACL=Null", "wfp.relative-sd-null-acl-preserved");
        sd[16] = 20;
        check(!WfpSecurityDescriptor(sd), "wfp.relative-sd-out-of-buffer-acl-rejected");
    }
    {
        ByteFixture memory;
        memory.Text(first, {}, 16);
        memory.Put(first, 2, 4);
        memory.Put(first + 8, second);
        memory.Put(second, 0xd800, 2);
        WalkBudget budget;
        WfpReader read(memory, architecture, budget);
        const auto value = read.Value(FWP_BYTE_BLOB_TYPE, first, L"ALE_APP_ID");
        check(value.Get(L"value").IsNull() && value.Get(L"bytes").AsString(L"") == L"00d8" &&
                  budget.Report.Collected.Unknown == 1,
              "wfp.invalid-utf16-app-id-retains-raw-bytes-and-unknown-state");
    }
    check(!WfpFieldName(FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V6, 12).starts_with(L"Field#") &&
              !WfpFieldName(FWPS_LAYER_OUTBOUND_ICMP_ERROR_V6, 11).starts_with(L"Field#"),
          "wfp.current-vm-ipv6-condition-fields-have-sdk-names");
}
} // namespace knself
