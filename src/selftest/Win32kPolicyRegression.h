#pragma once

#include "CollectorRegression.h"
#include "../core/Win32kPolicy.h"
#include "../core/Snapshot.h"
#include "../core/ResultAddress.h"
#include "../util/SnapshotStore.h"
#include "../cmd/CommandSpec.h"

namespace knself
{
template <typename Check> void RunWin32kPolicyRegression(Check check)
{
    using namespace kncore;
    kncmd::ParsedCommand parsed;
    check(kncmd::ParseCommand(L"!ssdt", &parsed) && kncmd::ParseCommand(L"!ssdt /policy", &parsed) &&
        kncmd::ParseCommand(L"!ssdt /policy pid:100", &parsed) &&
        !kncmd::ParseCommand(L"!ssdt /policy /policy", &parsed) && !kncmd::ParseCommand(L"!ssdt /policy 100 extra", &parsed),
        "policy.command-catalog-admits-bounded-policy-view");
    constexpr uint64_t address = 0xffff800001000000ULL;
    const TargetArchitecture architecture{0x8664, 8, 48, {}};
    ProcessRow process;
    process.Eprocess = address;
    process.Pid = 100;
    process.CreateTime = 200;
    process.PidKnown = process.CreateTimeKnown = true;
    ByteFixture memory;
    memory.Put(address + 0x1d0, 100);
    memory.Put(address + 0x1f8, 200);
    memory.Put(address + 0x2e8, address + 0x1000);
    memory.Put(address + 0x1008, 1, 4);
    memory.Put(address + 0x5fc, 0, 4);
    memory.Put(address + 0x6e8, 3, 4);
    memory.Put(address + 0x750, 0x4000, 4);
    const std::vector<DispatchSnapshot::Range> ranges{{address + 0x1d0, 8}, {address + 0x1f8, 8}, {address + 0x2e8, 8},
        {address + 0x1008, 4}, {address + 0x5fc, 4}, {address + 0x6e8, 4}, {address + 0x750, 4}};
    const auto read = [&]()
    {
        DispatchSnapshot snapshot;
        WalkBudget budget;
        snapshot.Capture(memory, architecture, budget, ranges);
        return ReadWin32kProcessPolicy(snapshot, architecture, process);
    };
    auto policy = read();
    for (const auto state : {Status::Cancelled, Status::StaleContext, Status::InternalFault})
    {
        for (size_t failure = 1; failure <= memory.Reads; ++failure)
        {
            auto source = memory;
            TerminalReadFixture stopped(source, state, failure);
            DispatchSnapshot snapshot;
            WalkBudget budget;
            snapshot.Capture(stopped, architecture, budget, ranges);
            budget.Complete();
            check(budget.Report.State == state && !budget.Report.Collected.Complete && stopped.Requests == failure,
                  "dispatch.terminal-read-stops-remaining-snapshot-ranges");
        }
        auto source = memory;
        TerminalReadFixture stopped(source, state, 1);
        Win32kPolicySnapshot snapshot;
        WalkBudget budget;
        snapshot.Capture(stopped, architecture, {process}, address + 0x2000000, address + 0x4000000, address + 0x6000000,
                         budget, [](std::span<const unsigned char>)
                         {
                             return std::wstring();
                         });
        budget.Complete();
        check(budget.Report.State == state && !budget.Report.Collected.Complete && stopped.Requests == 1,
              "policy.terminal-snapshot-read-is-not-demoted-to-unavailable-layout");
    }
    check(policy.IdentityValid && policy.Session == 1 && policy.Set == 3 && policy.Flags == 0x4000,
          "policy.reads-current-process-fields-and-session-id");
    memory.Put(address + 0x1f8, 201);
    const auto reused = read();
    check(!reused.IdentityValid && !reused.Flags && !reused.Set, "policy.process-reuse-never-inherits-old-policy");
    memory.Put(address + 0x1f8, 200);
    memory.Put(address + 0x2e8, 0);
    check(read().NoSession && !read().Session, "policy.null-session-is-explicit-not-applicable");
    memory.Put(address + 0x2e8, address + 0x1000);
    memory.Put(address + 0x5fc, 0x1000, 4);
    check(read().NoSession, "policy.minimal-process-has-no-gui-session");
    memory.Put(address + 0x5fc, 0, 4);
    memory.Bytes.erase(address + 0x1008);
    check(!read().NoSession && !read().Session, "policy.unreadable-session-is-not-session-zero");

    Win32kPolicySession session;
    session.HelpersVerified = true;
    session.Root = address + 0x2000;
    session.User = address + 0x3000;
    auto &bitmap = session.Bitmaps[3];
    bitmap.Address = address + 0x4000;
    bitmap.Bytes.assign(188, 0xff);
    bitmap.Valid.assign(188, 1);
    bitmap.Bytes[0] &= ~1;
    const auto evaluate = [&](uint32_t index, bool verified = true)
    {
        return EvaluateWin32kPolicy(policy, &session, index, verified);
    };
    check(std::wstring_view(evaluate(0).Value) == L"Allowed" && std::wstring_view(evaluate(1).Value) == L"Blocked",
          "policy.bitmap-zero-allows-and-one-blocks");
    check(evaluate(1496).Bit == true && std::wstring_view(evaluate(1497).Value) == L"Unknown",
          "policy.last-service-is-bounded-before-tail-bits");
    for (const auto flags : {0u, 0x4000u, 0x8000u, 0xc000u})
    {
        policy.Flags = flags;
        const auto expected = (flags & 0x4000) ? L"Blocked" : (flags & 0x8000) ? L"Audit only" : L"Allowed";
        check(std::wstring_view(evaluate(1).Value) == expected && std::wstring_view(evaluate(0).Value) == L"Allowed",
              "policy.enforce-and-audit-remain-independent");
    }
    policy.Flags = 0x4000;
    bitmap.Valid[0] = 0;
    check(std::wstring_view(evaluate(1).Value) == L"Unknown" && std::wstring_view(evaluate(8).Value) == L"Blocked",
          "policy.partial-bitmap-invalidates-only-affected-byte");
    bitmap.Address = 0;
    check(evaluate(1).Bit == false && std::wstring_view(evaluate(1).Value) == L"Allowed",
          "policy.null-bitmap-is-predicate-false-even-with-enforcement");
    bitmap.Address.reset();
    check(!evaluate(1).Bit && std::wstring_view(evaluate(1).Value) == L"Unknown", "policy.unreadable-bitmap-is-not-null");
    for (const auto set : {7u, 0xffffffffu})
    {
        policy.Set = set;
        check(evaluate(0).Bit == true && std::wstring_view(evaluate(0).Value) == L"Blocked",
              "policy.out-of-range-set-follows-native-predicate-true");
    }
    check(std::wstring_view(evaluate(0, false).Value) == L"Unknown", "policy.changed-wrapper-cannot-authorize-service");
    session.HelpersVerified = false;
    check(std::wstring_view(evaluate(0).Value) == L"Unknown", "policy.changed-session-helper-cannot-authorize-service");
    session.HelpersVerified = true;
    policy.Flags.reset();
    check(std::wstring_view(evaluate(0).Value) == L"Unknown", "policy.missing-flags-never-mean-disabled");
    policy.Flags = 0x3000;
    check(std::wstring_view(evaluate(0).Value) == L"Allowed", "policy.gui-conversion-disable-is-separate-from-filter-decision");
    auto row = Win32kPolicyRow(policy, &session);
    check(row.Get(L"win32kDisable").AsBool(false) && row.Get(L"win32kDisableAudit").AsBool(false) &&
        !row.Get(L"filterEnabled").AsBool(true), "policy.gui-disable-and-audit-are-visible");
    check(!SnapshotKey(row, false).empty() && SnapshotKey(row, true).empty(), "policy.snapshot-requires-same-target-process-identity");
    auto second = row;
    second.Set(L"createTime", knjson::Value(L"201"));
    check(SnapshotKey(row, false) != SnapshotKey(second, false), "policy.snapshot-distinguishes-pid-reuse");
    second = row;
    second.Set(L"kind", knjson::Value(L"Win32kServicePolicy"));
    check(SnapshotKey(second, false).empty(), "policy.service-snapshot-requires-service-index");
    second.Set(L"index", knjson::Value(L"0"));
    check(!SnapshotKey(second, false).empty(), "policy.service-snapshot-is-keyed-by-process-and-index");
    check(AddressFieldSpace(row, L"filterBitmap", L"virtual") == L"virtual" &&
        !AddressFieldSpace(row, L"mitigationFlags", L"virtual"), "policy.navigation-keeps-flags-out-of-address-actions");

    Win32kPolicySnapshot stable;
    WalkBudget initial;
    stable.Memory.Capture(memory, architecture, initial, {{address + 0x6e8, 4}});
    stable.Captures = stable.Checks = {{address + 0x6e8, 4}};
    WalkBudget unchanged;
    stable.Recheck(memory, architecture, unchanged);
    check(!unchanged.Stopped, "policy.unchanged-policy-survives-recheck");
    memory.Put(address + 0x6e8, 4, 4);
    WalkBudget changed;
    stable.Recheck(memory, architecture, changed);
    check(changed.Report.State == Status::StaleContext, "policy.changed-filter-set-invalidates-collection");
    Win32kPolicySnapshot sparse;
    WalkBudget sparseInitial;
    memory.Bytes.erase(address + 0x6e9);
    sparse.Memory.Capture(memory, architecture, sparseInitial, {{address + 0x6e8, 4}});
    sparse.Captures = sparse.Checks = {{address + 0x6e8, 4}};
    memory.Put(address + 0x6e8, 5, 1);
    WalkBudget sparseChanged;
    sparse.Recheck(memory, architecture, sparseChanged);
    check(sparseChanged.Report.State == Status::StaleContext, "policy.unreadable-byte-cannot-hide-an-adjacent-policy-change");
    WalkBudget cancelled;
    cancelled.Cancelled = []()
    {
        return true;
    };
    const auto reads = memory.Reads;
    stable.Recheck(memory, architecture, cancelled);
    check(cancelled.Report.State == Status::Cancelled && memory.Reads == reads, "policy.cancel-before-recheck-does-not-read-target");

    ModuleIdentity identity;
    identity.Matched = true;
    identity.Machine = 0x8664;
    identity.PdbAge = 1;
    identity.Timestamp = 0xd072766b;
    identity.ImageSize = 0x33f000;
    identity.Base = address;
    identity.PdbGuid = L"{49EC72D0-0D46-EF4D-3193-C271992D24AA}";
    check(Win32kBasePolicyIdentity(identity), "policy.matches-reviewed-win32kbase-identity");
    ++identity.PdbAge;
    check(!Win32kBasePolicyIdentity(identity), "policy.mismatched-win32kbase-pdb-refuses-profile");

    // Independent native predicate bytes with cross-image displacements cleared.
    const std::string predicate =
        "48895c2408574883ec208bf94c8b1515401c00e8000000008bd883f80773460faee84c8b15f73c1c00e800000000"
        "4c8b84d8101501004d85c074268bc7408acf48c1e80380e107ba01000000d2e2428414000f95c0488b5c24304883c4205fc3"
        "cc32c0ebf0b801000000ebe9";
    std::vector<unsigned char> code;
    for (size_t i = 0; i < predicate.size(); i += 2)
    {
        code.push_back(static_cast<unsigned char>(std::stoul(predicate.substr(i, 2), nullptr, 16)));
    }
    const auto &profile = Win32kPolicyCode()[0];
    const auto nt = address + 0x4000000, image = address + 0x2000000, function = address + profile.Rva;
    for (const auto &binding : profile.Calls)
    {
        const auto target = (binding.Win32k ? image : nt) + binding.Rva;
        const auto displacement = static_cast<uint32_t>(target - function - binding.Offset - 4);
        std::memcpy(code.data() + binding.Offset, &displacement, 4);
    }
    const auto hash = [](std::span<const unsigned char> bytes)
    {
        return knutil::Sha256Bytes(bytes);
    };
    check(VerifyPolicyFunction(code, profile, function, nt, image, hash), "policy.native-predicate-verifies-after-image-relocation");
    code[profile.Calls[0].Offset] ^= 1;
    check(!VerifyPolicyFunction(code, profile, function, nt, image, hash), "policy.normalized-call-still-checks-its-destination");
    code[profile.Calls[0].Offset] ^= 1;
    code[0x1a] = 6;
    check(!VerifyPolicyFunction(code, profile, function, nt, image, hash), "policy.changed-filter-set-bound-refuses-profile");
}
} // namespace knself
