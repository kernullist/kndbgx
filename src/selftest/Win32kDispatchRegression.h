#pragma once

#include "CollectorRegression.h"
#include "../core/Win32kDispatch.h"
#include "../core/ResultAddress.h"
#include "../util/SnapshotStore.h"

namespace knself
{
template <typename Check> void RunWin32kDispatchRegression(Check check)
{
    using namespace kncore;
    constexpr uint64_t image = 0xffff800001000000ULL, nt = image + 0x2000000;
    const TargetArchitecture architecture{0x8664, 8, 48, {}};
    ByteFixture memory;
    const auto bytes = [&](uint64_t address, const std::string &hex)
    {
        for (size_t i = 0; i < hex.size(); i += 2)
        {
            memory.Put(address + i / 2, std::stoul(hex.substr(i, 2), nullptr, 16), 1);
        }
    };
    const auto &route = Win32kRoutes[0];
    bytes(image + route.Entry,
          "48895c2408574883ec308bd94c8b15fd5c0900e800000000488bc84c8b15fe5c0900e800000000bfffffffff3bc7744a83f80172358d48ff488b05a12f080048"
          "8b04c8488b8088000000488b4878488b41284885c074218bcbe800000000488b5c24404883c4305fc3cc0faee88bc8488d05a22f0800ebc7ebe44c8b158f5c09"
          "00e8000000004c8bc748c7442420000000004c8bc8ba30000000b9640100004c8b15ea5c0900e800000000cc");
    const std::array<uint64_t, 7> calls{0, nt + 0x45d7c0, nt + 0x2cb700, nt + 0xc79860, nt + 0x5438f0, nt + 0x1000, 0};
    for (const auto binding : route.Calls)
    {
        if (binding)
        {
            const auto offset = binding & 0xffff;
            memory.Put(image + route.Entry + offset + 1, calls[binding >> 16] - (image + route.Entry + offset + 5), 4);
        }
    }
    const auto hash = [](std::span<const unsigned char> input)
    {
        return knutil::Sha256Bytes(input);
    };
    const auto capture = [&](ByteFixture &source, uint64_t address, size_t length)
    {
        DispatchSnapshot result;
        WalkBudget budget;
        result.Capture(source, architecture, budget, {{address, length}});
        return result;
    };
    auto code = capture(memory, image + route.Entry, route.Size);
    check(VerifyDispatchRoute(code, route, image, calls, hash), "win32k.reviewed-code-hash-survives-kernel-relocation");
    auto broken = memory;
    broken.Put(image + route.Entry, 0xcc, 1);
    check(!VerifyDispatchRoute(capture(broken, image + route.Entry, route.Size), route, image, calls, hash),
          "win32k.changed-thunk-code-cannot-produce-a-dispatch-target");
    broken = memory;
    broken.Put(image + route.Entry + (route.Calls[0] & 0xffff) + 1, 0, 4);
    check(!VerifyDispatchRoute(capture(broken, image + route.Entry, route.Size), route, image, calls, hash),
          "win32k-normalized-call-still-requires-the-reviewed-destination");

    constexpr uint64_t api0 = image + 0x200000, api1 = image + 0x210000, host0 = image + 0x220000, host1 = image + 0x230000;
    memory.Put(api0 + route.Host, host0);
    memory.Put(api1 + route.Host, host1);
    memory.Put(host0 + route.Target, nt + 0x1000);
    memory.Put(host1 + route.Target, nt + 0x2000);
    DispatchSnapshot pointers;
    WalkBudget budget;
    const std::vector<DispatchSnapshot::Range> fields{
        {api0 + route.Host, 8}, {api1 + route.Host, 8}, {host0 + route.Target, 8}, {host1 + route.Target, 8}};
    pointers.Capture(memory, architecture, budget, fields);
    const Win32kSessionView first{0, 0, 0, api0}, second{1, 0, 0, api1};
    check(ResolveWin32kTarget(pointers, code, architecture, route, first, image, true).Routine == nt + 0x1000 &&
              ResolveWin32kTarget(pointers, code, architecture, route, second, image, true).Routine == nt + 0x2000,
          "win32k.sessions-with-the-same-service-keep-distinct-bindings");
    memory.Put(host0 + route.Target, 0);
    pointers.Capture(memory, architecture, budget, fields);
    check(KnownDispatch(ResolveWin32kTarget(pointers, code, architecture, route, first, image, true)),
          "win32k.verified-null-target-is-not-an-unreadable-target");
    memory.Bytes.erase(host0 + route.Target);
    pointers.Capture(memory, architecture, budget, fields);
    check(!KnownDispatch(ResolveWin32kTarget(pointers, code, architecture, route, first, image, true)),
          "win32k.missing-target-byte-is-unknown");
    memory.Put(host0 + route.Target, 0x1000);
    pointers.Capture(memory, architecture, budget, fields);
    check(!KnownDispatch(ResolveWin32kTarget(pointers, code, architecture, route, first, image, true)),
          "win32k.user-address-is-not-a-kernel-dispatch");

    const auto &direct = Win32kRoutes[266];
    bytes(image + direct.Entry, "4c8b1500000000e900000000");
    memory.Put(image + direct.Entry + 3, direct.Import - direct.Entry - 7, 4);
    memory.Put(image + direct.Entry + 8, nt + 0x3000 - (image + direct.Entry + 12), 4);
    memory.Put(image + direct.Import, nt + 0x3000);
    const auto directCode = capture(memory, image + direct.Entry, direct.Size);
    check(VerifyDispatchRoute(directCode, direct, image, calls, hash) &&
              KnownDispatch(
                  ResolveWin32kTarget(capture(memory, image + direct.Import, 8), directCode, architecture, direct, first, image, true)),
          "win32k.direct-import-agrees-with-verified-tail-jump");
    memory.Put(image + direct.Import, nt + 0x4000);
    const auto divergent =
        ResolveWin32kTarget(capture(memory, image + direct.Import, 8), directCode, architecture, direct, first, image, true);
    check(!KnownDispatch(divergent) && divergent.Routine == nt + 0x3000,
          "win32k.changed-import-keeps-actual-direct-jump-and-reports-disagreement");

    const auto wrapper = image + 0x2fcc0;
    for (size_t i = 0; i < Win32kFilterTemplate.size(); ++i)
    {
        memory.Put(wrapper + i, Win32kFilterTemplate[i], 1);
    }
    const std::pair<unsigned, uint64_t> relative[] = {{0x22, image + 0x73a88},       {0x27, image + 0xce520},
                                                      {0x32, image + route.NameRva}, {0x40, image + 0x73a80},
                                                      {0x45, image + 0xce520},       {0x4c, image + 0x9ca80},
                                                      {0x51, nt + 0x4a1be0},         {0x5c, image + 0xa3330},
                                                      {0x62, image + 0xa5074},       {0x86, image + route.FilterImport},
                                                      {0xa3, image + 0xce400}};
    for (const auto &[offset, target] : relative)
    {
        memory.Put(wrapper + offset, target - (wrapper + offset + 4), 4);
    }
    check(VerifyFilterWrapper(capture(memory, wrapper, 167), route, 0, image, nt), "win32k.filtered-wrapper-recognizes-conditional-route");
    memory.Put(wrapper + 0x39, 1, 4);
    check(!VerifyFilterWrapper(capture(memory, wrapper, 167), route, 0, image, nt), "win32k.filtered-wrong-service-id-refuses-pairing");
    check(FilteredServiceReturn(0) == 0 && FilteredServiceReturn(8) == 0xc000001c && FilteredServiceReturn(0xff) == 0xffffffff,
          "win32k.filtered-return-preserves-signed-byte-semantics");

    Snapshot oldSnapshot;
    oldSnapshot.Metadata.Set(L"schema", knjson::Value(L"kndbgx.snapshot.v2"));
    oldSnapshot.Metadata.Set(L"target", SessionStamp{L"dispatch-fixture", 1, 1, 1, 1}.ToJson());
    oldSnapshot.Metadata.Set(L"targetStable", knjson::Value(true));
    Result services;
    services.Collected.Complete = true;
    auto service = knjson::Value::MakeObject();
    service.Set(L"kind", knjson::Value(L"RoutineObservation"));
    service.Set(L"family", knjson::Value(L"ShadowSSDT"));
    service.Set(L"index", knjson::Value(L"0"));
    service.Set(L"sessionId", knjson::Value(L"0"));
    service.Set(L"sessionState", knjson::Value(Hex(api0)));
    service.Set(L"routine", knjson::Value(Hex(nt + 0x1000)));
    services.Rows.Push(service);
    service.Set(L"sessionId", knjson::Value(L"1"));
    service.Set(L"sessionState", knjson::Value(Hex(api1)));
    services.Rows.Push(service);
    oldSnapshot.Collections[L"ssdt"] = services.ToJson();
    const auto unchanged = DiffSnapshots(oldSnapshot, oldSnapshot);
    check(unchanged.Collected.Unknown == 0 && unchanged.Rows.Items().size() == 2,
          "win32k.snapshot-keeps-two-sessions-with-the-same-service-id-distinct");
    check(SnapshotKey(service, true).empty(), "win32k.session-id-does-not-establish-cross-target-identity");
    auto legacySnapshot = oldSnapshot;
    auto legacy = service;
    legacy.Set(L"sessionId", knjson::Value());
    Result entryOnly;
    entryOnly.Collected.Complete = true;
    entryOnly.Rows.Push(legacy);
    legacySnapshot.Collections[L"ssdt"] = entryOnly.ToJson();
    const auto upgraded = DiffSnapshots(legacySnapshot, oldSnapshot);
    check(upgraded.Collected.Unknown == upgraded.Rows.Items().size() && upgraded.State == Status::Partial,
          "win32k.entry-only-snapshot-does-not-imply-added-or-removed-session-bindings");

    memory.Put(image + 0x89ca0, 0);
    memory.Put(image + 0x89cd8, image + 0x240000);
    memory.Put(image + 0x89ce0, 0, 4);
    memory.Put(image + 0x240088, api0);
    memory.Put(host0 + route.Target, nt + 0x1000);
    memory.Put(image + 0xa1000, (route.Entry - 0xa1000) << 4, 4);
    OwnershipIndex owners({}, false, {});
    WalkBudget cancelled;
    cancelled.Cancelled = []()
    {
        return true;
    };
    const auto readsBeforeCancel = memory.Reads;
    CollectWin32kDispatch(memory, architecture, owners, image, nt, 0, false, cancelled, hash,
                          [&](const knjson::Value &row)
                          {
                              cancelled.Report.Rows.Push(row);
                          });
    check(cancelled.Report.State == Status::Cancelled && memory.Reads == readsBeforeCancel,
          "win32k.cancelled-collection-does-not-read-session-globals");
    WalkBudget limited;
    limited.MaxNodes = 1;
    CollectWin32kDispatch(memory, architecture, owners, image, nt, 0, false, limited, hash,
                          [&](const knjson::Value &row)
                          {
                              limited.Report.Rows.Push(row);
                          });
    check(limited.Report.State == Status::Partial && limited.Report.Rows.Items().size() == 1 &&
              limited.Report.Rows.Items()[0].Get(L"routine").AsString(L"") == Hex(nt + 0x1000),
          "win32k.row-bound-retains-a-verified-dispatch-with-incomplete-coverage");
    WalkBudget stale;
    CollectWin32kDispatch(memory, architecture, owners, image, nt, 0, false, stale, hash,
                          [&](const knjson::Value &row)
                          {
                              stale.Report.Rows.Push(row);
                              memory.Put(image + 0x89ce0, 1, 4);
                          });
    check(stale.Report.State == Status::StaleContext && stale.Report.Rows.Items().size() == 1497,
          "win32k.changed-session-count-invalidates-the-completed-inventory");
    check(stale.Report.ToJson().Get(L"analysis").Get(L"win32kSessions").AsString(L"") == L"1" &&
              stale.Report.Analysis.Get(L"dispatchTraversalMs").IsString(),
          "win32k.collection-metrics-survive-result-serialization");
    memory.Put(image + 0x89ce0, 256, 4);
    WalkBudget excessive;
    const auto readsBeforeLimit = memory.Reads;
    CollectWin32kDispatch(memory, architecture, owners, image, nt, 0, false, excessive, hash,
                          [&](const knjson::Value &row)
                          {
                              excessive.Report.Rows.Push(row);
                          });
    check(excessive.Report.State == Status::Unavailable && excessive.Report.Rows.Items().empty() && memory.Reads - readsBeforeLimit <= 2,
          "win32k.excessive-session-count-refuses-unbounded-pointer-reads");

    memory.Text(api0, "", 64);
    memory.Put(api0 + 24, 123);
    DispatchSnapshot overlap;
    overlap.Capture(memory, architecture, budget, {{api0, 64}});
    overlap.Capture(memory, architecture, budget, {{api0 + 8, 8}});
    check(overlap.Number(api0 + 24) == 123, "win32k.overlapping-captures-preserve-earlier-tail");
    WalkBudget expired;
    expired.StartTraversal(std::chrono::steady_clock::now() - std::chrono::seconds(121), std::chrono::seconds(120));
    const auto before = memory.Reads;
    overlap.Capture(memory, architecture, expired, {{api0, 8}});
    check(expired.Stopped && before == memory.Reads, "win32k.expired-snapshot-budget-performs-no-read");
    for (const auto *field : {L"entryRoutine", L"dispatchSlot", L"filterPredicate", L"filterHandler", L"filterImport"})
    {
        check(AddressFieldSpace(knjson::Value::MakeObject(), field, L"virtual") == L"virtual",
              "win32k.dispatch-addresses-remain-navigable");
    }
}
} // namespace knself
