#pragma once

#include "CollectorRegression.h"
#include "../core/CallbackLayout.h"
#include "../core/CallbackRows.h"
#include "../core/Snapshot.h"
#include "../engine/SessionEvents.h"
#include <future>

namespace knself
{
template <typename Check> void RunCallbackRegression(Check check)
{
    using namespace kncore;
    constexpr uint64_t base = 0xfffff8008ee00000ULL;
    ModuleIdentity identity{L"{11D7FE79-CC24-5612-0555-03EE86BB0E3E}", 1, 0x8664, 0x90b083da, 0x1450000, base, true};
    ByteFixture code;
    std::map<std::wstring, uint64_t> symbols;
    symbols[L"CallbackListHead"] = base + 0xef78e0;
    symbols[L"CmpCallBackCount"] = base + 0xeef98c;
    const auto resolve = [&](const wchar_t *name) -> std::optional<uint64_t>
    {
        const auto it = symbols.find(name);
        return it == symbols.end() ? std::nullopt : std::optional<uint64_t>(it->second);
    };
    for (const auto family :
         {CallbackFamily::Process, CallbackFamily::Thread, CallbackFamily::Image, CallbackFamily::Object, CallbackFamily::Registry})
    {
        symbols[NotifyTableName(family)] = base + NotifyTableRva(family);
        for (const auto &window : CallbackProfileWindows(family))
        {
            symbols[window.Symbol] = base + window.SymbolRva;
            const std::wstring bytes(window.Bytes);
            for (size_t i = 0; i < bytes.size(); i += 2)
            {
                code.Put(base + window.SymbolRva + window.Offset + i / 2, std::stoul(bytes.substr(i, 2), nullptr, 16), 1);
            }
        }
        check(std::wstring_view(VerifyCallbackProfile(code, identity, family, resolve)) == L"Verified",
              "callbacks.profile-family-identity-code-and-symbols-agree");
    }
    const size_t before = code.Reads;
    auto wrong = identity;
    wrong.PdbGuid[1] = L'0';
    check(std::wstring_view(VerifyCallbackProfile(code, wrong, CallbackFamily::Process, resolve)) == L"NoMatchingCallbackProfile" &&
              code.Reads == before,
          "callbacks.wrong-pdb-rejected-before-memory-read");
    wrong = identity;
    wrong.PdbAge = 2;
    check(!CallbackProfileIdentity(wrong), "callbacks.wrong-pdb-age-rejected");
    wrong = identity;
    wrong.Timestamp ^= 1;
    check(!CallbackProfileIdentity(wrong), "callbacks.wrong-image-timestamp-rejected");
    wrong = identity;
    wrong.ImageSize -= 4096;
    check(!CallbackProfileIdentity(wrong), "callbacks.wrong-image-size-rejected");
    wrong = identity;
    wrong.Machine = 0x14c;
    check(!CallbackProfileIdentity(wrong), "callbacks.wrong-machine-rejected");
    wrong = identity;
    wrong.Matched = false;
    check(!CallbackProfileIdentity(wrong), "callbacks.unmatched-pdb-rejected");
    wrong = identity;
    wrong.Base = UINT64_MAX - 4096;
    check(!CallbackProfileIdentity(wrong), "callbacks.module-range-overflow-rejected");
    symbols[L"PspCreateProcessNotifyRoutine"] += 8;
    check(std::wstring_view(VerifyCallbackProfile(code, identity, CallbackFamily::Process, resolve)) == L"CallbackTableSymbolMismatch",
          "callbacks.neighbor-table-not-used-as-extent");
    symbols[L"PspCreateProcessNotifyRoutine"] -= 8;
    symbols[L"ExAllocateCallBack"] += 1;
    check(std::wstring_view(VerifyCallbackProfile(code, identity, CallbackFamily::Process, resolve)) == L"CallbackCodeSymbolMismatch",
          "callbacks.wrong-code-symbol-rejected");
    symbols[L"ExAllocateCallBack"] -= 1;
    symbols[L"CallbackListHead"] += 8;
    check(std::wstring_view(VerifyCallbackProfile(code, identity, CallbackFamily::Registry, resolve)) == L"RegistryCallbackSymbolMismatch",
          "callbacks.wrong-registry-list-symbol-rejected");
    symbols[L"CallbackListHead"] -= 8;
    code.Bytes[base + 0xa86510] ^= 1;
    check(std::wstring_view(VerifyCallbackProfile(code, identity, CallbackFamily::Process, resolve)) == L"CallbackCodeMismatch",
          "callbacks.changed-code-rejects-layout-fallback");
    code.Bytes.erase(base + 0xa86510);
    check(std::wstring_view(VerifyCallbackProfile(code, identity, CallbackFamily::Process, resolve)) == L"CallbackCodeUnavailable",
          "callbacks.missing-code-page-rejects-layout-fallback");

    const auto table = CallbackProfileTable();
    check(NotifyTableValid(table, base + 0xf05440), "callbacks.verified-table-extent-positive");
    auto badTable = table;
    badTable.Size -= 8;
    check(!NotifyTableValid(badTable, base) && !NotifyTableValid(table, UINT64_MAX - 7),
          "callbacks.inconsistent-or-overflowed-table-rejected");
    badTable = table;
    badTable.ArrayCount = 0;
    check(!NotifyTableValid(badTable, base) && !NotifyTableValid(table, base + 1), "callbacks.empty-or-misaligned-table-rejected");
    badTable = table;
    badTable.Size = 4097 * 8;
    badTable.ArrayCount = 4097;
    check(!NotifyTableValid(badTable, base), "callbacks.table-count-budget-enforced");

    std::optional<FieldInfo> links, operations, pre, post;
    pre = CallbackProfileField(0x28, 8);
    pre->Source = L"DbgEngMatchedPdb";
    check(ApplyObjectCallbackProfile(links, operations, pre, post) && links->Offset == 0 && operations->Offset == 0x10 &&
              post->Offset == 0x30 && pre->Source == L"DbgEngMatchedPdb",
          "callbacks.partial-object-metadata-completed-with-provenance-preserved");
    links.reset();
    pre->Offset = 0x38;
    check(!ApplyObjectCallbackProfile(links, operations, pre, post) && !links && pre->Offset == 0x38,
          "callbacks.contradictory-partial-object-metadata-refuses-fallback");
    pre->Offset = 0x28;
    pre->BitOffset = 0;
    pre->BitWidth = 8;
    check(!ApplyObjectCallbackProfile(links, operations, pre, post) && !links, "callbacks.bitfield-object-routine-refuses-fallback");

    constexpr uint64_t slot = base + 0xf05440;
    constexpr uint64_t block = 0xffffa902f03fecd0ULL;
    constexpr uint64_t routine = 0xfffff80012345000ULL;
    TargetArchitecture architecture{0x8664, 8, 48, 52};
    ByteFixture memory;
    memory.Put(slot, block | 15);
    memory.Put(block, 0xffff800000009000ULL);
    memory.Put(block + 8, routine);
    memory.Put(block + 16, 2);
    auto refs = CallbackProfileField(0, 8);
    refs.BitOffset = 0;
    refs.BitWidth = 4;
    const auto function = CallbackProfileField(8, 8);
    auto observed = ReadNotifyCallback(memory, architecture, slot, refs, function);
    check(observed.Block == block && observed.Routine == routine && std::wstring_view(observed.Reason) == L"Decoded",
          "callbacks.fast-ref-mask-and-function-field-not-rundown");
    memory.Put(slot, 0);
    const size_t emptyBefore = memory.Reads;
    observed = ReadNotifyCallback(memory, architecture, slot, refs, function);
    check(observed.Raw == 0 && !observed.Block && !observed.Unreadable && memory.Reads == emptyBefore + 1,
          "callbacks.empty-slot-never-dereferenced");
    memory.Put(slot, 15);
    observed = ReadNotifyCallback(memory, architecture, slot, refs, function);
    check(!observed.Routine && std::wstring_view(observed.Reason) == L"InvalidCallbackBlock", "callbacks.flags-only-fast-ref-not-pointer");
    memory.Put(slot, block | 7);
    auto unknownRefs = refs;
    unknownRefs.BitWidth.reset();
    observed = ReadNotifyCallback(memory, architecture, slot, unknownRefs, function);
    check(!observed.Block && !observed.Routine, "callbacks.missing-fast-ref-bit-layout-not-guessed");
    observed = ReadNotifyCallback(memory, architecture, slot, refs, std::nullopt);
    check(!observed.Routine, "callbacks.missing-function-layout-not-guessed");
    memory.Bytes.erase(slot + 7);
    observed = ReadNotifyCallback(memory, architecture, slot, refs, function);
    check(!observed.Raw && observed.Unreadable, "callbacks.short-slot-read-not-zero-filled");
    memory.Put(slot, block | 7);
    memory.Bytes.erase(block + 15);
    observed = ReadNotifyCallback(memory, architecture, slot, refs, function);
    check(!observed.Routine && observed.Unreadable, "callbacks.short-routine-read-remains-unreadable");
    memory.Put(block + 8, 0);
    observed = ReadNotifyCallback(memory, architecture, slot, refs, function);
    check(observed.Routine == 0 && std::wstring_view(observed.Reason) == L"InvalidNotifyRoutine",
          "callbacks.nonempty-registration-with-null-routine-not-complete");

    ByteFixture registry;
    for (unsigned i = 0; i < 0x50; ++i)
    {
        registry.Put(block + i, 0, 1);
    }
    registry.Put(block + 0x10, 0x80000001, 4);
    registry.Put(block + 0x18, 0xfedcba9876543210ULL);
    registry.Put(block + 0x20, 0x12345678);
    registry.Put(block + 0x28, routine);
    auto registered = ReadProfiledRegistryCallback(registry, architecture, block);
    check(registered.Routine == routine && registered.Cookie == 0xfedcba9876543210ULL && registered.Context == 0x12345678 &&
              registered.References == 0x80000001U && !registered.Unreadable,
          "callbacks.registry-function-cookie-context-and-removal-bit-distinct");
    registry.Bytes.erase(block + 0x4f);
    registered = ReadProfiledRegistryCallback(registry, architecture, block);
    check(!registered.Routine && !registered.Cookie && registered.Unreadable, "callbacks.short-registry-record-not-zero-filled");
    const size_t registryReads = registry.Reads;
    registered = ReadProfiledRegistryCallback(registry, architecture, UINT64_MAX - 7);
    check(!registered.Routine && registry.Reads == registryReads, "callbacks.registry-range-overflow-rejected-before-read");
    ByteFixture registrationContext;
    registrationContext.Put(slot, block | 15);
    registrationContext.Put(block + 8, routine);
    registrationContext.Put(block + 16, 6);
    const auto contextField = CallbackProfileField(16, 8);
    auto contextObservation = ReadNotifyCallback(registrationContext, architecture, slot, refs, function, contextField);
    check(contextObservation.Context == 6 && contextObservation.Routine == routine && !contextObservation.Unreadable,
          "callbacks.notify-registration-flags-exclude-fast-reference-count");
    registrationContext.Bytes.erase(block + 23);
    contextObservation = ReadNotifyCallback(registrationContext, architecture, slot, refs, function, contextField);
    check(!contextObservation.Context && contextObservation.Routine == routine && contextObservation.Unreadable,
          "callbacks.short-registration-context-keeps-routine-but-not-fabricated-flags");
    registry.Put(block + 0x4f, 0, 1);
    registry.Put(block + 0x14, 1, 4);
    registered = ReadProfiledRegistryCallback(registry, architecture, block);
    check(registered.Flags == 1 && registered.References && (*registered.References & 0x80000000u) != 0,
          "callbacks.registry-flags-are-distinct-from-reference-removal-bit");

    ModuleIdentity insider{L"{4660396C-2030-4C03-9AF4-5FC6B15ADF98}", 1, 0x8664, 0xe1a9f520, 0x1459000, base, true};
    ByteFixture insiderCode;
    symbols.clear();
    symbols[L"CallbackListHead"] = base + 0xefc450;
    symbols[L"CmpCallBackCount"] = base + 0xeefe54;
    for (const auto family :
         {CallbackFamily::Process, CallbackFamily::Thread, CallbackFamily::Image, CallbackFamily::Object, CallbackFamily::Registry})
    {
        symbols[NotifyTableName(family)] = base + NotifyTableRva(family, true);
        for (const auto &window : CallbackProfileWindows(family, true))
        {
            symbols[window.Symbol] = base + window.SymbolRva;
            const std::wstring bytes(window.Bytes);
            for (size_t i = 0; i < bytes.size(); i += 2)
            {
                insiderCode.Put(base + window.SymbolRva + window.Offset + i / 2, std::stoul(bytes.substr(i, 2), nullptr, 16), 1);
            }
        }
        check(std::wstring_view(VerifyCallbackProfile(insiderCode, insider, family, resolve)) == L"Verified",
              "callbacks.28000-reviewed-family-code-and-symbols-agree");
    }
    insiderCode.Put(base + 0xa808c0 + 0x15a, 0x90, 1);
    check(std::wstring_view(VerifyCallbackProfile(insiderCode, insider, CallbackFamily::Object, resolve)) == L"CallbackCodeMismatch",
          "callbacks.28000-modified-object-code-refuses-decoding");
    const auto insiderReads = insiderCode.Reads;
    insider.PdbAge = 2;
    check(std::wstring_view(VerifyCallbackProfile(insiderCode, insider, CallbackFamily::Process, resolve)) == L"NoMatchingCallbackProfile" &&
              insiderCode.Reads == insiderReads,
          "callbacks.28000-different-pdb-rejected-before-read");

    Result pairedReport;
    OwnershipIndex pairedOwners({{routine, 0x1000, L"sample", L"sample-id"}}, true, pairedReport.Stamp);
    const auto paired = ObjectCallbackRegistration(pairedReport, architecture, pairedOwners, L"Process", block, routine, routine + 8, 3);
    check(paired.Get(L"preRoutine").AsString(L"") == Hex(routine) && paired.Get(L"postRoutine").AsString(L"") == Hex(routine + 8) &&
              paired.Get(L"flags").AsString(L"") == Hex(3) && paired.Get(L"callbackType").AsString(L"") == L"Object.Process" &&
              pairedReport.Collected.Unknown == 0,
          "callbacks.registration-keeps-pre-post-and-operation-flags-together");
    Result optionalReport;
    OwnershipIndex optionalOwners({{routine, 0x1000, L"sample", L"sample-id"}}, true, optionalReport.Stamp);
    const auto optionalPair = ObjectCallbackRegistration(optionalReport, architecture, optionalOwners, L"Thread", block, routine, 0, 1);
    check(optionalReport.Collected.Unknown == 0 && optionalPair.Get(L"post").Get(L"ownership").AsString(L"") == L"NullObserved",
          "callbacks.null-optional-post-is-distinct-from-unreadable-post");
    const auto unknownPair = ObjectCallbackRegistration(optionalReport, architecture, optionalOwners, L"Thread", block, routine,
                                                        std::nullopt, 1);
    check(optionalReport.Collected.Unknown == 1 && unknownPair.Get(L"postRoutine").IsNull(),
          "callbacks.unreadable-post-remains-unknown");
    Result diagnosticReport;
    diagnosticReport.State = Status::Partial;
    diagnosticReport.Collected.Unknown = 1;
    diagnosticReport.Rows.Push(paired);
    auto gap = knjson::Value::MakeObject();
    gap.Set(L"kind", knjson::Value(L"CoverageGap"));
    gap.Set(L"reason", knjson::Value(L"Missing type"));
    diagnosticReport.Rows.Push(gap);
    SeparateCallbackDiagnostics(diagnosticReport);
    check(diagnosticReport.Rows.Items().size() == 1 && diagnosticReport.Analysis.Get(L"diagnostics").Items().size() == 1 &&
              diagnosticReport.Collected.Unknown == 1 && diagnosticReport.State == Status::Partial,
          "callbacks.diagnostic-details-do-not-create-empty-registration-rows-or-complete-coverage");
    const auto comparablePair = ComparableRow(paired, true);
    check(comparablePair.Get(L"preRoutine").IsNull() && comparablePair.Get(L"postRoutine").IsNull() &&
              comparablePair.Get(L"pre").Get(L"routine").IsNull(),
          "callbacks.cross-session-paired-addresses-do-not-become-confirmed-changes");
    knjson::Value symbolPair;
    knjson::Parse(paired.Write(), &symbolPair);
    symbolPair.Set(L"preSymbol", knjson::Value(L"sample!NewlyLoadedSymbol"));
    symbolPair.Set(L"preSymbolSource", knjson::Value(L"LoadedDebuggerSymbols"));
    bool unknownSymbol = false;
    check(SameKnownValue(ComparableRow(paired), ComparableRow(symbolPair), unknownSymbol) && !unknownSymbol,
          "callbacks.loading-host-symbols-does-not-report-target-registration-changes");
    bool unknownOptional = false;
    check(SameKnownValue(ComparableRow(optionalPair), ComparableRow(optionalPair), unknownOptional) && !unknownOptional,
          "callbacks.known-null-optional-post-does-not-make-snapshot-comparison-unknown");

    EpochTracker epochs(L"callback-event-regression");
    knengine::SessionEvents events(epochs);
    std::atomic<uint64_t> sequence{0};
    knengine::SessionEvents hitObserver(epochs, &sequence);
    const auto beforeHit = epochs.Stamp();
    ULONG eventMask = 0, observerMask = 0;
    events.GetInterestMask(&eventMask);
    hitObserver.GetInterestMask(&observerMask);
    const auto hitStatus = std::async(std::launch::async, [&]()
    {
        return hitObserver.Breakpoint(nullptr);
    }).get();
    check((eventMask & DEBUG_EVENT_BREAKPOINT) == 0 && (observerMask & DEBUG_EVENT_BREAKPOINT) != 0 &&
              hitStatus == DEBUG_STATUS_NO_CHANGE && sequence.load() == 1 && epochs.Stamp() == beforeHit,
          "callbacks.breakpoint-observer-counts-without-engine-calls-or-execution-votes");
    events.Breakpoint(nullptr);
    hitObserver.Breakpoint(nullptr);
    check(sequence.load() == 2, "callbacks.only-dedicated-observer-counts-each-breakpoint-hit");
    const auto stamp = epochs.Stamp();
    bool crossThread = false;
    try
    {
        crossThread = std::async(std::launch::async,
                                 [&]()
                                 {
                                     return events.SessionStatus(DEBUG_SESSION_ACTIVE) == S_OK &&
                                            events.ChangeEngineState(DEBUG_CES_EXECUTION_STATUS, DEBUG_STATUS_BREAK) == S_OK &&
                                            events.ChangeSymbolState(DEBUG_CSS_LOADS, 0) == S_OK &&
                                            events.ChangeDebuggeeState(DEBUG_CDS_DATA, DEBUG_DATA_SPACE_VIRTUAL) == S_OK;
                                 })
                          .get();
    }
    catch (...)
    {
        crossThread = false;
    }
    check(crossThread && epochs.Stamp().TargetGeneration > stamp.TargetGeneration &&
              epochs.Stamp().SymbolGeneration > stamp.SymbolGeneration && epochs.Stamp().ContextGeneration > stamp.ContextGeneration,
          "callbacks.engine-notifications-cross-thread-without-owner-exception");
    const auto beforeRefresh = epochs.Stamp();
    events.ChangeDebuggeeState(DEBUG_CDS_REFRESH, DEBUG_CDS_REFRESH_EVALUATE);
    events.ChangeDebuggeeState(DEBUG_CDS_REFRESH, DEBUG_CDS_REFRESH_EXECUTE);
    events.ChangeDebuggeeState(DEBUG_CDS_REFRESH, DEBUG_CDS_REFRESH_EXECUTECOMMANDFILE);
    check(epochs.Stamp() == beforeRefresh, "callbacks.display-refresh-does-not-stale-results");
    events.ChangeDebuggeeState(DEBUG_CDS_REFRESH, DEBUG_CDS_REFRESH_SETSCOPE);
    check(epochs.Stamp().ContextGeneration > beforeRefresh.ContextGeneration, "callbacks.scope-refresh-still-invalidates-context");
    const auto beforeInternal = epochs.Stamp();
    ++knengine::InternalContextDepth;
    events.ChangeDebuggeeState(DEBUG_CDS_REGISTERS, DEBUG_ANY_ID);
    events.ChangeEngineState(DEBUG_CES_CURRENT_THREAD, 1);
    --knengine::InternalContextDepth;
    check(epochs.Stamp() == beforeInternal, "callbacks.internal-context-notification-suppressed");
    events.ChangeDebuggeeState(DEBUG_CDS_ALL, 0);
    check(epochs.Stamp().ContextGeneration > beforeInternal.ContextGeneration, "callbacks.general-target-change-still-invalidates");
    const auto symbolStamp = epochs.Stamp();
    {
        knengine::SymbolQueryScope query;
        events.ChangeSymbolState(DEBUG_CSS_LOADS, base);
        check(epochs.Stamp() == symbolStamp, "symbols.passive-deferred-load-keeps-current-read-valid");
        events.ChangeSymbolState(DEBUG_CSS_SCOPE, base);
        events.ChangeSymbolState(DEBUG_CSS_LOADS | DEBUG_CSS_SCOPE, base);
        check(epochs.Stamp() == symbolStamp, "symbols.query-initialized-scope-keeps-current-read-valid");
        events.ChangeSymbolState(DEBUG_CSS_UNLOADS, base);
        check(epochs.Stamp().SymbolGeneration > symbolStamp.SymbolGeneration, "symbols.unload-within-query-still-invalidates");
    }
    const auto explicitStamp = epochs.Stamp();
    events.ChangeSymbolState(DEBUG_CSS_LOADS, base);
    check(epochs.Stamp().SymbolGeneration > explicitStamp.SymbolGeneration, "symbols.explicit-load-still-invalidates");
    const auto scopeStamp = epochs.Stamp();
    events.ChangeSymbolState(DEBUG_CSS_SCOPE, 0);
    check(epochs.Stamp().SymbolGeneration > scopeStamp.SymbolGeneration, "symbols.external-scope-change-still-invalidates");
    const auto pathStamp = epochs.Stamp();
    {
        knengine::SymbolQueryScope query;
        events.ChangeSymbolState(DEBUG_CSS_PATHS | DEBUG_CSS_LOADS, 0);
    }
    check(epochs.Stamp().SymbolGeneration > pathStamp.SymbolGeneration, "symbols.path-change-during-query-still-invalidates");
}
} // namespace knself
