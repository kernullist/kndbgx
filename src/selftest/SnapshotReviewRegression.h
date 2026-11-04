#pragma once

#include "../core/Snapshot.h"

namespace knself
{
template <typename Check> void RunSnapshotReviewRegression(Check check)
{
    using namespace kncore;
    Snapshot baseline;
    baseline.Metadata.Set(L"schema", knjson::Value(L"kndbgx.snapshot.v2"));
    baseline.Metadata.Set(L"target", SessionStamp{L"rereview", 1, 1, 1, 1}.ToJson());
    Result collection;
    collection.Collected.Complete = true;
    collection.Collected.StopReason = L"EndOfList";
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"Module"));
    row.Set(L"moduleIdentity", knjson::Value(L"fixture-guid:1"));
    row.Set(L"size", knjson::Value(L"4096"));
    collection.Rows.Push(row);
    baseline.Collections[L"modules"] = collection.ToJson();
    for (const auto status : {Status::Partial, Status::Cancelled, Status::EngineError, Status::Unavailable})
    {
        auto partial = collection;
        partial.State = status;
        partial.Collected.Complete = false;
        partial.Collected.StopReason = L"NodeBudget";
        partial.Collected.Unknown = 2;
        partial.Limitations.Push(knjson::Value(L"fixture coverage gap"));
        auto before = baseline;
        before.Collections[L"modules"] = partial.ToJson();
        for (bool reverse : {false, true})
        {
            const auto result = reverse ? DiffSnapshots(baseline, before) : DiffSnapshots(before, baseline);
            const auto &input = result.Analysis.Get(L"inputCollections").Items()[0].Get(reverse ? L"after" : L"before");
            check(result.State == Status::Partial && !result.Collected.Complete &&
                      result.Rows.Items()[0].Get(L"state").AsString(L"") == L"Unchanged" &&
                      result.Analysis.Get(L"comparisonComplete").AsBool(false) &&
                      !result.Analysis.Get(L"inputCoverageComplete").AsBool(true) &&
                      input.Get(L"status").AsString(L"") == StatusName(status) &&
                      input.Get(L"coverage").Get(L"stopReason").AsString(L"") == L"NodeBudget" &&
                      input.Get(L"limitations").Items().size() == 1,
                  "rereview.diff-partial-common-rows-retain-source-coverage-and-error-state");
        }
        const auto identical = DiffSnapshots(before, before);
        check(identical.State == Status::Partial && !identical.Collected.Complete,
              "rereview.diff-identical-incomplete-inputs-never-promoted");
        partial.Rows = knjson::Value::MakeArray();
        before.Collections[L"modules"] = partial.ToJson();
        check(DiffSnapshots(before, before).State == Status::Partial &&
                  DiffSnapshots(before, baseline).Rows.Items()[0].Get(L"state").AsString(L"") == L"Unknown" &&
                  DiffSnapshots(baseline, before).Rows.Items()[0].Get(L"state").AsString(L"") == L"Unknown",
              "rereview.diff-empty-or-missing-partial-observations-not-added-or-removed");
    }
    for (const auto *pair :
         {LR"([{"known":1,"unknown":null},{"known":2,"unknown":null}])", LR"([{"unknown":null,"known":1},{"unknown":null,"known":2}])",
          LR"([{"nested":{"a":null,"b":1}},{"nested":{"a":null,"b":2}}])", LR"([{"array":[null,1]},{"array":[null,2]}])",
          LR"([{"array":[null]},{"array":[null,2]}])"})
    {
        knjson::Value values;
        knjson::Parse(pair, &values);
        auto before = baseline;
        auto after = baseline;
        for (size_t side = 0; side < 2; ++side)
        {
            auto changed = row;
            changed.Set(L"value", values.Items()[side]);
            auto next = collection;
            next.Rows = knjson::Value::MakeArray();
            next.Rows.Push(changed);
            (side == 0 ? before : after).Collections[L"modules"] = next.ToJson();
        }
        for (bool reverse : {false, true})
        {
            const auto result = reverse ? DiffSnapshots(after, before) : DiffSnapshots(before, after);
            const auto &difference = result.Rows.Items()[0];
            check(result.State == Status::Partial && difference.Get(L"state").AsString(L"") == L"Changed" &&
                      difference.Get(L"knownChanged").AsBool(false) && difference.Get(L"unknownFields").AsBool(false),
                  "rereview.diff-confirmed-change-survives-null-fields-nested-objects-and-arrays");
        }
    }
    auto missing = baseline;
    missing.Collections[L"other"] = collection.ToJson();
    check(!DiffSnapshots(baseline, missing).Collected.Complete && DiffSnapshots(baseline, baseline).State == Status::Success,
          "rereview.diff-mixed-missing-collection-partial-and-complete-positive-control");
    for (const wchar_t *reason : {L"TimeBudget", L"NodeBudget", L"Unreadable"})
    {
        auto incomplete = baseline;
        auto partial = collection;
        partial.Collected.Complete = false;
        partial.Collected.StopReason = reason;
        partial.Collected.Unreadable = 1;
        incomplete.Collections[L"modules"] = partial.ToJson();
        check(DiffSnapshots(incomplete, incomplete).Collected.StopReason == L"InputCoverageIncomplete",
              "rereview.diff-input-budget-or-unreadable-gap-survives-common-known-rows");
    }
    auto unverifiedRoutine = knjson::Value::MakeObject();
    unverifiedRoutine.Set(L"kind", knjson::Value(L"RoutineObservation"));
    unverifiedRoutine.Set(L"moduleIdentity", knjson::Value(L""));
    unverifiedRoutine.Set(L"rva", knjson::Value(L"0x10"));
    unverifiedRoutine.Set(L"routine", knjson::Value(L"0xffff800000001010"));
    check(ComparableRow(unverifiedRoutine).Get(L"routine").IsString(), "diff.empty-module-identity-cannot-hide-routine-address");
    unverifiedRoutine.Set(L"objectKey", knjson::Value(L"0xffff800000001000"));
    check(SnapshotKey(unverifiedRoutine, true).empty() && !SnapshotKey(unverifiedRoutine, false).empty(),
          "diff.opaque-object-key-is-session-local");
    unverifiedRoutine.Set(L"moduleIdentity", knjson::Value(L"driver.sys:0:4096"));
    unverifiedRoutine.Set(L"moduleIdentityKind", knjson::Value(L"ImagePathTimestampSize"));
    unverifiedRoutine.Set(L"family", knjson::Value(L"NativeSSDT"));
    unverifiedRoutine.Set(L"index", knjson::Value(L"1"));
    check(ComparableRow(unverifiedRoutine).Get(L"routine").IsString() && ComparableRow(unverifiedRoutine, true).Get(L"routine").IsNull(),
          "diff.weak-image-identity-cannot-normalize-routines-across-sessions");
    auto weakCollection = collection;
    weakCollection.Rows = knjson::Value::MakeArray();
    weakCollection.Rows.Push(unverifiedRoutine);
    auto weakBefore = baseline;
    weakBefore.Collections[L"modules"] = weakCollection.ToJson();
    auto weakAfter = weakBefore;
    weakAfter.Metadata.Set(L"target", SessionStamp{L"another-target", 1, 1, 1, 1}.ToJson());
    const auto weakComparison = DiffSnapshots(weakBefore, weakAfter, true);
    check(weakComparison.State == Status::Partial && !weakComparison.Collected.Complete &&
              weakComparison.Rows.Items()[0].Get(L"state").AsString(L"") == L"Unknown",
          "diff.cross-target-routine-identity-remains-unknown");
    unverifiedRoutine.Set(L"routine", knjson::Value(Hex(0)));
    check(ComparableRow(unverifiedRoutine, true).Get(L"routine").AsString(L"") == Hex(0),
          "diff.observed-null-routine-needs-no-image-identity");
    unverifiedRoutine.Set(L"routine", knjson::Value(L"0xffff800000001010"));
    unverifiedRoutine.Set(L"moduleIdentityKind", knjson::Value(L"MatchedPdbImage"));
    check(ComparableRow(unverifiedRoutine, true).Get(L"routine").IsNull() && ComparableRow(unverifiedRoutine).Get(L"routine").IsString(),
          "diff.verified-relocation-normalization-is-cross-session-only");
    auto firstKey = knjson::Value::MakeObject();
    firstKey.Set(L"kind", knjson::Value(L"RoutineObservation"));
    firstKey.Set(L"family", knjson::Value(L"a:b"));
    firstKey.Set(L"index", knjson::Value(L"c"));
    auto secondKey = firstKey;
    secondKey.Set(L"family", knjson::Value(L"a"));
    secondKey.Set(L"index", knjson::Value(L"b:c"));
    check(SnapshotKey(firstKey, true) != SnapshotKey(secondKey, true), "diff.identity-components-cannot-impersonate-delimiters");

    auto unloaded = knjson::Value::MakeObject();
    unloaded.Set(L"kind", knjson::Value(L"UnloadedDriver"));
    unloaded.Set(L"name", knjson::Value(L"fixture.sys"));
    unloaded.Set(L"StartAddress", knjson::Value(Hex(0xffff800000100000)));
    unloaded.Set(L"EndAddress", knjson::Value(Hex(0xffff800000104000)));
    unloaded.Set(L"CurrentTime", knjson::Value(Hex(100)));
    unloaded.Set(L"identityComplete", knjson::Value(true));
    unloaded.Set(L"index", knjson::Value(L"0"));
    unloaded.Set(L"record", knjson::Value(Hex(0xffff800000200000)));
    unloaded.Set(L"ringNextIndex", knjson::Value(L"1"));
    const auto unloadSnapshot = [&](std::initializer_list<knjson::Value> rows, bool complete = true)
    {
        auto snapshot = baseline;
        snapshot.Collections.clear();
        Result events;
        events.State = complete ? Status::Success : Status::Partial;
        events.Collected.Complete = complete;
        events.Collected.Unknown = complete ? 0 : 1;
        for (const auto &event : rows)
        {
            events.Rows.Push(event);
        }
        snapshot.Collections[L"unloaded-drivers"] = events.ToJson();
        return snapshot;
    };
    auto shifted = unloaded;
    shifted.Set(L"index", knjson::Value(L"49"));
    shifted.Set(L"record", knjson::Value(Hex(0xffff800000300000)));
    shifted.Set(L"ringNextIndex", knjson::Value());
    const auto shiftedDiff = DiffSnapshots(unloadSnapshot({unloaded}), unloadSnapshot({shifted}));
    check(!SnapshotKey(unloaded, false).empty() && SnapshotKey(unloaded, false) == SnapshotKey(shifted, false) &&
              shiftedDiff.State == Status::Success && shiftedDiff.Rows.Items().size() == 1 &&
              shiftedDiff.Rows.Items()[0].Get(L"state").AsString(L"") == L"Unchanged",
          "diff.unloaded-ring-position-and-optional-ring-cursor-do-not-change-event");
    auto reloaded = unloaded;
    reloaded.Set(L"CurrentTime", knjson::Value(Hex(200)));
    const auto repeatedDiff = DiffSnapshots(unloadSnapshot({unloaded}), unloadSnapshot({unloaded, reloaded}));
    const auto countState = [](const Result &report, const wchar_t *state)
    {
        return std::count_if(report.Rows.Items().begin(), report.Rows.Items().end(), [&](const auto &item)
        {
            return item.Get(L"state").AsString(L"") == state;
        });
    };
    check(SnapshotKey(unloaded, false) != SnapshotKey(reloaded, false) && repeatedDiff.State == Status::Success &&
              countState(repeatedDiff, L"Added") == 1 && countState(repeatedDiff, L"Unchanged") == 1,
          "diff.unloaded-reused-name-and-base-retain-distinct-unload-events");
    const auto replaced = DiffSnapshots(unloadSnapshot({unloaded}), unloadSnapshot({reloaded}));
    check(countState(replaced, L"Added") == 1 && countState(replaced, L"Removed") == 1,
          "diff.unloaded-reused-ring-slot-does-not-become-a-changed-event");
    for (const auto *field : {L"name", L"StartAddress", L"EndAddress", L"CurrentTime", L"identityComplete"})
    {
        auto incomplete = unloaded;
        incomplete.Set(field, knjson::Value());
        const auto gap = DiffSnapshots(unloadSnapshot({incomplete}), unloadSnapshot({incomplete}));
        check(SnapshotKey(incomplete, false).empty() && gap.State == Status::Partial && countState(gap, L"Unknown") == 2,
              "diff.unloaded-missing-identity-never-matches-or-proves-absence");
        for (const bool reverse : {false, true})
        {
            const auto identified = unloadSnapshot({unloaded, reloaded});
            const auto unidentified = unloadSnapshot({incomplete, reloaded});
            const auto mixed = reverse ? DiffSnapshots(unidentified, identified) : DiffSnapshots(identified, unidentified);
            check(mixed.State == Status::Partial && countState(mixed, L"Added") == 0 && countState(mixed, L"Removed") == 0 &&
                      countState(mixed, L"Unknown") == 2 && countState(mixed, L"Unchanged") == 1 &&
                      mixed.Analysis.Get(L"inputCoverageComplete").AsBool(false) &&
                      !mixed.Analysis.Get(L"inputIdentitiesKnown").AsBool(true),
                  "diff.unloaded-unknown-identity-invalidates-absence-despite-complete-imported-coverage");
        }
    }
    for (const auto *value : {L"0x0", L"not-a-time", L"0x10000000000000000"})
    {
        auto invalid = unloaded;
        invalid.Set(L"CurrentTime", knjson::Value(value));
        check(SnapshotKey(invalid, false).empty(), "diff.unloaded-zero-malformed-overflow-time-is-unknown");
    }
    auto inverted = unloaded;
    inverted.Set(L"EndAddress", unloaded.Get(L"StartAddress"));
    check(SnapshotKey(inverted, false).empty(), "diff.unloaded-empty-or-inverted-range-is-unknown");
    const auto duplicate = DiffSnapshots(unloadSnapshot({unloaded, shifted}), unloadSnapshot({unloaded}));
    check(duplicate.State == Status::Partial && countState(duplicate, L"Unknown") == 1,
          "diff.unloaded-duplicate-identities-remain-ambiguous");
    const auto partialUnload = DiffSnapshots(unloadSnapshot({unloaded}), unloadSnapshot({reloaded}, false));
    check(partialUnload.State == Status::Partial && countState(partialUnload, L"Unknown") == 2,
          "diff.unloaded-incomplete-inventory-cannot-prove-addition-or-removal");
    auto otherSession = unloadSnapshot({unloaded});
    otherSession.Metadata.Set(L"target", SessionStamp{L"other-unload-session", 1, 1, 1, 1}.ToJson());
    check(DiffSnapshots(unloadSnapshot({unloaded}), otherSession).State == Status::Unavailable &&
              SnapshotKey(unloaded, true).empty() &&
              countState(DiffSnapshots(unloadSnapshot({unloaded}), otherSession, true), L"Unknown") == 2,
          "diff.unloaded-cross-session-events-remain-unknown-even-with-override");
    auto oldSnapshot = baseline;
    const auto oldVsNew = DiffSnapshots(oldSnapshot, unloadSnapshot({unloaded}));
    check(oldVsNew.State == Status::Partial && countState(oldVsNew, L"Added") == 0,
          "diff.unloaded-new-collection-is-unknown-against-old-baseline");
}
} // namespace knself
