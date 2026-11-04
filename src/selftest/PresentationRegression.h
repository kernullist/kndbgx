#pragma once

#include "../core/ResultPresentation.h"
#include "../core/MemoryView.h"
#include "../core/Snapshot.h"
#include "../engine/PageWalk.h"
#include "../cmd/CmdUtil.h"
#include "../cmd/CollectorSupport.h"

namespace knself
{
template <typename Check> void RunPresentationRegression(Check check)
{
    using namespace kncore;
    check(!SymbolNameCanBind(L"nt!HalpPciMmConfigWriteHandlers <PERF> (nt+0x0)") &&
              SymbolNameCanBind(L"nt!KeBugCheckEx") && !SymbolNameCanBind(L"nt!") && !SymbolNameCanBind(L"unqualified"),
          "presentation.synthetic-perf-text-is-not-a-qualified-symbol-name");
    constexpr uint64_t imageBase = 0xfffff8039be00000;
    check(!ExactSymbolBinding(imageBase, 0, imageBase + 0x1000, imageBase, 0x1459000),
          "presentation.synthetic-perf-header-label-is-not-a-function-binding");
    check(ExactSymbolBinding(imageBase + 0x1004, 4, imageBase + 0x1000, imageBase, 0x1459000),
          "presentation.real-symbol-and-displacement-bind-to-the-requested-address");
    check(!ExactSymbolBinding(imageBase, UINT64_MAX, imageBase + 1, imageBase, 0x1459000) &&
              !ExactSymbolBinding(imageBase + 0x1459000, 0, imageBase + 0x1459000, imageBase, 0x1459000),
          "presentation.symbol-binding-refuses-underflow-and-an-outside-module-address");
    {
        SymbolAddressCache bindings;
        unsigned lookups = 0;
        const auto resolve = [&]() -> std::optional<uint64_t>
        {
            ++lookups;
            return imageBase + 0x1000;
        };
        bool bound = true;
        for (uint64_t displacement = 0; displacement < 32; ++displacement)
        {
            const auto start = bindings.Get(imageBase, L"nt!Routine", resolve);
            bound = bound && start && ExactSymbolBinding(imageBase + 0x1000 + displacement, displacement,
                                                         *start, imageBase, 0x2000);
        }
        check(bound && lookups == 1, "presentation.adjacent-instructions-resolve-a-symbol-address-once");
        const auto same = bindings.Get(imageBase, L"nt!Routine", resolve);
        check(same && !ExactSymbolBinding(imageBase + 0x1100, 0, *same, imageBase, 0x2000),
              "presentation.cached-symbol-still-requires-exact-displacement-binding");
        const auto other = bindings.Get(imageBase + 0x4000, L"nt!Routine", [&]() -> std::optional<uint64_t>
        {
            return imageBase + 0x5000;
        });
        check(other == imageBase + 0x5000, "presentation.symbol-address-cache-keeps-module-identities-separate");
        unsigned unavailableLookups = 0;
        const auto unavailable = [&]() -> std::optional<uint64_t>
        {
            ++unavailableLookups;
            return std::nullopt;
        };
        const auto missing = bindings.Get(imageBase, L"nt!Missing", unavailable);
        const auto repeated = bindings.Get(imageBase, L"nt!Missing", unavailable);
        check(!missing && !repeated && unavailableLookups == 1,
              "presentation.unavailable-symbol-binding-is-not-retried-for-every-row");
        SymbolAddressCache nextResult;
        const auto loaded = nextResult.Get(imageBase, L"nt!Missing", resolve);
        check(loaded == imageBase + 0x1000, "presentation.new-result-retries-a-previously-unavailable-symbol");
    }
    Result result;
    result.State = Status::Partial;
    result.Collected.Unknown = 3;
    auto routine = knjson::Value::MakeObject();
    routine.Set(L"kind", knjson::Value(L"RoutineObservation"));
    routine.Set(L"family", knjson::Value(L"IdtGate"));
    routine.Set(L"routine", knjson::Value(Hex(0xffff800000001000)));
    result.Rows.Push(routine);
    auto gap = knjson::Value::MakeObject();
    gap.Set(L"kind", knjson::Value(L"CoverageGap"));
    gap.Set(L"reason", knjson::Value(L"No matched layout"));
    result.Rows.Push(gap);
    SeparateResultDiagnostics(result);
    check(result.Rows.Items().size() == 1 && result.Analysis.Get(L"diagnostics").Items().size() == 1 &&
              result.State == Status::Partial && result.Collected.Unknown == 3,
          "presentation.diagnostics-leave-observations-and-coverage-intact");
    SeparateResultDiagnostics(result);
    check(result.Analysis.Get(L"diagnostics").Items().size() == 1, "presentation.diagnostic-partition-is-idempotent");
    Result empty;
    empty.Collected.Complete = true;
    empty.Rows.Push(knjson::Value::MakeObject());
    empty.Rows.Push(knjson::Value());
    SeparateResultDiagnostics(empty);
    check(empty.Rows.Items().empty() && empty.State == Status::Partial && !empty.Collected.Complete &&
              empty.Collected.Unknown == 2 && empty.Analysis.Get(L"diagnostics").Items().size() == 2,
          "presentation.empty-records-remain-explicit-incomplete-diagnostics");
    auto zeros = knjson::Value::MakeObject();
    zeros.Set(L"enabled", knjson::Value(false));
    zeros.Set(L"value", knjson::Value(0.0));
    check(HasObservationValue(zeros), "presentation.false-and-zero-are-observed-values");
    knjson::Value annotated;
    knjson::Parse(routine.Write(), &annotated);
    annotated.Set(L"symbol", knjson::Value(L"nt!LoadedLater"));
    annotated.Set(L"symbolSource", knjson::Value(L"LoadedDebuggerSymbols"));
    annotated.Set(L"symbolAddress", routine.Get(L"routine"));
    annotated.Set(L"symbolDisplacement", knjson::Value(Hex(4)));
    annotated.Set(L"startSymbol", knjson::Value(L"nt!OtherName"));
    bool unknown = false;
    check(SameKnownValue(ComparableRow(routine), ComparableRow(annotated), unknown) && !unknown,
          "presentation.symbol-loading-does-not-create-target-differences");
    annotated.Set(L"routine", knjson::Value(Hex(0xffff800000002000)));
    check(!SameKnownValue(ComparableRow(routine), ComparableRow(annotated), unknown),
          "presentation.symbol-normalization-preserves-real-address-changes");
    auto operation = routine;
    operation.Set(L"family", knjson::Value(L"Minifilter.PreOperation"));
    operation.Set(L"major", knjson::Value(L"3"));
    auto namedOperation = operation;
    namedOperation.Set(L"majorName", knjson::Value(L"IRP_MJ_READ"));
    check(SameKnownValue(ComparableRow(operation), ComparableRow(namedOperation), unknown),
          "presentation.minifilter-major-label-does-not-create-target-differences");
    namedOperation.Set(L"major", knjson::Value(L"4"));
    check(!SameKnownValue(ComparableRow(operation), ComparableRow(namedOperation), unknown),
          "presentation.minifilter-major-code-changes-remain-comparable");
    for (const auto *phase : {L"Minifilter.PreOperation", L"Minifilter.PostOperation"})
    {
        auto rawOperation = operation;
        rawOperation.Set(L"family", knjson::Value(phase));
        rawOperation.Set(L"slot", knjson::Value(Hex(0xffff800000003000)));
        Result collection;
        collection.Collected.Complete = true;
        collection.Rows.Push(rawOperation);
        Snapshot before;
        before.Metadata.Set(L"schema", knjson::Value(L"kndbgx.snapshot.v2"));
        before.Metadata.Set(L"target", SessionStamp{L"major-review", 1, 1, 1, 1}.ToJson());
        before.Collections[L"minifilter"] = collection.ToJson();
        auto after = before;
        rawOperation.Set(L"majorName", knjson::Value(L"IRP_MJ_READ"));
        collection.Rows = knjson::Value::MakeArray();
        collection.Rows.Push(rawOperation);
        after.Collections[L"minifilter"] = collection.ToJson();
        bool labelsUnchanged = true;
        for (const bool reverse : {false, true})
        {
            const auto diff = reverse ? DiffSnapshots(after, before) : DiffSnapshots(before, after);
            labelsUnchanged = labelsUnchanged && diff.State == Status::Success && diff.Collected.Unknown == 0 &&
                diff.Rows.Items().size() == 1 && diff.Rows.Items()[0].Get(L"state").AsString(L"") == L"Unchanged";
        }
        check(labelsUnchanged, "presentation.minifilter-label-only-diff-is-complete-in-both-directions");
        rawOperation.Set(L"major", knjson::Value(L"4"));
        collection.Rows = knjson::Value::MakeArray();
        collection.Rows.Push(rawOperation);
        after.Collections[L"minifilter"] = collection.ToJson();
        bool codesChanged = true;
        for (const bool reverse : {false, true})
        {
            const auto diff = reverse ? DiffSnapshots(after, before) : DiffSnapshots(before, after);
            codesChanged = codesChanged && diff.State == Status::Success && diff.Rows.Items().size() == 1 &&
                diff.Rows.Items()[0].Get(L"state").AsString(L"") == L"Changed" &&
                diff.Rows.Items()[0].Get(L"knownChanged").AsBool(false);
        }
        check(codesChanged, "presentation.minifilter-real-code-diff-survives-a-stale-display-label");
    }
    const std::vector<unsigned char> bytes{0x34, 0x12, 0, 0, 0, 0x80, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa};
    std::vector<unsigned char> valid(bytes.size(), 1);
    const auto pointers = MemoryPointerRows(0x1000, 8, bytes, valid);
    check(pointers.Items().size() == 3 && pointers.Items()[0].Get(L"pointer").AsString(L"") == Hex(0xffff800000001234) &&
              pointers.Items()[1].Get(L"pointer").AsString(L"") == Hex(0) &&
              pointers.Items()[2].Get(L"pointer").IsNull() && !pointers.Items()[2].Get(L"readable").AsBool(true),
          "presentation.pointer-rows-distinguish-address-zero-and-short-tail");
    valid[3] = 0;
    const auto unreadable = MemoryPointerRows(0x1000, 8, bytes, valid);
    check(unreadable.Items()[0].Get(L"pointer").IsNull() && MemoryPointerRows(0x1000, 2, bytes, valid).Items().empty(),
          "presentation.partial-pointer-never-becomes-a-zero-or-a-decoded-address");
    knengine::PageWalkResult walk;
    walk.VirtualAddress = 0xffff800000001000;
    walk.DirectoryTableBase = 0x1000;
    walk.Ok = true;
    walk.PhysicalAddress = 0;
    walk.LevelCount = 1;
    walk.EntrySlotPhysical[0] = 0x1ff8;
    walk.EntryValue[0] = 0x2003;
    const auto mapped = knengine::PageWalkObservation(walk);
    check(mapped.Get(L"pa").AsString(L"") == Hex(0) &&
              mapped.Get(L"entries").Items()[0].Get(L"addressSpace").AsString(L"") == L"physical" &&
              mapped.Get(L"va").AsString(L"") == Hex(walk.VirtualAddress),
          "presentation.translation-keeps-virtual-address-and-physical-entry-spaces-distinct");
    walk.Ok = false;
    walk.Error = L"UnreadablePhysicalEntry";
    check(knengine::PageWalkObservation(walk).Get(L"pa").IsNull() &&
              knengine::PageWalkObservation(walk).Get(L"error").AsString(L"") == walk.Error,
          "presentation.failed-translation-retains-error-without-a-false-physical-zero");
    const bool wasFaulted = knengine::Epochs().State() == SessionState::Faulted;
    knengine::Epochs().Reconnect();
    knengine::DbgSession disconnected;
    knengine::PageWalkResult unavailable;
    const bool translated = knengine::WalkVirtualToPhysical(disconnected, 0xffff800012345000, 0x12345000, false, &unavailable);
    const auto unavailableRow = knengine::PageWalkObservation(unavailable);
    check(!translated && unavailableRow.Get(L"va").AsString(L"") == Hex(0xffff800012345000) &&
              unavailableRow.Get(L"dtb").AsString(L"") == Hex(0x12345000) && unavailableRow.Get(L"pa").IsNull(),
          "presentation.unavailable-paging-mode-retains-requested-address-and-dtb");
    for (const auto state : {Status::StaleContext, Status::Cancelled, Status::InternalFault})
    {
        Result rejected;
        rejected.State = state;
        auto retained = knjson::Value::MakeObject();
        retained.Set(L"routine", knjson::Value(Hex(0)));
        rejected.Rows.Push(retained);
        kncmd::AnnotateResultSymbols(disconnected, rejected);
        check(rejected.Rows.Items()[0].Get(L"symbolSource").IsNull() && rejected.State == state,
              "presentation.rejected-context-does-not-annotate-retained-observations");
    }
    Result observedNull;
    auto nullRoutine = knjson::Value::MakeObject();
    nullRoutine.Set(L"routine", knjson::Value(Hex(0)));
    observedNull.Rows.Push(nullRoutine);
    kncmd::AnnotateResultSymbols(disconnected, observedNull);
    check(observedNull.Rows.Items()[0].Get(L"symbolSource").AsString(L"") == L"NullAddress",
          "presentation.valid-context-keeps-null-address-provenance");
    kncmd::CmdText output;
    const std::vector<std::wstring> args{L"fixture"};
    kncmd::Ctx context{disconnected, args, output};
    WalkBudget emptyBudget;
    emptyBudget.Report.Stamp = disconnected.RefreshStamp();
    emptyBudget.Report.Rows.Push(knjson::Value::MakeObject());
    kncmd::FinishCollection(context, emptyBudget);
    check(output.Details.State == Status::Partial && output.Text().find(L"status=Partial") != std::wstring::npos &&
              output.Text().find(L"unknown=1") != std::wstring::npos,
          "presentation.console-coverage-reflects-empty-observation-diagnostic");
    if (wasFaulted)
    {
        knengine::Epochs().Fault();
    }
}
} // namespace knself
