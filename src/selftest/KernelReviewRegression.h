#pragma once

#include "KernelAnalysisRegression.h"
#include "../engine/ContextGuard.h"
#include "../engine/SymbolQuery.h"

namespace knself
{
inline knjson::Value ReviewSarif(const knjson::Value &item, const knjson::Value &invocations = {})
{
    auto document = SarifFixture();
    auto run = document.Get(L"runs").Items()[0];
    auto results = knjson::Value::MakeArray();
    results.Push(item);
    run.Set(L"results", results);
    run.Set(L"invocations", invocations);
    auto runs = knjson::Value::MakeArray();
    runs.Push(run);
    document.Set(L"runs", runs);
    return document;
}

inline std::vector<unsigned char> ReviewImportPe(bool is64)
{
    auto bytes = PeFixture(is64);
    bytes.resize(0x600);
    const size_t directories =
        0x98 + (is64 ? offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) : offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory));
    StoreFixture(bytes, directories + IMAGE_DIRECTORY_ENTRY_IMPORT * sizeof(IMAGE_DATA_DIRECTORY), IMAGE_DATA_DIRECTORY{0x1000, 40});
    IMAGE_IMPORT_DESCRIPTOR descriptor = {};
    descriptor.Name = 0x1080;
    descriptor.OriginalFirstThunk = 0x1090;
    descriptor.FirstThunk = 0x10d0;
    StoreFixture(bytes, 0x400, descriptor);
    std::memcpy(bytes.data() + 0x480, "ntoskrnl.exe", 13);
    StoreFixture(bytes, 0x490, uint64_t(0x10b0));
    StoreFixture(bytes, 0x4d0, uint64_t(0x10b0));
    std::memcpy(bytes.data() + 0x4b2, "ExAllocatePool2", 16);
    return bytes;
}

inline void RunKernelReviewRegression(CheckFn check)
{
    using namespace kncore;
    const auto original = SarifFixture().Get(L"runs").Items()[0].Get(L"results").Items()[0];
    bool kinds = true;
    for (const auto *kind : {L"pass", L"open", L"informational", L"notApplicable", L"review"})
    {
        auto item = original;
        item.Set(L"kind", knjson::Value(kind));
        const auto imported = ImportSarif(ReviewSarif(item));
        kinds = kinds && imported.State == Status::Success && imported.Rows.Items()[1].Get(L"level").AsString(L"") == L"none" &&
                imported.Rows.Items()[1].Get(L"resultKind").AsString(L"") == kind;
    }
    check(kinds, "review2.sarif-nonfailure-kind-never-inherits-error");
    knjson::Value invocations;
    knjson::Parse(
        LR"([{"executionSuccessful":true,"ruleConfigurationOverrides":[{"descriptor":{"index":0},"configuration":{"level":"note"}}]}])",
        &invocations);
    auto item = original;
    knjson::Value provenance;
    knjson::Parse(LR"({"invocationIndex":0})", &provenance);
    item.Set(L"provenance", provenance);
    const auto overridden = ImportSarif(ReviewSarif(item, invocations));
    check(overridden.State == Status::Success && overridden.Rows.Items()[1].Get(L"level").AsString(L"") == L"note",
          "review2.sarif-invocation-severity-override");
    provenance.Set(L"invocationIndex", knjson::Value(9.0));
    item.Set(L"provenance", provenance);
    const auto missingInvocation = ImportSarif(ReviewSarif(item, invocations));
    check(missingInvocation.State == Status::Partial && missingInvocation.Rows.Items()[1].Get(L"level").AsString(L"") == L"unknown",
          "review2.sarif-unresolved-invocation-cannot-guess-severity");
    knjson::Value failedRun;
    knjson::Parse(
        LR"({"version":"2.1.0","runs":[{"tool":{"driver":{"name":"failed analyzer"}},"invocations":[{"executionSuccessful":false}]}]})",
        &failedRun);
    const auto failed = ImportSarif(failedRun);
    check(failed.State == Status::Partial && failed.Rows.Items().size() == 1 &&
              failed.Rows.Items()[0].Get(L"invocations").Items().size() == 1,
          "review2.sarif-missing-results-preserve-run-failure-evidence");
    knjson::Value message;
    knjson::Parse(LR"({"text":"Use {{address}}"})", &message);
    check(SarifMessage(message, {}, {}).value_or(L"") == L"Use {address}", "review2.sarif-brace-escaping-without-arguments");
    knjson::Parse(LR"({"text":"Missing {0}"})", &message);
    check(!SarifMessage(message, {}, {}), "review2.sarif-placeholder-requires-arguments");
    knjson::Parse(LR"({"text":"Unescaped }","arguments":[]})", &message);
    check(!SarifMessage(message, {}, {}), "review2.sarif-unmatched-brace-is-unresolved");
    for (const bool is64 : {false, true})
    {
        auto bytes = ReviewImportPe(is64);
        check(AuditDriverPe(bytes).State == Status::Success, is64 ? "review2.pe64-valid-iat-control" : "review2.pe32-valid-iat-control");
        StoreFixture(bytes, 0x400 + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk), DWORD(0xfffffff8));
        const auto badIat = AuditDriverPe(bytes);
        check(badIat.State == Status::Partial && badIat.Rows.Items().back().Get(L"iatRva").IsNull(),
              is64 ? "review2.pe64-iat-outside-image-not-reported-as-valid" : "review2.pe32-iat-outside-image-not-reported-as-valid");
        bytes = ReviewImportPe(is64);
        const uint64_t ordinal = (is64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32) | 0x10001;
        StoreFixture(bytes, 0x490, ordinal);
        check(AuditDriverPe(bytes).State == Status::Partial,
              is64 ? "review2.pe64-ordinal-reserved-bits" : "review2.pe32-ordinal-reserved-bits");
    }
    auto debug = PeFixture(true);
    debug.resize(0x600);
    StoreFixture(debug,
                 0x98 + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) + IMAGE_DIRECTORY_ENTRY_DEBUG * sizeof(IMAGE_DATA_DIRECTORY),
                 IMAGE_DATA_DIRECTORY{0x1000, sizeof(IMAGE_DEBUG_DIRECTORY)});
    IMAGE_DEBUG_DIRECTORY record = {};
    record.Type = IMAGE_DEBUG_TYPE_CODEVIEW;
    record.PointerToRawData = 0x5f8;
    record.SizeOfData = 32;
    StoreFixture(debug, 0x400, record);
    check(AuditDriverPe(debug).State == Status::Partial, "review2.pe-invalid-codeview-is-not-absent-metadata");
    auto malformedDefault = SarifFixture();
    auto malformedRun = malformedDefault.Get(L"runs").Items()[0];
    knjson::Value malformedTool;
    knjson::Parse(LR"({"driver":{"name":"fixture","rules":[{"id":"cpp/test","defaultConfiguration":{"level":42}}]}})", &malformedTool);
    malformedRun.Set(L"tool", malformedTool);
    auto malformedRuns = knjson::Value::MakeArray();
    malformedRuns.Push(malformedRun);
    malformedDefault.Set(L"runs", malformedRuns);
    const auto malformed = ImportSarif(malformedDefault);
    check(malformed.State == Status::Partial && malformed.Rows.Items()[1].Get(L"level").AsString(L"") == L"unknown",
          "review3.sarif-malformed-default-is-not-warning");

    const SessionStamp stamp{L"review-target", 1, 2, 3, 4};
    auto changed = stamp;
    ++changed.TargetGeneration;
    kncmd::CommandResult partial = {};
    partial.Data.Stamp = stamp;
    partial.Data.State = Status::Partial;
    partial.Data.Rows.Push(knjson::Value(L"retained observation"));
    kncmd::FinalizeCollection(partial, kncmd::FindCommand(L"irp"), changed, false);
    check(partial.Data.State == Status::StaleContext && !partial.Data.Collected.Complete && partial.Data.Rows.Items().size() == 1,
          "review3.partial-target-collection-must-become-stale");
    kncmd::CommandResult offline = {};
    offline.Ok = true;
    offline.Data.Stamp = stamp;
    offline.Data.Collected.Complete = true;
    kncmd::FinalizeCollection(offline, kncmd::FindCommand(L"driver-audit"), changed, false);
    check(offline.Ok && offline.Data.State == Status::Success && offline.Data.Collected.Complete,
          "review3.offline-file-result-does-not-depend-on-target-epoch");
    kncmd::CommandResult fault = {};
    fault.Data.State = Status::InternalFault;
    fault.Data.Stamp = stamp;
    fault.Data.Error.Message = L"Native handler fault";
    kncmd::FinalizeCollection(fault, kncmd::FindCommand(L"irp"), stamp, true);
    check(fault.Data.State == Status::InternalFault && fault.Data.Error.Message == L"Native handler fault",
          "review3.cancellation-cannot-hide-native-fault");

    knengine::DbgSession session;
    kncmd::CmdText output;
    const std::vector<std::wstring> arguments;
    kncmd::Ctx context{session, arguments, output};
    const unsigned depth = knengine::InternalContextDepth;
    const unsigned symbolDepth = knengine::PassiveSymbolQueryDepth;
    kncmd::ExecuteCollector(
        [](kncmd::Ctx &ctx)
        {
            knengine::ContextGuard guard(ctx.Session);
            knengine::SymbolQueryScope query;
            RaiseException(0xE0424343, 0, 0, nullptr);
        },
        context);
    check(output.Details.State == Status::InternalFault && knengine::InternalContextDepth == depth,
          "review3.native-fault-restores-context-event-tracking-depth");
    check(knengine::PassiveSymbolQueryDepth == symbolDepth, "symbols.native-fault-restores-passive-symbol-scope");
    knengine::InternalContextDepth = depth;

    knjson::Parse(LR"([{"ruleConfigurationOverrides":[{"descriptor":{"id":"cpp/test"},"configuration":{"level":"note"}}]}])", &invocations);
    provenance.Set(L"invocationIndex", knjson::Value(0.0));
    item = original;
    item.Set(L"provenance", provenance);
    check(ImportSarif(ReviewSarif(item, invocations)).Rows.Items()[1].Get(L"level").AsString(L"") == L"note",
          "review3.sarif-override-resolves-rule-id");
    item.Set(L"level", knjson::Value(L"error"));
    check(ImportSarif(ReviewSarif(item, invocations)).Rows.Items()[1].Get(L"level").AsString(L"") == L"error",
          "review3.sarif-explicit-level-precedes-override");
    item.Set(L"kind", knjson::Value(L"pass"));
    const auto contradiction = ImportSarif(ReviewSarif(item, invocations));
    check(contradiction.State == Status::Partial && contradiction.Rows.Items()[1].Get(L"level").AsString(L"") == L"unknown",
          "review3.sarif-contradictory-pass-error-is-unresolved");
    item = original;
    provenance.Set(L"invocationIndex", knjson::Value(-1.0));
    item.Set(L"provenance", provenance);
    check(ImportSarif(ReviewSarif(item, invocations)).Rows.Items()[1].Get(L"level").AsString(L"") == L"error",
          "review3.sarif-absent-invocation-default-does-not-select-first");
    knjson::Parse(
        LR"([{"ruleConfigurationOverrides":[{"descriptor":{"index":0},"configuration":{"level":"note"}},{"descriptor":{"index":0},"configuration":{"level":"error"}}]}])",
        &invocations);
    provenance.Set(L"invocationIndex", knjson::Value(0.0));
    item.Set(L"provenance", provenance);
    const auto duplicate = ImportSarif(ReviewSarif(item, invocations));
    check(duplicate.State == Status::Partial && duplicate.Rows.Items()[1].Get(L"level").AsString(L"") == L"unknown",
          "review3.sarif-conflicting-overrides-are-not-first-wins");
    knjson::Parse(LR"({"text":"{{{0}}}","arguments":["value"]})", &message);
    check(SarifMessage(message, {}, {}).value_or(L"") == L"{value}", "review3.sarif-nested-escape-and-placeholder");

    record.Type = IMAGE_DEBUG_TYPE_REPRO;
    record.PointerToRawData = 0;
    record.SizeOfData = 0;
    StoreFixture(debug, 0x400, record);
    check(AuditDriverPe(debug).State == Status::Success && AuditDriverPe(debug).Rows.Items()[0].Get(L"codeViewGuidAgeBytes").IsNull(),
          "review3.pe-debug-table-without-codeview-is-not-corrupt");
    record.Type = IMAGE_DEBUG_TYPE_CODEVIEW;
    record.PointerToRawData = 0x500;
    record.SizeOfData = 24;
    StoreFixture(debug, 0x400, record);
    std::memcpy(debug.data() + 0x500, "RSDS", 4);
    StoreFixture(debug, 0x514, DWORD(1));
    const auto pdb = AuditDriverPe(debug);
    check(pdb.State == Status::Success && pdb.Rows.Items()[0].Get(L"codeViewGuidAgeBytes").Items().size() == 20,
          "review3.pe-valid-codeview-identity-control");
    auto missingIat = ReviewImportPe(true);
    StoreFixture(missingIat, 0x400 + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk), DWORD(0));
    check(AuditDriverPe(missingIat).State == Status::Partial && AuditDriverPe(missingIat).Rows.Items().back().Get(L"iatRva").IsNull(),
          "review3.pe-null-iat-is-not-header-address");
    auto validOrdinal = ReviewImportPe(true);
    StoreFixture(validOrdinal, 0x490, uint64_t(IMAGE_ORDINAL_FLAG64 | 42));
    const auto ordinal = AuditDriverPe(validOrdinal);
    check(ordinal.State == Status::Success && ordinal.Rows.Items().back().Get(L"ordinal").AsString(L"") == L"42",
          "review3.pe-valid-ordinal-control");

    changed = stamp;
    ++changed.SymbolGeneration;
    partial.Data.State = Status::Partial;
    kncmd::FinalizeCollection(partial, kncmd::FindCommand(L"irp"), changed, false);
    check(partial.Data.State == Status::StaleContext, "review3.partial-symbol-change-invalidates-observation");
    kncmd::FinalizeCollection(offline, kncmd::FindCommand(L"driver-audit"), stamp, true);
    check(offline.Data.State == Status::Cancelled && !offline.Data.Collected.Complete, "review3.offline-file-command-still-honors-cancel");
    fault.Data.State = Status::StaleContext;
    kncmd::FinalizeCollection(fault, kncmd::FindCommand(L"irp"), stamp, true);
    check(fault.Data.State == Status::StaleContext, "review3.cancellation-preserves-stale-context");
    {
        knengine::ContextGuard caller(session);
        const unsigned nestedDepth = knengine::InternalContextDepth;
        output = {};
        kncmd::ExecuteCollector(
            [](kncmd::Ctx &ctx)
            {
                knengine::ContextGuard guard(ctx.Session);
                RaiseException(0xE0424343, 0, 0, nullptr);
            },
            context);
        check(knengine::InternalContextDepth == nestedDepth && output.Details.State == Status::InternalFault,
              "review3.native-fault-preserves-caller-context-scope");
    }
    output = {};
    kncmd::ExecuteCollector(
        [](kncmd::Ctx &ctx)
        {
            knengine::ContextGuard guard(ctx.Session);
        },
        context);
    check(output.Details.State == Status::Success && knengine::InternalContextDepth == depth,
          "review3.normal-context-scope-remains-balanced");
    changed = stamp;
    ++changed.ContextGeneration;
    ++changed.SymbolGeneration;
    check(DiagnosticTargetMatches(stamp, changed), "review3.diagnostic-allows-internal-context-and-symbol-observations");
    ++changed.StopEpoch;
    check(!DiagnosticTargetMatches(stamp, changed), "review3.diagnostic-rejects-between-step-resume");
    changed = stamp;
    ++changed.TargetGeneration;
    check(!DiagnosticTargetMatches(stamp, changed), "review3.diagnostic-rejects-between-step-target-change");
    changed = stamp;
    changed.SessionId = L"replacement-session";
    check(!DiagnosticTargetMatches(stamp, changed), "review3.diagnostic-rejects-replacement-session");
    bool retentionPreserved = true;
    for (const auto state : {Status::Cancelled, Status::StaleContext, Status::InternalFault, Status::IOError})
    {
        kncmd::CommandResult rejected = {};
        rejected.Data.State = state;
        rejected.Data.Error = {L"Native", 42, L"Fixture", L"Original failure"};
        rejected.Data.Collected.StopReason = L"Original stop";
        kncmd::MarkResultNotRetained(rejected);
        retentionPreserved = retentionPreserved && !rejected.Ok && rejected.Data.State == state && rejected.Data.Error.Code == 42 &&
                             rejected.Data.Error.Message.find(L"Original failure") != std::wstring::npos &&
                             rejected.Data.Collected.StopReason == L"Original stop";
    }
    check(retentionPreserved, "review4.retention-failure-preserves-original-failure-and-stop-reason");
    kncmd::CommandResult unretained = {};
    unretained.Ok = true;
    unretained.ResultId = L"obsolete";
    unretained.Data.Collected.Complete = true;
    kncmd::MarkResultNotRetained(unretained);
    check(!unretained.Ok && unretained.Data.State == Status::Partial && !unretained.Data.Collected.Complete &&
              unretained.Data.Collected.StopReason == L"ResultRetentionBudget" && unretained.ResultId.empty() &&
              unretained.Data.Limitations.Items().size() == 1,
          "review4.retention-rejection-invalidates-success-and-id");
    auto missingName = ReviewImportPe(true);
    StoreFixture(missingName, 0x400 + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name), DWORD(0));
    const auto missingModule = AuditDriverPe(missingName);
    check(missingModule.State == Status::Partial && missingModule.Rows.Items().size() == 2,
          "review4.pe-null-module-rva-cannot-read-dos-signature");
    auto nullConfig = PeFixture(true);
    nullConfig.resize(0x10200);
    StoreFixture(nullConfig, 0x98 + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders), DWORD(0x10000));
    StoreFixture(nullConfig, 0x98 + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage), DWORD(0x20000));
    const size_t section = 0x98 + sizeof(IMAGE_OPTIONAL_HEADER64);
    StoreFixture(nullConfig, section + offsetof(IMAGE_SECTION_HEADER, VirtualAddress), DWORD(0x10000));
    StoreFixture(nullConfig, section + offsetof(IMAGE_SECTION_HEADER, PointerToRawData), DWORD(0x10000));
    StoreFixture(nullConfig,
                 0x98 + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * sizeof(IMAGE_DATA_DIRECTORY),
                 IMAGE_DATA_DIRECTORY{0, 0x6000});
    const auto missingConfig = AuditDriverPe(nullConfig);
    check(missingConfig.State == Status::Partial && !missingConfig.Rows.Items()[0].Get(L"loadConfigValid").AsBool(true),
          "review4.pe-null-load-config-rva-cannot-read-dos-header");
}
} // namespace knself
