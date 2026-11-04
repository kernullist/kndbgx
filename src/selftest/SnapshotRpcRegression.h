#pragma once

#include "../util/SnapshotStore.h"
#include "../core/Rpc.h"
#include "../core/ResultStore.h"
#include "../ui/Bridge.h"
#include "../cmd/CommandSpec.h"
#include "../cmd/WriteGate.h"
#include "../cmd/Jobs.h"

namespace knself
{
inline knjson::Value FixtureRpc(const wchar_t *method, unsigned id, const knjson::Value &params = knjson::Value::MakeObject())
{
    auto request = knjson::Value::MakeObject();
    request.Set(L"schema", knjson::Value(L"kndbgx.rpc.v3"));
    request.Set(L"requestId", knjson::Value(std::to_wstring(id)));
    request.Set(L"uiGeneration", knjson::Value(std::wstring(method) == L"hello" ? L"" : L"7"));
    request.Set(L"sessionId", knjson::Value(L"fixture"));
    request.Set(L"expectedTargetGeneration", knjson::Value(L"1"));
    request.Set(L"method", knjson::Value(method));
    request.Set(L"params", params);
    if (std::wstring(method) == L"hello")
    {
        auto helloParams = params;
        helloParams.Set(L"documentToken", knjson::Value(L""));
        request.Set(L"params", helloParams);
    }
    return request;
}

template <typename Check> void RunSnapshotRpcRegression(Check check)
{
    using namespace kncore;
    const std::vector<unsigned char> hashFixture{1, 2, 3};
    check(!knutil::MatchesSnapshotHash(hashFixture, L"") && knutil::MatchesSnapshotHash(hashFixture, knutil::Sha256Bytes(hashFixture)) &&
              !knutil::MatchesSnapshotHash(hashFixture, std::wstring(64, L'0')),
          "review.snapshot-checksum-requires-complete-sha256-digest");
    Snapshot first;
    first.Metadata.Set(L"schema", knjson::Value(L"kndbgx.snapshot.v2"));
    SessionStamp stamp{L"snapshot-fixture", 1, 1, 1, 1};
    first.Metadata.Set(L"target", stamp.ToJson());
    first.Metadata.Set(L"targetStable", knjson::Value(true));
    Result collection;
    collection.Collected.Complete = true;
    ProcessRow process{0xffff800000001000ULL, 100, L"test", 0x1000, 1234, true, true, true, true};
    collection.Rows.Push(process.ToJson());
    first.Collections.emplace(L"processes", collection.ToJson());
    auto scalarCollection = collection;
    scalarCollection.Rows.Push(knjson::Value(1.0));
    check(!ValidCollection(scalarCollection.ToJson()), "review.snapshot-scalar-row-rejected-before-save");
    Snapshot second = first;
    check(DiffSnapshots(first, second).Rows.Items()[0].Get(L"state").AsString(L"") == L"Unchanged", "snapshot.same-identity-positive");
    auto other = process;
    other.Pid = 200;
    other.Eprocess += 4096;
    collection.Rows.Push(other.ToJson());
    first.Collections[L"processes"] = collection.ToJson();
    auto reverse = knjson::Value::MakeArray();
    reverse.Push(other.ToJson());
    reverse.Push(process.ToJson());
    auto reversed = collection.ToJson();
    reversed.Set(L"rows", reverse);
    second.Collections[L"processes"] = reversed;
    auto compared = DiffSnapshots(first, second);
    check(compared.State == Status::Success && std::all_of(compared.Rows.Items().begin(), compared.Rows.Items().end(),
                                                           [](const auto &row)
                                                           {
                                                               return row.Get(L"state").AsString(L"") == L"Unchanged";
                                                           }),
          "snapshot.row-order-is-not-a-change");
    reverse.Push(process.ToJson());
    second.Collections[L"processes"].Set(L"rows", reverse);
    check(DiffSnapshots(first, second).Collected.Unknown == 1, "snapshot.duplicate-identities-preserve-ambiguity");
    second = first;
    auto unavailable = Result();
    unavailable.State = Status::Unavailable;
    second.Collections[L"processes"] = unavailable.ToJson();
    compared = DiffSnapshots(first, second);
    check(compared.Collected.Unknown == 2 && compared.Rows.Items()[0].Get(L"state").AsString(L"") == L"Unknown",
          "snapshot.failed-collector-not-removed");
    first.Collections[L"processes"] = Result().ToJson();
    collection.Rows = knjson::Value::MakeArray();
    collection.Rows.Push(process.ToJson());
    first.Collections[L"processes"] = collection.ToJson();
    ++process.CreateTime;
    collection.Rows = knjson::Value::MakeArray();
    collection.Rows.Push(process.ToJson());
    second = first;
    second.Collections[L"processes"] = collection.ToJson();
    compared = DiffSnapshots(first, second);
    check(compared.Rows.Items().size() == 2 && compared.Rows.Items()[0].Get(L"state").AsString(L"") != L"Changed",
          "snapshot.pid-reuse-distinct-process-identity");
    auto module = knjson::Value::MakeObject();
    module.Set(L"kind", knjson::Value(L"Module"));
    module.Set(L"moduleIdentity", knjson::Value(L"guid:1:8664:1234"));
    module.Set(L"base", knjson::Value(L"0xffff800010000000"));
    collection.Rows = knjson::Value::MakeArray();
    collection.Rows.Push(module);
    first.Collections.clear();
    first.Collections[L"modules"] = collection.ToJson();
    module.Set(L"base", knjson::Value(L"0xffff800020000000"));
    collection.Rows = knjson::Value::MakeArray();
    collection.Rows.Push(module);
    second = first;
    second.Collections[L"modules"] = collection.ToJson();
    check(DiffSnapshots(first, second).Rows.Items()[0].Get(L"state").AsString(L"") == L"Unchanged", "snapshot.ASLR-normalized-module");
    auto target = stamp;
    target.SessionId = L"different";
    second.Metadata.Set(L"target", target.ToJson());
    check(DiffSnapshots(first, second).State == Status::Unavailable && DiffSnapshots(first, second, true).State == Status::Success,
          "snapshot.cross-session-explicit-mode");
    second.Metadata.Set(L"schema", knjson::Value(L"unknown"));
    check(DiffSnapshots(first, second).State == Status::InvalidInput, "snapshot.schema-mismatch-rejected");
    second = first;
    second.Metadata.Set(L"targetStable", knjson::Value(false));
    check(DiffSnapshots(first, second).State == Status::StaleContext, "snapshot.target-change-during-capture-not-compared");
    check(!SnapshotLeaf(L"../escape.jsonl") && !SnapshotLeaf(L"c:stream") && !SnapshotLeaf(L"file.jsonl:ads") &&
              !SnapshotLeaf(L"dir\\file") && !SnapshotLeaf(L"x%2foutside") && SnapshotLeaf(L"modules.jsonl"),
          "snapshot.path-traversal-and-ADS-rejected");

    auto metadata = knjson::Value::MakeObject();
    metadata.Set(L"type", knjson::Value(L"metadata"));
    metadata.Set(L"schema", knjson::Value(L"kndbgx.snapshot-collection.v2"));
    metadata.Set(L"collector", knjson::Value(L"modules"));
    auto empty = collection.ToJson();
    empty.Set(L"rows", knjson::Value::MakeArray());
    metadata.Set(L"result", empty);
    knjson::Value imported;
    check(knutil::ParseSnapshotCollection(metadata.Write() + L"\n", L"modules", imported) &&
              imported.Get(L"status").AsString(L"") == L"Partial" && !imported.Get(L"coverage").Get(L"complete").AsBool(true),
          "snapshot.missing-footer-imports-incomplete");
    check(!knutil::ParseSnapshotCollection(metadata.Write() + L"\n{\"type\":\"completion\",\"records\":\"99\",\"complete\":true}\n",
                                           L"modules", imported),
          "snapshot.footer-count-mismatch-rejected");

    wchar_t temporary[32768] = {};
    GetTempPathW(_countof(temporary), temporary);
    const std::filesystem::path root = std::filesystem::path(temporary) / (L"kndbgx-snapshot-test-" + knutil::UniqueSuffix());
    for (unsigned scenario = 0; scenario < 3; ++scenario)
    {
        auto oversized = first;
        if (scenario == 0)
        {
            oversized.Metadata.Set(L"note", knjson::Value(std::wstring(500000, L'\uac00')));
        }
        else if (scenario == 1)
        {
            oversized.Collections[L"modules"].Set(L"diagnostic", knjson::Value(std::wstring(550000, L'x')));
        }
        else
        {
            auto nested = knjson::Value::MakeObject();
            for (unsigned level = 0; level < 40; ++level)
            {
                auto parent = knjson::Value::MakeObject();
                parent.Set(L"nested", nested);
                nested = parent;
            }
            auto rows = knjson::Value::MakeArray();
            rows.Push(nested);
            oversized.Collections[L"modules"].Set(L"rows", rows);
        }
        const auto rejectedPath = std::filesystem::path(root.wstring() + L"-rejected-" + std::to_wstring(scenario));
        const auto rejected = knutil::SaveSnapshot(rejectedPath.wstring(), oversized);
        check(rejected.State != Status::Success && !std::filesystem::exists(rejectedPath),
              "review.snapshot-writer-rejects-import-budget-violation-before-commit");
        for (const auto *leaf : {L"modules.jsonl", L"manifest.json", L"checksums.json"})
        {
            DeleteFileW((rejectedPath / leaf).c_str());
        }
        RemoveDirectoryW(rejectedPath.c_str());
    }
    {
        auto allRows = knjson::Value::MakeArray();
        for (unsigned index = 0; index < 50001; ++index)
        {
            allRows.Push(knjson::Value::MakeObject());
        }
        auto many = collection.ToJson();
        many.Set(L"rows", allRows);
        auto oversized = first;
        oversized.Collections[L"modules"] = many;
        oversized.Collections[L"processes"] = many;
        check(!ValidSnapshot(oversized), "review.snapshot-total-row-budget-spans-collections");
    }
    const auto cancelRoot = std::filesystem::path(root.wstring() + L"-cancel");
    CreateDirectoryW(cancelRoot.c_str(), nullptr);
    unsigned checkpoints = 0;
    const auto baseline = cancelRoot / L"baseline";
    const auto counted = knutil::SaveSnapshot(baseline.wstring(), first,
                                              [&]()
                                              {
                                                  ++checkpoints;
                                                  return false;
                                              });
    check(counted.State == Status::Success && checkpoints > 10, "third.T07.snapshot-save-polls-write-hash-and-commit-boundaries");
    for (const auto *name : {L"modules.jsonl", L"manifest.json", L"checksums.json"})
    {
        DeleteFileW((baseline / name).c_str());
    }
    RemoveDirectoryW(baseline.c_str());
    for (unsigned threshold = 1; threshold <= checkpoints; ++threshold)
    {
        unsigned polls = 0;
        const auto cancelled = knutil::SaveSnapshot((cancelRoot / L"cancelled").wstring(), first,
                                                    [&]()
                                                    {
                                                        return ++polls >= threshold;
                                                    });
        check(cancelled.State == Status::Cancelled && std::filesystem::is_empty(cancelRoot),
              "third.T07.snapshot-cancel-at-every-save-checkpoint-removes-only-staging-and-never-publishes");
    }
    RemoveDirectoryW(cancelRoot.c_str());
    const auto saved = knutil::SaveSnapshot(root.wstring(), first);
    kncmd::CommandResult committed;
    committed.Data = saved;
    committed.Data.Stamp = stamp;
    kncmd::FinalizeCollection(committed, kncmd::FindCommand(L"!snapshot"), stamp, true);
    check(committed.Data.State == Status::Success && committed.Data.Analysis.Get(L"artifactCommitted").AsBool(false),
          "third.T07.snapshot-dispatch-keeps-published-success-after-late-cancellation");
    Snapshot loaded;
    const auto load = knutil::LoadSnapshot(root.wstring(), loaded);
    check(saved.State == Status::Success && load.State == Status::Success && DiffSnapshots(first, loaded).State == Status::Success,
          "snapshot.actual-Windows-directory-commit-and-checksum-roundtrip");
    check(knutil::SaveSnapshot(root.wstring(), first).State == Status::IOError &&
              knutil::LoadSnapshot(root.wstring(), loaded).State == Status::Success,
          "snapshot.existing-directory-preserved");
    {
        knutil::ArtifactWriter corrupt;
        check(corrupt.Open((root / L"modules.jsonl").wstring(), true) && corrupt.WriteText(L"tampered") && corrupt.Commit(),
              "snapshot.checksum-negative-fixture-created");
    }
    check(knutil::LoadSnapshot(root.wstring(), loaded).State == Status::InvalidInput, "snapshot.checksum-tamper-rejected");
    for (const auto *name : {L"modules.jsonl", L"manifest.json", L"checksums.json"})
    {
        DeleteFileW((root / name).c_str());
    }
    RemoveDirectoryW(root.c_str());

    auto enableParameters = knjson::Value::MakeObject();
    enableParameters.Set(L"enabled", knjson::Value(true));
    const auto retiredPolicy = knbridge::HandleRequest(FixtureRpc(L"setGate", 91, enableParameters));
    check(!retiredPolicy.Get(L"ok").AsBool(true), "approval.removed-policy-rpc-is-rejected");
    auto policyParameters = knjson::Value::MakeObject();
    policyParameters.Set(L"command", knjson::Value(L"policy planned"));
    const auto retiredCommand = knbridge::HandleRequest(FixtureRpc(L"execute", 92, policyParameters));
    check(!retiredCommand.Get(L"result").Get(L"ok").AsBool(true) &&
              retiredCommand.Get(L"result").Get(L"error").AsString(L"").find(L"global write policy has been removed") != std::wstring::npos,
          "approval.legacy-policy-command-reports-removal");
    const auto retiredQuery = knbridge::HandleRequest(FixtureRpc(L"gate", 93));
    check(!retiredQuery.Get(L"ok").AsBool(true), "approval.removed-policy-query-is-rejected");
    knengine::DbgSession cancelledSession;
    unsigned cancelChecks = 0;
    const auto cancelledAdmission = knbridge::HandleRequest(FixtureRpc(L"status", 85), &cancelledSession,
                                                            [&]()
                                                            {
                                                                return ++cancelChecks >= 2;
                                                            });
    check(!cancelledAdmission.Get(L"ok").AsBool(true) && cancelledAdmission.Get(L"error").AsString(L"") == L"CancelledBeforeExecution" &&
              !knengine::Coordinator().Busy(),
          "review.rpc-cancellation-between-dequeue-and-engine-admission-is-not-lost");
    auto staleSubmission = knengine::Epochs().Stamp();
    ++staleSubmission.ContextGeneration;
    const auto queued = kncmd::SubmitJob(L"status", true, &staleSubmission);
    const auto queuedId = queued.Rows.Items().empty() ? L"" : queued.Rows.Items()[0].Get(L"jobId").AsString(L"");
    const bool activated = queued.State == Status::Success && kncmd::ActivateJob(queuedId);
    bool rejectedJob = false;
    const auto jobDeadline = GetTickCount64() + 3000;
    while (activated && GetTickCount64() < jobDeadline)
    {
        const auto details = kncmd::DispatchCommand(cancelledSession, L"job " + queuedId);
        if (!details.Data.Rows.Items().empty())
        {
            const auto state = details.Data.Rows.Items()[0].Get(L"state").AsString(L"");
            if (state != L"Running" && state != L"Queued")
            {
                rejectedJob = state == L"StaleContext";
                break;
            }
        }
        Sleep(10);
    }
    check(rejectedJob && !knengine::Coordinator().Busy(), "review.job-submission-context-is-checked-before-engine-use");

    RpcGate gate;
    gate.Navigate(7);
    std::wstring reason;
    const auto hello = FixtureRpc(L"hello", 1);
    check(!gate.Accept(hello, L"https://app.kndbgx.local.attacker/index.html", 100, reason) &&
              !gate.Accept(hello, L"https://app.kndbgx.local/other.html", 100, reason),
          "rpc.actual-document-source-required");
    check(gate.Accept(hello, L"https://app.kndbgx.local/index.html", 100, reason), "rpc.handshake-positive");
    const auto catalog = FixtureRpc(L"catalog", 2);
    check(gate.Accept(catalog, L"https://app.kndbgx.local/index.html", 100, reason) &&
              !gate.Accept(catalog, L"https://app.kndbgx.local/index.html", 100, reason),
          "rpc.request-replay-rejected");
    auto invalid = FixtureRpc(L"catalog", 3);
    invalid.Set(L"uiGeneration", knjson::Value(L"6"));
    check(!gate.Accept(invalid, L"https://app.kndbgx.local/index.html", 100, reason), "rpc.previous-navigation-rejected");
    check(!gate.Accept(FixtureRpc(L"shell", 3), L"https://app.kndbgx.local/index.html", 100, reason) &&
              !gate.Accept(FixtureRpc(L"catalog", 3), L"https://app.kndbgx.local/index.html", 65537, reason),
          "rpc.unknown-method-and-byte-budget-rejected");
    auto params = knjson::Value::MakeObject();
    params.Set(L"command", knjson::Value(true));
    check(!RpcShape(FixtureRpc(L"classify", 3, params), reason), "rpc.parameter-type-not-coerced");
    gate.Navigate(8);
    check(!gate.Accept(FixtureRpc(L"catalog", 4), L"https://app.kndbgx.local/index.html", 100, reason),
          "rpc.new-navigation-requires-handshake");

    ResultStore store;
    Result original;
    Result excessiveResult;
    excessiveResult.Limitations.Push(knjson::Value(std::wstring(3 * 1024 * 1024, wchar_t(1))));
    bool refusedOversized = false;
    try
    {
        refusedOversized = !store.Publish(L"oversized", excessiveResult, L"");
    }
    catch (...)
    {
    }
    check(refusedOversized && store.List().empty(), "review.result-budget-rejection-does-not-escape-as-executor-fault");
    check(!store.Publish(L"malformed-text", original, std::wstring(1, wchar_t(0xd800))),
          "review.result-store-rejects-unserializable-console-text");
    original.Rows.Push(module);
    const auto immutable = store.Publish(L"fixture", original, L"hello");
    original.Rows.Push(module);
    check(immutable && immutable->Data.Rows.Items().size() == 1 && !store.Publish(L"fixture", original, L""),
          "resultstore.immutable-copy-and-unique-identity");
    for (unsigned i = 0; i < 20; ++i)
    {
        store.Publish(std::to_wstring(i), original, L"");
    }
    check(store.List().size() == 16 && !store.Find(L"fixture") && immutable->Text == L"hello",
          "resultstore.bounded-retention-consumer-lease-survives");
    {
        ResultStore tabs;
        std::vector<std::wstring> pinned;
        bool retainedAll = true;
        for (size_t i = 0; i < ResultStore::MaximumUiPins; ++i)
        {
            const auto id = L"tab-" + std::to_wstring(i);
            retainedAll = static_cast<bool>(tabs.Publish(id, original, L"saved text")) && retainedAll;
            pinned.push_back(id);
            retainedAll = tabs.SetUiPins(pinned) && retainedAll;
        }
        for (unsigned i = 0; i < 40; ++i)
        {
            tabs.Publish(L"aux-" + std::to_wstring(i), original, L"");
        }
        check(retainedAll && tabs.Find(L"tab-0") && tabs.Find(L"tab-127") && tabs.List().size() == 144,
              "resultstore.ui-tabs-preserve-open-results-beyond-recent-retention");
        auto excessivePins = pinned;
        excessivePins.push_back(L"overflow");
        check(!tabs.SetUiPins(excessivePins) && !tabs.SetUiPins({L""}) &&
                  !tabs.SetUiPins({std::wstring(1, wchar_t(0xd800))}) && tabs.Find(L"tab-0"),
              "resultstore.ui-tabs-invalid-or-excessive-pins-preserve-existing-leases");
        std::vector<std::wstring> missing;
        check(tabs.SetUiPins({L"tab-0", L"missing"}, &missing) && missing == std::vector<std::wstring>{L"missing"} &&
                  tabs.Find(L"tab-0") && tabs.List().size() == 17,
              "resultstore.ui-tabs-missing-ids-are-explicit-and-released-tabs-are-trimmed");
        check(tabs.SetUiPins({}) && tabs.List().size() == 16 && !tabs.Find(L"tab-0"),
              "resultstore.ui-tabs-document-reset-restores-normal-retention");
    }
    {
        ResultStore budget;
        const std::wstring text(17 * 1024 * 1024, L'x');
        const auto first = budget.Publish(L"pinned-budget", Result{}, text);
        const bool pinned = budget.SetUiPins({L"pinned-budget"});
        check(first && pinned && !budget.Publish(L"over-budget", Result{}, text) && budget.Find(L"pinned-budget"),
              "resultstore.ui-tabs-memory-budget-refuses-new-result-without-evicting-open-tab");
        budget.SetUiPins({});
        check(budget.Publish(L"after-close", Result{}, text) && !budget.Find(L"pinned-budget") && first->Text == text,
              "resultstore.ui-tabs-close-releases-budget-and-keeps-consumer-lease-valid");
    }
    {
        auto tabParams = knjson::Value::MakeObject();
        auto ids = knjson::Value::MakeArray();
        ids.Push(knjson::Value(L"absent-tab"));
        tabParams.Set(L"resultIds", ids);
        const auto pinned = knbridge::HandleRequest(FixtureRpc(L"resultTabs", 94, tabParams));
        check(!RpcNeedsWorker(L"resultTabs") && pinned.Get(L"ok").AsBool(false) &&
                  pinned.Get(L"result").Get(L"missing").Items().size() == 1,
              "rpc.ui-tabs-retention-is-target-independent-and-reports-missing-data");
        ids.Push(knjson::Value(true));
        tabParams.Set(L"resultIds", ids);
        check(!knbridge::HandleRequest(FixtureRpc(L"resultTabs", 95, tabParams)).Get(L"ok").AsBool(true),
              "rpc.ui-tabs-malformed-result-identities-are-refused");
        ids = knjson::Value::MakeArray();
        for (size_t i = 0; i <= ResultStore::MaximumUiPins; ++i)
        {
            ids.Push(knjson::Value(std::to_wstring(i)));
        }
        tabParams.Set(L"resultIds", ids);
        check(!knbridge::HandleRequest(FixtureRpc(L"resultTabs", 96, tabParams)).Get(L"ok").AsBool(true),
              "rpc.ui-tabs-retention-cap-is-enforced-before-store-update");
        Results().SetUiPins({});
    }
    const auto shared = Results().Publish(L"rpc-regression", original, std::wstring(9000, L'X'));
    params = knjson::Value::MakeObject();
    params.Set(L"resultId", knjson::Value(shared->Id));
    params.Set(L"cursor", knjson::Value(L"0"));
    const auto chunk = knbridge::HandleRequest(FixtureRpc(L"outputChunk", 5, params));
    check(chunk.Get(L"ok").AsBool(false) && chunk.Get(L"result").Get(L"text").AsString(L"").size() == 4096 &&
              knutil::WideToUtf8(chunk.Write()).size() < 65536,
          "rpc.product-bounded-output-chunk");
    params.Set(L"cursor", knjson::Value(L"99999"));
    check(!knbridge::HandleRequest(FixtureRpc(L"outputChunk", 6, params)).Get(L"ok").AsBool(true), "rpc.product-invalid-cursor-rejected");
    params = knjson::Value::MakeObject();
    params.Set(L"resultId", knjson::Value(shared->Id));
    params.Set(L"offset", knjson::Value(L"0"));
    params.Set(L"collection", knjson::Value(L"rows"));
    const auto page = knbridge::HandleRequest(FixtureRpc(L"resultPage", 7, params));
    check(page.Get(L"ok").AsBool(false) && page.Get(L"result").Get(L"rows").Items().size() == 2,
          "rpc.product-result-page-uses-same-immutable-data");
    const auto catalogReply = knbridge::HandleRequest(FixtureRpc(L"catalog", 90));
    bool labelsMatch = catalogReply.Get(L"ok").AsBool(false);
    size_t labels = 0;
    for (const auto &[name, group] : catalogReply.Get(L"result").Get(L"groups").Fields())
    {
        for (const auto &entry : group.Items())
        {
            const auto *spec = kncmd::FindCommand(entry.Get(L"name").AsString(L""));
            labelsMatch = spec != nullptr && entry.Get(L"support").AsString(L"") == kncmd::SupportName(spec->Support) && labelsMatch;
            ++labels;
        }
    }
    check(labelsMatch && labels >= kncmd::CommandSpecs().size(), "rpc.catalog-support-matches-command-registry");
}
} // namespace knself
