#pragma once

#include "../core/UiOperations.h"
#include "../core/Execution.h"
#include "SnapshotRpcRegression.h"

namespace knself
{
template <typename Check> void RunUiOperationsRegression(Check check)
{
    using namespace kncore;
    auto terminal = knjson::Value::MakeObject();
    terminal.Set(L"ok", knjson::Value(true));
    auto result = knjson::Value::MakeObject();
    result.Set(L"path", knjson::Value(L"fixture.json"));
    terminal.Set(L"result", result);
    for (const bool sameId : {false, true})
    {
        for (const bool sameDocument : {false, true})
        {
            if (sameId && sameDocument)
            {
                continue;
            }
            UiOperations ledger;
            const RequestKey oldKey{1, 7, L"5"};
            const RequestKey newKey{1, sameDocument ? 7ULL : 8ULL, sameId ? L"5" : L"6"};
            const auto old = ledger.Admit(oldKey, L"status");
            ledger.Running(old);
            const auto current = ledger.Admit(newKey, L"status");
            check(ledger.Cancel(newKey) == current, "third.T01-T02.exact-generation-cancel-accepted");
            ledger.Complete(old, terminal);
            check(current->Cancelled.load() && !old->Cancelled.load(), "third.T01-T02.old-completion-preserves-new-cancel");
            check(ledger.Cancel(oldKey) == nullptr, "third.T03.completed-operation-rejects-cancel");
        }
    }
    UiOperations ledger;
    const RequestKey key{3, 9, L"5"};
    const auto state = ledger.Admit(key, L"saveLog");
    const auto completed = ledger.Complete(state, terminal);
    for (const int32_t status : {static_cast<int32_t>(0x80004005u), 0})
    {
        ledger.Delivery(state->Id, status);
        const auto stored = ledger.Status(key);
        check(stored.Get(L"terminal").Write() == completed.Write() && stored.Get(L"delivery").AsString(L"") != L"Acknowledged",
              "third.T08-T09.transport-outcome-keeps-terminal-without-implying-ack");
    }
    check(ledger.Ack(state->Id) && ledger.Ack(state->Id), "third.T09.terminal-ack-is-idempotent");
    ledger.Delivery(state->Id, static_cast<int32_t>(0x80004005u));
    check(ledger.Status(key).Get(L"delivery").AsString(L"") == L"Acknowledged", "third.T09.late-post-failure-cannot-undo-ack");
    check(ledger.Status({4, 10, L"5"}).IsNull() && ledger.Status({}, state->Id).Get(L"path").AsString(L"") == L"fixture.json",
          "third.T06.new-document-recovers-same-artifact-by-operation");
    UiOperations polling;
    const auto saved = polling.Admit({1, 1, L"saved"}, L"saveLog");
    polling.Complete(saved, terminal);
    polling.Ack(saved->Id);
    for (size_t index = 0; index < UiOperations::Capacity * 3; ++index)
    {
        const auto background = polling.Admit({1, 1, std::to_wstring(index)}, index % 2 == 0 ? L"status" : L"completeSymbols");
        polling.Complete(background, terminal);
        polling.Ack(background->Id);
    }
    check(!polling.Status({}, saved->Id).IsNull() && polling.Page(0).Get(L"records").Items().size() == 1,
          "ux.operations-background-polling-preserves-acknowledged-user-outcomes-and-does-not-fill-history");
    const auto uncertain = polling.Admit({1, 2, L"unacknowledged"}, L"status");
    polling.Complete(uncertain, terminal);
    polling.Admit({1, 2, L"later"}, L"status");
    check(!polling.Status({}, uncertain->Id).IsNull() && polling.Page(0).Get(L"records").Items().size() == 3,
          "ux.operations-unacknowledged-and-active-background-work-remain-recoverable");
    UiOperations full;
    for (size_t index = 1; index <= UiOperations::Capacity; ++index)
    {
        const auto entry = full.Admit({1, 1, std::to_wstring(index)}, L"status");
        full.Complete(entry, terminal);
    }
    check(!full.Admit({1, 2, L"1"}, L"status") && full.List().Items().size() == UiOperations::Capacity,
          "third.T10.unacknowledged-capacity-backpressures-instead-of-dropping-outcomes");
    full.Ack(L"1");
    const auto page = full.Page(0);
    check(page.Get(L"records").Items().size() == 16 && !page.Get(L"complete").AsBool(true) && full.Page(112).Get(L"complete").AsBool(false),
          "third.T10.recovery-list-pages-bounded-records-with-stable-operation-cursor");
    check(full.Admit({1, 2, L"1"}, L"status") != nullptr, "third.T10.acknowledged-terminal-can-be-evicted");
    const auto later = UiOperations::Clock::now() + UiOperations::Retention;
    check(full.Admit({1, 3, L"1"}, L"status", later) != nullptr && !full.Status({1, 2, L"1"}).IsNull(),
          "third.T10.ttl-expires-terminal-but-never-active");
    ExecutionCoordinator coordinator;
    coordinator.Begin(ExecutionDomain::Ui);
    state->Serial.store(coordinator.Serial());
    coordinator.End();
    auto failure = terminal;
    auto failedResult = result;
    failedResult.Set(L"ok", knjson::Value(false));
    failure.Set(L"result", failedResult);
    const auto failed = ledger.Admit({1, 14, L"1"}, L"execute");
    ledger.Complete(failed, failure);
    ledger.DocumentChanged(1, 15);
    const auto failedStatus = ledger.Status({}, failed->Id);
    check(!failedStatus.Get(L"ok").AsBool(true) && failedStatus.Get(L"outcome").AsString(L"") == L"Failed" &&
              failedStatus.Get(L"delivery").AsString(L"") == L"DocumentGone",
          "third.T09.command-failure-is-not-transport-success-and-document-loss-preserves-receipt");
    coordinator.Begin(ExecutionDomain::Ui);
    check(!coordinator.Cancel(ExecutionDomain::Ui, state->Serial.load()) && !coordinator.Cancelled(),
          "third.T03.stale-operation-serial-cannot-interrupt-next-execution");
    coordinator.End();
    auto huge = terminal;
    auto hugeResult = result;
    hugeResult.Set(L"data", knjson::Value(std::wstring(100000, L'x')));
    hugeResult.Set(L"resultId", knjson::Value(L"huge-result"));
    hugeResult.Set(L"artifactCommitted", knjson::Value(true));
    auto currentTarget = knjson::Value::MakeObject();
    currentTarget.Set(L"sessionId", knjson::Value(L"1"));
    currentTarget.Set(L"targetGeneration", knjson::Value(L"3"));
    hugeResult.Set(L"currentTarget", currentTarget);
    huge.Set(L"result", hugeResult);
    const auto large = ledger.Admit({1, 11, L"99"}, L"execute");
    const auto receipt = ledger.Complete(large, huge);
    check(receipt.Write().size() < 65536 && receipt.Get(L"result").Get(L"resultId").AsString(L"") == L"huge-result" &&
              receipt.Get(L"result").Get(L"data").Get(L"kind").AsString(L"") == L"MetadataReference",
          "third.T10.terminal-receipts-bound-large-metadata-and-preserve-result-identity");
    check(receipt.Get(L"result").Get(L"currentTarget").Write() == currentTarget.Write(),
          "ui-command.compact-receipt-preserves-current-target");
    check(receipt.Get(L"result").Get(L"artifactCommitted").AsBool(false),
          "memory-dump.compact-receipt-preserves-committed-file");
    RpcGate gate;
    gate.Navigate(12, L"fresh-document-token");
    std::wstring reason;
    auto hello = FixtureRpc(L"hello", 1);
    check(!gate.Accept(hello, L"https://app.kndbgx.local/index.html", 256, reason), "third.T11.late-old-document-hello-rejected");
    auto params = knjson::Value::MakeObject();
    params.Set(L"documentToken", knjson::Value(L"fresh-document-token"));
    hello.Set(L"params", params);
    check(gate.Accept(hello, L"https://app.kndbgx.local/index.html", 256, reason), "third.T11.fresh-document-hello-accepted");
}
} // namespace knself
