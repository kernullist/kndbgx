#pragma once

#include "../core/SymbolHealth.h"
#include "../core/UiOperations.h"
#include "SnapshotRpcRegression.h"

namespace knself
{
template <typename Check> void RunDiagnosticRegression(Check check)
{
    using namespace kncore;
    const SymbolModuleKey key{0xfffff80012340000ULL, 0x10000, 123, 456};
    check(ParseSymbolModuleKey(key.ToJson()) == key, "diagnostics.module-key-preserves-high-address-and-image-identity");
    for (const auto field : {L"base", L"size", L"timestamp", L"checksum"})
    {
        auto invalid = key.ToJson();
        invalid.Set(field, knjson::Value(123.0));
        check(!ParseSymbolModuleKey(invalid), "diagnostics.module-key-rejects-numeric-json-field");
    }
    auto invalid = key.ToJson();
    invalid.Set(L"base", knjson::Value(Hex(UINT64_MAX)));
    check(!ParseSymbolModuleKey(invalid), "diagnostics.module-key-rejects-wrapped-range");
    invalid = key.ToJson();
    invalid.Set(L"timestamp", knjson::Value(L"4294967296"));
    check(!ParseSymbolModuleKey(invalid), "diagnostics.module-key-rejects-truncated-image-timestamp");
    invalid = key.ToJson();
    invalid.Set(L"command", knjson::Value(L"g"));
    check(!ParseSymbolModuleKey(invalid), "diagnostics.module-key-refuses-extra-fields");
    check(SymbolIdentifier(L"_EPROCESS", 128) && SymbolIdentifier(L"UniqueProcessId", 128) &&
          SymbolIdentifier(L"driver-name.sys", 127, true) && !SymbolIdentifier(L"nt;g", 127, true) &&
          !SymbolIdentifier(L"nt!*", 128) && !SymbolIdentifier(L"_EPROCESS\n", 128),
          "diagnostics.symbol-operands-are-identifiers-not-command-expressions");
    check(std::wstring(SymbolImageMatch(true, true, true, false)) == L"Matched" &&
          std::wstring(SymbolImageMatch(true, true, true, true)) == L"Mismatched",
          "diagnostics.match-requires-pdb-identity-and-honors-mismatch");
    check(std::wstring(SymbolImageMatch(false, true, true, false)) == L"Unknown" &&
          std::wstring(SymbolImageMatch(true, false, false, false)) == L"Unknown" &&
          std::wstring(SymbolImageMatch(true, true, false, false)) == L"Unknown",
          "diagnostics.deferred-exports-and-missing-metadata-are-not-mismatch");

    UiOperations ledger;
    const auto begin = UiOperations::Clock::now();
    const RequestKey request{1, 1, L"1"};
    const auto operation = ledger.Admit(request, L"symbolHealth", begin);
    ledger.Running(operation, begin + std::chrono::milliseconds(100));
    ledger.Observe(operation, OperationStage::SymbolQuery, begin + std::chrono::milliseconds(200));
    ledger.Observe(operation, OperationStage::SymbolQuery, begin + std::chrono::milliseconds(500));
    ledger.Cancel(request, begin + std::chrono::milliseconds(600));
    auto record = ledger.Status(request, L"", begin + std::chrono::milliseconds(1000));
    const auto &observation = record.Get(L"observation");
    check(record.Get(L"phase").AsString(L"") == L"CancelRequested" &&
          observation.Get(L"stage").AsString(L"") == L"SymbolQuery" &&
          observation.Get(L"elapsedMs").AsString(L"") == L"1000" &&
          observation.Get(L"stageElapsedMs").AsString(L"") == L"800" &&
          observation.Get(L"sinceProgressMs").AsString(L"") == L"500" &&
          observation.Get(L"cancelElapsedMs").AsString(L"") == L"400" && observation.Get(L"waitReason").IsNull(),
          "diagnostics.cancellation-keeps-observed-stage-and-does-not-invent-wait-cause");
    auto reply = knjson::Value::MakeObject();
    reply.Set(L"ok", knjson::Value(true));
    ledger.Complete(operation, reply, begin + std::chrono::milliseconds(1100));
    ledger.Observe(operation, OperationStage::EngineCommand, begin + std::chrono::seconds(10));
    record = ledger.Status(request, L"", begin + std::chrono::seconds(20));
    check(record.Get(L"phase").AsString(L"") == L"Completed" && record.Get(L"delivery").AsString(L"") == L"Pending" &&
          record.Get(L"observation").Get(L"elapsedMs").AsString(L"") == L"1100" &&
          record.Get(L"observation").Get(L"stage").AsString(L"") == L"ResultReady",
          "diagnostics.completed-timing-is-frozen-and-independent-of-delivery");
    std::vector<OperationStage> stages;
    const OperationProgressSink sink = [&](OperationStage stage)
    {
        stages.push_back(stage);
    };
    {
        OperationProgressScope scope(sink);
        {
            ObservedStage command(OperationStage::EngineCommand);
            {
                ObservedStage read(OperationStage::MemoryIo);
            }
        }
    }
    check(stages == std::vector<OperationStage>{OperationStage::Worker, OperationStage::EngineCommand, OperationStage::MemoryIo,
                                               OperationStage::EngineCommand, OperationStage::Worker} && CurrentProgressSink == nullptr,
          "diagnostics.nested-engine-observation-restores-call-boundary-and-detaches-sink");
    const OperationProgressSink failing = [](OperationStage)
    {
        throw 1;
    };
    {
        OperationProgressScope scope(failing);
        ObservedStage observed(OperationStage::SymbolQuery);
    }
    check(CurrentProgressSink == nullptr, "diagnostics.telemetry-failure-cannot-fail-engine-operation");

    std::wstring reason;
    auto params = knjson::Value::MakeObject();
    params.Set(L"moduleKey", key.ToJson());
    params.Set(L"typeName", knjson::Value(L"_EPROCESS"));
    params.Set(L"fieldName", knjson::Value(L"UniqueProcessId"));
    params.Set(L"expectedStamp", SessionStamp{L"fixture", 1, 1, 1, 1}.ToJson());
    check(RpcShape(FixtureRpc(L"symbolHealth", 2, params), reason) && RpcNeedsWorker(L"symbolHealth") &&
          RpcNeedsWorker(L"symbolModules") && !RpcNeedsWorker(L"operationStatus"),
          "diagnostics.symbol-inspection-is-worker-owned-observation-recovery-is-not");
    params.Set(L"reload", knjson::Value(true));
    check(!RpcShape(FixtureRpc(L"symbolHealth", 3, params), reason), "diagnostics.symbol-health-cannot-enable-implicit-reload");
}
} // namespace knself
