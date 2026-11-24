#pragma once

#include "Result.h"
#include <map>
#include <set>

namespace kncore
{
inline bool RpcNeedsWorker(const std::wstring &method)
{
    return method == L"execute" || method == L"status" || method == L"previewWrite" || method == L"executePlan" || method == L"saveLog" ||
           method == L"navigateResult" || method == L"processAction" || method == L"memoryRead" || method == L"memoryDump" || method == L"disassemblyRead" ||
           method == L"breakpointPlan" || method == L"breakpointApply" || method == L"debuggerAction" || method == L"completeSymbols" ||
           method == L"symbolModules" || method == L"symbolHealth";
}

inline bool AppDocument(const std::wstring &source)
{
    return source == L"https://app.kndbgx.local/index.html";
}

inline bool RpcShape(const knjson::Value &request, std::wstring &reason)
{
    reason = L"InvalidRpcSchema";
    const std::set<std::wstring> fields = {L"schema", L"requestId", L"uiGeneration", L"sessionId", L"expectedTargetGeneration",
                                           L"method", L"params"};
    if (!request.IsObject() || request.Fields().size() != fields.size() || request.Get(L"schema").AsString(L"") != L"kndbgx.rpc.v3")
    {
        return false;
    }
    for (const auto &[name, value] : request.Fields())
    {
        if (!fields.contains(name) || (name != L"params" && (!value.IsString() || value.AsString(L"").size() > 256)))
        {
            return false;
        }
    }
    const auto &params = request.Get(L"params");
    const auto method = request.Get(L"method").AsString(L"");
    const std::map<std::wstring, std::map<std::wstring, knjson::Type>> methods = {
        {L"hello", {{L"documentToken", knjson::Type::String}}},
        {L"status", {}},
        {L"symbolModules", {{L"cursor", knjson::Type::String}, {L"expectedStamp", knjson::Type::Object}}},
        {L"symbolHealth", {{L"moduleKey", knjson::Type::Object}, {L"typeName", knjson::Type::String},
                           {L"fieldName", knjson::Type::String}, {L"expectedStamp", knjson::Type::Object}}},
        {L"catalog", {}},
        {L"inspectionWindow", {{L"action", knjson::Type::String}, {L"token", knjson::Type::String},
                                {L"visibilityEpoch", knjson::Type::String}}},
        {L"complete", {{L"prefix", knjson::Type::String}}},
        {L"completeSymbols", {{L"prefix", knjson::Type::String}, {L"suffix", knjson::Type::String},
                              {L"expectedStamp", knjson::Type::Object}}},
        {L"classify", {{L"command", knjson::Type::String}}},
        {L"execute", {{L"command", knjson::Type::String}}},
        {L"memoryDump",
         {{L"source", knjson::Type::Object}, {L"operation", knjson::Type::String},
          {L"length", knjson::Type::String}, {L"path", knjson::Type::String}}},
        {L"memoryRead",
         {{L"expression", knjson::Type::String}, {L"space", knjson::Type::String},
          {L"length", knjson::Type::String}, {L"source", knjson::Type::Object}, {L"expectedStamp", knjson::Type::Object}}},
        {L"disassemblyRead",
         {{L"expression", knjson::Type::String}, {L"count", knjson::Type::String},
          {L"source", knjson::Type::Object}, {L"expectedStamp", knjson::Type::Object}}},
        {L"breakpointPlan",
         {{L"operation", knjson::Type::String}, {L"expression", knjson::Type::String},
          {L"source", knjson::Type::Object}, {L"expectedStamp", knjson::Type::Object}}},
        {L"breakpointApply",
         {{L"planId", knjson::Type::String}, {L"approvalToken", knjson::Type::String}, {L"expectedStamp", knjson::Type::Object}}},
        {L"debuggerAction", {{L"operation", knjson::Type::String}, {L"expectedStamp", knjson::Type::Object}}},
        {L"breakExecution", {{L"expectedStamp", knjson::Type::Object}}},
        {L"processAction",
         {{L"resultId", knjson::Type::String}, {L"index", knjson::Type::String},
          {L"action", knjson::Type::String}, {L"expectedStamp", knjson::Type::Object}}},
        {L"navigateResult",
         {{L"resultId", knjson::Type::String},
          {L"collection", knjson::Type::String},
          {L"index", knjson::Type::String},
          {L"action", knjson::Type::String},
          {L"expectedStamp", knjson::Type::Object}}},
        {L"previewWrite", {{L"command", knjson::Type::String}}},
        {L"executePlan", {{L"planId", knjson::Type::String}, {L"approvalToken", knjson::Type::String}}},
        {L"discardPlan", {{L"planId", knjson::Type::String}, {L"approvalToken", knjson::Type::String}}},
        {L"interrupt", {{L"requestId", knjson::Type::String}}},
        {L"operationStatus", {{L"operationId", knjson::Type::String}, {L"requestId", knjson::Type::String}}},
        {L"operationAck", {{L"operationId", knjson::Type::String}}},
        {L"operations", {{L"cursor", knjson::Type::String}}},
        {L"outputChunk", {{L"resultId", knjson::Type::String}, {L"cursor", knjson::Type::String}}},
        {L"resultPage", {{L"resultId", knjson::Type::String}, {L"offset", knjson::Type::String}, {L"collection", knjson::Type::String}}},
        {L"resultInfo", {{L"resultId", knjson::Type::String}}},
        {L"resultTabs", {{L"resultIds", knjson::Type::Array}}},
        {L"saveLog", {{L"resultId", knjson::Type::String}}}};
    const auto specification = methods.find(method);
    if (specification == methods.end() || !params.IsObject() || params.Fields().size() != specification->second.size())
    {
        reason = L"UnknownRpcMethodOrParameters";
        return false;
    }
    for (const auto &[name, type] : specification->second)
    {
        const auto &value = params.Get(name);
        if (value.GetType() != type || (value.IsString() && value.AsString(L"").size() > 16384))
        {
            reason = L"InvalidRpcParameterTypeOrLimit";
            return false;
        }
    }
    uint64_t id = 0;
    if (!ParseUnsigned(request.Get(L"requestId").AsString(L""), 10, &id) || id == 0 || id > 9007199254740991ULL)
    {
        reason = L"InvalidRequestId";
        return false;
    }
    return true;
}

class RpcGate
{
  public:
    void Navigate(uint64_t generation, std::wstring documentToken = L"")
    {
        generation_ = generation;
        lastId_ = 0;
        hello_ = false;
        documentToken_ = std::move(documentToken);
    }
    bool Accept(const knjson::Value &request, const std::wstring &source, size_t utf8Bytes, std::wstring &reason)
    {
        if (!AppDocument(source) || utf8Bytes > 65536)
        {
            reason = L"UntrustedSourceOrRequestTooLarge";
            return false;
        }
        if (!RpcShape(request, reason))
        {
            return false;
        }
        uint64_t id = 0;
        ParseUnsigned(request.Get(L"requestId").AsString(L""), 10, &id);
        if (id <= lastId_)
        {
            reason = L"ReplayOrOutOfOrderRequest";
            return false;
        }
        const bool hello = request.Get(L"method").AsString(L"") == L"hello";
        if (hello && request.Get(L"params").Get(L"documentToken").AsString(L"") != documentToken_)
        {
            reason = L"StaleDocumentToken";
            return false;
        }
        if (hello ? hello_ || !request.Get(L"uiGeneration").AsString(L"").empty()
                  : !hello_ || request.Get(L"uiGeneration").AsString(L"") != std::to_wstring(generation_))
        {
            reason = L"StaleNavigationOrHandshakeRequired";
            return false;
        }
        lastId_ = id;
        hello_ = hello_ || hello;
        return true;
    }

  private:
    uint64_t generation_ = 0;
    uint64_t lastId_ = 0;
    bool hello_ = false;
    std::wstring documentToken_;
};
} // namespace kncore
