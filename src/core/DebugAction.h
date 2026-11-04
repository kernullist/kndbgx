#pragma once
#include "Result.h"
#include <map>
#include <mutex>
#include <optional>

namespace kncore
{
inline bool ExecutionOperation(const std::wstring &operation)
{
    return operation == L"go" || operation == L"step-into" || operation == L"step-over";
}

struct DebugAction
{
    std::wstring Id;
    std::wstring Token;
    std::wstring Operation;
    uint64_t Operand = 0;
    SessionStamp Stamp;
    std::wstring Original;
    std::chrono::steady_clock::time_point Expires;
    knjson::Value ToJson() const
    {
        auto row = knjson::Value::MakeObject();
        row.Set(L"planId", knjson::Value(Id));
        row.Set(L"approvalToken", knjson::Value(Token));
        row.Set(L"operation", knjson::Value(Operation));
        row.Set(L"operand", knjson::Value(Hex(Operand)));
        row.Set(L"target", Stamp.ToJson());
        row.Set(L"original", knjson::Value(Original));
        row.Set(L"expiresAfterSeconds", knjson::Value(L"60"));
        row.Set(L"effect", knjson::Value(L"ExecutionControl"));
        return row;
    }
};
inline Status RevalidateDebugAction(const DebugAction &action, const SessionStamp &stamp, bool cancelled,
                                    std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now())
{
    if (cancelled)
    {
        return Status::Cancelled;
    }
    return stamp == action.Stamp && now < action.Expires ? Status::Success : Status::StaleContext;
}
class DebugActions
{
  public:
    bool Add(const DebugAction &plan)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::erase_if(plans_,
                      [](const auto &item)
                      {
                          return item.second.Expires <= std::chrono::steady_clock::now();
                      });
        return !plan.Id.empty() && !plan.Token.empty() && plans_.size() < 16 && plans_.emplace(plan.Id, plan).second;
    }
    std::optional<DebugAction> Consume(const std::wstring &id, const std::wstring &token, const SessionStamp &stamp,
                                       std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now())
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto found = plans_.find(id);
        if (found == plans_.end())
        {
            return {};
        }
        const auto plan = found->second;
        plans_.erase(found);
        return plan.Token == token && plan.Stamp == stamp && now < plan.Expires ? std::optional<DebugAction>(plan) : std::nullopt;
    }
    void Clear()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        plans_.clear();
    }
    std::optional<DebugAction> Find(const std::wstring &id, const std::wstring &token)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = plans_.find(id);
        return found != plans_.end() && found->second.Token == token &&
                       std::chrono::steady_clock::now() < found->second.Expires ?
            std::optional<DebugAction>(found->second) : std::nullopt;
    }
    void Discard(const std::wstring &id, const std::wstring &token)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = plans_.find(id);
        if (found != plans_.end() && found->second.Token == token)
        {
            plans_.erase(found);
        }
    }

  private:
    std::mutex mutex_;
    std::map<std::wstring, DebugAction> plans_;
};
inline DebugActions &ActionPlans()
{
    static DebugActions plans;
    return plans;
}
} // namespace kncore
