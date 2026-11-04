#pragma once

#include "Result.h"
#include "Layout.h"
#include <map>
#include <mutex>
#include <algorithm>
#include <string>

namespace knlog
{
void Write(const std::wstring &line);
}

namespace kncore
{
// Diagnostics-only: names the refusing stage when mutation planning fails
// without a specific message (KNDBGX_DIAGNOSTICS=1 gates the write).
inline void TraceMutationRefusal(const wchar_t *stage, Status state, const SessionStamp &planned, const SessionStamp &current)
{
    knlog::Write(std::wstring(stage) + L" refused state=" + StatusName(state) + L" planned(t=" +
                 std::to_wstring(planned.TargetGeneration) + L",s=" + std::to_wstring(planned.StopEpoch) + L",c=" +
                 std::to_wstring(planned.ContextGeneration) + L",y=" + std::to_wstring(planned.SymbolGeneration) + L") current(t=" +
                 std::to_wstring(current.TargetGeneration) + L",s=" + std::to_wstring(current.StopEpoch) + L",c=" +
                 std::to_wstring(current.ContextGeneration) + L",y=" + std::to_wstring(current.SymbolGeneration) + L")");
}

struct MutationIntent
{
    std::wstring CommandId;
    std::wstring NormalizedArguments;
    uint64_t Address = 0;
    std::vector<unsigned char> Desired;
    std::wstring LayoutProfile;
    std::optional<FieldInfo> Field;
    std::wstring ModuleName;
    std::wstring TypeName;
    std::wstring FieldName;
};

class MutationTarget : public TargetReader
{
  public:
    virtual SessionStamp CurrentStamp() = 0;
    virtual Status CheckWritable(uint64_t address, size_t bytes) = 0;
    virtual TransferResult Write(uint64_t address, std::span<const unsigned char> bytes) = 0;
    virtual bool Cancelled() const = 0;
    virtual std::chrono::steady_clock::time_point Now() const
    {
        return std::chrono::steady_clock::now();
    }
    virtual Status ValidateIntent(const MutationIntent &)
    {
        return Status::Success;
    }
};

inline std::wstring BytesHex(std::span<const unsigned char> bytes)
{
    constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring value;
    value.reserve(bytes.size() * 2);
    for (const auto byte : bytes)
    {
        value += digits[byte >> 4];
        value += digits[byte & 15];
    }
    return value;
}

struct MutationPlan
{
    std::wstring Id;
    std::wstring ApprovalToken;
    MutationIntent Intent;
    SessionStamp Stamp;
    std::vector<unsigned char> Original;
    std::chrono::steady_clock::time_point Created;
    std::chrono::steady_clock::time_point Expires;
    int64_t CreatedUtcMilliseconds = 0;

    knjson::Value ToJson() const
    {
        auto value = knjson::Value::MakeObject();
        value.Set(L"planId", knjson::Value(Id));
        value.Set(L"approvalToken", knjson::Value(ApprovalToken));
        value.Set(L"commandId", knjson::Value(Intent.CommandId));
        value.Set(L"arguments", knjson::Value(Intent.NormalizedArguments));
        value.Set(L"stamp", Stamp.ToJson());
        value.Set(L"addressSpace", knjson::Value(L"virtual"));
        value.Set(L"address", knjson::Value(Hex(Intent.Address)));
        value.Set(L"length", knjson::Value(std::to_wstring(Intent.Desired.size())));
        value.Set(L"before", knjson::Value(BytesHex(Original)));
        value.Set(L"after", knjson::Value(BytesHex(Intent.Desired)));
        value.Set(L"effect", knjson::Value(L"TargetMutation"));
        value.Set(L"verification", knjson::Value(L"ExactReadBack"));
        value.Set(L"expiresInSeconds", knjson::Value(60.0));
        value.Set(L"createdUtcMilliseconds", knjson::Value(std::to_wstring(CreatedUtcMilliseconds)));
        value.Set(L"expiresUtcMilliseconds", knjson::Value(std::to_wstring(CreatedUtcMilliseconds + 60000)));
        value.Set(L"atomic", knjson::Value(false));
        value.Set(L"layoutProfile", knjson::Value(Intent.LayoutProfile));
        if (Intent.Field)
        {
            auto field = knjson::Value::MakeObject();
            field.Set(L"offset", knjson::Value(Hex(Intent.Field->Offset)));
            field.Set(L"size", knjson::Value(std::to_wstring(Intent.Field->Size)));
            field.Set(L"signed", knjson::Value(Intent.Field->Kind == FieldKind::Signed));
            field.Set(L"source", knjson::Value(Intent.Field->Source));
            value.Set(L"field", field);
        }
        return value;
    }
};

class MutationPlans
{
  public:
    static constexpr size_t MaxBytes = 65536;

    Result Prepare(MutationTarget &target, const MutationIntent &intent, const std::wstring &id, const std::wstring &token,
                   MutationPlan *prepared, std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now())
    {
        Result result;
        result.CommandId = intent.CommandId;
        result.Source = L"target-memory";
        const auto started = target.Now();
        do
        {
            if (prepared == nullptr || id.empty() || token.empty() || intent.Desired.empty() || intent.Desired.size() > MaxBytes ||
                !ValidRange(intent.Address, intent.Desired.size()))
            {
                result.State = Status::InvalidInput;
                TraceMutationRefusal(L"PlanStore::Prepare entry validation", result.State, SessionStamp{}, SessionStamp{});
                break;
            }
            result.State = target.CheckWritable(intent.Address, intent.Desired.size());
            if (result.State != Status::Success)
            {
                break;
            }
            MutationPlan plan;
            plan.Id = id;
            plan.ApprovalToken = token;
            plan.Intent = intent;
            plan.Stamp = target.CurrentStamp();
            plan.Created = now;
            plan.Expires = now + std::chrono::seconds(60);
            plan.CreatedUtcMilliseconds =
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            const auto original = target.Read(AddressSpace::Virtual, intent.Address, intent.Desired.size());
            if (!Exact(original, intent.Desired.size()))
            {
                result.State = original.State == Status::Success ? Status::Partial : original.State;
                result.Error = original.Error;
                TraceMutationRefusal(L"PlanStore::Prepare original read", result.State, plan.Stamp, target.CurrentStamp());
                break;
            }
            if (target.Cancelled() || target.CurrentStamp() != plan.Stamp || target.Now() - started >= std::chrono::seconds(60))
            {
                result.State = target.Cancelled() ? Status::Cancelled : Status::StaleContext;
                TraceMutationRefusal(L"PlanStore::Prepare stamp recheck", result.State, plan.Stamp, target.CurrentStamp());
                break;
            }
            plan.Original = original.Bytes;
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto it = plans_.begin(); it != plans_.end();)
            {
                if (it->second.Expires <= now)
                {
                    it = plans_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
            if (plans_.size() >= 16 || plans_.contains(id))
            {
                result.State = Status::Unavailable;
                result.Error.Message = L"PlanStoreFullOrDuplicate";
                break;
            }
            plans_.emplace(id, plan);
            result.Stamp = plan.Stamp;
            *prepared = std::move(plan);
        } while (false);
        return result;
    }

    Result Execute(MutationTarget &target, const std::wstring &id, const std::wstring &token,
                   std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now())
    {
        Result result;
        result.Source = L"target-memory";
        result.Consistency = L"StoppedTargetRecheckedNonAtomic";
        const auto started = target.Now();
        MutationPlan plan;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto found = plans_.find(id);
            if (found == plans_.end() || found->second.ApprovalToken != token)
            {
                result.State = Status::InvalidInput;
                result.Error.Message = L"UnknownPlanOrApprovalToken";
                return result;
            }
            plan = std::move(found->second);
            plans_.erase(found);
        }
        result.CommandId = plan.Intent.CommandId;
        result.Stamp = plan.Stamp;
        result.Collected.Expected = plan.Intent.Desired.size();
        const auto expired = [&]()
        {
            return now >= plan.Expires || target.Now() - started >= plan.Expires - now;
        };
        do
        {
            if (target.CurrentStamp() != plan.Stamp || expired())
            {
                result.State = Status::StaleContext;
                result.Error.Message = L"PlanStaleOrExpired";
                break;
            }
            result.State = target.CheckWritable(plan.Intent.Address, plan.Intent.Desired.size());
            if (result.State != Status::Success)
            {
                break;
            }
            result.State = target.ValidateIntent(plan.Intent);
            if (result.State != Status::Success)
            {
                result.Error.Message = L"PdbLayoutChangedOrUnavailable";
                break;
            }
            const auto original = target.Read(AddressSpace::Virtual, plan.Intent.Address, plan.Original.size());
            if (!Exact(original, plan.Original.size()) || original.Bytes != plan.Original || target.CurrentStamp() != plan.Stamp)
            {
                result.State = Status::StaleContext;
                result.Error.Message = L"OriginalStateChangedOrUnavailable";
                break;
            }
            size_t applied = 0;
            while (applied < plan.Intent.Desired.size())
            {
                if (target.Cancelled() || target.CurrentStamp() != plan.Stamp || expired())
                {
                    result.State = target.Cancelled() ? Status::Cancelled : Status::StaleContext;
                    result.Error.Message = L"PlanCancelledStaleOrExpiredDuringExecution";
                    break;
                }
                const size_t count = std::min<size_t>(4096, plan.Intent.Desired.size() - applied);
                const uint64_t address = plan.Intent.Address + applied;
                const auto desired = std::span(plan.Intent.Desired).subspan(applied, count);
                const auto write = target.Write(address, desired);
                auto row = knjson::Value::MakeObject();
                row.Set(L"address", knjson::Value(Hex(address)));
                row.Set(L"requestedBytes", knjson::Value(std::to_wstring(count)));
                row.Set(L"appliedBytes", knjson::Value(std::to_wstring(write.Transferred)));
                bool verified = false;
                if (write.Transferred != 0 && write.Transferred <= count)
                {
                    const auto observed = target.Read(AddressSpace::Virtual, address, write.Transferred);
                    verified =
                        Exact(observed, write.Transferred) && std::equal(observed.Bytes.begin(), observed.Bytes.end(), desired.begin());
                }
                row.Set(L"verified", knjson::Value(verified));
                row.Set(L"status", knjson::Value(StatusName(write.State)));
                result.Rows.Push(row);
                result.Collected.Visited += count;
                result.Collected.Read += std::min(count, write.Transferred);
                if (verified)
                {
                    result.Collected.Decoded += write.Transferred;
                }
                if (write.State != Status::Success || write.Transferred != count || !verified)
                {
                    result.State = Status::Partial;
                    result.Error = write.Error;
                    result.Collected.StopReason = L"WriteOrVerificationIncompleteNoRetry";
                    break;
                }
                applied += count;
            }
            if (result.State == Status::Success && (target.Cancelled() || target.CurrentStamp() != plan.Stamp || expired()))
            {
                result.State = target.Cancelled() ? Status::Cancelled : Status::StaleContext;
                result.Collected.StopReason = L"ContextChangedAfterWrite";
            }
            result.Collected.Complete = applied == plan.Intent.Desired.size() && result.State == Status::Success;
            if (result.Collected.Complete)
            {
                result.Collected.StopReason = L"AppliedAndVerified";
            }
        } while (false);
        return result;
    }

    void Clear()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        plans_.clear();
    }

    void Discard(const std::wstring &id, const std::wstring &token)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = plans_.find(id);
        if (found != plans_.end() && found->second.ApprovalToken == token)
        {
            plans_.erase(found);
        }
    }

  private:
    static bool Exact(const ReadResult &read, size_t length)
    {
        return read.State == Status::Success && read.Transferred == length && read.Bytes.size() == length && read.Valid.size() == length &&
               std::all_of(read.Valid.begin(), read.Valid.end(),
                           [](unsigned char bit)
                           {
                               return bit != 0;
                           });
    }
    std::mutex mutex_;
    std::map<std::wstring, MutationPlan> plans_;
};
} // namespace kncore
