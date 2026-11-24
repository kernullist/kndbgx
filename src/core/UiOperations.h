#pragma once

#include "../util/Json.h"
#include "OperationProgress.h"
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <vector>
#include <algorithm>

namespace kncore
{
struct RequestKey
{
    uint64_t Window = 0;
    uint64_t Document = 0;
    std::wstring Request;
    bool operator==(const RequestKey &) const = default;
};

struct UiOperationState
{
    const RequestKey Key;
    const std::wstring Id;
    const std::wstring Method;
    std::atomic<bool> Cancelled{false};
    std::atomic<uint64_t> Serial{0};
    UiOperationState(RequestKey key, std::wstring id, std::wstring method)
        : Key(std::move(key)), Id(std::move(id)), Method(std::move(method))
    {
    }
};

// Execution and delivery are independent. A completion record must also exist outside the queue buffers.
class UiOperations
{
  public:
    using State = std::shared_ptr<UiOperationState>;
    using Clock = std::chrono::steady_clock;
    static constexpr size_t Capacity = 128;
    static constexpr auto Retention = std::chrono::minutes(30);

    State Admit(const RequestKey &key, const std::wstring &method, Clock::time_point now = Clock::now())
    {
        std::lock_guard lock(mutex_);
        std::erase_if(records_,
                      [&](const Record &record)
                      {
                          return record.Done && (now - record.Completed >= Retention || (record.Acked && BackgroundRead(record)));
                      });
        if (records_.size() >= Capacity)
        {
            const auto acknowledged = std::find_if(records_.begin(), records_.end(),
                                                   [](const Record &record)
                                                   {
                                                       return record.Done && record.Acked;
                                                   });
            if (acknowledged != records_.end())
            {
                records_.erase(acknowledged);
            }
        }
        if (records_.size() >= Capacity || FindKey(key) != nullptr)
        {
            return {};
        }
        auto state = std::make_shared<UiOperationState>(key, std::to_wstring(++next_), method);
        Record record;
        record.Operation = state;
        record.Admitted = now;
        record.StageObserved = now;
        record.ProgressObserved = now;
        records_.push_back(std::move(record));
        return state;
    }

    State Cancel(const RequestKey &key, Clock::time_point now = Clock::now())
    {
        std::lock_guard lock(mutex_);
        auto record = FindKey(key);
        if (record == nullptr || record->Done)
        {
            return {};
        }
        if (!record->Operation->Cancelled.exchange(true))
        {
            record->CancelObserved = now;
        }
        return record->Operation;
    }

    void Running(const State &state, Clock::time_point now = Clock::now())
    {
        std::lock_guard lock(mutex_);
        if (auto record = FindId(state->Id); record != nullptr && !record->Done)
        {
            record->Started = true;
            ObserveRecord(*record, OperationStage::Worker, now);
        }
    }

    void Observe(const State &state, OperationStage stage, Clock::time_point now = Clock::now())
    {
        std::lock_guard lock(mutex_);
        if (auto record = FindId(state->Id); record != nullptr && !record->Done)
        {
            ObserveRecord(*record, stage, now);
        }
    }

    // Called before any transport attempt. A committed success is never changed by a late cancel.
    knjson::Value Complete(const State &state, knjson::Value reply, Clock::time_point now = Clock::now())
    {
        std::lock_guard lock(mutex_);
        auto record = FindId(state->Id);
        if (record != nullptr && !record->Done)
        {
            reply.Set(L"operationId", knjson::Value(state->Id));
            size_t units = 0;
            const bool bounded = reply.WriteStream(
                [&](std::wstring_view fragment)
                {
                    units += fragment.size();
                    return units <= 65536;
                });
            if (!bounded)
            {
                // Stored results keep full metadata. Completion records have a size limit.
                auto compact = knjson::Value::MakeObject();
                for (const auto field : {L"schema", L"requestId", L"uiGeneration", L"type", L"ok", L"operationId"})
                {
                    compact.Set(field, reply.Get(field));
                }
                auto result = knjson::Value::MakeObject();
                for (const auto field :
                     {L"ok", L"resultId", L"path", L"rowCount", L"findingCount", L"outputLength", L"currentTarget", L"artifactCommitted"})
                {
                    result.Set(field, reply.Get(L"result").Get(field));
                }
                auto data = knjson::Value::MakeObject();
                data.Set(L"status", reply.Get(L"result").Get(L"data").Get(L"status"));
                data.Set(L"target", reply.Get(L"result").Get(L"data").Get(L"target"));
                data.Set(L"kind", knjson::Value(L"MetadataReference"));
                data.Set(L"reason",
                         knjson::Value(L"Completion metadata exceeds 64K UTF-16 units; export the stored result for all details"));
                result.Set(L"data", data);
                compact.Set(L"result", result);
                if (!reply.Get(L"error").IsNull())
                {
                    compact.Set(L"error", knjson::Value(L"Error details exceed the completion record limit; inspect the stored result"));
                }
                reply = std::move(compact);
            }
            record->Terminal = std::move(reply);
            record->Done = true;
            record->Completed = now;
            ObserveRecord(*record, OperationStage::ResultReady, now);
        }
        return record != nullptr ? record->Terminal : knjson::Value();
    }

    void Delivery(const std::wstring &id, int32_t status, bool documentGone = false)
    {
        std::lock_guard lock(mutex_);
        if (auto record = FindId(id); record != nullptr && record->Done && !record->Acked)
        {
            record->Delivery = documentGone ? L"DocumentGone" : status < 0 ? L"DeliveryFailed" : L"Posted";
            record->DeliveryError = status;
        }
    }

    bool Ack(const std::wstring &id)
    {
        std::lock_guard lock(mutex_);
        auto record = FindId(id);
        if (record == nullptr || !record->Done)
        {
            return false;
        }
        record->Acked = true;
        record->Delivery = L"Acknowledged";
        return true;
    }

    knjson::Value Status(const RequestKey &key, const std::wstring &id = L"", Clock::time_point now = Clock::now())
    {
        std::lock_guard lock(mutex_);
        auto record = id.empty() ? FindKey(key) : FindId(id);
        return record != nullptr ? Describe(*record, true, now) : knjson::Value();
    }

    knjson::Value List()
    {
        std::lock_guard lock(mutex_);
        auto result = knjson::Value::MakeArray();
        for (const auto &record : records_)
        {
            result.Push(Describe(record, false));
        }
        return result;
    }

    knjson::Value Page(uint64_t after)
    {
        std::lock_guard lock(mutex_);
        auto result = knjson::Value::MakeObject();
        auto records = knjson::Value::MakeArray();
        bool complete = true;
        uint64_t next = after;
        for (const auto &record : records_)
        {
            const auto number = std::stoull(record.Operation->Id);
            if (number <= after || (record.Done && record.Acked && BackgroundRead(record)))
            {
                continue;
            }
            if (records.Items().size() == 16)
            {
                complete = false;
                break;
            }
            records.Push(Describe(record, false));
            next = number;
        }
        result.Set(L"records", records);
        result.Set(L"next", knjson::Value(std::to_wstring(next)));
        result.Set(L"complete", knjson::Value(complete));
        return result;
    }

    void DocumentChanged(uint64_t window, uint64_t document)
    {
        std::lock_guard lock(mutex_);
        for (auto &record : records_)
        {
            if (!record.Acked && (record.Operation->Key.Window != window || record.Operation->Key.Document != document))
            {
                record.Delivery = L"DocumentGone";
            }
        }
    }

  private:
    struct Record
    {
        State Operation;
        bool Started = false;
        bool Done = false;
        bool Acked = false;
        std::wstring Delivery = L"Pending";
        int32_t DeliveryError = 0;
        OperationStage Stage = OperationStage::Queued;
        Clock::time_point Admitted{};
        Clock::time_point StageObserved{};
        Clock::time_point ProgressObserved{};
        Clock::time_point CancelObserved{};
        Clock::time_point Completed{};
        knjson::Value Terminal;
    };
    static void ObserveRecord(Record &record, OperationStage stage, Clock::time_point now)
    {
        if (record.Stage != stage)
        {
            record.Stage = stage;
            record.StageObserved = now;
        }
        record.ProgressObserved = now;
    }
    static bool BackgroundRead(const Record &record)
    {
        return record.Operation->Method == L"status" || record.Operation->Method == L"completeSymbols" ||
               record.Operation->Method == L"symbolModules";
    }
    Record *FindKey(const RequestKey &key)
    {
        for (auto &record : records_)
        {
            if (record.Operation->Key == key)
            {
                return &record;
            }
        }
        return nullptr;
    }
    Record *FindId(const std::wstring &id)
    {
        for (auto &record : records_)
        {
            if (record.Operation->Id == id)
            {
                return &record;
            }
        }
        return nullptr;
    }
    static knjson::Value Describe(const Record &record, bool terminal, Clock::time_point now = Clock::now())
    {
        const auto &state = *record.Operation;
        auto result = knjson::Value::MakeObject();
        result.Set(L"operationId", knjson::Value(state.Id));
        result.Set(L"requestId", knjson::Value(state.Key.Request));
        result.Set(L"windowGeneration", knjson::Value(std::to_wstring(state.Key.Window)));
        result.Set(L"uiGeneration", knjson::Value(std::to_wstring(state.Key.Document)));
        result.Set(L"method", knjson::Value(state.Method));
        result.Set(L"serial", knjson::Value(std::to_wstring(state.Serial.load())));
        result.Set(L"phase", knjson::Value(record.Done              ? L"Completed"
                                           : state.Cancelled.load() ? L"CancelRequested"
                                           : record.Started         ? L"Running"
                                                                    : L"Queued"));
        result.Set(L"delivery", knjson::Value(record.Delivery));
        result.Set(L"deliveryError", knjson::Value(std::to_wstring(record.DeliveryError)));
        const auto end = record.Done ? record.Completed : now;
        const auto milliseconds = [&](Clock::time_point begin)
        {
            return knjson::Value(std::to_wstring((std::max)(int64_t{0},
                static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count()))));
        };
        auto observation = knjson::Value::MakeObject();
        observation.Set(L"stage", knjson::Value(OperationStageName(record.Stage)));
        observation.Set(L"elapsedMs", milliseconds(record.Admitted));
        observation.Set(L"stageElapsedMs", milliseconds(record.StageObserved));
        observation.Set(L"sinceProgressMs", milliseconds(record.ProgressObserved));
        observation.Set(L"cancelElapsedMs", state.Cancelled.load() && record.CancelObserved != Clock::time_point{}
            ? milliseconds(record.CancelObserved) : knjson::Value());
        observation.Set(L"waitReason", knjson::Value());
        result.Set(L"observation", observation);
        if (record.Done)
        {
            const bool ok = record.Terminal.Get(L"ok").AsBool(false) && record.Terminal.Get(L"result").Get(L"ok").AsBool(true);
            result.Set(L"ok", knjson::Value(ok));
            auto outcome = record.Terminal.Get(L"result").Get(L"data").Get(L"status").AsString(L"");
            if (outcome.empty())
            {
                outcome = ok                                                                                     ? L"Success"
                          : record.Terminal.Get(L"error").AsString(L"").find(L"Cancelled") != std::wstring::npos ? L"Cancelled"
                                                                                                                 : L"Failed";
            }
            result.Set(L"outcome", knjson::Value(outcome));
            result.Set(L"resultId", record.Terminal.Get(L"result").Get(L"resultId"));
            if (terminal)
            {
                result.Set(L"path", record.Terminal.Get(L"result").Get(L"path"));
                result.Set(L"error", record.Terminal.Get(L"error"));
                result.Set(L"terminal", record.Terminal);
            }
        }
        return result;
    }
    std::mutex mutex_;
    std::vector<Record> records_;
    uint64_t next_ = 0;
};
} // namespace kncore
