#pragma once

#include "Result.h"
#include <algorithm>
#include <array>
#include <vector>

namespace kncore
{
class ReadLatency
{
  public:
    void Observe(AddressSpace space, uint64_t address, size_t requested, const ReadResult &result,
                 std::chrono::steady_clock::duration elapsed)
    {
        const auto us = static_cast<uint64_t>((std::max)(int64_t(0),
            std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count()));
        ++reads_;
        maximumUs_ = (std::max)(maximumUs_, us);
        size_t bucket = 0;
        while (bucket < limitsUs_.size() && us >= limitsUs_[bucket])
        {
            ++bucket;
        }
        ++buckets_[bucket];
        if (us >= 250000)
        {
            ++slowReads_;
            slowUs_ += us;
            if (samples_.size() < 8)
            {
                samples_.push_back({space, address, requested, result.Transferred, result.State, result.Error.Code, reads_, us});
            }
        }
    }

    knjson::Value ToJson() const
    {
        auto value = knjson::Value::MakeObject();
        value.Set(L"maximumReadUs", knjson::Value(std::to_wstring(maximumUs_)));
        value.Set(L"slowThresholdUs", knjson::Value(L"250000"));
        value.Set(L"slowReadCount", knjson::Value(std::to_wstring(slowReads_)));
        value.Set(L"slowReadElapsedUs", knjson::Value(std::to_wstring(slowUs_)));
        auto buckets = knjson::Value::MakeArray();
        for (size_t i = 0; i < buckets_.size(); ++i)
        {
            auto bucket = knjson::Value::MakeObject();
            bucket.Set(L"upperExclusiveUs", i < limitsUs_.size() ? knjson::Value(std::to_wstring(limitsUs_[i])) : knjson::Value());
            bucket.Set(L"count", knjson::Value(std::to_wstring(buckets_[i])));
            buckets.Push(std::move(bucket));
        }
        value.Set(L"buckets", std::move(buckets));
        auto samples = knjson::Value::MakeArray();
        for (const auto &sample : samples_)
        {
            auto row = knjson::Value::MakeObject();
            row.Set(L"space", knjson::Value(sample.Space == AddressSpace::Virtual ? L"virtual" : L"physical"));
            row.Set(L"address", knjson::Value(Hex(sample.Address)));
            row.Set(L"requestedBytes", knjson::Value(std::to_wstring(sample.Requested)));
            row.Set(L"transferredBytes", knjson::Value(std::to_wstring(sample.Transferred)));
            row.Set(L"status", knjson::Value(StatusName(sample.State)));
            row.Set(L"errorCode", knjson::Value(Hex(sample.ErrorCode)));
            row.Set(L"readOrdinal", knjson::Value(std::to_wstring(sample.Ordinal)));
            row.Set(L"elapsedUs", knjson::Value(std::to_wstring(sample.ElapsedUs)));
            samples.Push(std::move(row));
        }
        value.Set(L"firstSlowReads", std::move(samples));
        value.Set(L"slowSamplesTruncated", knjson::Value(slowReads_ > samples_.size()));
        return value;
    }

  private:
    struct Sample
    {
        AddressSpace Space;
        uint64_t Address;
        size_t Requested;
        size_t Transferred;
        Status State;
        uint64_t ErrorCode;
        uint64_t Ordinal;
        uint64_t ElapsedUs;
    };
    static constexpr std::array<uint64_t, 5> limitsUs_{1000, 10000, 50000, 250000, 1000000};
    std::array<uint64_t, 6> buckets_{};
    std::vector<Sample> samples_;
    uint64_t reads_ = 0;
    uint64_t maximumUs_ = 0;
    uint64_t slowReads_ = 0;
    uint64_t slowUs_ = 0;
};
} // namespace kncore
