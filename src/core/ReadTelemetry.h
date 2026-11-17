#pragma once

#include "ReadLatency.h"

namespace kncore
{
struct ReadTelemetry
{
    void Observe(AddressSpace space, uint64_t address, size_t length, const TransferResult &result,
                 std::chrono::steady_clock::duration elapsed, const ReadTiming &timing) noexcept
    {
        ++Requests;
        Bytes += length;
        Elapsed += elapsed;
        EngineElapsed += timing.EngineElapsed;
        try
        {
            Latency.Observe(space, address, length, result, elapsed, &timing);
        }
        catch (...)
        {
            EvidenceIncomplete = true;
        }
    }

    knjson::Value ToJson() const
    {
        auto value = knjson::Value::MakeObject();
        value.Set(L"readRequests", knjson::Value(std::to_wstring(Requests)));
        value.Set(L"requestedBytes", knjson::Value(std::to_wstring(Bytes)));
        value.Set(L"readElapsedUs", knjson::Value(std::to_wstring(
            std::chrono::duration_cast<std::chrono::microseconds>(Elapsed).count())));
        value.Set(L"engineElapsedUs", knjson::Value(std::to_wstring(
            std::chrono::duration_cast<std::chrono::microseconds>(EngineElapsed).count())));
        value.Set(L"latency", Latency.ToJson());
        value.Set(L"evidenceIncomplete", knjson::Value(EvidenceIncomplete));
        return value;
    }

    uint64_t Requests = 0;
    uint64_t Bytes = 0;
    std::chrono::steady_clock::duration Elapsed{};
    std::chrono::steady_clock::duration EngineElapsed{};
    ReadLatency Latency;
    bool EvidenceIncomplete = false;
};

inline thread_local ReadTelemetry *CurrentReadTelemetry = nullptr;

class ReadTelemetryScope
{
  public:
    explicit ReadTelemetryScope(ReadTelemetry &telemetry) noexcept : previous_(CurrentReadTelemetry)
    {
        CurrentReadTelemetry = &telemetry;
    }
    ~ReadTelemetryScope()
    {
        CurrentReadTelemetry = previous_;
    }
    ReadTelemetryScope(const ReadTelemetryScope &) = delete;
    ReadTelemetryScope &operator=(const ReadTelemetryScope &) = delete;

  private:
    ReadTelemetry *previous_;
};
} // namespace kncore
