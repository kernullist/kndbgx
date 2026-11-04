#pragma once

#include <functional>

namespace kncore
{
enum class OperationStage
{
    Queued,
    Worker,
    ContextQuery,
    SymbolQuery,
    MemoryIo,
    EngineCommand,
    ResultReady
};

inline const wchar_t *OperationStageName(OperationStage stage)
{
    switch (stage)
    {
    case OperationStage::Queued:
        return L"Queued";
    case OperationStage::Worker:
        return L"Worker";
    case OperationStage::ContextQuery:
        return L"ContextQuery";
    case OperationStage::SymbolQuery:
        return L"SymbolQuery";
    case OperationStage::MemoryIo:
        return L"MemoryIo";
    case OperationStage::EngineCommand:
        return L"EngineCommand";
    case OperationStage::ResultReady:
        return L"ResultReady";
    }
    return L"Unknown";
}

using OperationProgressSink = std::function<void(OperationStage)>;
inline thread_local const OperationProgressSink *CurrentProgressSink = nullptr;
inline thread_local OperationStage CurrentOperationStage = OperationStage::Worker;

inline void PublishOperationStage(OperationStage stage) noexcept
{
    if (CurrentProgressSink != nullptr)
    {
        try
        {
            (*CurrentProgressSink)(stage);
        }
        catch (...)
        {
            // Optional observation must not change the operation outcome.
        }
    }
}

class OperationProgressScope
{
  public:
    explicit OperationProgressScope(const OperationProgressSink &sink) noexcept
        : previous_(CurrentProgressSink), previousStage_(CurrentOperationStage)
    {
        CurrentProgressSink = &sink;
        CurrentOperationStage = OperationStage::Worker;
        PublishOperationStage(CurrentOperationStage);
    }
    ~OperationProgressScope()
    {
        CurrentProgressSink = previous_;
        CurrentOperationStage = previousStage_;
    }
    OperationProgressScope(const OperationProgressScope &) = delete;
    OperationProgressScope &operator=(const OperationProgressScope &) = delete;

  private:
    const OperationProgressSink *previous_;
    OperationStage previousStage_;
};

class ObservedStage
{
  public:
    explicit ObservedStage(OperationStage stage) noexcept : previous_(CurrentOperationStage)
    {
        CurrentOperationStage = stage;
        PublishOperationStage(stage);
    }
    ~ObservedStage()
    {
        CurrentOperationStage = previous_;
        PublishOperationStage(previous_);
    }
    ObservedStage(const ObservedStage &) = delete;
    ObservedStage &operator=(const ObservedStage &) = delete;

  private:
    OperationStage previous_;
};
} // namespace kncore
